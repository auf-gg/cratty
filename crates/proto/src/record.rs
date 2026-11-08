use crate::error::{Error, Result};
use crate::host::HostRecord;
use crate::ids::{DeviceId, RecordId, VaultId};
use crate::key::KeyRecord;
use crate::proxy::ProxyRecord;
use crate::wire::{Writer, take_magic};
use serde::{Deserialize, Serialize};
use vault::{RecordContext, RecordKey};
use zeroize::Zeroize;

pub const RECORD_MAGIC: &[u8] = b"cratty/record\x01";

pub const BODY_VERSION: u32 = 1;

/// Id записи со свойствами хранилища. Фиксированный, чтобы все устройства
/// писали в одну запись и сходились по обычному правилу «новее побеждает».
pub const VAULT_META_ID: &str = "00000000000000000000000000000000";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMeta {
    #[serde(default)]
    pub name: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum RecordBody {
    Host(HostRecord),
    Key(KeyRecord),
    Proxy(ProxyRecord),
    Snippet(crate::SnippetRecord),
    /// Свойства самого хранилища (имя). Одна запись с [`VAULT_META_ID`].
    Vault(VaultMeta),
    #[serde(other)]
    Tombstone,
}

impl core::fmt::Debug for RecordBody {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Host(_) => f.write_str("Host(<скрыт>)"),
            Self::Key(_) => f.write_str("Key(<скрыт>)"),
            Self::Proxy(_) => f.write_str("Proxy(<скрыт>)"),
            Self::Snippet(_) => f.write_str("Snippet(<скрыт>)"),
            Self::Vault(_) => f.write_str("Vault(<скрыт>)"),
            Self::Tombstone => f.write_str("Tombstone"),
        }
    }
}

impl RecordBody {
    pub fn is_tombstone(&self) -> bool {
        matches!(self, Self::Tombstone)
    }

    pub fn as_host(&self) -> Option<&HostRecord> {
        match self {
            Self::Host(host) => Some(host),
            _ => None,
        }
    }

    pub fn as_key(&self) -> Option<&KeyRecord> {
        match self {
            Self::Key(key) => Some(key),
            _ => None,
        }
    }

    pub fn as_proxy(&self) -> Option<&ProxyRecord> {
        match self {
            Self::Proxy(proxy) => Some(proxy),
            _ => None,
        }
    }

    pub fn as_vault(&self) -> Option<&VaultMeta> {
        match self {
            Self::Vault(meta) => Some(meta),
            _ => None,
        }
    }

    pub fn as_snippet(&self) -> Option<&crate::SnippetRecord> {
        match self {
            Self::Snippet(snippet) => Some(snippet),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub id: RecordId,
    pub rev: u64,
    pub device_id: DeviceId,
    pub updated_ms: u64,
    pub device_only: bool,
    pub body: RecordBody,
}

#[derive(Serialize, Deserialize)]
struct SealedBody {
    v: u32,
    device_id: String,
    updated_ms: u64,
    #[serde(default, with = "flag_as_number")]
    device_only: bool,
    body: RecordBody,
}

mod flag_as_number {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &bool, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(u8::from(*value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
        Ok(u8::deserialize(deserializer)? != 0)
    }
}

impl Record {
    pub fn new(id: RecordId, device_id: DeviceId, updated_ms: u64, body: RecordBody) -> Self {
        Self {
            id,
            rev: 1,
            device_id,
            updated_ms,
            device_only: false,
            body,
        }
    }

    pub fn with_device_only(mut self, device_only: bool) -> Self {
        self.device_only = device_only;
        self
    }

    pub fn syncable(&self) -> bool {
        !self.device_only
    }

    pub fn next_rev(&self, device_id: DeviceId, updated_ms: u64, body: RecordBody) -> Self {
        Self {
            id: self.id.clone(),
            rev: self.rev.saturating_add(1),
            device_id,
            updated_ms,
            device_only: self.device_only,
            body,
        }
    }

    pub fn tombstone(&self, device_id: DeviceId, updated_ms: u64) -> Self {
        self.next_rev(device_id, updated_ms, RecordBody::Tombstone)
    }

    pub fn seal(
        &self,
        key: &RecordKey,
        vault_id: &VaultId,
        key_gen: u32,
    ) -> Result<EncryptedRecord> {
        let sealed_body = SealedBody {
            v: BODY_VERSION,
            device_id: self.device_id.to_string(),
            updated_ms: self.updated_ms,
            device_only: self.device_only,
            body: self.body.clone(),
        };
        let mut plaintext =
            serde_json::to_vec(&sealed_body).map_err(|error| Error::Body(error.to_string()))?;

        let context = RecordContext {
            vault_id: vault_id.as_str(),
            record_id: self.id.as_str(),
            rev: self.rev,
            key_gen,
        };
        let payload = vault::seal_record(key, &context, &plaintext);
        plaintext.zeroize();
        let payload = payload?;

        Ok(EncryptedRecord {
            id: self.id.clone(),
            rev: self.rev,
            key_gen,
            device_id: self.device_id.clone(),
            updated_ms: self.updated_ms,
            payload,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedRecord {
    pub id: RecordId,
    pub rev: u64,
    pub key_gen: u32,
    pub device_id: DeviceId,
    pub updated_ms: u64,
    pub payload: Vec<u8>,
}

impl EncryptedRecord {
    pub fn open(&self, key: &RecordKey, vault_id: &VaultId) -> Result<Record> {
        let context = RecordContext {
            vault_id: vault_id.as_str(),
            record_id: self.id.as_str(),
            rev: self.rev,
            key_gen: self.key_gen,
        };
        let plaintext = vault::open_record(key, &context, &self.payload)?;

        let sealed: SealedBody = {
            use vault::secrecy::ExposeSecret;
            serde_json::from_slice(plaintext.expose_secret())
                .map_err(|error| Error::Body(error.to_string()))?
        };

        if sealed.v != BODY_VERSION {
            return Err(Error::Body(format!(
                "версия тела записи {} не поддерживается",
                sealed.v
            )));
        }
        if sealed.device_id != self.device_id.as_str() {
            return Err(Error::EnvelopeMismatch("device_id"));
        }
        if sealed.updated_ms != self.updated_ms {
            return Err(Error::EnvelopeMismatch("updated_ms"));
        }

        Ok(Record {
            id: self.id.clone(),
            rev: self.rev,
            device_id: self.device_id.clone(),
            updated_ms: self.updated_ms,
            device_only: sealed.device_only,
            body: sealed.body,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer
            .str(self.id.as_str())
            .u64(self.rev)
            .u32(self.key_gen)
            .str(self.device_id.as_str())
            .u64(self.updated_ms)
            .bytes(&self.payload);

        let mut out = RECORD_MAGIC.to_vec();
        out.extend_from_slice(&writer.finish());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = take_magic(bytes, RECORD_MAGIC)?;
        let id = RecordId::parse(reader.str()?)?;
        let rev = reader.u64()?;
        let key_gen = reader.u32()?;
        let device_id = DeviceId::parse(reader.str()?)?;
        let updated_ms = reader.u64()?;
        let payload = reader.bytes()?.to_vec();
        reader.finish()?;

        Ok(Self {
            id,
            rev,
            key_gen,
            device_id,
            updated_ms,
            payload,
        })
    }
}

pub fn wins<'a>(left: &'a EncryptedRecord, right: &'a EncryptedRecord) -> &'a EncryptedRecord {
    let order = left
        .rev
        .cmp(&right.rev)
        .then(left.updated_ms.cmp(&right.updated_ms))
        .then(left.device_id.cmp(&right.device_id));
    if order == core::cmp::Ordering::Less {
        right
    } else {
        left
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault::{DataKey, Key32};

    #[test]
    fn starye_vidy_zapisey_chitayutsya_kak_udalyonnye() {
        for json in [
            r#"{"kind":"server","base":"http://x","email":"a@b","seq":3}"#,
            r#"{"kind":"team","vault_id":"v","name":"боевой"}"#,
            r#"{"kind":"peer","user_id":"u","pubkey":"AA"}"#,
        ] {
            let body: RecordBody = serde_json::from_str(json).expect(json);
            assert!(body.is_tombstone(), "{json}");
        }
    }

    fn key() -> RecordKey {
        DataKey::from_key(Key32::from_bytes([0x42; 32]))
            .record_key()
            .expect("подключ")
    }

    fn ids() -> (VaultId, RecordId, DeviceId) {
        (
            VaultId::generate().expect("CSPRNG"),
            RecordId::generate().expect("CSPRNG"),
            DeviceId::generate().expect("CSPRNG"),
        )
    }

    fn sample() -> (VaultId, Record) {
        let (vault_id, record_id, device_id) = ids();
        let mut host = HostRecord::new("prod-01.example.com");
        host.label = "боевой".into();
        host.user = "root".into();
        (
            vault_id,
            Record::new(
                record_id,
                device_id,
                1_700_000_000_000,
                RecordBody::Host(host),
            ),
        )
    }

    #[test]
    fn roundtrip_cherez_shifrovanie_i_bayty() {
        let (vault_id, record) = sample();
        let sealed = record.seal(&key(), &vault_id, 1).expect("шифрование");

        let restored = EncryptedRecord::decode(&sealed.encode()).expect("разбор");
        assert_eq!(restored, sealed);

        let opened = restored.open(&key(), &vault_id).expect("расшифровка");
        assert_eq!(opened, record);
    }

    #[test]
    fn shifrotekst_ne_soderzhit_imya_hosta() {
        let (vault_id, record) = sample();
        let bytes = record
            .seal(&key(), &vault_id, 1)
            .expect("шифрование")
            .encode();
        let needle = b"prod-01.example.com";
        assert!(!bytes.windows(needle.len()).any(|window| window == needle));
    }

    #[test]
    fn chuzhoy_klyuch_ne_otkryvaet() {
        let (vault_id, record) = sample();
        let sealed = record.seal(&key(), &vault_id, 1).expect("шифрование");

        let alien = DataKey::generate()
            .expect("CSPRNG")
            .record_key()
            .expect("подключ");
        assert!(sealed.open(&alien, &vault_id).is_err());
    }

    #[test]
    fn zapis_iz_chuzhogo_hranilishcha_ne_otkryvaetsya() {
        let (vault_id, record) = sample();
        let sealed = record.seal(&key(), &vault_id, 1).expect("шифрование");

        let other_vault = VaultId::generate().expect("CSPRNG");
        assert!(sealed.open(&key(), &other_vault).is_err());
    }

    #[test]
    fn pravka_konverta_ne_prohodit() {
        let (vault_id, record) = sample();
        let sealed = record.seal(&key(), &vault_id, 1).expect("шифрование");

        let mut bumped_rev = sealed.clone();
        bumped_rev.rev += 1;
        assert!(bumped_rev.open(&key(), &vault_id).is_err());

        let mut bumped_gen = sealed.clone();
        bumped_gen.key_gen += 1;
        assert!(bumped_gen.open(&key(), &vault_id).is_err());

        let mut moved_time = sealed.clone();
        moved_time.updated_ms += 1;
        assert!(matches!(
            moved_time.open(&key(), &vault_id),
            Err(Error::EnvelopeMismatch("updated_ms"))
        ));

        let mut other_device = sealed.clone();
        other_device.device_id = DeviceId::generate().expect("CSPRNG");
        assert!(matches!(
            other_device.open(&key(), &vault_id),
            Err(Error::EnvelopeMismatch("device_id"))
        ));
    }

    #[test]
    fn izmenennyy_bayt_fayla_ne_razbiraetsya_ili_ne_otkryvaetsya() {
        let (vault_id, record) = sample();
        let sealed = record.seal(&key(), &vault_id, 1).expect("шифрование");
        let bytes = sealed.encode();

        for i in 0..bytes.len() {
            let mut damaged = bytes.clone();
            damaged[i] ^= 0x01;
            let opened =
                EncryptedRecord::decode(&damaged).and_then(|record| record.open(&key(), &vault_id));
            assert!(opened.is_err(), "байт {i} изменён, а запись открылась");
        }
    }

    #[test]
    fn obrezannyy_fayl_ne_razbiraetsya() {
        let (vault_id, record) = sample();
        let bytes = record
            .seal(&key(), &vault_id, 1)
            .expect("шифрование")
            .encode();
        for cut in 0..bytes.len() {
            assert!(
                EncryptedRecord::decode(&bytes[..cut]).is_err(),
                "файл обрезан до {cut} байт и разобрался"
            );
        }
    }

    #[test]
    fn chuzhoy_fayl_ne_razbiraetsya() {
        assert!(EncryptedRecord::decode(b"").is_err());
        assert!(EncryptedRecord::decode(b"{\"hosts\":[]}").is_err());
    }

    #[test]
    fn nadgrobie_zamenyaet_telo_no_ne_zapis() {
        let (vault_id, record) = sample();
        let device = DeviceId::generate().expect("CSPRNG");
        let dead = record.tombstone(device, 1_700_000_001_000);

        assert_eq!(dead.id, record.id);
        assert_eq!(dead.rev, record.rev + 1);
        assert!(dead.body.is_tombstone());

        let sealed = dead.seal(&key(), &vault_id, 1).expect("шифрование");
        let opened = sealed.open(&key(), &vault_id).expect("расшифровка");
        assert!(opened.body.is_tombstone());
    }

    #[test]
    fn konflikt_reshaetsya_po_rev_potom_mtime_potom_device() {
        let (vault_id, record) = sample();
        let sealed = record.seal(&key(), &vault_id, 1).expect("шифрование");

        let mut newer_rev = sealed.clone();
        newer_rev.rev = sealed.rev + 1;
        assert_eq!(wins(&sealed, &newer_rev), &newer_rev);
        assert_eq!(wins(&newer_rev, &sealed), &newer_rev);

        let mut newer_time = sealed.clone();
        newer_time.updated_ms = sealed.updated_ms + 1;
        assert_eq!(wins(&sealed, &newer_time), &newer_time);

        let mut left = sealed.clone();
        let mut right = sealed.clone();
        left.device_id = DeviceId::parse("00000000000000000000000000000001").expect("id");
        right.device_id = DeviceId::parse("00000000000000000000000000000002").expect("id");
        assert_eq!(wins(&left, &right).device_id, right.device_id);
        assert_eq!(wins(&right, &left).device_id, right.device_id);
    }

    #[test]
    fn parol_perezhivaet_shifrovanie_i_disk() {
        let (vault_id, mut record) = sample();
        let mut host = record.body.as_host().expect("хост").clone();
        host.set_password(crate::Secret::new(b"hunter2".to_vec()));
        record.body = RecordBody::Host(host);

        let sealed = record.seal(&key(), &vault_id, 1).expect("шифрование");
        let opened = EncryptedRecord::decode(&sealed.encode())
            .expect("разбор")
            .open(&key(), &vault_id)
            .expect("расшифровка");

        assert_eq!(
            opened
                .body
                .as_host()
                .expect("хост")
                .password()
                .expect("пароль")
                .expose(),
            b"hunter2"
        );
    }

    #[test]
    fn parolya_net_v_shifrotekste() {
        let (vault_id, mut record) = sample();
        let mut host = record.body.as_host().expect("хост").clone();
        host.set_password(crate::Secret::new(b"hunter2".to_vec()));
        record.body = RecordBody::Host(host);

        let bytes = record
            .seal(&key(), &vault_id, 1)
            .expect("шифрование")
            .encode();
        let needle = b"hunter2";
        assert!(!bytes.windows(needle.len()).any(|window| window == needle));
    }

    #[test]
    fn zapis_bez_sekretov_ne_rastet() {
        let (vault_id, record) = sample();
        let without = record.seal(&key(), &vault_id, 1).expect("шифрование");

        let mut host = record.body.as_host().expect("хост").clone();
        host.set_password(crate::Secret::new(b"x".to_vec()));
        let with = Record {
            body: RecordBody::Host(host),
            ..record.clone()
        }
        .seal(&key(), &vault_id, 1)
        .expect("шифрование");

        assert!(with.payload.len() > without.payload.len());
    }

    #[test]
    fn privyazka_k_ustroystvu_perezhivaet_disk() {
        let (vault_id, record) = sample();
        let bound = record.clone().with_device_only(true);

        assert!(record.syncable(), "по умолчанию запись синхронизируется");
        assert!(!bound.syncable());

        let opened = EncryptedRecord::decode(
            &bound
                .seal(&key(), &vault_id, 1)
                .expect("шифрование")
                .encode(),
        )
        .expect("разбор")
        .open(&key(), &vault_id)
        .expect("расшифровка");

        assert!(opened.device_only);
        assert!(!opened.syncable());
    }

    #[test]
    fn privyazka_ne_vidna_v_konverte() {
        let (vault_id, record) = sample();
        let free = record
            .clone()
            .seal(&key(), &vault_id, 1)
            .expect("шифрование");
        let bound = record
            .with_device_only(true)
            .seal(&key(), &vault_id, 1)
            .expect("шифрование");

        assert_eq!(free.id, bound.id);
        assert_eq!(free.rev, bound.rev);
        assert_eq!(free.key_gen, bound.key_gen);
        assert_eq!(free.updated_ms, bound.updated_ms);
        assert_eq!(free.device_id, bound.device_id);
        assert_eq!(
            free.payload.len(),
            bound.payload.len(),
            "по длине шифротекста флаг тоже не должен угадываться"
        );
    }

    #[test]
    fn pravka_ne_snimaet_privyazku() {
        let (_, record) = sample();
        let bound = record.with_device_only(true);

        let device = DeviceId::generate().expect("CSPRNG");
        let edited = bound.next_rev(
            device.clone(),
            1_700_000_500_000,
            RecordBody::Host(HostRecord::new("example.org")),
        );
        assert!(edited.device_only, "привязка потерялась при правке");

        let dead = bound.tombstone(device, 1_700_000_600_000);
        assert!(dead.device_only, "привязка потерялась при удалении");
    }

    #[test]
    fn staraya_zapis_bez_flaga_sinhroniziruetsya() {
        let (vault_id, record) = sample();

        let legacy = format!(
            r#"{{"v":{},"device_id":"{}","updated_ms":{},"body":{{"kind":"host","label":"","host":"example.com","port":22,"user":"","auth":{{"kind":"auto"}}}}}}"#,
            BODY_VERSION, record.device_id, record.updated_ms
        );
        let context = RecordContext {
            vault_id: vault_id.as_str(),
            record_id: record.id.as_str(),
            rev: record.rev,
            key_gen: 1,
        };
        let payload = vault::seal_record(&key(), &context, legacy.as_bytes()).expect("шифрование");
        let stored = EncryptedRecord {
            id: record.id.clone(),
            rev: record.rev,
            key_gen: 1,
            device_id: record.device_id.clone(),
            updated_ms: record.updated_ms,
            payload,
        };

        let opened = stored.open(&key(), &vault_id).expect("расшифровка");
        assert!(!opened.device_only);
        assert!(opened.syncable());
    }

    #[test]
    fn debug_ne_pechataet_telo() {
        let (_, mut record) = sample();
        let mut host = record.body.as_host().expect("хост").clone();
        host.set_password(crate::Secret::new(b"hunter2".to_vec()));
        record.body = RecordBody::Host(host);

        let text = format!("{record:?}");
        assert!(!text.contains("hunter2"), "пароль в Debug: {text}");
        assert!(!text.contains("prod-01"), "адрес в Debug: {text}");
        assert!(text.contains("<скрыт>"));

        assert_eq!(format!("{:?}", RecordBody::Tombstone), "Tombstone");
    }

    #[test]
    fn ravnye_zapisi_ne_menyayut_pobeditelya() {
        let (vault_id, record) = sample();
        let sealed = record.seal(&key(), &vault_id, 1).expect("шифрование");
        let same = sealed.clone();
        assert_eq!(wins(&sealed, &same), &sealed);
    }
}
