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

/// Id of the record holding vault properties. Fixed so that all devices
/// write to one record and converge by the usual "newer wins" rule.
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
    /// Host group presentation: name and icon.
    Group(crate::GroupRecord),
    /// Downloaded icon (for example, from the selfh.st catalog) so it is available offline.
    Icon(crate::IconRecord),
    /// Properties of the vault itself (name). A single record with [`VAULT_META_ID`].
    Vault(VaultMeta),
    #[serde(other)]
    Tombstone,
}

impl core::fmt::Debug for RecordBody {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Host(_) => f.write_str("Host(<hidden>)"),
            Self::Key(_) => f.write_str("Key(<hidden>)"),
            Self::Proxy(_) => f.write_str("Proxy(<hidden>)"),
            Self::Snippet(_) => f.write_str("Snippet(<hidden>)"),
            Self::Group(_) => f.write_str("Group(<hidden>)"),
            Self::Icon(_) => f.write_str("Icon(<hidden>)"),
            Self::Vault(_) => f.write_str("Vault(<hidden>)"),
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

    pub fn as_group(&self) -> Option<&crate::GroupRecord> {
        match self {
            Self::Group(group) => Some(group),
            _ => None,
        }
    }

    pub fn as_icon(&self) -> Option<&crate::IconRecord> {
        match self {
            Self::Icon(icon) => Some(icon),
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
                "record body version {} is not supported",
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
    fn old_record_kinds_are_read_as_deleted() {
        for json in [
            r#"{"kind":"server","base":"http://x","email":"a@b","seq":3}"#,
            r#"{"kind":"team","vault_id":"v","name":"production"}"#,
            r#"{"kind":"peer","user_id":"u","pubkey":"AA"}"#,
        ] {
            let body: RecordBody = serde_json::from_str(json).expect(json);
            assert!(body.is_tombstone(), "{json}");
        }
    }

    fn key() -> RecordKey {
        DataKey::from_key(Key32::from_bytes([0x42; 32]))
            .record_key()
            .expect("subkey")
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
        host.label = "production".into();
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
    fn roundtrip_through_encryption_and_bytes() {
        let (vault_id, record) = sample();
        let sealed = record.seal(&key(), &vault_id, 1).expect("encryption");

        let restored = EncryptedRecord::decode(&sealed.encode()).expect("parse");
        assert_eq!(restored, sealed);

        let opened = restored.open(&key(), &vault_id).expect("decryption");
        assert_eq!(opened, record);
    }

    #[test]
    fn ciphertext_does_not_contain_host_name() {
        let (vault_id, record) = sample();
        let bytes = record
            .seal(&key(), &vault_id, 1)
            .expect("encryption")
            .encode();
        let needle = b"prod-01.example.com";
        assert!(!bytes.windows(needle.len()).any(|window| window == needle));
    }

    #[test]
    fn foreign_key_does_not_open() {
        let (vault_id, record) = sample();
        let sealed = record.seal(&key(), &vault_id, 1).expect("encryption");

        let alien = DataKey::generate()
            .expect("CSPRNG")
            .record_key()
            .expect("subkey");
        assert!(sealed.open(&alien, &vault_id).is_err());
    }

    #[test]
    fn record_from_foreign_vault_does_not_open() {
        let (vault_id, record) = sample();
        let sealed = record.seal(&key(), &vault_id, 1).expect("encryption");

        let other_vault = VaultId::generate().expect("CSPRNG");
        assert!(sealed.open(&key(), &other_vault).is_err());
    }

    #[test]
    fn envelope_tampering_is_rejected() {
        let (vault_id, record) = sample();
        let sealed = record.seal(&key(), &vault_id, 1).expect("encryption");

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
    fn modified_file_byte_does_not_parse_or_open() {
        let (vault_id, record) = sample();
        let sealed = record.seal(&key(), &vault_id, 1).expect("encryption");
        let bytes = sealed.encode();

        for i in 0..bytes.len() {
            let mut damaged = bytes.clone();
            damaged[i] ^= 0x01;
            let opened =
                EncryptedRecord::decode(&damaged).and_then(|record| record.open(&key(), &vault_id));
            assert!(opened.is_err(), "byte {i} was modified but the record still opened");
        }
    }

    #[test]
    fn truncated_file_does_not_parse() {
        let (vault_id, record) = sample();
        let bytes = record
            .seal(&key(), &vault_id, 1)
            .expect("encryption")
            .encode();
        for cut in 0..bytes.len() {
            assert!(
                EncryptedRecord::decode(&bytes[..cut]).is_err(),
                "file truncated to {cut} bytes and still parsed"
            );
        }
    }

    #[test]
    fn foreign_file_does_not_parse() {
        assert!(EncryptedRecord::decode(b"").is_err());
        assert!(EncryptedRecord::decode(b"{\"hosts\":[]}").is_err());
    }

    #[test]
    fn tombstone_replaces_body_but_not_record() {
        let (vault_id, record) = sample();
        let device = DeviceId::generate().expect("CSPRNG");
        let dead = record.tombstone(device, 1_700_000_001_000);

        assert_eq!(dead.id, record.id);
        assert_eq!(dead.rev, record.rev + 1);
        assert!(dead.body.is_tombstone());

        let sealed = dead.seal(&key(), &vault_id, 1).expect("encryption");
        let opened = sealed.open(&key(), &vault_id).expect("decryption");
        assert!(opened.body.is_tombstone());
    }

    #[test]
    fn conflict_is_resolved_by_rev_then_mtime_then_device() {
        let (vault_id, record) = sample();
        let sealed = record.seal(&key(), &vault_id, 1).expect("encryption");

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
    fn password_survives_encryption_and_disk() {
        let (vault_id, mut record) = sample();
        let mut host = record.body.as_host().expect("host").clone();
        host.set_password(crate::Secret::new(b"hunter2".to_vec()));
        record.body = RecordBody::Host(host);

        let sealed = record.seal(&key(), &vault_id, 1).expect("encryption");
        let opened = EncryptedRecord::decode(&sealed.encode())
            .expect("parse")
            .open(&key(), &vault_id)
            .expect("decryption");

        assert_eq!(
            opened
                .body
                .as_host()
                .expect("host")
                .password()
                .expect("password")
                .expose(),
            b"hunter2"
        );
    }

    #[test]
    fn password_is_absent_from_ciphertext() {
        let (vault_id, mut record) = sample();
        let mut host = record.body.as_host().expect("host").clone();
        host.set_password(crate::Secret::new(b"hunter2".to_vec()));
        record.body = RecordBody::Host(host);

        let bytes = record
            .seal(&key(), &vault_id, 1)
            .expect("encryption")
            .encode();
        let needle = b"hunter2";
        assert!(!bytes.windows(needle.len()).any(|window| window == needle));
    }

    #[test]
    fn record_without_secrets_does_not_grow() {
        let (vault_id, record) = sample();
        let without = record.seal(&key(), &vault_id, 1).expect("encryption");

        let mut host = record.body.as_host().expect("host").clone();
        host.set_password(crate::Secret::new(b"x".to_vec()));
        let with = Record {
            body: RecordBody::Host(host),
            ..record.clone()
        }
        .seal(&key(), &vault_id, 1)
        .expect("encryption");

        assert!(with.payload.len() > without.payload.len());
    }

    #[test]
    fn device_binding_survives_disk() {
        let (vault_id, record) = sample();
        let bound = record.clone().with_device_only(true);

        assert!(record.syncable(), "a record is synced by default");
        assert!(!bound.syncable());

        let opened = EncryptedRecord::decode(
            &bound
                .seal(&key(), &vault_id, 1)
                .expect("encryption")
                .encode(),
        )
        .expect("parse")
        .open(&key(), &vault_id)
        .expect("decryption");

        assert!(opened.device_only);
        assert!(!opened.syncable());
    }

    #[test]
    fn binding_is_not_visible_in_envelope() {
        let (vault_id, record) = sample();
        let free = record
            .clone()
            .seal(&key(), &vault_id, 1)
            .expect("encryption");
        let bound = record
            .with_device_only(true)
            .seal(&key(), &vault_id, 1)
            .expect("encryption");

        assert_eq!(free.id, bound.id);
        assert_eq!(free.rev, bound.rev);
        assert_eq!(free.key_gen, bound.key_gen);
        assert_eq!(free.updated_ms, bound.updated_ms);
        assert_eq!(free.device_id, bound.device_id);
        assert_eq!(
            free.payload.len(),
            bound.payload.len(),
            "the flag must not be guessable from the ciphertext length either"
        );
    }

    #[test]
    fn tampering_does_not_remove_binding() {
        let (_, record) = sample();
        let bound = record.with_device_only(true);

        let device = DeviceId::generate().expect("CSPRNG");
        let edited = bound.next_rev(
            device.clone(),
            1_700_000_500_000,
            RecordBody::Host(HostRecord::new("example.org")),
        );
        assert!(edited.device_only, "device binding was lost on edit");

        let dead = bound.tombstone(device, 1_700_000_600_000);
        assert!(dead.device_only, "device binding was lost on deletion");
    }

    #[test]
    fn old_record_without_flag_is_synced() {
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
        let payload = vault::seal_record(&key(), &context, legacy.as_bytes()).expect("encryption");
        let stored = EncryptedRecord {
            id: record.id.clone(),
            rev: record.rev,
            key_gen: 1,
            device_id: record.device_id.clone(),
            updated_ms: record.updated_ms,
            payload,
        };

        let opened = stored.open(&key(), &vault_id).expect("decryption");
        assert!(!opened.device_only);
        assert!(opened.syncable());
    }

    #[test]
    fn debug_does_not_print_body() {
        let (_, mut record) = sample();
        let mut host = record.body.as_host().expect("host").clone();
        host.set_password(crate::Secret::new(b"hunter2".to_vec()));
        record.body = RecordBody::Host(host);

        let text = format!("{record:?}");
        assert!(!text.contains("hunter2"), "password in Debug: {text}");
        assert!(!text.contains("prod-01"), "address in Debug: {text}");
        assert!(text.contains("<hidden>"));

        assert_eq!(format!("{:?}", RecordBody::Tombstone), "Tombstone");
    }

    #[test]
    fn equal_records_do_not_change_winner() {
        let (vault_id, record) = sample();
        let sealed = record.seal(&key(), &vault_id, 1).expect("encryption");
        let same = sealed.clone();
        assert_eq!(wins(&sealed, &same), &sealed);
    }
}
