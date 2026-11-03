use crate::error::{Error, Result};
use crate::ids::VaultId;
use crate::wire::{Writer, take_magic};
use vault::SlotSet;

pub const ACCOUNT_MAGIC: &[u8] = b"cratty/account\x01";

pub const FIRST_KEY_GEN: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub vault_id: VaultId,
    pub key_gen: u32,
    pub slots: SlotSet,
    pub identity: Vec<u8>,
}

impl Account {
    pub fn new(vault_id: VaultId, slots: SlotSet, identity: Vec<u8>) -> Self {
        Self {
            vault_id,
            key_gen: FIRST_KEY_GEN,
            slots,
            identity,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer
            .str(self.vault_id.as_str())
            .u32(self.key_gen)
            .bytes(&self.slots.encode())
            .bytes(&self.identity);

        let mut out = ACCOUNT_MAGIC.to_vec();
        out.extend_from_slice(&writer.finish());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = take_magic(bytes, ACCOUNT_MAGIC)?;
        let vault_id = VaultId::parse(reader.str()?)?;
        let key_gen = reader.u32()?;
        let slots = SlotSet::decode(reader.bytes()?)?;
        let identity = reader.bytes()?.to_vec();
        reader.finish()?;

        if slots.is_empty() {
            return Err(Error::Format("в аккаунте нет ни одной обёртки Data Key"));
        }

        Ok(Self {
            vault_id,
            key_gen,
            slots,
            identity,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault::{Argon2idParams, DataKey, Key32, RecoveryCode, SlotKind, WrapSlot};

    fn account() -> (Account, DataKey, Key32, RecoveryCode) {
        let data_key = DataKey::generate().expect("CSPRNG");
        let params = Argon2idParams::new(1024, 1, 1, [0x31; vault::SALT_LEN]).expect("параметры");

        let (password_slot, _) =
            WrapSlot::from_password(&data_key, "пароль".as_bytes(), params, "мастер-пароль")
                .expect("обёртка");
        let external = Key32::generate().expect("CSPRNG");
        let code = RecoveryCode::generate().expect("CSPRNG");

        let mut slots = SlotSet::new();
        slots.push(password_slot);
        slots.push(WrapSlot::from_external_key(&data_key, &external, "keychain").expect("обёртка"));
        slots.push(WrapSlot::from_recovery_code(&data_key, &code, "код").expect("обёртка"));

        (
            Account::new(VaultId::generate().expect("CSPRNG"), slots, vec![0xA5; 48]),
            data_key,
            external,
            code,
        )
    }

    #[test]
    fn akkaunt_perezhivaet_serializaciyu() {
        let (account, _, _, _) = account();
        let restored = Account::decode(&account.encode()).expect("разбор");
        assert_eq!(restored, account);
        assert_eq!(restored.key_gen, FIRST_KEY_GEN);
        assert_eq!(restored.slots.len(), 3);
    }

    #[test]
    fn vse_tri_obertki_perezhivayut_disk() {
        let (account, data_key, external, code) = account();
        let restored = Account::decode(&account.encode()).expect("разбор");

        let record = crate::Record::new(
            crate::RecordId::generate().expect("CSPRNG"),
            crate::DeviceId::generate().expect("CSPRNG"),
            1_700_000_000_000,
            crate::RecordBody::Host(crate::HostRecord::new("prod-01.example.com")),
        );
        let sealed = record
            .seal(
                &data_key.record_key().expect("подключ"),
                &restored.vault_id,
                restored.key_gen,
            )
            .expect("шифрование");

        let by_password = restored
            .slots
            .iter_kind(SlotKind::Password)
            .next()
            .expect("слот пароля")
            .unlock_with_password("пароль".as_bytes())
            .expect("разблокировка")
            .0;
        let by_external = restored
            .slots
            .iter_kind(SlotKind::ExternalKey)
            .next()
            .expect("слот ключа ОС")
            .unlock_with_external_key(&external)
            .expect("разблокировка");
        let by_code = restored
            .slots
            .iter_kind(SlotKind::RecoveryCode)
            .next()
            .expect("слот кода")
            .unlock_with_recovery_code(&code)
            .expect("разблокировка");

        for opened in [by_password, by_external, by_code] {
            let unsealed = sealed
                .open(&opened.record_key().expect("подключ"), &restored.vault_id)
                .expect("расшифровка");
            assert_eq!(unsealed, record);
        }
    }

    #[test]
    fn akkaunt_ne_soderzhit_klyuchey_otkrytym() {
        let (account, _, external, code) = account();
        let bytes = account.encode();

        let needle = external.as_bytes();
        assert!(
            !bytes.windows(needle.len()).any(|window| window == needle),
            "ключ ОС нашёлся в файле аккаунта"
        );

        let shown = code.format_for_user();
        let needle = vault::secrecy::ExposeSecret::expose_secret(&shown);
        assert!(
            !bytes.windows(needle.len()).any(|window| window == needle),
            "код восстановления нашёлся в файле аккаунта"
        );
    }

    #[test]
    fn isporchennyy_fayl_ne_razbiraetsya() {
        let (account, _, _, _) = account();
        let bytes = account.encode();

        assert!(Account::decode(b"").is_err());
        assert!(Account::decode(b"{\"hosts\":[]}").is_err());
        for cut in 0..bytes.len() {
            assert!(
                Account::decode(&bytes[..cut]).is_err(),
                "файл обрезан до {cut} байт и разобрался"
            );
        }

        let mut extra = bytes.clone();
        extra.push(0);
        assert!(Account::decode(&extra).is_err());
    }

    #[test]
    fn akkaunt_bez_obertok_otvergaetsya() {
        let empty = Account::new(
            VaultId::generate().expect("CSPRNG"),
            SlotSet::new(),
            Vec::new(),
        );
        assert!(Account::decode(&empty.encode()).is_err());
    }
}
