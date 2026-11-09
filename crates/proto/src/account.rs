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
            return Err(Error::Format("the account has no Data Key wrap"));
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
        let params = Argon2idParams::new(1024, 1, 1, [0x31; vault::SALT_LEN]).expect("params");

        let (password_slot, _) =
            WrapSlot::from_password(&data_key, "password".as_bytes(), params, "master password")
                .expect("wrap");
        let external = Key32::generate().expect("CSPRNG");
        let code = RecoveryCode::generate().expect("CSPRNG");

        let mut slots = SlotSet::new();
        slots.push(password_slot);
        slots.push(WrapSlot::from_external_key(&data_key, &external, "keychain").expect("wrap"));
        slots.push(WrapSlot::from_recovery_code(&data_key, &code, "code").expect("wrap"));

        (
            Account::new(VaultId::generate().expect("CSPRNG"), slots, vec![0xA5; 48]),
            data_key,
            external,
            code,
        )
    }

    #[test]
    fn account_survives_serialization() {
        let (account, _, _, _) = account();
        let restored = Account::decode(&account.encode()).expect("parse");
        assert_eq!(restored, account);
        assert_eq!(restored.key_gen, FIRST_KEY_GEN);
        assert_eq!(restored.slots.len(), 3);
    }

    #[test]
    fn all_three_wrappers_survive_disk() {
        let (account, data_key, external, code) = account();
        let restored = Account::decode(&account.encode()).expect("parse");

        let record = crate::Record::new(
            crate::RecordId::generate().expect("CSPRNG"),
            crate::DeviceId::generate().expect("CSPRNG"),
            1_700_000_000_000,
            crate::RecordBody::Host(crate::HostRecord::new("prod-01.example.com")),
        );
        let sealed = record
            .seal(
                &data_key.record_key().expect("subkey"),
                &restored.vault_id,
                restored.key_gen,
            )
            .expect("encryption");

        let by_password = restored
            .slots
            .iter_kind(SlotKind::Password)
            .next()
            .expect("password slot")
            .unlock_with_password("password".as_bytes())
            .expect("unlock")
            .0;
        let by_external = restored
            .slots
            .iter_kind(SlotKind::ExternalKey)
            .next()
            .expect("OS key slot")
            .unlock_with_external_key(&external)
            .expect("unlock");
        let by_code = restored
            .slots
            .iter_kind(SlotKind::RecoveryCode)
            .next()
            .expect("code slot")
            .unlock_with_recovery_code(&code)
            .expect("unlock");

        for opened in [by_password, by_external, by_code] {
            let unsealed = sealed
                .open(&opened.record_key().expect("subkey"), &restored.vault_id)
                .expect("decryption");
            assert_eq!(unsealed, record);
        }
    }

    #[test]
    fn account_does_not_contain_keys_in_plaintext() {
        let (account, _, external, code) = account();
        let bytes = account.encode();

        let needle = external.as_bytes();
        assert!(
            !bytes.windows(needle.len()).any(|window| window == needle),
            "OS key found in the account file"
        );

        let shown = code.format_for_user();
        let needle = vault::secrecy::ExposeSecret::expose_secret(&shown);
        assert!(
            !bytes.windows(needle.len()).any(|window| window == needle),
            "recovery code found in the account file"
        );
    }

    #[test]
    fn corrupted_file_does_not_parse() {
        let (account, _, _, _) = account();
        let bytes = account.encode();

        assert!(Account::decode(b"").is_err());
        assert!(Account::decode(b"{\"hosts\":[]}").is_err());
        for cut in 0..bytes.len() {
            assert!(
                Account::decode(&bytes[..cut]).is_err(),
                "file truncated to {cut} bytes and still parsed"
            );
        }

        let mut extra = bytes.clone();
        extra.push(0);
        assert!(Account::decode(&extra).is_err());
    }

    #[test]
    fn account_without_wrappers_is_rejected() {
        let empty = Account::new(
            VaultId::generate().expect("CSPRNG"),
            SlotSet::new(),
            Vec::new(),
        );
        assert!(Account::decode(&empty.encode()).is_err());
    }
}
