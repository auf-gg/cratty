mod account;
mod error;
mod forward;
mod group;
mod host;
mod icon;
mod ids;
mod key;
mod proxy;
mod record;
mod secret;
mod snippet;
mod wire;

pub use account::{ACCOUNT_MAGIC, Account, FIRST_KEY_GEN};
pub use error::{Error, Result};
pub use forward::{ForwardKind, PortForward};
pub use group::GroupRecord;
pub use host::{HostAuth, HostRecord};
pub use icon::{IconRecord, IconVariant};
pub use ids::{DeviceId, RecordId, VaultId};
pub use key::KeyRecord;
pub use proxy::{ProxyKind, ProxyRecord, SOCKS_PORT};
pub use record::{
    BODY_VERSION, EncryptedRecord, RECORD_MAGIC, Record, RecordBody, VAULT_META_ID, VaultMeta, wins,
};
pub use secret::{Secret, SecretPurpose, Secrets};
pub use snippet::SnippetRecord;

pub const ACCOUNT_FILE: &str = "account";

pub const RECORDS_DIR: &str = "records";

#[cfg(test)]
mod tests {
    use super::*;
    use vault::{Argon2idParams, DataKey, SlotSet, WrapSlot};

    #[test]
    fn zhizn_hranilishcha_ot_sozdaniya_do_udaleniya() {
        let device = DeviceId::generate().expect("CSPRNG");
        let data_key = DataKey::generate().expect("CSPRNG");
        let params = Argon2idParams::new(1024, 1, 1, [0x51; vault::SALT_LEN]).expect("параметры");

        let (slot, _) = WrapSlot::from_password(
            &data_key,
            "мастер-пароль".as_bytes(),
            params,
            "мастер-пароль",
        )
        .expect("обёртка");
        let mut slots = SlotSet::new();
        slots.push(slot);

        let account = Account::new(VaultId::generate().expect("CSPRNG"), slots, Vec::new());

        let mut host = HostRecord::new("prod-01.example.com");
        host.label = "боевой".into();
        let record = Record::new(
            RecordId::generate().expect("CSPRNG"),
            device.clone(),
            1_700_000_000_000,
            RecordBody::Host(host.clone()),
        );
        let on_disk = record
            .seal(
                &data_key.record_key().expect("подключ"),
                &account.vault_id,
                account.key_gen,
            )
            .expect("шифрование")
            .encode();

        let account = Account::decode(&account.encode()).expect("разбор аккаунта");
        let stored = EncryptedRecord::decode(&on_disk).expect("разбор записи");

        let (unlocked, _) = account
            .slots
            .iter()
            .next()
            .expect("слот")
            .unlock_with_password("мастер-пароль".as_bytes())
            .expect("разблокировка");
        let record_key = unlocked.record_key().expect("подключ");

        let opened = stored.open(&record_key, &account.vault_id).expect("чтение");
        assert_eq!(opened.body.as_host(), Some(&host));

        let dead = opened.tombstone(device, 1_700_000_100_000);
        let dead_on_disk = dead
            .seal(&record_key, &account.vault_id, account.key_gen)
            .expect("шифрование")
            .encode();
        let dead = EncryptedRecord::decode(&dead_on_disk)
            .expect("разбор")
            .open(&record_key, &account.vault_id)
            .expect("чтение");

        assert_eq!(dead.id, opened.id);
        assert_eq!(dead.rev, opened.rev + 1);
        assert!(dead.body.is_tombstone());
        assert!(dead.body.as_host().is_none());
    }

    #[test]
    fn neverny_parol_ne_otkryvaet_hranilishche() {
        let data_key = DataKey::generate().expect("CSPRNG");
        let params = Argon2idParams::new(1024, 1, 1, [0x52; vault::SALT_LEN]).expect("параметры");
        let (slot, _) =
            WrapSlot::from_password(&data_key, "правильный".as_bytes(), params, "пароль")
                .expect("обёртка");
        let mut slots = SlotSet::new();
        slots.push(slot);
        let account = Account::new(VaultId::generate().expect("CSPRNG"), slots, Vec::new());

        let restored = Account::decode(&account.encode()).expect("разбор");
        assert!(
            restored
                .slots
                .iter()
                .next()
                .expect("слот")
                .unlock_with_password("неправильный".as_bytes())
                .is_err()
        );
    }
}
