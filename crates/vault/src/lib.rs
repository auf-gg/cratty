#![forbid(unsafe_code)]

mod aad;
mod aead;
mod base32;
mod datakey;
mod error;
mod kdf;
mod record;
mod recovery;
mod rng;
mod secret;

pub use datakey::{DataKey, IdentityKey, Purpose, RecordKey, SshKeysKey};
pub use error::{Error, Result};
pub use kdf::{
    Argon2idParams, AuthHash, Calibrated, CalibrationLimits, MASTER_OUTPUT_LEN, MasterSecrets,
    SALT_LEN, calibrate, derive_master_secrets,
};
pub use record::{RECORD_VERSION, RecordContext, open_record, seal_record};
pub use recovery::{
    RECOVERY_CODE_BITS, RECOVERY_CODE_BYTES, RECOVERY_CODE_SYMBOLS, RECOVERY_ENTROPY_BYTES,
    RECOVERY_SALT_LEN, RecoveryCode,
};
pub use secret::{KEY_LEN, Key32};
pub use slot::{SLOT_ID_LEN, SlotKind, SlotSet, WrapSlot};

mod slot;

pub use aead::{NONCE_LEN, TAG_LEN};

pub use secrecy;

#[cfg(test)]
mod flow_tests {

    use super::*;
    use secrecy::ExposeSecret;

    fn params() -> Argon2idParams {
        Argon2idParams::for_tests([0x99; SALT_LEN])
    }

    struct Vault {
        slots: SlotSet,
        records: Vec<(String, Vec<u8>)>,
    }

    fn create(password: &[u8]) -> (Vault, Key32, RecoveryCode) {
        let data_key = DataKey::generate().expect("CSPRNG");

        let (password_slot, _) =
            WrapSlot::from_password(&data_key, password, params(), "master password")
                .expect("wrap");
        let keychain_key = Key32::generate().expect("CSPRNG");
        let keychain_slot =
            WrapSlot::from_external_key(&data_key, &keychain_key, "Touch ID").expect("wrap");
        let code = RecoveryCode::generate().expect("CSPRNG");
        let recovery_slot =
            WrapSlot::from_recovery_code(&data_key, &code, "recovery code").expect("wrap");

        let mut slots = SlotSet::new();
        slots.push(password_slot);
        slots.push(keychain_slot);
        slots.push(recovery_slot);

        let record_key = data_key.record_key().expect("subkey");
        let ctx = RecordContext {
            vault_id: "personal",
            record_id: "prod-01",
            rev: 1,
            key_gen: 1,
        };
        let sealed = seal_record(&record_key, &ctx, b"root@prod-01 / 22").expect("encryption");

        (
            Vault {
                slots,
                records: vec![("prod-01".to_owned(), sealed)],
            },
            keychain_key,
            code,
        )
    }

    fn read_record(vault: &Vault, data_key: &DataKey) -> Vec<u8> {
        let record_key = data_key.record_key().expect("subkey");
        let (record_id, sealed) = &vault.records[0];
        let ctx = RecordContext {
            vault_id: "personal",
            record_id,
            rev: 1,
            key_gen: 1,
        };
        open_record(&record_key, &ctx, sealed)
            .expect("decryption")
            .expose_secret()
            .to_vec()
    }

    #[test]
    fn three_unlock_methods_yield_one_data_key() {
        let (vault, keychain_key, code) = create("correct password".as_bytes());

        let by_password = vault
            .slots
            .iter_kind(SlotKind::Password)
            .next()
            .expect("password slot")
            .unlock_with_password("correct password".as_bytes())
            .expect("unlock")
            .0;
        let by_keychain = vault
            .slots
            .iter_kind(SlotKind::ExternalKey)
            .next()
            .expect("keychain slot")
            .unlock_with_external_key(&keychain_key)
            .expect("unlock");
        let by_recovery = vault
            .slots
            .iter_kind(SlotKind::RecoveryCode)
            .next()
            .expect("code slot")
            .unlock_with_recovery_code(&code)
            .expect("unlock");

        assert_eq!(
            read_record(&vault, &by_password),
            b"root@prod-01 / 22".to_vec()
        );
        assert_eq!(
            read_record(&vault, &by_keychain),
            b"root@prod-01 / 22".to_vec()
        );
        assert_eq!(
            read_record(&vault, &by_recovery),
            b"root@prod-01 / 22".to_vec()
        );
    }

    #[test]
    fn password_change_does_not_touch_records() {
        let (mut vault, _, _) = create("old password".as_bytes());
        let before = vault.records.clone();

        let old_slot = vault
            .slots
            .iter_kind(SlotKind::Password)
            .next()
            .expect("password slot")
            .clone();
        let (data_key, _) = old_slot
            .unlock_with_password("old password".as_bytes())
            .expect("unlock");

        let (new_slot, _) = WrapSlot::from_password(
            &data_key,
            "new password".as_bytes(),
            Argon2idParams::for_tests([0xAA; SALT_LEN]),
            "master password",
        )
        .expect("wrap");
        vault.slots.push(new_slot);
        vault.slots.remove(old_slot.id()).expect("removal of the old one");

        assert_eq!(vault.records, before, "records should not have changed");

        let reopened = vault
            .slots
            .iter_kind(SlotKind::Password)
            .next()
            .expect("password slot")
            .unlock_with_password("new password".as_bytes())
            .expect("unlock")
            .0;
        assert_eq!(
            read_record(&vault, &reopened),
            b"root@prod-01 / 22".to_vec()
        );

        assert!(vault.slots.iter_kind(SlotKind::Password).all(|slot| {
            slot.unlock_with_password("old password".as_bytes())
                .is_err()
        }));
    }

    #[test]
    fn recovery_code_opens_forgotten_vault() {
        let (vault, _, code) = create("forgotten password".as_bytes());

        let shown = code.format_for_user();
        let typed = String::from_utf8(shown.expose_secret().to_vec())
            .expect("ASCII")
            .to_lowercase();
        let retyped = RecoveryCode::parse(typed.as_bytes()).expect("parse");

        let data_key = vault
            .slots
            .iter_kind(SlotKind::RecoveryCode)
            .next()
            .expect("code slot")
            .unlock_with_recovery_code(&retyped)
            .expect("unlock");
        assert_eq!(
            read_record(&vault, &data_key),
            b"root@prod-01 / 22".to_vec()
        );
    }

    #[test]
    fn vault_survives_serialization() {
        let (vault, keychain_key, _) = create("password".as_bytes());
        let restored = SlotSet::decode(&vault.slots.encode()).expect("parse");
        assert_eq!(restored, vault.slots);

        let data_key = restored
            .iter_kind(SlotKind::ExternalKey)
            .next()
            .expect("keychain slot")
            .unlock_with_external_key(&keychain_key)
            .expect("unlock");
        assert_eq!(
            read_record(&vault, &data_key),
            b"root@prod-01 / 22".to_vec()
        );
    }

    #[test]
    fn serialized_vault_contains_no_secrets() {
        let password = "correct horse battery staple".as_bytes();
        let (vault, keychain_key, code) = create(password);
        let bytes = vault.slots.encode();

        let data_key = vault
            .slots
            .iter_kind(SlotKind::ExternalKey)
            .next()
            .expect("keychain slot")
            .unlock_with_external_key(&keychain_key)
            .expect("unlock");

        for (what, needle) in [
            ("Data Key", data_key.as_key().as_bytes().as_slice()),
            ("keychain key", keychain_key.as_bytes().as_slice()),
            ("recovery code", code.format_for_user().expose_secret()),
            ("master password", password),
        ] {
            assert!(
                !bytes.windows(needle.len()).any(|window| window == needle),
                "{what} found in the serialized vault"
            );
        }
    }
}
