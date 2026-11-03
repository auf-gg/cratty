use crate::aad::Aad;
use crate::aead;
use crate::datakey::RecordKey;
use crate::error::Result;
use secrecy::SecretSlice;

pub const RECORD_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordContext<'a> {
    pub vault_id: &'a str,
    pub record_id: &'a str,
    pub rev: u64,
    pub key_gen: u32,
}

impl RecordContext<'_> {
    fn aad(&self) -> Vec<u8> {
        let mut aad = Aad::new("record");
        aad.u8(RECORD_VERSION)
            .bytes(self.vault_id.as_bytes())
            .bytes(self.record_id.as_bytes())
            .u64(self.rev)
            .u32(self.key_gen);
        aad.finish()
    }
}

pub fn seal_record(key: &RecordKey, ctx: &RecordContext<'_>, plaintext: &[u8]) -> Result<Vec<u8>> {
    aead::seal(key.as_key(), &ctx.aad(), plaintext)
}

pub fn open_record(
    key: &RecordKey,
    ctx: &RecordContext<'_>,
    sealed: &[u8],
) -> Result<SecretSlice<u8>> {
    aead::open(key.as_key(), &ctx.aad(), sealed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datakey::DataKey;
    use crate::error::Error;
    use crate::secret::{KEY_LEN, Key32};
    use secrecy::ExposeSecret;

    fn key() -> RecordKey {
        DataKey::from_key(Key32::from_bytes([0x42; KEY_LEN]))
            .record_key()
            .expect("подключ")
    }

    fn ctx() -> RecordContext<'static> {
        RecordContext {
            vault_id: "personal",
            record_id: "host-prod-01",
            rev: 7,
            key_gen: 1,
        }
    }

    #[test]
    fn aad_zapisi_izvestnyy_vektor() {
        let mut expected = Vec::new();
        expected.extend_from_slice(&15u32.to_le_bytes());
        expected.extend_from_slice(b"cratty/vault/v1");
        expected.extend_from_slice(&6u32.to_le_bytes());
        expected.extend_from_slice(b"record");
        expected.push(RECORD_VERSION);
        expected.extend_from_slice(&8u32.to_le_bytes());
        expected.extend_from_slice(b"personal");
        expected.extend_from_slice(&12u32.to_le_bytes());
        expected.extend_from_slice(b"host-prod-01");
        expected.extend_from_slice(&7u64.to_le_bytes());
        expected.extend_from_slice(&1u32.to_le_bytes());

        assert_eq!(ctx().aad(), expected);
    }

    #[test]
    fn roundtrip() {
        let sealed = seal_record(&key(), &ctx(), b"ssh://root@prod").expect("шифрование");
        let opened = open_record(&key(), &ctx(), &sealed).expect("расшифровка");
        assert_eq!(opened.expose_secret(), b"ssh://root@prod");
    }

    #[test]
    fn pustaya_zapis_shifruetsya() {
        let sealed = seal_record(&key(), &ctx(), b"").expect("шифрование");
        let opened = open_record(&key(), &ctx(), &sealed).expect("расшифровка");
        assert!(opened.expose_secret().is_empty());
    }

    #[test]
    fn shifrotekst_ne_soderzhit_otkrytyy_tekst() {
        let plaintext = b"pa$$w0rd from prod";
        let sealed = seal_record(&key(), &ctx(), plaintext).expect("шифрование");
        assert!(
            !sealed
                .windows(plaintext.len())
                .any(|window| window == plaintext)
        );
    }

    #[test]
    fn chuzhoy_klyuch_ne_otkryvaet() {
        let sealed = seal_record(&key(), &ctx(), "секрет".as_bytes()).expect("шифрование");
        let alien = DataKey::generate()
            .expect("CSPRNG")
            .record_key()
            .expect("подключ");
        assert_eq!(
            open_record(&alien, &ctx(), &sealed).unwrap_err(),
            Error::Decrypt
        );
    }

    #[test]
    fn zapis_ne_perestavlyaetsya_na_chuzhoy_adres() {
        let sealed = seal_record(&key(), &ctx(), "пароль от прода".as_bytes()).expect("шифрование");

        let elsewhere = [
            RecordContext {
                vault_id: "team-prod",
                ..ctx()
            },
            RecordContext {
                record_id: "host-staging-01",
                ..ctx()
            },
            RecordContext { rev: 8, ..ctx() },
            RecordContext {
                key_gen: 2,
                ..ctx()
            },
        ];

        for other in elsewhere {
            assert_eq!(
                open_record(&key(), &other, &sealed).unwrap_err(),
                Error::Decrypt,
                "запись открылась по адресу {other:?}"
            );
        }
    }

    #[test]
    fn granicy_identifikatorov_ne_skleivayutsya() {
        let left = RecordContext {
            vault_id: "ab",
            record_id: "c",
            rev: 1,
            key_gen: 1,
        };
        let right = RecordContext {
            vault_id: "a",
            record_id: "bc",
            rev: 1,
            key_gen: 1,
        };
        let sealed = seal_record(&key(), &left, "секрет".as_bytes()).expect("шифрование");
        assert_eq!(
            open_record(&key(), &right, &sealed).unwrap_err(),
            Error::Decrypt
        );
    }

    #[test]
    fn izmenennyy_bayt_shifroteksta_ne_otkryvaet() {
        let sealed = seal_record(&key(), &ctx(), "секрет".as_bytes()).expect("шифрование");
        for i in 0..sealed.len() {
            let mut damaged = sealed.clone();
            damaged[i] ^= 0x01;
            assert_eq!(
                open_record(&key(), &ctx(), &damaged).unwrap_err(),
                Error::Decrypt,
                "байт {i} изменён, а запись открылась"
            );
        }
    }

    #[test]
    fn dve_odinakovye_zapisi_daut_raznye_shifroteksty() {
        let a = seal_record(&key(), &ctx(), "одно и то же".as_bytes()).expect("шифрование");
        let b = seal_record(&key(), &ctx(), "одно и то же".as_bytes()).expect("шифрование");
        assert_ne!(a, b);
    }

    #[test]
    fn klyuch_zapisey_ne_otkryvaet_chuzhoy_domen() {
        let data_key = DataKey::generate().expect("CSPRNG");
        let sealed = seal_record(
            &data_key.record_key().expect("подключ"),
            &ctx(),
            "секрет".as_bytes(),
        )
        .expect("шифрование");

        let identity = data_key.identity_key().expect("подключ");
        let aad = crate::aead::key_material_aad("identity", 1);
        assert_eq!(
            crate::aead::open_to_vec(identity.as_key(), &aad, &sealed).unwrap_err(),
            Error::Decrypt
        );
    }
}
