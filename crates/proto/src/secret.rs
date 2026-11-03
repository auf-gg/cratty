use core::fmt;
use std::collections::BTreeMap;

use serde::de::{MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq;
use vault::secrecy::{ExposeSecret, SecretBox};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecretPurpose {
    Password,
    KeyPassphrase,
    PrivateKey,
    ServerToken,
    Sudo,
}

impl SecretPurpose {
    pub fn tag(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::KeyPassphrase => "key-passphrase",
            Self::Sudo => "sudo",
            Self::PrivateKey => "private-key",
            Self::ServerToken => "server-token",
        }
    }

    fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "password" => Some(Self::Password),
            "key-passphrase" => Some(Self::KeyPassphrase),
            "sudo" => Some(Self::Sudo),
            "private-key" => Some(Self::PrivateKey),
            "server-token" => Some(Self::ServerToken),
            _ => None,
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Password => "пароль",
            Self::KeyPassphrase => "passphrase от ключа",
            Self::Sudo => "пароль для sudo",
            Self::PrivateKey => "приватный ключ",
            Self::ServerToken => "пропуск на сервер",
        }
    }
}

pub struct Secret(SecretBox<Vec<u8>>);

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(SecretBox::new(Box::new(bytes)))
    }

    pub fn expose(&self) -> &[u8] {
        self.0.expose_secret()
    }

    pub fn is_empty(&self) -> bool {
        self.expose().is_empty()
    }

    pub fn len(&self) -> usize {
        self.expose().len()
    }
}

impl Clone for Secret {
    fn clone(&self) -> Self {
        Self::new(self.expose().to_vec())
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<скрыт>)")
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        self.expose().len() == other.expose().len()
            && bool::from(self.expose().ct_eq(other.expose()))
    }
}

impl Eq for Secret {}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secrets(BTreeMap<SecretPurpose, Secret>);

impl Secrets {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, purpose: SecretPurpose) -> Option<&Secret> {
        self.0.get(&purpose)
    }

    pub fn set(&mut self, purpose: SecretPurpose, secret: Secret) {
        if secret.is_empty() {
            self.0.remove(&purpose);
        } else {
            self.0.insert(purpose, secret);
        }
    }

    pub fn remove(&mut self, purpose: SecretPurpose) -> bool {
        self.0.remove(&purpose).is_some()
    }

    pub fn contains(&self, purpose: SecretPurpose) -> bool {
        self.0.contains_key(&purpose)
    }

    pub fn purposes(&self) -> impl Iterator<Item = SecretPurpose> + '_ {
        self.0.keys().copied()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for Secrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set()
            .entries(self.0.keys().map(|purpose| purpose.tag()))
            .finish()
    }
}

impl Serialize for Secrets {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (purpose, secret) in &self.0 {
            map.serialize_entry(purpose.tag(), secret.expose())?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Secrets {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SecretsVisitor;

        impl<'de> Visitor<'de> for SecretsVisitor {
            type Value = Secrets;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("карта секретов записи")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Secrets, M::Error> {
                let mut secrets = Secrets::new();
                while let Some(tag) = map.next_key::<String>()? {
                    let bytes = map.next_value::<Vec<u8>>()?;
                    if let Some(purpose) = SecretPurpose::from_tag(&tag) {
                        secrets.set(purpose, Secret::new(bytes));
                    }
                }
                Ok(secrets)
            }
        }

        deserializer.deserialize_map(SecretsVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_ne_pechataet_ni_soderzhimoe_ni_dlinu() {
        let secret = Secret::new(b"hunter2".to_vec());
        assert_eq!(format!("{secret:?}"), "Secret(<скрыт>)");

        let mut secrets = Secrets::new();
        secrets.set(SecretPurpose::Password, secret);
        let text = format!("{secrets:?}");
        assert!(text.contains("password"), "назначение показать можно");
        assert!(!text.contains("hunter2"));
        assert!(!text.contains('7'), "длина — тоже сведение о секрете");
    }

    #[test]
    fn sravnenie_rabotaet_i_na_raznoy_dline() {
        let a = Secret::new(b"hunter2".to_vec());
        let b = Secret::new(b"hunter2".to_vec());
        let c = Secret::new(b"hunter3".to_vec());
        let short = Secret::new(b"h".to_vec());

        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, short);
    }

    #[test]
    fn pustoy_sekret_ne_hranitsya() {
        let mut secrets = Secrets::new();
        secrets.set(SecretPurpose::Password, Secret::new(Vec::new()));
        assert!(secrets.is_empty(), "пустой пароль — это отсутствие пароля");

        secrets.set(SecretPurpose::Password, Secret::new(b"x".to_vec()));
        assert_eq!(secrets.len(), 1);
        secrets.set(SecretPurpose::Password, Secret::new(Vec::new()));
        assert!(secrets.is_empty());
    }

    #[test]
    fn naznacheniya_ne_peresekayutsya() {
        let mut secrets = Secrets::new();
        secrets.set(
            SecretPurpose::Password,
            Secret::new("пароль".as_bytes().to_vec()),
        );
        secrets.set(
            SecretPurpose::KeyPassphrase,
            Secret::new(b"passphrase".to_vec()),
        );
        secrets.set(SecretPurpose::Sudo, Secret::new(b"sudo".to_vec()));

        assert_eq!(secrets.len(), 3);
        assert_eq!(
            secrets
                .get(SecretPurpose::Password)
                .expect("пароль")
                .expose(),
            "пароль".as_bytes()
        );
        assert_eq!(
            secrets
                .get(SecretPurpose::KeyPassphrase)
                .expect("passphrase")
                .expose(),
            b"passphrase"
        );

        assert!(secrets.remove(SecretPurpose::Sudo));
        assert!(!secrets.remove(SecretPurpose::Sudo));
        assert!(!secrets.contains(SecretPurpose::Sudo));
        assert!(secrets.contains(SecretPurpose::Password));
    }

    #[test]
    fn serializaciya_perezhivaet_roundtrip() {
        let mut secrets = Secrets::new();
        secrets.set(SecretPurpose::Password, Secret::new(b"hunter2".to_vec()));
        secrets.set(
            SecretPurpose::KeyPassphrase,
            Secret::new(vec![0x00, 0xFF, 0x80]),
        );

        let json = serde_json::to_string(&secrets).expect("сериализация");
        let restored: Secrets = serde_json::from_str(&json).expect("разбор");
        assert_eq!(restored, secrets);
    }

    #[test]
    fn ne_utf8_sekret_perezhivaet_roundtrip() {
        let mut secrets = Secrets::new();
        let bytes = vec![0xFF, 0xFE, 0x00, 0x41];
        secrets.set(SecretPurpose::Password, Secret::new(bytes.clone()));

        let json = serde_json::to_string(&secrets).expect("сериализация");
        let restored: Secrets = serde_json::from_str(&json).expect("разбор");
        assert_eq!(
            restored
                .get(SecretPurpose::Password)
                .expect("пароль")
                .expose(),
            &bytes[..]
        );
    }

    #[test]
    fn neznakomoe_naznachenie_propuskaetsya() {
        let json = r#"{"password":[104,105],"будущее":[1,2,3]}"#;
        let secrets: Secrets = serde_json::from_str(json).expect("разбор");
        assert_eq!(secrets.len(), 1);
        assert_eq!(
            secrets
                .get(SecretPurpose::Password)
                .expect("пароль")
                .expose(),
            b"hi"
        );
    }

    #[test]
    fn pustaya_karta_razbiraetsya() {
        let secrets: Secrets = serde_json::from_str("{}").expect("разбор");
        assert!(secrets.is_empty());
    }

    #[test]
    fn metki_naznacheniy_zafiksirovany() {
        assert_eq!(SecretPurpose::Password.tag(), "password");
        assert_eq!(SecretPurpose::KeyPassphrase.tag(), "key-passphrase");
        assert_eq!(SecretPurpose::Sudo.tag(), "sudo");

        for purpose in [
            SecretPurpose::Password,
            SecretPurpose::KeyPassphrase,
            SecretPurpose::Sudo,
        ] {
            assert_eq!(SecretPurpose::from_tag(purpose.tag()), Some(purpose));
            assert!(!purpose.description().is_empty());
        }
    }
}
