use serde::{Deserialize, Serialize};

use crate::secret::{Secret, SecretPurpose, Secrets};

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRecord {
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub comment: String,
    #[serde(default)]
    pub algorithm: String,
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default, with = "blob")]
    pub public: Vec<u8>,
    #[serde(default)]
    pub source: String,
    #[serde(default, skip_serializing_if = "Secrets::is_empty")]
    pub secrets: Secrets,
}

impl core::fmt::Debug for KeyRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KeyRecord(<скрыт>)")
    }
}

impl KeyRecord {
    pub fn new(public: Vec<u8>, private: Secret) -> Self {
        let mut secrets = Secrets::new();
        secrets.set(SecretPurpose::PrivateKey, private);
        Self {
            label: String::new(),
            comment: String::new(),
            algorithm: String::new(),
            fingerprint: String::new(),
            public,
            source: String::new(),
            secrets,
        }
    }

    pub fn private(&self) -> Option<&Secret> {
        self.secrets.get(SecretPurpose::PrivateKey)
    }

    pub fn is_usable(&self) -> bool {
        !self.public.is_empty() && self.private().is_some_and(|key| !key.is_empty())
    }

    pub fn title(&self) -> String {
        for candidate in [&self.label, &self.comment, &self.fingerprint] {
            if !candidate.trim().is_empty() {
                return candidate.clone();
            }
        }
        "ключ без имени".to_owned()
    }

    pub fn matches(&self, query: &str) -> bool {
        let query = query.trim().to_lowercase();
        query.is_empty()
            || self.label.to_lowercase().contains(&query)
            || self.comment.to_lowercase().contains(&query)
            || self.fingerprint.to_lowercase().contains(&query)
    }
}

mod blob {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(value.iter().copied())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        Vec::<u8>::deserialize(deserializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> KeyRecord {
        let mut record = KeyRecord::new(
            b"\x00\x00\x00\x0bssh-ed25519blob".to_vec(),
            Secret::new(b"PRIVATE".to_vec()),
        );
        record.comment = "dan@laptop".into();
        record.algorithm = "ssh-ed25519".into();
        record.fingerprint = "SHA256:0123".into();
        record.source = "~/.ssh/id_ed25519".into();
        record
    }

    #[test]
    fn zapis_perezhivaet_serializaciyu() {
        let record = key();
        let json = serde_json::to_vec(&record).expect("сериализация");
        let restored: KeyRecord = serde_json::from_slice(&json).expect("разбор");
        assert_eq!(restored, record);
        assert_eq!(
            restored.private().expect("приватная часть").expose(),
            b"PRIVATE"
        );
    }

    #[test]
    fn debug_nichego_ne_pechataet() {
        let text = format!("{:?}", key());
        assert_eq!(text, "KeyRecord(<скрыт>)");
        assert!(!text.contains("dan@laptop"));
    }

    #[test]
    fn nepolnaya_zapis_ne_goditsya() {
        assert!(key().is_usable());

        let mut without_public = key();
        without_public.public.clear();
        assert!(!without_public.is_usable());

        let mut without_private = key();
        without_private.secrets.remove(SecretPurpose::PrivateKey);
        assert!(!without_private.is_usable());
    }

    #[test]
    fn zagolovok_beret_pervoe_neputoe() {
        let mut record = key();
        assert_eq!(record.title(), "dan@laptop");
        record.label = "рабочий".into();
        assert_eq!(record.title(), "рабочий");

        let empty = KeyRecord::default();
        assert_eq!(empty.title(), "ключ без имени");
    }

    #[test]
    fn poisk_idet_po_imeni_kommentariyu_i_otpechatku() {
        let record = key();
        assert!(record.matches(""));
        assert!(record.matches("LAPTOP"));
        assert!(record.matches("sha256:01"));
        assert!(!record.matches("сервер"));
    }
}
