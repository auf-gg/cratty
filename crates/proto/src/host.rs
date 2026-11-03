use crate::ids::RecordId;
use crate::secret::{Secret, SecretPurpose, Secrets};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum HostAuth {
    #[default]
    Auto,
    Password,
    Key {
        path: String,
    },
}

impl HostAuth {
    pub fn summary(&self) -> String {
        match self {
            Self::Auto => "агент и ключи".into(),
            Self::Password => "пароль".into(),
            Self::Key { path } => {
                let name = path
                    .rsplit(['/', '\\'])
                    .next()
                    .filter(|name| !name.is_empty())
                    .unwrap_or(path.as_str());
                if name.is_empty() {
                    "ключ".into()
                } else {
                    format!("ключ {name}")
                }
            }
        }
    }
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRecord {
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub auth: HostAuth,
    #[serde(default, skip_serializing_if = "Secrets::is_empty")]
    pub secrets: Secrets,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub via: Vec<RecordId>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub forward_agent: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forwards: Vec<crate::PortForward>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl core::fmt::Debug for HostRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HostRecord(<скрыт>)")
    }
}

fn default_port() -> u16 {
    22
}

impl HostRecord {
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            label: String::new(),
            host: host.into(),
            port: default_port(),
            user: String::new(),
            auth: HostAuth::Auto,
            secrets: Secrets::new(),
            via: Vec::new(),
            forward_agent: false,
            forwards: Vec::new(),
        }
    }

    pub fn password(&self) -> Option<&Secret> {
        self.secrets.get(SecretPurpose::Password)
    }

    pub fn has_password(&self) -> bool {
        self.secrets.contains(SecretPurpose::Password)
    }

    pub fn set_password(&mut self, password: Secret) {
        self.secrets.set(SecretPurpose::Password, password);
    }

    pub fn forget_password(&mut self) -> bool {
        self.secrets.remove(SecretPurpose::Password)
    }

    pub fn target(&self) -> String {
        let mut text = String::new();
        if !self.user.is_empty() {
            text.push_str(&self.user);
            text.push('@');
        }
        text.push_str(&self.host);
        if self.port != default_port() {
            text.push(':');
            text.push_str(&self.port.to_string());
        }
        text
    }

    pub fn title(&self) -> String {
        if self.label.is_empty() {
            self.target()
        } else {
            self.label.clone()
        }
    }

    pub fn is_usable(&self) -> bool {
        !self.host.trim().is_empty()
    }

    pub fn matches(&self, query: &str) -> bool {
        let query = query.trim().to_lowercase();
        query.is_empty()
            || self.label.to_lowercase().contains(&query)
            || self.target().to_lowercase().contains(&query)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_sobiraetsya_kak_stroka_podklyucheniya() {
        let mut host = HostRecord::new("example.com");
        assert_eq!(host.target(), "example.com");

        host.user = "root".into();
        assert_eq!(host.target(), "root@example.com");

        host.port = 2222;
        assert_eq!(host.target(), "root@example.com:2222");

        host.port = 22;
        assert_eq!(host.target(), "root@example.com");
    }

    #[test]
    fn title_padaet_na_adres_bez_metki() {
        let mut host = HostRecord::new("example.com");
        assert_eq!(host.title(), "example.com");
        host.label = "прод".into();
        assert_eq!(host.title(), "прод");
    }

    #[test]
    fn podpis_klyucha_rezhet_put_lyuboy_platformy() {
        let posix = HostAuth::Key {
            path: "/home/user/.ssh/id_ed25519".into(),
        };
        assert_eq!(posix.summary(), "ключ id_ed25519");

        let windows = HostAuth::Key {
            path: r"C:\Users\user\.ssh\id_rsa".into(),
        };
        assert_eq!(windows.summary(), "ключ id_rsa");

        let bare = HostAuth::Key {
            path: "id_ecdsa".into(),
        };
        assert_eq!(bare.summary(), "ключ id_ecdsa");
    }

    #[test]
    fn poisk_ishchet_i_po_metke_i_po_adresu() {
        let mut host = HostRecord::new("prod-01.example.com");
        host.label = "Боевой".into();

        assert!(host.matches(""));
        assert!(host.matches("боевой"));
        assert!(host.matches("PROD"));
        assert!(host.matches("example"));
        assert!(!host.matches("staging"));
    }

    #[test]
    fn zapis_bez_adresa_negodna() {
        assert!(!HostRecord::default().is_usable());
        assert!(!HostRecord::new("   ").is_usable());
        assert!(HostRecord::new("example.com").is_usable());
    }

    #[test]
    fn razbor_perezhivaet_neznakomye_polya() {
        let json = r#"{"label":"прод","host":"example.com","port":2222,
                       "user":"root","auth":{"kind":"auto"},"будущее":42}"#;
        let host: HostRecord = serde_json::from_str(json).expect("разбор");
        assert_eq!(host.host, "example.com");
        assert_eq!(host.port, 2222);
    }

    #[test]
    fn razbor_perezhivaet_otsutstvuyushchie_polya() {
        let host: HostRecord = serde_json::from_str(r#"{"host":"example.com"}"#).expect("разбор");
        assert_eq!(host.port, 22, "порт обязан подставиться по умолчанию");
        assert_eq!(host.auth, HostAuth::Auto);
        assert!(host.label.is_empty());
    }

    #[test]
    fn cepochka_proksi_sohranyaet_poryadok() {
        let first = RecordId::generate().expect("CSPRNG");
        let second = RecordId::generate().expect("CSPRNG");
        let mut host = HostRecord::new("example.com");
        host.via = vec![first.clone(), second.clone()];

        let json = serde_json::to_string(&host).expect("сериализация");
        let back: HostRecord = serde_json::from_str(&json).expect("разбор");
        assert_eq!(back.via, vec![first, second]);

        let plain = serde_json::to_string(&HostRecord::new("example.com")).expect("сериализация");
        assert!(!plain.contains("via"), "{plain}");
    }

    #[test]
    fn zapis_perezhivaet_serializaciyu() {
        let mut host = HostRecord::new("example.com");
        host.label = "прод".into();
        host.user = "root".into();
        host.auth = HostAuth::Key {
            path: "/home/user/.ssh/id_ed25519".into(),
        };

        let json = serde_json::to_string(&host).expect("сериализация");
        assert_eq!(
            serde_json::from_str::<HostRecord>(&json).expect("разбор"),
            host
        );
    }
}
