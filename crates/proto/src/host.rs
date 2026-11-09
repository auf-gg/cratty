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
            Self::Auto => "agent and keys".into(),
            Self::Password => "password".into(),
            Self::Key { path } => {
                let name = path
                    .rsplit(['/', '\\'])
                    .next()
                    .filter(|name| !name.is_empty())
                    .unwrap_or(path.as_str());
                if name.is_empty() {
                    "key".into()
                } else {
                    format!("key {name}")
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
    /// Group name in the host list; empty — no group.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub group: String,
    /// Icon in the list: a built-in name or `selfhst:<name>`; empty — default.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub icon: String,
    /// Position in its group's list, starting from 1; 0 — unset (those go
    /// after the ordered ones, newer first).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub order: u64,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl core::fmt::Debug for HostRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HostRecord(<hidden>)")
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
            group: String::new(),
            icon: String::new(),
            order: 0,
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
            || self.group.to_lowercase().contains(&query)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_is_built_as_connection_string() {
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
    fn title_falls_back_to_address_without_label() {
        let mut host = HostRecord::new("example.com");
        assert_eq!(host.title(), "example.com");
        host.label = "prod".into();
        assert_eq!(host.title(), "prod");
    }

    #[test]
    fn key_label_strips_path_of_any_platform() {
        let posix = HostAuth::Key {
            path: "/home/user/.ssh/id_ed25519".into(),
        };
        assert_eq!(posix.summary(), "key id_ed25519");

        let windows = HostAuth::Key {
            path: r"C:\Users\user\.ssh\id_rsa".into(),
        };
        assert_eq!(windows.summary(), "key id_rsa");

        let bare = HostAuth::Key {
            path: "id_ecdsa".into(),
        };
        assert_eq!(bare.summary(), "key id_ecdsa");
    }

    #[test]
    fn search_matches_both_label_and_address() {
        let mut host = HostRecord::new("prod-01.example.com");
        host.label = "Production".into();

        assert!(host.matches(""));
        assert!(host.matches("production"));
        assert!(host.matches("PROD"));
        assert!(host.matches("example"));
        assert!(!host.matches("staging"));
    }

    #[test]
    fn record_without_address_is_invalid() {
        assert!(!HostRecord::default().is_usable());
        assert!(!HostRecord::new("   ").is_usable());
        assert!(HostRecord::new("example.com").is_usable());
    }

    #[test]
    fn parsing_survives_unknown_fields() {
        let json = r#"{"label":"prod","host":"example.com","port":2222,
                       "user":"root","auth":{"kind":"auto"},"future":42}"#;
        let host: HostRecord = serde_json::from_str(json).expect("parse");
        assert_eq!(host.host, "example.com");
        assert_eq!(host.port, 2222);
    }

    #[test]
    fn parsing_survives_missing_fields() {
        let host: HostRecord = serde_json::from_str(r#"{"host":"example.com"}"#).expect("parse");
        assert_eq!(host.port, 22, "the port must default");
        assert_eq!(host.auth, HostAuth::Auto);
        assert!(host.label.is_empty());
    }

    #[test]
    fn proxy_chain_keeps_order() {
        let first = RecordId::generate().expect("CSPRNG");
        let second = RecordId::generate().expect("CSPRNG");
        let mut host = HostRecord::new("example.com");
        host.via = vec![first.clone(), second.clone()];

        let json = serde_json::to_string(&host).expect("serialization");
        let back: HostRecord = serde_json::from_str(&json).expect("parse");
        assert_eq!(back.via, vec![first, second]);

        let plain = serde_json::to_string(&HostRecord::new("example.com")).expect("serialization");
        assert!(!plain.contains("via"), "{plain}");
    }

    #[test]
    fn record_survives_serialization() {
        let mut host = HostRecord::new("example.com");
        host.label = "prod".into();
        host.user = "root".into();
        host.auth = HostAuth::Key {
            path: "/home/user/.ssh/id_ed25519".into(),
        };

        let json = serde_json::to_string(&host).expect("serialization");
        assert_eq!(
            serde_json::from_str::<HostRecord>(&json).expect("parse"),
            host
        );
    }
}
