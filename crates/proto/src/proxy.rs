use serde::{Deserialize, Serialize};

use crate::secret::{Secret, SecretPurpose, Secrets};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyKind {
    #[default]
    Socks5,
    #[serde(other)]
    Unsupported,
}

impl ProxyKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Socks5 => "SOCKS5",
            Self::Unsupported => "unknown kind",
        }
    }
}

pub const SOCKS_PORT: u16 = 1080;

fn default_port() -> u16 {
    SOCKS_PORT
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyRecord {
    #[serde(default)]
    pub label: String,
    #[serde(default, rename = "protocol")]
    pub kind: ProxyKind,
    #[serde(default)]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub user: String,
    #[serde(default, skip_serializing_if = "Secrets::is_empty")]
    pub secrets: Secrets,
}

impl core::fmt::Debug for ProxyRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ProxyRecord(<hidden>)")
    }
}

impl ProxyRecord {
    pub fn new(kind: ProxyKind, host: impl Into<String>, port: u16) -> Self {
        Self {
            label: String::new(),
            kind,
            host: host.into(),
            port,
            user: String::new(),
            secrets: Secrets::new(),
        }
    }

    pub fn password(&self) -> Option<&Secret> {
        self.secrets.get(SecretPurpose::Password)
    }

    pub fn set_password(&mut self, password: Secret) {
        self.secrets.set(SecretPurpose::Password, password);
    }

    pub fn forget_password(&mut self) -> bool {
        self.secrets.remove(SecretPurpose::Password)
    }

    pub fn address(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    pub fn title(&self) -> String {
        if self.label.is_empty() {
            self.address()
        } else {
            self.label.clone()
        }
    }

    pub fn summary(&self) -> String {
        let login = if self.user.is_empty() {
            "no login".to_string()
        } else {
            format!("login {}", self.user)
        };
        format!("{} · {} · {}", self.kind.name(), self.address(), login)
    }

    pub fn is_usable(&self) -> bool {
        !self.host.trim().is_empty() && self.port != 0 && self.kind != ProxyKind::Unsupported
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_address_is_bracketed() {
        assert_eq!(
            ProxyRecord::new(ProxyKind::Socks5, "proxy.local", 1080).address(),
            "proxy.local:1080"
        );
        assert_eq!(
            ProxyRecord::new(ProxyKind::Socks5, "::1", 9050).address(),
            "[::1]:9050"
        );
    }

    #[test]
    fn record_survives_serialization_with_password() {
        let mut proxy = ProxyRecord::new(ProxyKind::Socks5, "proxy.local", 1080);
        proxy.label = "office".into();
        proxy.user = "dan".into();
        proxy.set_password(Secret::new(b"hunter2".to_vec()));

        let json = serde_json::to_string(&proxy).expect("serialization");
        let back: ProxyRecord = serde_json::from_str(&json).expect("parse");
        assert_eq!(back, proxy);
        assert_eq!(back.password().map(Secret::expose), Some(&b"hunter2"[..]));
    }

    #[test]
    fn unknown_kind_parses_but_is_invalid() {
        let proxy: ProxyRecord =
            serde_json::from_str(r#"{"protocol":"http","host":"proxy.local","port":3128}"#)
                .expect("parse");
        assert_eq!(proxy.kind, ProxyKind::Unsupported);
        assert!(!proxy.is_usable());
    }

    #[test]
    fn proxy_in_record_body_parses_back() {
        let body = crate::RecordBody::Proxy(ProxyRecord::new(ProxyKind::Socks5, "p", 1080));
        let json = serde_json::to_string(&body).expect("serialization");
        assert_eq!(json.matches("\"kind\"").count(), 1, "{json}");
        let back: crate::RecordBody = serde_json::from_str(&json).expect("parse");
        assert_eq!(back, body);
    }

    #[test]
    fn default_port_is_socks() {
        let proxy: ProxyRecord = serde_json::from_str(r#"{"host":"proxy.local"}"#).expect("parse");
        assert_eq!(proxy.port, SOCKS_PORT);
        assert_eq!(proxy.kind, ProxyKind::Socks5);
    }

    #[test]
    fn record_without_address_is_invalid() {
        assert!(!ProxyRecord::default().is_usable());
        assert!(!ProxyRecord::new(ProxyKind::Socks5, "  ", 1080).is_usable());
        assert!(!ProxyRecord::new(ProxyKind::Socks5, "p", 0).is_usable());
    }
}
