use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForwardKind {
    #[default]
    Local,
    Remote,
    Dynamic,
    #[serde(other)]
    Unsupported,
}

impl ForwardKind {
    pub fn flag(self) -> &'static str {
        match self {
            Self::Local => "-L",
            Self::Remote => "-R",
            Self::Dynamic => "-D",
            Self::Unsupported => "?",
        }
    }
}

fn yes() -> bool {
    true
}

fn is_true(value: &bool) -> bool {
    *value
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortForward {
    #[serde(default)]
    pub kind: ForwardKind,
    #[serde(default)]
    pub listen_port: u16,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target_host: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub target_port: u16,
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub enabled: bool,
}

fn is_zero(value: &u16) -> bool {
    *value == 0
}

impl PortForward {
    pub fn summary(&self) -> String {
        match self.kind {
            ForwardKind::Dynamic => format!("-D {} (SOCKS5)", self.listen_port),
            ForwardKind::Unsupported => "правило незнакомого вида".into(),
            kind => format!(
                "{} {} → {}",
                kind.flag(),
                self.listen_port,
                join(&self.target_host, self.target_port)
            ),
        }
    }

    pub fn target(&self) -> String {
        join(&self.target_host, self.target_port)
    }

    pub fn is_usable(&self) -> bool {
        match self.kind {
            ForwardKind::Local | ForwardKind::Remote => {
                self.listen_port != 0
                    && !self.target_host.trim().is_empty()
                    && self.target_port != 0
            }
            ForwardKind::Dynamic => self.listen_port != 0,
            ForwardKind::Unsupported => false,
        }
    }
}

fn join(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pravila_chitayutsya_kak_u_ssh() {
        let local = PortForward {
            kind: ForwardKind::Local,
            listen_port: 8080,
            target_host: "db".into(),
            target_port: 5432,
            enabled: true,
        };
        assert_eq!(local.summary(), "-L 8080 → db:5432");
        let dynamic = PortForward {
            kind: ForwardKind::Dynamic,
            listen_port: 1080,
            ..Default::default()
        };
        assert_eq!(dynamic.summary(), "-D 1080 (SOCKS5)");
        assert!(dynamic.is_usable());
        assert!(!PortForward::default().is_usable());
    }

    #[test]
    fn format_zapisi() {
        let rule = PortForward {
            kind: ForwardKind::Remote,
            listen_port: 9000,
            target_host: "localhost".into(),
            target_port: 3000,
            enabled: true,
        };
        let json = serde_json::to_string(&rule).expect("сериализация");
        assert_eq!(
            json,
            r#"{"kind":"remote","listen_port":9000,"target_host":"localhost","target_port":3000}"#
        );
        assert_eq!(
            serde_json::from_str::<PortForward>(&json).expect("разбор"),
            rule
        );

        let future: PortForward =
            serde_json::from_str(r#"{"kind":"udp","listen_port":53,"enabled":false}"#)
                .expect("разбор");
        assert_eq!(future.kind, ForwardKind::Unsupported);
        assert!(!future.enabled);
        assert!(!future.is_usable());
    }
}
