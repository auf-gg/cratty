use serde::{Deserialize, Serialize};

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnippetRecord {
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub run: bool,
}

impl core::fmt::Debug for SnippetRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SnippetRecord(<hidden>)")
    }
}

impl SnippetRecord {
    pub fn title(&self) -> String {
        if self.label.trim().is_empty() {
            self.command
                .lines()
                .next()
                .unwrap_or_default()
                .trim()
                .to_string()
        } else {
            self.label.clone()
        }
    }

    pub fn is_usable(&self) -> bool {
        !self.command.trim().is_empty()
    }

    pub fn keystrokes(&self) -> Vec<u8> {
        let mut text = self.command.replace("\r\n", "\n").replace('\n', "\r");
        if self.run && !text.ends_with('\r') {
            text.push('\r');
        }
        if !self.run {
            while text.ends_with('\r') {
                text.pop();
            }
        }
        text.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snippet(command: &str, run: bool) -> SnippetRecord {
        SnippetRecord {
            label: String::new(),
            command: command.into(),
            run,
        }
    }

    #[test]
    fn keypresses_as_from_keyboard() {
        assert_eq!(snippet("docker ps", true).keystrokes(), b"docker ps\r");
        assert_eq!(snippet("docker ps\n", true).keystrokes(), b"docker ps\r");
        assert_eq!(snippet("docker ps\r\n", false).keystrokes(), b"docker ps");
        assert_eq!(
            snippet("cd /opt\r\nls", true).keystrokes(),
            b"cd /opt\rls\r"
        );
    }

    #[test]
    fn title_from_command() {
        assert_eq!(snippet("  ./all_up.sh\n./x", false).title(), "./all_up.sh");
        let mut named = snippet("x", false);
        named.label = "Bring everything up".into();
        assert_eq!(named.title(), "Bring everything up");
        assert!(!snippet("  \n", true).is_usable());
    }

    #[test]
    fn record_body_parses_back() {
        let body = crate::RecordBody::Snippet(snippet("ls", true));
        let json = serde_json::to_string(&body).expect("serialization");
        assert_eq!(json.matches("\"kind\"").count(), 1, "{json}");
        assert_eq!(
            serde_json::from_str::<crate::RecordBody>(&json).expect("parse"),
            body
        );
    }
}
