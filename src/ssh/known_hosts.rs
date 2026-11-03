use russh::keys::{Error as KeysError, PublicKey, ssh_key::HashAlg};
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub enum HostKeyPolicy {
    KnownHosts,
    KnownHostsFile(PathBuf),
    Fingerprints(Vec<String>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostKeyVerdict {
    Trusted,
    Unknown { fingerprint: String },
    Changed { fingerprint: String, line: usize },
    Unreadable { reason: String },
}

impl HostKeyVerdict {
    pub fn is_trusted(&self) -> bool {
        matches!(self, Self::Trusted)
    }

    pub fn message(&self, host: &str, port: u16) -> String {
        match self {
            Self::Trusted => format!("ключ {host}:{port} известен"),
            Self::Unknown { .. } => format!(
                "Подключение к {host}:{port} впервые — его ключа нет среди известных. \
                 Сверьте отпечаток ниже с тем, что показывает сам сервер \
                 (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub), и доверяйте, \
                 только если совпадает"
            ),
            Self::Changed { fingerprint, line } => format!(
                "КЛЮЧ ХОСТА {host}:{port} ИЗМЕНИЛСЯ — возможна атака посредника. \
                 Записанный ключ в known_hosts, строка {line}; предъявленный отпечаток {fingerprint}"
            ),
            Self::Unreadable { reason } => {
                format!("не удалось проверить ключ {host}:{port}: {reason}")
            }
        }
    }
}

pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

pub fn verify(policy: &HostKeyPolicy, host: &str, port: u16, key: &PublicKey) -> HostKeyVerdict {
    let fingerprint = fingerprint(key);

    match policy {
        HostKeyPolicy::Fingerprints(trusted) => {
            if trusted.iter().any(|expected| expected == &fingerprint) {
                HostKeyVerdict::Trusted
            } else {
                HostKeyVerdict::Unknown { fingerprint }
            }
        }
        HostKeyPolicy::KnownHosts => match default_known_hosts_path() {
            Some(path) => check_file(&path, host, port, key, fingerprint),
            None => HostKeyVerdict::Unreadable {
                reason: "не найден домашний каталог, негде искать ~/.ssh/known_hosts".into(),
            },
        },
        HostKeyPolicy::KnownHostsFile(path) => check_file(path, host, port, key, fingerprint),
    }
}

pub fn learn(policy: &HostKeyPolicy, host: &str, port: u16, key: &PublicKey) -> anyhow::Result<()> {
    use anyhow::{Context, bail};

    let path = match policy {
        HostKeyPolicy::KnownHosts => default_known_hosts_path()
            .ok_or_else(|| anyhow::anyhow!("не найден домашний каталог"))?,
        HostKeyPolicy::KnownHostsFile(path) => path.clone(),
        HostKeyPolicy::Fingerprints(_) => {
            bail!("политика задана списком отпечатков — запоминать некуда")
        }
    };

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("не создать каталог {}", parent.display()))?;
    }

    russh::keys::known_hosts::learn_known_hosts_path(host, port, key, &path)
        .with_context(|| format!("не записать ключ в {}", path.display()))
}

fn default_known_hosts_path() -> Option<PathBuf> {
    #[allow(deprecated)]
    std::env::home_dir().map(|home| home.join(".ssh").join("known_hosts"))
}

fn check_file(
    path: &std::path::Path,
    host: &str,
    port: u16,
    key: &PublicKey,
    fingerprint: String,
) -> HostKeyVerdict {
    if !path.exists() {
        return HostKeyVerdict::Unknown { fingerprint };
    }

    match russh::keys::check_known_hosts_path(host, port, key, path) {
        Ok(true) => HostKeyVerdict::Trusted,
        Ok(false) => HostKeyVerdict::Unknown { fingerprint },
        Err(KeysError::KeyChanged { line }) => HostKeyVerdict::Changed { fingerprint, line },
        Err(err) => HostKeyVerdict::Unreadable {
            reason: format!("{}: {err}", path.display()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::{Algorithm, PrivateKey};

    fn key() -> PublicKey {
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
            .expect("не удалось сгенерировать ключ")
            .public_key()
            .clone()
    }

    #[test]
    fn fingerprint_looks_like_ssh_keygen_output() {
        assert!(fingerprint(&key()).starts_with("SHA256:"));
    }

    #[test]
    fn unlisted_fingerprint_is_not_trusted() {
        let policy = HostKeyPolicy::Fingerprints(vec!["SHA256:совсем-другой".into()]);
        assert!(!verify(&policy, "example", 22, &key()).is_trusted());
    }

    #[test]
    fn listed_fingerprint_is_trusted() {
        let key = key();
        let policy = HostKeyPolicy::Fingerprints(vec![fingerprint(&key)]);
        assert_eq!(
            verify(&policy, "example", 22, &key),
            HostKeyVerdict::Trusted
        );
    }

    #[test]
    fn empty_fingerprint_list_trusts_nobody() {
        let policy = HostKeyPolicy::Fingerprints(Vec::new());
        assert!(!verify(&policy, "example", 22, &key()).is_trusted());
    }

    #[test]
    fn missing_known_hosts_file_means_unknown_not_trusted() {
        let policy = HostKeyPolicy::KnownHostsFile("нет-такого-файла-надеюсь".into());
        assert!(matches!(
            verify(&policy, "example", 22, &key()),
            HostKeyVerdict::Unknown { .. }
        ));
    }
}
