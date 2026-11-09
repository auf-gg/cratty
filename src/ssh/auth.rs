use rust_i18n::t;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, decode_secret_key};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Credential {
    Agent,
    Key(PathBuf),
    Password,
    Stored,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthPlan {
    pub order: Vec<Credential>,
}

const DEFAULT_KEYS: &[&str] = &["id_ed25519", "id_ecdsa", "id_rsa", "id_dsa"];

impl AuthPlan {
    pub fn standard(identity_files: &[PathBuf], ssh_dir: Option<&Path>) -> Self {
        let mut order = vec![Credential::Agent];

        if identity_files.is_empty() {
            if let Some(dir) = ssh_dir {
                for name in DEFAULT_KEYS {
                    let path = dir.join(name);
                    if path.is_file() {
                        order.push(Credential::Key(path));
                    }
                }
            }
        } else {
            order.extend(identity_files.iter().cloned().map(Credential::Key));
        }

        order.push(Credential::Password);
        Self { order }
    }

    pub fn password_only() -> Self {
        Self {
            order: vec![Credential::Password],
        }
    }

    pub fn with_stored_password(mut self) -> Self {
        if self.order.contains(&Credential::Stored) {
            return self;
        }
        match self.order.iter().position(|c| *c == Credential::Password) {
            Some(at) => self.order.insert(at, Credential::Stored),
            None => self.order.push(Credential::Stored),
        }
        self
    }
}

pub fn ssh_dir() -> Option<PathBuf> {
    #[allow(deprecated)]
    std::env::home_dir().map(|home| home.join(".ssh"))
}

pub struct LoadedKey {
    pub key: PrivateKeyWithHashAlg,
    pub label: String,
}

pub fn load_key(path: &Path, passphrase: Option<&str>) -> Result<KeyLoad> {
    let text = std::fs::read_to_string(path)
        .with_context(|| t!("ssh.key_read_failed", path = path.display()))?;

    match decode_secret_key(&text, passphrase) {
        Ok(key) => Ok(KeyLoad::Loaded(key)),
        Err(err) if is_passphrase_error(&err) => Ok(KeyLoad::NeedsPassphrase),
        Err(err) => bail!(t!("ssh.key_parse_failed", path = path.display(), error = err)),
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum KeyLoad {
    Loaded(PrivateKey),
    NeedsPassphrase,
}

fn is_passphrase_error(error: &russh::keys::Error) -> bool {
    use russh::keys::Error;
    matches!(error, Error::KeyIsEncrypted)
        || matches!(error, Error::SshKey(err) if err.to_string().to_lowercase().contains("crypt"))
}

pub fn with_hash_alg(
    key: PrivateKey,
    best_rsa_hash: Option<Option<russh::keys::HashAlg>>,
) -> Result<PrivateKeyWithHashAlg> {
    let hash = match (key.algorithm(), best_rsa_hash) {
        (russh::keys::Algorithm::Rsa { .. }, Some(hash)) => hash,
        _ => None,
    };
    Ok(PrivateKeyWithHashAlg::new(std::sync::Arc::new(key), hash))
}

#[cfg(test)]
mod stored_password_tests {
    use super::*;

    #[test]
    fn stored_password_goes_before_asking_the_human() {
        let plan = AuthPlan::standard(&[], None).with_stored_password();

        let stored = plan
            .order
            .iter()
            .position(|c| *c == Credential::Stored)
            .expect("stored password step");
        let asked = plan
            .order
            .iter()
            .position(|c| *c == Credential::Password)
            .expect("prompt-the-user step");

        assert!(
            stored < asked,
            "the point of a stored password is that no dialog appears"
        );
    }

    #[test]
    fn agent_and_keys_stay_in_front() {
        let plan = AuthPlan::standard(&[], None).with_stored_password();
        assert_eq!(plan.order.first(), Some(&Credential::Agent));

        let agent = plan.order.iter().position(|c| *c == Credential::Agent);
        let stored = plan.order.iter().position(|c| *c == Credential::Stored);
        assert!(agent < stored);
    }

    #[test]
    fn single_password_plan_also_accepts_stored_one() {
        let plan = AuthPlan::password_only().with_stored_password();
        assert_eq!(
            plan.order,
            vec![Credential::Stored, Credential::Password],
            "stored first, then ask"
        );
    }

    #[test]
    fn adding_again_changes_nothing() {
        let once = AuthPlan::standard(&[], None).with_stored_password();
        let twice = once.clone().with_stored_password();
        assert_eq!(once.order, twice.order);
    }

    #[test]
    fn plan_without_password_gets_stored_one_at_the_end() {
        let plan = AuthPlan {
            order: vec![Credential::Agent],
        }
        .with_stored_password();
        assert_eq!(plan.order, vec![Credential::Agent, Credential::Stored]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_comes_first_and_password_last() {
        let plan = AuthPlan::standard(&[], None);
        assert_eq!(plan.order.first(), Some(&Credential::Agent));
        assert_eq!(plan.order.last(), Some(&Credential::Password));
    }

    #[test]
    fn explicit_identity_files_are_kept_in_order_even_if_missing() {
        let files = vec![
            PathBuf::from("/no/such/key"),
            PathBuf::from("/also/missing"),
        ];
        let plan = AuthPlan::standard(&files, None);
        assert_eq!(
            plan.order,
            vec![
                Credential::Agent,
                Credential::Key(files[0].clone()),
                Credential::Key(files[1].clone()),
                Credential::Password,
            ]
        );
    }

    #[test]
    fn default_keys_are_taken_only_when_they_exist() {
        let dir = std::env::temp_dir().join("cratty-auth-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("could not create directory");
        std::fs::write(dir.join("id_ed25519"), "irrelevant").expect("could not write file");

        let plan = AuthPlan::standard(&[], Some(&dir));
        assert_eq!(
            plan.order,
            vec![
                Credential::Agent,
                Credential::Key(dir.join("id_ed25519")),
                Credential::Password,
            ],
            "the plan contains a key that is not on disk"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn encrypted_key_asks_for_a_passphrase_rather_than_failing() {
        let key = PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .expect("could not generate key");
        let encrypted = key
            .encrypt(&mut rand::rng(), "secret")
            .expect("could not encrypt key")
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("could not serialize key");

        let path = std::env::temp_dir().join("cratty-encrypted-key");
        std::fs::write(&path, encrypted.as_bytes()).expect("could not write key");

        assert!(matches!(
            load_key(&path, None).expect("should not be an error"),
            KeyLoad::NeedsPassphrase
        ));
        assert!(matches!(
            load_key(&path, Some("wrong")).expect("should not be an error"),
            KeyLoad::NeedsPassphrase
        ));
        assert!(matches!(
            load_key(&path, Some("secret")).expect("should not be an error"),
            KeyLoad::Loaded(_)
        ));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_broken_file_is_an_error_not_a_passphrase_prompt() {
        let path = std::env::temp_dir().join("cratty-broken-key");
        std::fs::write(&path, "this is not a key at all").expect("could not write file");

        let error = load_key(&path, None).expect_err("a corrupt file should be an error");
        assert!(
            error.to_string().contains("could not be parsed"),
            "unclear error: {error}"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_reports_the_path() {
        let error = load_key(Path::new("/no/such/key"), None)
            .expect_err("a missing file should be an error");
        assert!(error.to_string().contains("could not read the key"));
    }
}
