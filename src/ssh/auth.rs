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
        .with_context(|| format!("не прочитать ключ {}", path.display()))?;

    match decode_secret_key(&text, passphrase) {
        Ok(key) => Ok(KeyLoad::Loaded(key)),
        Err(err) if is_passphrase_error(&err) => Ok(KeyLoad::NeedsPassphrase),
        Err(err) => bail!("ключ {} не разбирается: {err}", path.display()),
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
    fn sohranennyy_parol_vstaet_pered_voprosom_cheloveku() {
        let plan = AuthPlan::standard(&[], None).with_stored_password();

        let stored = plan
            .order
            .iter()
            .position(|c| *c == Credential::Stored)
            .expect("шаг сохранённого пароля");
        let asked = plan
            .order
            .iter()
            .position(|c| *c == Credential::Password)
            .expect("шаг вопроса человеку");

        assert!(
            stored < asked,
            "смысл сохранённого пароля в том, чтобы диалог не появлялся"
        );
    }

    #[test]
    fn agent_i_klyuchi_ostayutsya_vperedi() {
        let plan = AuthPlan::standard(&[], None).with_stored_password();
        assert_eq!(plan.order.first(), Some(&Credential::Agent));

        let agent = plan.order.iter().position(|c| *c == Credential::Agent);
        let stored = plan.order.iter().position(|c| *c == Credential::Stored);
        assert!(agent < stored);
    }

    #[test]
    fn plan_iz_odnogo_parolya_tozhe_prinimaet_sohranennyy() {
        let plan = AuthPlan::password_only().with_stored_password();
        assert_eq!(
            plan.order,
            vec![Credential::Stored, Credential::Password],
            "сначала сохранённый, потом спросить"
        );
    }

    #[test]
    fn povtornoe_dobavlenie_nichego_ne_menyaet() {
        let once = AuthPlan::standard(&[], None).with_stored_password();
        let twice = once.clone().with_stored_password();
        assert_eq!(once.order, twice.order);
    }

    #[test]
    fn plan_bez_parolya_poluchaet_sohranennyy_v_konec() {
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
            PathBuf::from("/нет/такого/ключа"),
            PathBuf::from("/тоже/нет"),
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
        std::fs::create_dir_all(&dir).expect("не создать каталог");
        std::fs::write(dir.join("id_ed25519"), "не важно").expect("не записать файл");

        let plan = AuthPlan::standard(&[], Some(&dir));
        assert_eq!(
            plan.order,
            vec![
                Credential::Agent,
                Credential::Key(dir.join("id_ed25519")),
                Credential::Password,
            ],
            "в план попал ключ, которого нет на диске"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn encrypted_key_asks_for_a_passphrase_rather_than_failing() {
        let key = PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .expect("не сгенерировать ключ");
        let encrypted = key
            .encrypt(&mut rand::rng(), "секрет")
            .expect("не зашифровать ключ")
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("не сериализовать ключ");

        let path = std::env::temp_dir().join("cratty-encrypted-key");
        std::fs::write(&path, encrypted.as_bytes()).expect("не записать ключ");

        assert!(matches!(
            load_key(&path, None).expect("не должно быть ошибкой"),
            KeyLoad::NeedsPassphrase
        ));
        assert!(matches!(
            load_key(&path, Some("не тот")).expect("не должно быть ошибкой"),
            KeyLoad::NeedsPassphrase
        ));
        assert!(matches!(
            load_key(&path, Some("секрет")).expect("не должно быть ошибкой"),
            KeyLoad::Loaded(_)
        ));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_broken_file_is_an_error_not_a_passphrase_prompt() {
        let path = std::env::temp_dir().join("cratty-broken-key");
        std::fs::write(&path, "это вообще не ключ").expect("не записать файл");

        let error = load_key(&path, None).expect_err("битый файл должен быть ошибкой");
        assert!(
            error.to_string().contains("не разбирается"),
            "невнятная ошибка: {error}"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_reports_the_path() {
        let error = load_key(Path::new("/нет/такого/ключа"), None)
            .expect_err("отсутствующий файл должен быть ошибкой");
        assert!(error.to_string().contains("не прочитать ключ"));
    }
}
