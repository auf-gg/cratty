//! Vault registry: which vaults the app knows about and where they live.
//!
//! The registry holds no secrets — only a name, a directory and a sync folder.
//! The `vaults.json` file sits next to the original vault directory
//! (`<data>/cratty/vaults.json`); new vaults are created in
//! `<data>/cratty/vaults/<id>/`.

use std::fs;
use std::path::{Path, PathBuf};

use rust_i18n::t;
use anyhow::{Context, Result, anyhow};
use proto::DeviceId;
use serde::{Deserialize, Serialize};

pub const FILE_NAME: &str = "vaults.json";
pub const VAULTS_DIR: &str = "vaults";

/// Localized name of the first vault (creation-time default).
pub fn first_vault_name() -> String {
    t!("store.first_vault_name").into_owned()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultEntry {
    pub id: String,
    pub name: String,
    pub path: PathBuf,
    #[serde(default)]
    pub sync_folder: String,
}

impl VaultEntry {
    pub fn sync_folder(&self) -> Option<PathBuf> {
        let trimmed = self.sync_folder.trim();
        (!trimmed.is_empty()).then(|| PathBuf::from(trimmed))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registry {
    #[serde(default)]
    pub vaults: Vec<VaultEntry>,
}

/// Load result: the registry itself and a flag saying it needs to be written.
pub struct Loaded {
    pub registry: Registry,
    pub dirty: bool,
}

impl Registry {
    /// Reads the registry. If the file is missing, carries over the former single
    /// vault (`legacy_root`), when it exists, along with its sync folder.
    pub fn load(file: &Path, legacy_root: &Path, legacy_sync_folder: &str) -> Result<Loaded> {
        match fs::read(file) {
            Ok(bytes) => {
                let registry: Registry = serde_json::from_slice(&bytes)
                    .with_context(|| t!("store.registry_corrupted", path = file.display()).into_owned())?;
                Ok(Loaded {
                    registry,
                    dirty: false,
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut registry = Registry::default();
                if legacy_root.join(proto::ACCOUNT_FILE).is_file() {
                    registry.vaults.push(VaultEntry {
                        id: new_id()?,
                        name: first_vault_name(),
                        path: legacy_root.to_path_buf(),
                        sync_folder: legacy_sync_folder.trim().to_owned(),
                    });
                }
                let dirty = !registry.vaults.is_empty();
                Ok(Loaded { registry, dirty })
            }
            Err(error) => Err(anyhow!(error))
                .with_context(|| t!("store.registry_read_failed", path = file.display()).into_owned()),
        }
    }

    pub fn save(&self, file: &Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self).context(t!("store.registry_serialize_failed").into_owned())?;
        if let Some(parent) = file.parent() {
            fs::create_dir_all(parent)
                .with_context(|| t!("store.create_failed", path = parent.display()).into_owned())?;
        }
        super::write_atomic(file, &bytes)
    }

    /// Describes a new vault in the `<base>/vaults/<id>` directory; the caller
    /// adds it to the registry once the vault has actually been created.
    pub fn new_entry(base: &Path, name: &str) -> Result<VaultEntry> {
        let id = new_id()?;
        Ok(VaultEntry {
            path: base.join(VAULTS_DIR).join(&id),
            id,
            name: name.trim().to_owned(),
            sync_folder: String::new(),
        })
    }

    pub fn get(&self, id: &str) -> Option<&VaultEntry> {
        self.vaults.iter().find(|entry| entry.id == id)
    }

    pub fn upsert(&mut self, entry: VaultEntry) {
        match self.vaults.iter_mut().find(|known| known.id == entry.id) {
            Some(known) => *known = entry,
            None => self.vaults.push(entry),
        }
    }

    pub fn remove(&mut self, id: &str) -> Option<VaultEntry> {
        let at = self.vaults.iter().position(|entry| entry.id == id)?;
        Some(self.vaults.remove(at))
    }
}

fn new_id() -> Result<String> {
    DeviceId::generate()
        .map(|id| id.as_str().to_owned())
        .map_err(|error| anyhow!("{error}"))
}

/// Default name for a new vault: "Vault N".
pub fn default_name(taken: &[String]) -> String {
    (1..)
        .map(|number| t!("store.default_name", number = number).into_owned())
        .find(|name| !taken.iter().any(|known| known == name))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let unique = DeviceId::generate().expect("CSPRNG");
        let path = std::env::temp_dir().join(format!("cratty-registry-{name}-{unique}"));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("directory");
        path
    }

    #[test]
    fn registry_survives_write_and_read() {
        let dir = temp_dir("roundtrip");
        let file = dir.join(FILE_NAME);

        let mut registry = Registry::default();
        let mut entry = Registry::new_entry(&dir, "  Work ").expect("write");
        entry.sync_folder = "/tmp/sync".into();
        registry.upsert(entry.clone());
        registry.save(&file).expect("write");

        let loaded = Registry::load(&file, &dir.join("vault"), "").expect("read");
        assert!(!loaded.dirty);
        assert_eq!(loaded.registry, registry);
        assert_eq!(entry.name, "Work");
        assert_eq!(entry.path, dir.join(VAULTS_DIR).join(&entry.id));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn registry_has_no_secrets_only_name_path_and_folder() {
        let dir = temp_dir("fields");
        let file = dir.join(FILE_NAME);
        let mut registry = Registry::default();
        registry.upsert(Registry::new_entry(&dir, "Home").expect("write"));
        registry.save(&file).expect("write");

        let text = fs::read_to_string(&file).expect("read");
        let value: serde_json::Value = serde_json::from_str(&text).expect("json");
        let keys: Vec<&String> = value["vaults"][0]
            .as_object()
            .expect("object")
            .keys()
            .collect();
        assert_eq!(keys, ["id", "name", "path", "sync_folder"]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn without_file_and_old_copy_registry_is_empty() {
        let dir = temp_dir("empty");
        let loaded =
            Registry::load(&dir.join(FILE_NAME), &dir.join("vault"), "/x").expect("read");
        assert!(loaded.registry.vaults.is_empty());
        assert!(!loaded.dirty);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn old_vault_becomes_primary_along_with_sync_folder() {
        let dir = temp_dir("legacy");
        let legacy = dir.join("vault");
        fs::create_dir_all(&legacy).expect("directory");
        fs::write(legacy.join(proto::ACCOUNT_FILE), b"x").expect("file");

        let loaded = Registry::load(&dir.join(FILE_NAME), &legacy, " /srv/sync ").expect("read");
        assert!(loaded.dirty);
        let [entry] = loaded.registry.vaults.as_slice() else {
            panic!("expected exactly one vault");
        };
        assert_eq!(entry.name, "Main");
        assert_eq!(entry.path, legacy);
        assert_eq!(entry.sync_folder, "/srv/sync");
        assert_eq!(entry.sync_folder(), Some(PathBuf::from("/srv/sync")));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn removal_deletes_only_the_needed_entry() {
        let dir = temp_dir("remove");
        let mut registry = Registry::default();
        let first = Registry::new_entry(&dir, "First").expect("write");
        let second = Registry::new_entry(&dir, "Second").expect("write");
        registry.upsert(first.clone());
        registry.upsert(second.clone());

        assert_eq!(registry.remove(&first.id), Some(first.clone()));
        assert!(registry.remove(&first.id).is_none());
        assert_eq!(registry.vaults, vec![second]);
        assert!(registry.get(&first.id).is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn damaged_registry_is_not_silently_overwritten() {
        let dir = temp_dir("broken");
        let file = dir.join(FILE_NAME);
        fs::write(&file, b"{not json").expect("file");
        assert!(Registry::load(&file, &dir.join("vault"), "").is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_name_does_not_repeat_taken_ones() {
        assert_eq!(default_name(&[]), "Vault 1");
        assert_eq!(
            default_name(&["Vault 1".into(), "Vault 3".into()]),
            "Vault 2"
        );
    }
}
