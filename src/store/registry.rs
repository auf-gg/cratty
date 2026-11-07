//! Реестр хранилищ: какие хранилища известны приложению и где они лежат.
//!
//! В реестре нет секретов — только имя, каталог и папка синхронизации.
//! Файл `vaults.json` лежит рядом с каталогом исходного хранилища
//! (`<данные>/cratty/vaults.json`), новые хранилища создаются в
//! `<данные>/cratty/vaults/<id>/`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use proto::DeviceId;
use serde::{Deserialize, Serialize};

pub const FILE_NAME: &str = "vaults.json";
pub const VAULTS_DIR: &str = "vaults";

pub const FIRST_VAULT_NAME: &str = "Основное";

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

/// Результат загрузки: сам реестр и признак того, что его нужно записать.
pub struct Loaded {
    pub registry: Registry,
    pub dirty: bool,
}

impl Registry {
    /// Читает реестр. Если файла нет, переносит прежнее единственное
    /// хранилище (`legacy_root`), когда оно существует, и его папку синхронизации.
    pub fn load(file: &Path, legacy_root: &Path, legacy_sync_folder: &str) -> Result<Loaded> {
        match fs::read(file) {
            Ok(bytes) => {
                let registry: Registry = serde_json::from_slice(&bytes)
                    .with_context(|| format!("реестр хранилищ {} повреждён", file.display()))?;
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
                        name: FIRST_VAULT_NAME.to_owned(),
                        path: legacy_root.to_path_buf(),
                        sync_folder: legacy_sync_folder.trim().to_owned(),
                    });
                }
                let dirty = !registry.vaults.is_empty();
                Ok(Loaded { registry, dirty })
            }
            Err(error) => Err(anyhow!(error))
                .with_context(|| format!("не прочитать реестр хранилищ {}", file.display())),
        }
    }

    pub fn save(&self, file: &Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self).context("не сериализовать реестр хранилищ")?;
        if let Some(parent) = file.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("не создать {}", parent.display()))?;
        }
        super::write_atomic(file, &bytes)
    }

    /// Описывает новое хранилище в каталоге `<base>/vaults/<id>`; в реестр
    /// его добавляет вызывающий, когда хранилище действительно создано.
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

/// Имя по умолчанию для нового хранилища: «Хранилище N».
pub fn default_name(taken: &[String]) -> String {
    (1..)
        .map(|number| format!("Хранилище {number}"))
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
        fs::create_dir_all(&path).expect("каталог");
        path
    }

    #[test]
    fn reestr_perezhivaet_zapis_i_chtenie() {
        let dir = temp_dir("roundtrip");
        let file = dir.join(FILE_NAME);

        let mut registry = Registry::default();
        let mut entry = Registry::new_entry(&dir, "  Работа ").expect("запись");
        entry.sync_folder = "/tmp/sync".into();
        registry.upsert(entry.clone());
        registry.save(&file).expect("запись");

        let loaded = Registry::load(&file, &dir.join("vault"), "").expect("чтение");
        assert!(!loaded.dirty);
        assert_eq!(loaded.registry, registry);
        assert_eq!(entry.name, "Работа");
        assert_eq!(entry.path, dir.join(VAULTS_DIR).join(&entry.id));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn v_reestre_net_sekretov_tolko_imya_put_i_papka() {
        let dir = temp_dir("fields");
        let file = dir.join(FILE_NAME);
        let mut registry = Registry::default();
        registry.upsert(Registry::new_entry(&dir, "Дом").expect("запись"));
        registry.save(&file).expect("запись");

        let text = fs::read_to_string(&file).expect("чтение");
        let value: serde_json::Value = serde_json::from_str(&text).expect("json");
        let keys: Vec<&String> = value["vaults"][0]
            .as_object()
            .expect("объект")
            .keys()
            .collect();
        assert_eq!(keys, ["id", "name", "path", "sync_folder"]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn bez_fayla_i_bez_staroy_kopii_reestr_pust() {
        let dir = temp_dir("empty");
        let loaded =
            Registry::load(&dir.join(FILE_NAME), &dir.join("vault"), "/x").expect("чтение");
        assert!(loaded.registry.vaults.is_empty());
        assert!(!loaded.dirty);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn staroe_hranilishche_stanovitsya_osnovnym_vmeste_s_papkoy_sinhronizacii() {
        let dir = temp_dir("legacy");
        let legacy = dir.join("vault");
        fs::create_dir_all(&legacy).expect("каталог");
        fs::write(legacy.join(proto::ACCOUNT_FILE), b"x").expect("файл");

        let loaded = Registry::load(&dir.join(FILE_NAME), &legacy, " /srv/sync ").expect("чтение");
        assert!(loaded.dirty);
        let [entry] = loaded.registry.vaults.as_slice() else {
            panic!("ожидалось одно хранилище");
        };
        assert_eq!(entry.name, FIRST_VAULT_NAME);
        assert_eq!(entry.path, legacy);
        assert_eq!(entry.sync_folder, "/srv/sync");
        assert_eq!(entry.sync_folder(), Some(PathBuf::from("/srv/sync")));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn udalenie_ubiraet_tolko_nuzhnuyu_zapis() {
        let dir = temp_dir("remove");
        let mut registry = Registry::default();
        let first = Registry::new_entry(&dir, "Первое").expect("запись");
        let second = Registry::new_entry(&dir, "Второе").expect("запись");
        registry.upsert(first.clone());
        registry.upsert(second.clone());

        assert_eq!(registry.remove(&first.id), Some(first.clone()));
        assert!(registry.remove(&first.id).is_none());
        assert_eq!(registry.vaults, vec![second]);
        assert!(registry.get(&first.id).is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn povrezhdyonnyy_reestr_ne_zatiraetsya_molcha() {
        let dir = temp_dir("broken");
        let file = dir.join(FILE_NAME);
        fs::write(&file, b"{not json").expect("файл");
        assert!(Registry::load(&file, &dir.join("vault"), "").is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn imya_po_umolchaniyu_ne_povtoryaet_zanyatye() {
        assert_eq!(default_name(&[]), "Хранилище 1");
        assert_eq!(
            default_name(&["Хранилище 1".into(), "Хранилище 3".into()]),
            "Хранилище 2"
        );
    }
}
