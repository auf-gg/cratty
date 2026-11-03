use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use futures::channel::mpsc;
use futures::stream::{BoxStream, StreamExt};
use proto::{EncryptedRecord, RECORDS_DIR, VaultId};

use crate::{Cursor, Pulled, VaultBackend};

const VAULT_FILE: &str = "vault";

const TEMP_SUFFIX: &str = ".tmp";

pub struct FolderBackend {
    root: PathBuf,
    vault_id: VaultId,
}

impl FolderBackend {
    pub fn open(root: impl Into<PathBuf>, vault_id: &VaultId) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(root.join(RECORDS_DIR))
            .with_context(|| format!("не создать каталог синхронизации {}", root.display()))?;

        let marker = root.join(VAULT_FILE);
        match std::fs::read_to_string(&marker) {
            Ok(existing) => {
                let existing = existing.trim();
                if existing != vault_id.as_str() {
                    bail!(
                        "в папке {} лежит другое хранилище — синхронизировать их вместе нельзя",
                        root.display()
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                write_atomic(&marker, vault_id.as_str().as_bytes())?;
            }
            Err(error) => {
                return Err(error).with_context(|| format!("не прочитать {}", marker.display()));
            }
        }

        Ok(Self {
            root,
            vault_id: vault_id.clone(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn vault_id(&self) -> &VaultId {
        &self.vault_id
    }

    fn records_dir(&self) -> PathBuf {
        self.root.join(RECORDS_DIR)
    }

    fn read_all(&self) -> Result<Pulled> {
        let dir = self.records_dir();
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Pulled::default());
            }
            Err(error) => {
                return Err(error).with_context(|| format!("не прочитать {}", dir.display()));
            }
        };

        let mut pulled = Pulled::default();
        let mut newest = 0u64;

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    pulled.broken.push(format!("{}: {error}", dir.display()));
                    continue;
                }
            };
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "tmp") || !path.is_file() {
                continue;
            }

            match std::fs::read(&path) {
                Ok(bytes) => match EncryptedRecord::decode(&bytes) {
                    Ok(record) => {
                        newest = newest.max(record.updated_ms);
                        pulled.records.push(record);
                    }
                    Err(error) => pulled.broken.push(format!("{}: {error}", path.display())),
                },
                Err(error) => pulled.broken.push(format!("{}: {error}", path.display())),
            }
        }

        pulled.cursor = Cursor(newest);
        Ok(pulled)
    }
}

#[async_trait]
impl VaultBackend for FolderBackend {
    async fn pull(&self, since: Cursor) -> Result<Pulled> {
        let mut pulled = self.read_all()?;
        if !since.is_beginning() {
            pulled.records.retain(|record| record.updated_ms >= since.0);
        }
        Ok(pulled)
    }

    async fn push(&self, records: Vec<EncryptedRecord>) -> Result<Cursor> {
        let dir = self.records_dir();
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("не создать каталог {}", dir.display()))?;

        let mut newest = 0u64;
        for record in records {
            let path = dir.join(record.id.as_str());

            if let Ok(bytes) = std::fs::read(&path)
                && let Ok(existing) = EncryptedRecord::decode(&bytes)
                && proto::wins(&existing, &record) == &existing
            {
                newest = newest.max(existing.updated_ms);
                continue;
            }

            write_atomic(&path, &record.encode())?;
            newest = newest.max(record.updated_ms);
        }

        Ok(Cursor(newest))
    }

    fn watch(&self) -> BoxStream<'static, ()> {
        watch_dir(self.records_dir())
    }
}

fn watch_dir(dir: PathBuf) -> BoxStream<'static, ()> {
    use notify::{RecursiveMode, Watcher};

    let (mut tx, rx) = mpsc::channel::<()>(1);

    let watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
        if event.is_err() {
            return;
        }
        let _ = tx.try_send(());
    });

    let mut watcher = match watcher {
        Ok(watcher) => watcher,
        Err(_) => return futures::stream::empty().boxed(),
    };

    if watcher.watch(&dir, RecursiveMode::NonRecursive).is_err() {
        return futures::stream::empty().boxed();
    }

    rx.map(move |()| {
        let _keep = &watcher;
    })
    .boxed()
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    let temp = path.with_extension(TEMP_SUFFIX.trim_start_matches('.'));
    {
        let mut file = std::fs::File::create(&temp)
            .with_context(|| format!("не создать {}", temp.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("не записать {}", temp.display()))?;
        file.sync_all()
            .with_context(|| format!("не сбросить на диск {}", temp.display()))?;
    }
    std::fs::rename(&temp, path).with_context(|| format!("не заменить {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::{DeviceId, RecordId};

    fn temp_dir(name: &str) -> PathBuf {
        let unique = DeviceId::generate().expect("CSPRNG");
        let path = std::env::temp_dir().join(format!("cratty-sync-{name}-{unique}"));
        let _ = std::fs::remove_dir_all(&path);
        path
    }

    fn record(id: &RecordId, rev: u64, updated_ms: u64, device: &DeviceId) -> EncryptedRecord {
        EncryptedRecord {
            id: id.clone(),
            rev,
            key_gen: 1,
            device_id: device.clone(),
            updated_ms,
            payload: vec![rev as u8; 32],
        }
    }

    #[tokio::test]
    async fn zapisi_edut_tuda_i_obratno() {
        let root = temp_dir("roundtrip");
        let vault_id = VaultId::generate().expect("CSPRNG");
        let backend = FolderBackend::open(&root, &vault_id).expect("папка");

        let device = DeviceId::generate().expect("CSPRNG");
        let id = RecordId::generate().expect("CSPRNG");
        let mine = record(&id, 1, 1_000, &device);

        backend.push(vec![mine.clone()]).await.expect("push");
        let pulled = backend.pull(Cursor::BEGINNING).await.expect("pull");

        assert_eq!(pulled.records, vec![mine]);
        assert!(pulled.broken.is_empty());
        assert_eq!(pulled.cursor, Cursor(1_000));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn staraya_reviziya_ne_zatiraet_novuyu() {
        let root = temp_dir("stale");
        let vault_id = VaultId::generate().expect("CSPRNG");
        let backend = FolderBackend::open(&root, &vault_id).expect("папка");

        let device = DeviceId::generate().expect("CSPRNG");
        let id = RecordId::generate().expect("CSPRNG");
        let fresh = record(&id, 5, 5_000, &device);
        let stale = record(&id, 2, 2_000, &device);

        backend.push(vec![fresh.clone()]).await.expect("push");
        backend.push(vec![stale]).await.expect("push");

        let pulled = backend.pull(Cursor::BEGINNING).await.expect("pull");
        assert_eq!(pulled.records, vec![fresh]);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn novaya_reviziya_zamenyaet_staruyu() {
        let root = temp_dir("fresh");
        let vault_id = VaultId::generate().expect("CSPRNG");
        let backend = FolderBackend::open(&root, &vault_id).expect("папка");

        let device = DeviceId::generate().expect("CSPRNG");
        let id = RecordId::generate().expect("CSPRNG");
        backend
            .push(vec![record(&id, 1, 1_000, &device)])
            .await
            .expect("push");
        let newer = record(&id, 2, 2_000, &device);
        backend.push(vec![newer.clone()]).await.expect("push");

        let pulled = backend.pull(Cursor::BEGINNING).await.expect("pull");
        assert_eq!(pulled.records, vec![newer]);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn chuzhoe_hranilishche_ne_prinimaetsya() {
        let root = temp_dir("alien");
        let mine = VaultId::generate().expect("CSPRNG");
        let alien = VaultId::generate().expect("CSPRNG");

        FolderBackend::open(&root, &mine).expect("папка");
        let Err(error) = FolderBackend::open(&root, &alien) else {
            panic!("чужая папка принялась как своя");
        };
        assert!(format!("{error:#}").contains("другое хранилище"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn musor_v_kataloge_ne_lomaet_sinhronizaciyu() {
        let root = temp_dir("garbage");
        let vault_id = VaultId::generate().expect("CSPRNG");
        let backend = FolderBackend::open(&root, &vault_id).expect("папка");

        let device = DeviceId::generate().expect("CSPRNG");
        let id = RecordId::generate().expect("CSPRNG");
        let good = record(&id, 1, 1_000, &device);
        backend.push(vec![good.clone()]).await.expect("push");

        std::fs::write(root.join(RECORDS_DIR).join("мусор"), "не запись".as_bytes())
            .expect("мусор");
        std::fs::write(root.join(RECORDS_DIR).join("сосед.tmp"), b"half").expect("временный");

        let pulled = backend.pull(Cursor::BEGINNING).await.expect("pull");
        assert_eq!(pulled.records, vec![good]);
        assert_eq!(pulled.broken.len(), 1, "про мусор надо сказать один раз");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn kursor_ne_teryaet_zapisi_toy_zhe_millisekundy() {
        let root = temp_dir("cursor");
        let vault_id = VaultId::generate().expect("CSPRNG");
        let backend = FolderBackend::open(&root, &vault_id).expect("папка");

        let device = DeviceId::generate().expect("CSPRNG");
        let old = record(&RecordId::generate().expect("CSPRNG"), 1, 1_000, &device);
        let same = record(&RecordId::generate().expect("CSPRNG"), 1, 2_000, &device);
        backend
            .push(vec![old.clone(), same.clone()])
            .await
            .expect("push");

        let pulled = backend.pull(Cursor(2_000)).await.expect("pull");
        assert_eq!(pulled.records, vec![same]);

        let _ = std::fs::remove_dir_all(&root);
    }
}
