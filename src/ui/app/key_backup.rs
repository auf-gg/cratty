//! Файлы ключей хостов живут и в хранилище: при сохранении хоста и открытии
//! хранилища файл копируется туда как есть (зашифрованный — зашифрованным),
//! а если в пользовательском каталоге его нет, восстанавливается обратно.

use std::path::{Path, PathBuf};

use super::key_tools::{display_path, expand_home};
use super::*;
use anyhow::Context as _;

/// Запись хранилища с копией файла ключа. Путь хранится в виде `~/…`, чтобы
/// ключ восстанавливался и на другом компьютере.
pub(super) fn record_from_file(path: &Path) -> anyhow::Result<proto::KeyRecord> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("не прочитать {}", path.display()))?;

    // Не зашифрован — сразу пригоден и для агента.
    let decoded = ssh_agent::keys::decode_private(&text, None).ok();
    let public = match &decoded {
        Some(key) => Some(key.public_key().clone()),
        None => public_of(path, &text),
    };

    let mut record = proto::KeyRecord::from_file(
        display_path(path),
        proto::Secret::new(text.into_bytes()),
        match &public {
            Some(public) => ssh_agent::keys::public_blob(public)?,
            None => Vec::new(),
        },
        match &decoded {
            Some(key) => Some(proto::Secret::new(ssh_agent::keys::to_openssh(key)?)),
            None => None,
        },
    );
    if let Some(public) = &public {
        record.comment = public.comment().to_string();
        record.algorithm = public.algorithm().to_string();
        record.fingerprint = ssh_agent::keys::fingerprint(public);
    }
    record.label = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok(record)
}

/// Открытая часть зашифрованного ключа: из `.pub` рядом или из самого файла —
/// в формате OpenSSH она хранится открыто.
fn public_of(path: &Path, text: &str) -> Option<russh::keys::PublicKey> {
    let pub_file = pub_path(path);
    if let Ok(line) = std::fs::read_to_string(&pub_file)
        && let Ok(public) = russh::keys::PublicKey::from_openssh(line.trim())
    {
        return Some(public);
    }
    russh::keys::PrivateKey::from_openssh(text)
        .ok()
        .map(|key| key.public_key().clone())
}

fn pub_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".pub");
    PathBuf::from(name)
}

/// Возвращает файл ключа на место, если его там нет. Существующий файл не
/// трогает. `Some(path)` — ключ восстановлен.
pub(super) fn restore(record: &proto::KeyRecord) -> anyhow::Result<Option<PathBuf>> {
    let Some(file) = record.key_file().filter(|file| !file.is_empty()) else {
        return Ok(None);
    };
    if record.source.trim().is_empty() {
        return Ok(None);
    }
    let path = expand_home(record.source.trim());
    if path.exists() {
        return Ok(None);
    }
    if let Some(dir) = path.parent() {
        create_private_dir(dir)?;
    }
    write_new(&path, file.expose(), 0o600)?;

    let pub_file = pub_path(&path);
    if !record.public.is_empty()
        && !pub_file.exists()
        && let Ok(public) = ssh_agent::keys::parse_public(&record.public)
        && let Ok(line) = public.to_openssh()
    {
        let _ = write_new(&pub_file, format!("{line}\n").as_bytes(), 0o644);
    }
    Ok(Some(path))
}

fn create_private_dir(dir: &Path) -> anyhow::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(dir).with_context(|| format!("не создать {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options
        .open(path)
        .with_context(|| format!("не создать {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("не записать {}", path.display()))
}

impl AppView {
    /// Копирует в хранилище файлы ключей его хостов и восстанавливает те,
    /// которых нет на диске.
    pub(super) fn sync_key_files(&mut self, id: &str) {
        let Some(ix) = self.vault_ix(id) else {
            return;
        };
        let store = VaultStore::new(self.vaults[ix].root());
        let Some(unlocked) = self.vaults[ix].session.unlocked_mut() else {
            return;
        };

        let mut problems: Vec<String> = Vec::new();

        let paths: Vec<PathBuf> = unlocked
            .hosts()
            .into_iter()
            .filter_map(|entry| match entry.host.auth {
                HostAuth::Key { path } if !path.trim().is_empty() => Some(expand_home(path.trim())),
                _ => None,
            })
            .collect();
        for path in paths.iter().filter(|path| path.is_file()) {
            let result =
                record_from_file(path).and_then(|record| unlocked.backup_key_file(&store, record));
            if let Err(error) = result {
                problems.push(format!("{}: {error:#}", display_path(path)));
            }
        }

        let mut restored: Vec<String> = Vec::new();
        for entry in unlocked.key_backups() {
            match restore(&entry.key) {
                Ok(Some(path)) => restored.push(display_path(&path)),
                Ok(None) => {}
                Err(error) => problems.push(format!("{}: {error:#}", entry.key.source)),
            }
        }

        let mut lines = Vec::new();
        if !restored.is_empty() {
            lines.push(format!(
                "Из хранилища восстановлены ключи: {}.",
                restored.join(", ")
            ));
        }
        if !problems.is_empty() {
            lines.push(format!("Ключи: {}", problems.join("; ")));
        }
        if !lines.is_empty() {
            self.import_notice = Some(lines.join(" ").into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let unique = proto::DeviceId::generate().expect("случайность");
        std::env::temp_dir().join(format!("cratty-key-backup-{name}-{}", unique.as_str()))
    }

    #[test]
    fn kopiya_i_vosstanovlenie_klyucha() {
        let dir = temp_dir("plain");
        let path = crate::ssh::keygen::generate(&dir, "srv", "me@pc").expect("ключ");
        let original = std::fs::read(&path).expect("файл");
        let public = std::fs::read_to_string(pub_path(&path)).expect(".pub");

        let mut record = record_from_file(&path).expect("копия");
        assert!(
            record.is_usable(),
            "незашифрованный ключ должен годиться агенту"
        );
        assert_eq!(
            record.key_file().expect("файл").expose(),
            original.as_slice()
        );
        assert!(record.fingerprint.starts_with("SHA256:"));

        // Путь восстановления — абсолютный, раз каталог не в домашнем.
        record.source = path.display().to_string();
        assert_eq!(
            restore(&record).expect("на месте"),
            None,
            "существующий файл тронут"
        );

        std::fs::remove_file(&path).expect("удалить ключ");
        std::fs::remove_file(pub_path(&path)).expect("удалить .pub");
        assert_eq!(
            restore(&record).expect("восстановление"),
            Some(path.clone())
        );
        assert_eq!(std::fs::read(&path).expect("файл"), original);
        assert_eq!(
            std::fs::read_to_string(pub_path(&path))
                .expect(".pub")
                .split_whitespace()
                .nth(1),
            public.split_whitespace().nth(1)
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("файл").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn zashifrovannyy_klyuch_hranitsya_kak_est() {
        use russh::keys::ssh_key::{
            LineEnding, PrivateKey,
            private::{Ed25519Keypair, KeypairData},
        };

        let dir = temp_dir("encrypted");
        std::fs::create_dir_all(&dir).expect("каталог");
        let key = PrivateKey::new(
            KeypairData::Ed25519(Ed25519Keypair::from_seed(&[7u8; 32])),
            "enc@pc",
        )
        .expect("ключ");
        let encrypted = key
            .encrypt(&mut getrandom::SysRng, "фраза")
            .expect("шифрование");
        let path = dir.join("id_enc");
        std::fs::write(&path, encrypted.to_openssh(LineEnding::LF).expect("текст"))
            .expect("запись");

        let record = record_from_file(&path).expect("копия без фразы");
        assert!(
            record.private().is_none(),
            "зашифрованный ключ не расшифровывали"
        );
        assert!(!record.public.is_empty(), "открытая часть не найдена");
        assert_eq!(
            record.key_file().expect("файл").expose(),
            std::fs::read(&path).expect("файл").as_slice()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
