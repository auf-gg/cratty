//! Host key files also live in the vault: when a host is saved and when the
//! vault is opened, the file is copied there as is (encrypted stays encrypted),
//! and if it is missing from the user's directory, it is restored.

use std::path::{Path, PathBuf};

use super::key_tools::{display_path, expand_home};
use super::*;
use anyhow::Context as _;

/// Vault record with a copy of the key file. The path is stored as `~/…` so that
/// the key can be restored on another computer too.
pub(super) fn record_from_file(path: &Path) -> anyhow::Result<proto::KeyRecord> {
    let text = std::fs::read_to_string(path)
        .with_context(|| t!("keys.could_not_read", path = path.display().to_string()).to_string())?;

    // Not encrypted — immediately usable by the agent too.
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

/// Public part of an encrypted key: from the adjacent `.pub` or from the file itself —
/// in OpenSSH format it is stored in the clear.
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

/// Puts the key file back in place if it is missing. An existing file is not
/// touched. `Some(path)` means the key was restored.
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
    std::fs::create_dir_all(dir)
        .with_context(|| t!("keys.could_not_create", path = dir.display().to_string()).to_string())?;
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
        .with_context(|| t!("keys.could_not_create", path = path.display().to_string()).to_string())?;
    file.write_all(bytes)
        .with_context(|| t!("keys.could_not_write", path = path.display().to_string()).to_string())
}

impl AppView {
    /// Copies the key files of its hosts into the vault and restores those
    /// that are missing on disk.
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
            lines.push(t!("keys.restored", list = restored.join(", ")).to_string());
        }
        if !problems.is_empty() {
            lines.push(t!("keys.problems", list = problems.join("; ")).to_string());
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
        let unique = proto::DeviceId::generate().expect("randomness");
        std::env::temp_dir().join(format!("cratty-key-backup-{name}-{}", unique.as_str()))
    }

    #[test]
    fn key_backup_and_restore() {
        let dir = temp_dir("plain");
        let path = crate::ssh::keygen::generate(&dir, "srv", "me@pc").expect("key");
        let original = std::fs::read(&path).expect("file");
        let public = std::fs::read_to_string(pub_path(&path)).expect(".pub");

        let mut record = record_from_file(&path).expect("copy");
        assert!(
            record.is_usable(),
            "an unencrypted key should be usable by the agent"
        );
        assert_eq!(
            record.key_file().expect("file").expose(),
            original.as_slice()
        );
        assert!(record.fingerprint.starts_with("SHA256:"));

        // The restore path is absolute since the directory is not under home.
        record.source = path.display().to_string();
        assert_eq!(
            restore(&record).expect("in place"),
            None,
            "existing file was touched"
        );

        std::fs::remove_file(&path).expect("remove key");
        std::fs::remove_file(pub_path(&path)).expect("remove .pub");
        assert_eq!(
            restore(&record).expect("restore"),
            Some(path.clone())
        );
        assert_eq!(std::fs::read(&path).expect("file"), original);
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
            let mode = std::fs::metadata(&path).expect("file").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn encrypted_key_is_stored_as_is() {
        use russh::keys::ssh_key::{
            LineEnding, PrivateKey,
            private::{Ed25519Keypair, KeypairData},
        };

        let dir = temp_dir("encrypted");
        std::fs::create_dir_all(&dir).expect("directory");
        let key = PrivateKey::new(
            KeypairData::Ed25519(Ed25519Keypair::from_seed(&[7u8; 32])),
            "enc@pc",
        )
        .expect("key");
        let encrypted = key
            .encrypt(&mut getrandom::SysRng, "phrase")
            .expect("encryption");
        let path = dir.join("id_enc");
        std::fs::write(&path, encrypted.to_openssh(LineEnding::LF).expect("text"))
            .expect("write");

        let record = record_from_file(&path).expect("copy without passphrase");
        assert!(
            record.private().is_none(),
            "the encrypted key was not decrypted"
        );
        assert!(!record.public.is_empty(), "public part not found");
        assert_eq!(
            record.key_file().expect("file").expose(),
            std::fs::read(&path).expect("file").as_slice()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
