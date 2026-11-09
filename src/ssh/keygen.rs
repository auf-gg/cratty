//! Keys for file-based login: a list of those existing in ~/.ssh, generating a new
//! Ed25519 key, and a command that appends the public key on the server
//! (like `ssh-copy-id`).

use rust_i18n::t;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use russh::keys::ssh_key::{
    LineEnding, PrivateKey,
    private::{Ed25519Keypair, KeypairData},
};

/// Private keys in a directory: files with a "PRIVATE KEY" header.
pub fn private_keys(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut keys: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path.extension().is_none_or(|ext| ext != "pub")
                && std::fs::metadata(path).is_ok_and(|meta| meta.len() < 64 * 1024)
                && std::fs::read(path).is_ok_and(|bytes| {
                    let head = &bytes[..bytes.len().min(64)];
                    head.starts_with(b"-----BEGIN")
                        && bytes.windows(11).any(|w| w == b"PRIVATE KEY")
                })
        })
        .collect();
    keys.sort();
    keys
}

/// Creates an Ed25519 key without a passphrase in `dir` under a free name
/// `id_ed25519_<hint>`. The private key is owner-only, with a `.pub` next to it.
pub fn generate(dir: &Path, hint: &str, comment: &str) -> Result<PathBuf> {
    create_private_dir(dir)?;
    let base = format!("id_ed25519_{}", sanitize(hint, "cratty"));
    let path = (1..1000)
        .map(|n| {
            if n == 1 {
                dir.join(&base)
            } else {
                dir.join(format!("{base}_{n}"))
            }
        })
        .find(|path| !path.exists() && !path.with_extension("pub").exists())
        .ok_or_else(|| anyhow!(t!("ssh.keygen_no_free_name", dir = dir.display())))?;

    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|error| anyhow!(t!("ssh.keygen_no_random", error = error)))?;
    let keypair = Ed25519Keypair::from_seed(&seed);
    seed.fill(0);
    let key = PrivateKey::new(KeypairData::Ed25519(keypair), comment)
        .map_err(|error| anyhow!(t!("ssh.keygen_build_failed", error = error)))?;

    let private = key
        .to_openssh(LineEnding::LF)
        .map_err(|error| anyhow!(t!("ssh.keygen_write_failed", error = error)))?;
    let public = key
        .public_key()
        .to_openssh()
        .map_err(|error| anyhow!(t!("ssh.keygen_write_public_failed", error = error)))?;

    write_new(&path, private.as_bytes(), 0o600)?;
    write_new(&pub_path(&path), format!("{public}\n").as_bytes(), 0o644)?;
    Ok(path)
}

/// The public key as a `type base64 comment` string: from the `.pub` next to it, or, if it is
/// missing, from the private key itself (if it is not encrypted).
pub fn public_line(path: &Path) -> Result<String> {
    let pub_file = pub_path(path);
    if let Ok(text) = std::fs::read_to_string(&pub_file) {
        let line = text
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("");
        return Ok(line.trim().to_owned());
    }
    let key = russh::keys::load_secret_key(path, None).map_err(|_| {
        anyhow!(t!("ssh.keygen_no_public_file", path = pub_file.display()))
    })?;
    key.public_key()
        .to_openssh()
        .map_err(|error| anyhow!(t!("ssh.keygen_public_failed", error = error)))
}

/// A command for the server: create ~/.ssh and authorized_keys with the right permissions
/// and append the key if it is not there yet.
pub fn install_command(public_line: &str) -> Result<String> {
    let mut parts = public_line.split_whitespace();
    let (Some(kind), Some(blob)) = (parts.next(), parts.next()) else {
        bail!(t!("ssh.keygen_not_public_key"));
    };
    // Only safe characters: the string goes to the server's shell.
    let kind_ok = kind
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "@.-".contains(c));
    let blob_ok = blob
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c));
    if !kind_ok || !blob_ok {
        bail!(t!("ssh.keygen_foreign_chars"));
    }
    let comment = sanitize(&parts.collect::<Vec<_>>().join("_"), "");
    let line = if comment.is_empty() {
        format!("{kind} {blob}")
    } else {
        format!("{kind} {blob} {comment}")
    };
    // A script for sh: the user's shell on the server may be fish or csh, where
    // `if …; then …; fi` does not work (ssh-copy-id does the same). There are no
    // double quotes or `$` inside, so the outer shell will pass it through as is.
    let script = format!(
        "umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys \
         && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys \
         && if grep -qF '{blob}' ~/.ssh/authorized_keys; \
         then echo 'Key is already on the server.'; \
         else echo '{line}' >> ~/.ssh/authorized_keys && echo 'Key added to the server.'; fi"
    );
    debug_assert!(!script.contains(['"', '$', '`', '\\']));
    Ok(format!("exec sh -c \"{script}\""))
}

fn pub_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".pub");
    PathBuf::from(name)
}

fn sanitize(text: &str, fallback: &str) -> String {
    let clean: String = text
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "@._-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    let clean = clean.trim_matches('_').to_owned();
    if clean.is_empty() {
        fallback.to_owned()
    } else {
        clean
    }
}

fn create_private_dir(dir: &Path) -> Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(dir)
        .with_context(|| t!("ssh.keygen_create_failed", path = dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
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
        .with_context(|| t!("ssh.keygen_create_failed", path = path.display()))?;
    file.write_all(bytes)
        .with_context(|| t!("ssh.keygen_file_write_failed", path = path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).expect("randomness");
        let suffix: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        std::env::temp_dir().join(format!("cratty-keygen-{name}-{suffix}"))
    }

    #[test]
    fn generation_list_and_public_key() {
        let dir = temp_dir("gen");
        let first = generate(&dir, "prod.example.com", "me@laptop").expect("key");
        let second = generate(&dir, "prod.example.com", "me@laptop").expect("second key");
        assert_ne!(first, second, "the second key overwrote the first");
        assert!(first.ends_with("id_ed25519_prod.example.com"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&first)
                .expect("file")
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "the private key is visible to more than the owner"
            );
        }

        assert_eq!(private_keys(&dir), vec![first.clone(), second.clone()]);

        let line = public_line(&first).expect("public key");
        assert!(line.starts_with("ssh-ed25519 "), "{line}");
        assert!(line.ends_with(" me@laptop"));

        // Without .pub the public part is taken from the key itself.
        std::fs::remove_file(pub_path(&first)).expect("remove .pub");
        let derived = public_line(&first).expect("from private");
        assert_eq!(
            derived.split_whitespace().nth(1),
            line.split_whitespace().nth(1)
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_command_does_not_allow_injection() {
        let command = install_command("ssh-ed25519 AAAAC3Nza+/= me@host").expect("command");
        assert!(command.starts_with("exec sh -c \""));
        assert!(command.contains("echo 'ssh-ed25519 AAAAC3Nza+/= me@host' >>"));
        assert!(command.contains("grep -qF 'AAAAC3Nza+/='"));

        assert!(install_command("ssh-ed25519 AAAA'; rm -rf ~ #").is_err());
        assert!(install_command("ssh-ed25519").is_err());
        let quoted = install_command("ssh-ed25519 AAAA x'; reboot; '").expect("command");
        assert!(
            !quoted.contains("reboot;"),
            "comment was not sanitized: {quoted}"
        );
    }
}
