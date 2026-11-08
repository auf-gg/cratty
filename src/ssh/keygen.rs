//! Ключи для входа по файлу: список существующих в ~/.ssh, генерация нового
//! Ed25519 и команда, которая дописывает открытый ключ на сервер
//! (как `ssh-copy-id`).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use russh::keys::ssh_key::{
    LineEnding, PrivateKey,
    private::{Ed25519Keypair, KeypairData},
};

/// Закрытые ключи в каталоге: файлы с заголовком «PRIVATE KEY».
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

/// Создаёт ключ Ed25519 без парольной фразы в `dir` под свободным именем
/// `id_ed25519_<hint>`. Закрытый ключ — только владельцу, рядом `.pub`.
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
        .ok_or_else(|| anyhow!("не нашлось свободного имени для ключа в {}", dir.display()))?;

    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|error| anyhow!("нет случайных чисел: {error}"))?;
    let keypair = Ed25519Keypair::from_seed(&seed);
    seed.fill(0);
    let key = PrivateKey::new(KeypairData::Ed25519(keypair), comment)
        .map_err(|error| anyhow!("не собрать ключ: {error}"))?;

    let private = key
        .to_openssh(LineEnding::LF)
        .map_err(|error| anyhow!("не записать ключ: {error}"))?;
    let public = key
        .public_key()
        .to_openssh()
        .map_err(|error| anyhow!("не записать открытый ключ: {error}"))?;

    write_new(&path, private.as_bytes(), 0o600)?;
    write_new(&pub_path(&path), format!("{public}\n").as_bytes(), 0o644)?;
    Ok(path)
}

/// Открытый ключ строкой `тип base64 комментарий`: из `.pub` рядом, а если его
/// нет — из самого закрытого ключа (если он не зашифрован).
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
        anyhow!(
            "рядом с ключом нет {} , а сам ключ зашифрован или не читается",
            pub_file.display()
        )
    })?;
    key.public_key()
        .to_openssh()
        .map_err(|error| anyhow!("не получить открытый ключ: {error}"))
}

/// Команда для сервера: создать ~/.ssh и authorized_keys с правильными правами
/// и дописать ключ, если его там ещё нет.
pub fn install_command(public_line: &str) -> Result<String> {
    let mut parts = public_line.split_whitespace();
    let (Some(kind), Some(blob)) = (parts.next(), parts.next()) else {
        bail!("это не похоже на открытый ключ SSH");
    };
    // Только безопасные символы: строка уходит в оболочку сервера.
    let kind_ok = kind
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "@.-".contains(c));
    let blob_ok = blob
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c));
    if !kind_ok || !blob_ok {
        bail!("в открытом ключе посторонние символы");
    }
    let comment = sanitize(&parts.collect::<Vec<_>>().join("_"), "");
    let line = if comment.is_empty() {
        format!("{kind} {blob}")
    } else {
        format!("{kind} {blob} {comment}")
    };
    // Скрипт для sh: у пользователя на сервере может быть fish или csh, где
    // `if …; then …; fi` не работает (так же делает ssh-copy-id). Внутри нет
    // двойных кавычек и `$`, поэтому внешняя оболочка передаст его как есть.
    let script = format!(
        "umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys \
         && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys \
         && if grep -qF '{blob}' ~/.ssh/authorized_keys; \
         then echo 'Ключ уже есть на сервере.'; \
         else echo '{line}' >> ~/.ssh/authorized_keys && echo 'Ключ добавлен на сервер.'; fi"
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
    std::fs::create_dir_all(dir).with_context(|| format!("не создать {}", dir.display()))?;
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
        .with_context(|| format!("не создать {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("не записать {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).expect("случайность");
        let suffix: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        std::env::temp_dir().join(format!("cratty-keygen-{name}-{suffix}"))
    }

    #[test]
    fn generaciya_spisok_i_otkrytyy_klyuch() {
        let dir = temp_dir("gen");
        let first = generate(&dir, "prod.example.com", "me@laptop").expect("ключ");
        let second = generate(&dir, "prod.example.com", "me@laptop").expect("второй ключ");
        assert_ne!(first, second, "второй ключ затёр первый");
        assert!(first.ends_with("id_ed25519_prod.example.com"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&first)
                .expect("файл")
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "закрытый ключ виден не только владельцу"
            );
        }

        assert_eq!(private_keys(&dir), vec![first.clone(), second.clone()]);

        let line = public_line(&first).expect("открытый ключ");
        assert!(line.starts_with("ssh-ed25519 "), "{line}");
        assert!(line.ends_with(" me@laptop"));

        // Без .pub открытая часть берётся из самого ключа.
        std::fs::remove_file(pub_path(&first)).expect("удалить .pub");
        let derived = public_line(&first).expect("из закрытого");
        assert_eq!(
            derived.split_whitespace().nth(1),
            line.split_whitespace().nth(1)
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn komanda_ustanovki_ne_propuskaet_inekcii() {
        let command = install_command("ssh-ed25519 AAAAC3Nza+/= me@host").expect("команда");
        assert!(command.starts_with("exec sh -c \""));
        assert!(command.contains("echo 'ssh-ed25519 AAAAC3Nza+/= me@host' >>"));
        assert!(command.contains("grep -qF 'AAAAC3Nza+/='"));

        assert!(install_command("ssh-ed25519 AAAA'; rm -rf ~ #").is_err());
        assert!(install_command("ssh-ed25519").is_err());
        let quoted = install_command("ssh-ed25519 AAAA x'; reboot; '").expect("команда");
        assert!(
            !quoted.contains("reboot;"),
            "комментарий не очищен: {quoted}"
        );
    }
}
