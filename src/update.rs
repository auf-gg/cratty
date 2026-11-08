//! Автообновление на Windows: последний релиз на GitHub и его установщик.
//!
//! Релизы собирает `.github/workflows/build.yml`; установщик NSIS
//! (`dist/windows/installer.nsi`) в тихом режиме (`/S`) дожидается выхода
//! старого `cratty.exe`, заменяет его и сам запускает новую версию.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};

const REPO: &str = "auf-gg/cratty";
const USER_AGENT: &str = concat!("cratty/", env!("CARGO_PKG_VERSION"));
/// Ответ API о релизе: с запасом, обычно это десятки килобайт.
const MAX_RELEASE_JSON: u64 = 4 * 1024 * 1024;
/// Установщик заметно меньше, это защита от бесконечного ответа.
const MAX_INSTALLER: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Release {
    pub version: String,
    pub url: String,
    pub notes: String,
}

fn parse(version: &str) -> Option<(u32, u32, u32)> {
    let mut parts = version
        .trim_start_matches('v')
        .split('.')
        .map(|p| p.parse().ok());
    Some((parts.next()??, parts.next()??, parts.next()??))
}

/// Версия `remote` новее `current`; непонятные теги не считаются новыми.
pub fn newer(remote: &str, current: &str) -> bool {
    matches!((parse(remote), parse(current)), (Some(r), Some(c)) if r > c)
}

fn asset_name(version: &str) -> String {
    format!("cratty-{version}-{}-setup.exe", std::env::consts::ARCH)
}

fn agent() -> ureq::Agent {
    // Без общего таймаута: установщик по медленной сети качается долго.
    ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_recv_response(Some(Duration::from_secs(30)))
        .build()
        .into()
}

/// Последний релиз, если он новее текущей версии и в нём есть установщик
/// под эту архитектуру.
pub fn check() -> Result<Option<Release>> {
    let mut response = agent()
        .get(format!(
            "https://api.github.com/repos/{REPO}/releases/latest"
        ))
        .header("User-Agent", USER_AGENT)
        .header("Accept", "application/vnd.github+json")
        .call()
        .context("не удалось запросить последний релиз")?;
    let mut body = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(MAX_RELEASE_JSON)
        .read_to_end(&mut body)
        .context("ответ GitHub оборвался")?;
    let json: serde_json::Value =
        serde_json::from_slice(&body).context("непонятный ответ GitHub")?;

    let Some(tag) = json["tag_name"].as_str() else {
        return Ok(None);
    };
    if !newer(tag, env!("CARGO_PKG_VERSION")) {
        return Ok(None);
    }
    let version = tag.trim_start_matches('v').to_string();
    let name = asset_name(&version);
    let url = json["assets"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|asset| asset["name"].as_str() == Some(name.as_str()))
        .and_then(|asset| asset["browser_download_url"].as_str());
    let notes = json["body"].as_str().unwrap_or_default().trim().to_string();
    Ok(url.map(|url| Release {
        version,
        url: url.to_string(),
        notes,
    }))
}

/// Скачивает установщик и запускает его в тихом режиме. `progress` — доли
/// от 0 до 1000. После успеха приложение должно сразу выйти: установщик ждёт,
/// пока освободится `cratty.exe`.
pub fn install(release: &Release, progress: &AtomicU32) -> Result<()> {
    let dir = std::env::temp_dir().join(format!("cratty-update-{}", release.version));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).context("не удалось создать временную папку")?;
    let file = dir.join(asset_name(&release.version));
    download(&release.url, &file, progress)?;
    run_installer(&file)
}

fn download(url: &str, file: &PathBuf, progress: &AtomicU32) -> Result<()> {
    progress.store(0, Ordering::Relaxed);
    let mut response = agent()
        .get(url)
        .header("User-Agent", USER_AGENT)
        .call()
        .context("не удалось скачать обновление")?;
    let total = response.body().content_length().unwrap_or(0);
    let mut reader = response.body_mut().as_reader().take(MAX_INSTALLER);
    let mut out = std::fs::File::create(file).context("не удалось сохранить обновление")?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut done = 0u64;
    loop {
        let n = reader.read(&mut buf).context("загрузка оборвалась")?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n])
            .context("не удалось сохранить обновление")?;
        done += n as u64;
        if let Some(share) = (done * 1000).checked_div(total) {
            progress.store(share.min(1000) as u32, Ordering::Relaxed);
        }
    }
    out.sync_all().context("не удалось сохранить обновление")?;
    if total > 0 && done != total {
        bail!("загрузка оборвалась");
    }
    Ok(())
}

fn run_installer(file: &PathBuf) -> Result<()> {
    let mut command = std::process::Command::new(file);
    command.arg("/S");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command.spawn().context("не удалось запустить установщик")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sravnenie_versiy() {
        assert!(newer("v0.3.2", "0.3.1"));
        assert!(newer("v0.10.0", "0.9.9"));
        assert!(newer("1.0.0", "0.99.99"));
        assert!(!newer("v0.3.1", "0.3.1"));
        assert!(!newer("v0.3.0", "0.3.1"));
        assert!(!newer("nightly", "0.3.1"));
    }
}
