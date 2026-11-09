//! Auto-update on Windows: the latest GitHub release and its installer.
//!
//! Releases are built by `.github/workflows/build.yml`; the NSIS installer
//! (`dist/windows/installer.nsi`) in silent mode (`/S`) waits for the old
//! `cratty.exe` to exit, replaces it and launches the new version itself.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rust_i18n::t;

const REPO: &str = "auf-gg/cratty";
const USER_AGENT: &str = concat!("cratty/", env!("CARGO_PKG_VERSION"));
/// API release response: with a margin, usually tens of kilobytes.
const MAX_RELEASE_JSON: u64 = 4 * 1024 * 1024;
/// The installer is noticeably smaller; this guards against an endless response.
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

/// Version `remote` is newer than `current`; unparseable tags do not count as newer.
pub fn newer(remote: &str, current: &str) -> bool {
    matches!((parse(remote), parse(current)), (Some(r), Some(c)) if r > c)
}

fn asset_name(version: &str) -> String {
    format!("cratty-{version}-{}-setup.exe", std::env::consts::ARCH)
}

fn agent() -> ureq::Agent {
    // No overall timeout: the installer takes long to download on a slow network.
    ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_recv_response(Some(Duration::from_secs(30)))
        .build()
        .into()
}

/// The latest release, if it is newer than the current version and contains an installer
/// for this architecture.
pub fn check() -> Result<Option<Release>> {
    let mut response = agent()
        .get(format!(
            "https://api.github.com/repos/{REPO}/releases/latest"
        ))
        .header("User-Agent", USER_AGENT)
        .header("Accept", "application/vnd.github+json")
        .call()
        .with_context(|| t!("updater.request_failed").to_string())?;
    let mut body = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(MAX_RELEASE_JSON)
        .read_to_end(&mut body)
        .with_context(|| t!("updater.cut_off").to_string())?;
    let json: serde_json::Value =
        serde_json::from_slice(&body).with_context(|| t!("updater.unexpected").to_string())?;

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

/// Downloads the installer and runs it in silent mode. `progress` — fractions
/// from 0 to 1000. After success the app must exit right away: the installer waits
/// for `cratty.exe` to be released.
pub fn install(release: &Release, progress: &AtomicU32) -> Result<()> {
    let dir = std::env::temp_dir().join(format!("cratty-update-{}", release.version));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).with_context(|| t!("updater.temp_failed").to_string())?;
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
        .with_context(|| t!("updater.download_failed").to_string())?;
    let total = response.body().content_length().unwrap_or(0);
    let mut reader = response.body_mut().as_reader().take(MAX_INSTALLER);
    let mut out = std::fs::File::create(file).with_context(|| t!("updater.save_failed").to_string())?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut done = 0u64;
    loop {
        let n = reader.read(&mut buf).with_context(|| t!("updater.interrupted").to_string())?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n])
            .with_context(|| t!("updater.save_failed").to_string())?;
        done += n as u64;
        if let Some(share) = (done * 1000).checked_div(total) {
            progress.store(share.min(1000) as u32, Ordering::Relaxed);
        }
    }
    out.sync_all().with_context(|| t!("updater.save_failed").to_string())?;
    if total > 0 && done != total {
        bail!("{}", t!("updater.interrupted"));
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
    command.spawn().with_context(|| t!("updater.launch_failed").to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_comparison() {
        assert!(newer("v0.3.2", "0.3.1"));
        assert!(newer("v0.10.0", "0.9.9"));
        assert!(newer("1.0.0", "0.99.99"));
        assert!(!newer("v0.3.1", "0.3.1"));
        assert!(!newer("v0.3.0", "0.3.1"));
        assert!(!newer("nightly", "0.3.1"));
    }
}
