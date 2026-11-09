//! The selfh.st icon catalog: the list is kept in a cache and refreshed via ETag,
//! the icons themselves are downloaded only when the user picks one.
//!
//! All functions here are blocking: call them from a background thread.

use std::io::Read as _;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use rust_i18n::t;
use proto::IconRecord;

pub const SOURCE: &str = "selfhst";

const CATALOG_URL: &str =
    "https://raw.githubusercontent.com/selfhst/icons/refs/heads/main/index-consolidated.json";
const FILES_URL: &str = "https://cdn.jsdelivr.net/gh/selfhst/icons";

/// The catalog weighs hundreds of kilobytes, an icon a few; anything larger is wrong.
const MAX_CATALOG: u64 = 16 * 1024 * 1024;
const MAX_ICON: u64 = 2 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(20);

/// An icon in the catalog.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    /// File name without extension: `github` → `svg/github.svg`.
    pub reference: String,
    pub svg: bool,
    pub light: bool,
    pub dark: bool,
    pub category: String,
    pub tags: String,
}

impl Entry {
    /// Icon key in host records: `selfhst:github`, the colored one —
    /// `selfhst:github:color`.
    pub fn key(&self, colored: bool) -> String {
        IconRecord::key_of(SOURCE, &self.reference, colored)
    }

    fn matches(&self, query: &str) -> bool {
        self.name.to_lowercase().contains(query)
            || self.reference.contains(query)
            || self.tags.to_lowercase().contains(query)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Catalog {
    pub entries: Vec<Entry>,
    /// ETag of the response the catalog was built from: with it the server will answer "not modified".
    pub etag: Option<String>,
}

impl Catalog {
    /// Parses `index-consolidated.json`: an array of rows
    /// `[name, file, svg, png, webp, light, dark, category, tags, …]`.
    pub fn parse(text: &str, etag: Option<String>) -> Result<Self> {
        let rows: Vec<Vec<serde_json::Value>> =
            serde_json::from_str(text).with_context(|| t!("selfhst.parse_failed").to_string())?;
        let text_at = |row: &[serde_json::Value], index: usize| {
            row.get(index)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let yes = |row: &[serde_json::Value], index: usize| text_at(row, index) == "Y";

        let mut entries: Vec<Entry> = rows
            .iter()
            .filter_map(|row| {
                let reference = text_at(row, 1);
                // The file name goes into a URL: only what occurs in the catalog is allowed.
                let safe = !reference.is_empty()
                    && reference
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
                    && !reference.starts_with('.');
                safe.then(|| Entry {
                    name: text_at(row, 0),
                    reference,
                    svg: yes(row, 2),
                    light: yes(row, 5),
                    dark: yes(row, 6),
                    category: text_at(row, 7),
                    tags: text_at(row, 8),
                })
            })
            .collect();
        if entries.is_empty() {
            bail!("{}", t!("selfhst.empty"));
        }
        entries.sort_by_key(|entry| entry.name.to_lowercase());
        Ok(Self { entries, etag })
    }

    /// Icons matching a query: first those whose name starts with it.
    pub fn search(&self, query: &str) -> Vec<&Entry> {
        let query = query.trim().to_lowercase();
        let mut found: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|entry| query.is_empty() || entry.matches(&query))
            .collect();
        if !query.is_empty() {
            found.sort_by_key(|entry| !entry.name.to_lowercase().starts_with(&query));
        }
        found
    }

    pub fn find(&self, reference: &str) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|entry| entry.reference == reference)
    }
}

fn cache_dir() -> Option<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        home().map(|home| home.join("Library").join("Caches"))
    } else {
        std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| home().map(|home| home.join(".cache")))
    };
    Some(base?.join("cratty").join("selfhst"))
}

fn home() -> Option<PathBuf> {
    #[allow(deprecated)]
    std::env::home_dir()
}

/// The catalog from the cache, if it is there and readable.
pub fn cached() -> Option<Catalog> {
    let dir = cache_dir()?;
    let text = std::fs::read_to_string(dir.join("index.json")).ok()?;
    let etag = std::fs::read_to_string(dir.join("etag"))
        .ok()
        .map(|etag| etag.trim().to_owned())
        .filter(|etag| !etag.is_empty());
    Catalog::parse(&text, etag).ok()
}

/// Result of a catalog refresh.
pub enum Refresh {
    /// The server replied that the catalog has not changed.
    Unchanged,
    Updated(Catalog),
}

/// Compares the catalog with the server via ETag and caches the new one if it changed.
pub fn refresh(etag: Option<&str>) -> Result<Refresh> {
    let agent = agent();
    let mut request = agent.get(CATALOG_URL);
    if let Some(etag) = etag {
        request = request.header("If-None-Match", etag);
    }
    let mut response = request.call().with_context(|| t!("selfhst.load_failed").to_string())?;
    if response.status() == 304 {
        return Ok(Refresh::Unchanged);
    }
    let etag = response
        .headers()
        .get("etag")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let text = read_limited(response.body_mut().as_reader(), MAX_CATALOG)?;
    let text = String::from_utf8(text).map_err(|_| anyhow!("{}", t!("selfhst.not_utf8")))?;
    let catalog = Catalog::parse(&text, etag.clone())?;

    if let Some(dir) = cache_dir() {
        // The cache is not critical: if it was not written, we will download again next time.
        let _ = std::fs::create_dir_all(&dir)
            .and_then(|()| std::fs::write(dir.join("index.json"), &text))
            .and_then(|()| std::fs::write(dir.join("etag"), etag.unwrap_or_default()));
    }
    Ok(Refresh::Updated(catalog))
}

/// Downloads an icon. The colored one is a single file. Otherwise light and dark, and the colored
/// one only as a replacement for whichever of them is missing from the catalog.
pub fn download(entry: &Entry, colored: bool) -> Result<IconRecord> {
    let agent = agent();
    let format = if entry.svg { "svg" } else { "png" };
    let fetch = |suffix: &str| -> Result<Vec<u8>> {
        let url = format!("{FILES_URL}/{format}/{}{suffix}.{format}", entry.reference);
        let mut response = agent
            .get(&url)
            .call()
            .with_context(|| t!("selfhst.icon_failed", name = entry.name).to_string())?;
        read_limited(response.body_mut().as_reader(), MAX_ICON)
    };

    let themed = !colored;
    let light = if themed && entry.light {
        fetch("-light")?
    } else {
        Vec::new()
    };
    let dark = if themed && entry.dark {
        fetch("-dark")?
    } else {
        Vec::new()
    };
    let color = if colored || light.is_empty() || dark.is_empty() {
        fetch("")?
    } else {
        Vec::new()
    };
    Ok(IconRecord {
        source: SOURCE.into(),
        name: entry.reference.clone(),
        format: format.into(),
        colored,
        color,
        light,
        dark,
    })
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .build()
        .into()
}

fn read_limited(reader: impl std::io::Read, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .with_context(|| t!("selfhst.cut_off").to_string())?;
    if bytes.len() as u64 > limit {
        bail!("{}", t!("selfhst.too_large"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"[
        ["GitHub", "github", "Y", "Y", "Y", "Y", "Y", "Other", "Git", "2313"],
        ["13 Feet Ladder", "13-feet-ladder", "N", "Y", "Y", "N", "N", "Self-Hosted", "", "643"],
        ["Gitea", "gitea", "Y", "Y", "Y", "N", "N", "Self-Hosted", "Git", "1"],
        ["Evil", "../etc/passwd", "Y", "Y", "Y", "N", "N", "", "", "1"]
    ]"#;

    /// Live server: `cargo test -- --ignored selfhst`.
    #[test]
    #[ignore = "hits the network"]
    fn live_catalog_and_icon() {
        let Refresh::Updated(catalog) = refresh(None).expect("catalog") else {
            panic!("without an ETag a \"not modified\" response is impossible");
        };
        assert!(catalog.entries.len() > 1000);
        assert!(matches!(
            refresh(catalog.etag.as_deref()).expect("repeat"),
            Refresh::Unchanged
        ));

        let github = catalog.find("github").expect("github");
        let icon = download(github, false).expect("icon");
        assert!(icon.light.starts_with(b"<svg") || icon.light.starts_with(b"<?xml"));
        assert!(!icon.dark.is_empty());
        assert!(
            icon.color.is_empty(),
            "both variants exist — the colored one is not needed"
        );
        assert!(icon.is_complete());

        let icon = download(github, true).expect("colored");
        assert!(!icon.color.is_empty() && icon.light.is_empty() && icon.dark.is_empty());

        let png = catalog
            .entries
            .iter()
            .find(|entry| !entry.svg && !entry.light)
            .expect("without svg and variants");
        let icon = download(png, false).expect("png");
        assert!(icon.color.starts_with(b"\x89PNG"), "fallback colored");
        assert!(icon.is_complete());
    }

    #[test]
    fn catalog_parses() {
        let catalog = Catalog::parse(SAMPLE, Some("\"abc\"".into())).expect("parse");
        assert_eq!(catalog.entries.len(), 3, "dangerous file name dropped");
        let github = catalog.find("github").expect("present");
        assert!(github.svg && github.light && github.dark);
        assert_eq!(github.key(false), "selfhst:github");
        assert_eq!(github.key(true), "selfhst:github:color");
        let ladder = catalog.find("13-feet-ladder").expect("present");
        assert!(!ladder.svg && !ladder.light);
        assert!(Catalog::parse("[]", None).is_err());
    }

    #[test]
    fn search_matches_name_prefix_first() {
        let catalog = Catalog::parse(SAMPLE, None).expect("parse");
        let names = |query: &str| -> Vec<String> {
            catalog
                .search(query)
                .into_iter()
                .map(|entry| entry.reference.clone())
                .collect()
        };
        assert_eq!(names("git"), vec!["gitea", "github"]);
        // The tag is searched too, but a match at the start of the name ranks higher.
        assert_eq!(names("GIT").len(), 2);
        assert_eq!(names("ladder"), vec!["13-feet-ladder"]);
        assert_eq!(names("").len(), 3);
    }
}
