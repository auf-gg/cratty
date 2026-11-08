//! Каталог значков selfh.st: список хранится в кеше и обновляется по ETag,
//! сами значки скачиваются, только когда пользователь выбрал один из них.
//!
//! Все функции здесь блокирующие: зовите их из фонового потока.

use std::io::Read as _;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use proto::IconRecord;

pub const SOURCE: &str = "selfhst";

const CATALOG_URL: &str =
    "https://raw.githubusercontent.com/selfhst/icons/refs/heads/main/index-consolidated.json";
const FILES_URL: &str = "https://cdn.jsdelivr.net/gh/selfhst/icons";

/// Каталог весит сотни килобайт, значок — единицы; больше — что-то не то.
const MAX_CATALOG: u64 = 16 * 1024 * 1024;
const MAX_ICON: u64 = 2 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(20);

/// Значок в каталоге.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    /// Имя файла без расширения: `github` → `svg/github.svg`.
    pub reference: String,
    pub svg: bool,
    pub light: bool,
    pub dark: bool,
    pub category: String,
    pub tags: String,
}

impl Entry {
    /// Ключ значка в записях хостов: `selfhst:github`, цветной —
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
    /// ETag ответа, из которого собран каталог: по нему сервер скажет «не изменился».
    pub etag: Option<String>,
}

impl Catalog {
    /// Разбирает `index-consolidated.json`: массив строк
    /// `[имя, файл, svg, png, webp, light, dark, категория, теги, …]`.
    pub fn parse(text: &str, etag: Option<String>) -> Result<Self> {
        let rows: Vec<Vec<serde_json::Value>> =
            serde_json::from_str(text).context("каталог selfh.st не разобрать")?;
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
                // Имя файла пойдёт в адрес: только то, что бывает в каталоге.
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
            bail!("каталог selfh.st пуст");
        }
        entries.sort_by_key(|entry| entry.name.to_lowercase());
        Ok(Self { entries, etag })
    }

    /// Значки, подходящие под запрос: сначала те, чьё имя с него начинается.
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

/// Каталог из кеша, если он там есть и читается.
pub fn cached() -> Option<Catalog> {
    let dir = cache_dir()?;
    let text = std::fs::read_to_string(dir.join("index.json")).ok()?;
    let etag = std::fs::read_to_string(dir.join("etag"))
        .ok()
        .map(|etag| etag.trim().to_owned())
        .filter(|etag| !etag.is_empty());
    Catalog::parse(&text, etag).ok()
}

/// Итог обновления каталога.
pub enum Refresh {
    /// Сервер ответил, что каталог не изменился.
    Unchanged,
    Updated(Catalog),
}

/// Сверяет каталог с сервером по ETag и при изменении кладёт новый в кеш.
pub fn refresh(etag: Option<&str>) -> Result<Refresh> {
    let agent = agent();
    let mut request = agent.get(CATALOG_URL);
    if let Some(etag) = etag {
        request = request.header("If-None-Match", etag);
    }
    let mut response = request.call().context("каталог selfh.st не загрузился")?;
    if response.status() == 304 {
        return Ok(Refresh::Unchanged);
    }
    let etag = response
        .headers()
        .get("etag")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let text = read_limited(response.body_mut().as_reader(), MAX_CATALOG)?;
    let text = String::from_utf8(text).map_err(|_| anyhow!("каталог selfh.st не UTF-8"))?;
    let catalog = Catalog::parse(&text, etag.clone())?;

    if let Some(dir) = cache_dir() {
        // Кеш — не критичен: не записался, значит в другой раз скачаем снова.
        let _ = std::fs::create_dir_all(&dir)
            .and_then(|()| std::fs::write(dir.join("index.json"), &text))
            .and_then(|()| std::fs::write(dir.join("etag"), etag.unwrap_or_default()));
    }
    Ok(Refresh::Updated(catalog))
}

/// Скачивает значок. Цветной — один файл. Иначе светлый и тёмный, а цветной
/// только на замену тому из них, которого в каталоге нет.
pub fn download(entry: &Entry, colored: bool) -> Result<IconRecord> {
    let agent = agent();
    let format = if entry.svg { "svg" } else { "png" };
    let fetch = |suffix: &str| -> Result<Vec<u8>> {
        let url = format!("{FILES_URL}/{format}/{}{suffix}.{format}", entry.reference);
        let mut response = agent
            .get(&url)
            .call()
            .with_context(|| format!("значок {} не скачался", entry.name))?;
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
        .context("ответ оборвался")?;
    if bytes.len() as u64 > limit {
        bail!("ответ слишком большой");
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
        ["Злой", "../etc/passwd", "Y", "Y", "Y", "N", "N", "", "", "1"]
    ]"#;

    /// Живой сервер: `cargo test -- --ignored selfhst`.
    #[test]
    #[ignore = "ходит в сеть"]
    fn zhivoy_katalog_i_znachok() {
        let Refresh::Updated(catalog) = refresh(None).expect("каталог") else {
            panic!("без ETag ответ «не изменился» невозможен");
        };
        assert!(catalog.entries.len() > 1000);
        assert!(matches!(
            refresh(catalog.etag.as_deref()).expect("повтор"),
            Refresh::Unchanged
        ));

        let github = catalog.find("github").expect("github");
        let icon = download(github, false).expect("значок");
        assert!(icon.light.starts_with(b"<svg") || icon.light.starts_with(b"<?xml"));
        assert!(!icon.dark.is_empty());
        assert!(
            icon.color.is_empty(),
            "оба варианта есть — цветной не нужен"
        );
        assert!(icon.is_complete());

        let icon = download(github, true).expect("цветной");
        assert!(!icon.color.is_empty() && icon.light.is_empty() && icon.dark.is_empty());

        let png = catalog
            .entries
            .iter()
            .find(|entry| !entry.svg && !entry.light)
            .expect("без svg и вариантов");
        let icon = download(png, false).expect("png");
        assert!(icon.color.starts_with(b"\x89PNG"), "запасной цветной");
        assert!(icon.is_complete());
    }

    #[test]
    fn katalog_razbiraetsya() {
        let catalog = Catalog::parse(SAMPLE, Some("\"abc\"".into())).expect("разбор");
        assert_eq!(catalog.entries.len(), 3, "опасное имя файла отброшено");
        let github = catalog.find("github").expect("есть");
        assert!(github.svg && github.light && github.dark);
        assert_eq!(github.key(false), "selfhst:github");
        assert_eq!(github.key(true), "selfhst:github:color");
        let ladder = catalog.find("13-feet-ladder").expect("есть");
        assert!(!ladder.svg && !ladder.light);
        assert!(Catalog::parse("[]", None).is_err());
    }

    #[test]
    fn poisk_snachala_po_nachalu_imeni() {
        let catalog = Catalog::parse(SAMPLE, None).expect("разбор");
        let names = |query: &str| -> Vec<String> {
            catalog
                .search(query)
                .into_iter()
                .map(|entry| entry.reference.clone())
                .collect()
        };
        assert_eq!(names("git"), vec!["gitea", "github"]);
        // Тег тоже ищется, но совпадение с началом имени — выше.
        assert_eq!(names("GIT").len(), 2);
        assert_eq!(names("ladder"), vec!["13-feet-ladder"]);
        assert_eq!(names("").len(), 3);
    }
}
