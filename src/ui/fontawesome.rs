//! Значки Font Awesome Free: наборы Brands и Classic (Solid, Regular).
//!
//! Контуры лежат в бинарнике сжатым списком (`assets/fontawesome`) и
//! распаковываются при первом обращении. Картинку значка отдаёт загрузчик
//! ассетов по пути `fa/<стиль>/<имя>.svg`, поэтому рисуется он как любой
//! встроенный значок — одним цветом темы.

use std::io::Read as _;
use std::sync::LazyLock;

static DATA: &[u8] = include_bytes!("../../assets/fontawesome/icons.tsv.gz");

pub struct FaIcon {
    /// `solid`, `regular` или `brands`.
    pub style: String,
    pub name: String,
    pub label: String,
    terms: String,
    width: u32,
    height: u32,
    path: String,
}

impl FaIcon {
    /// Ключ значка в записях хостов и групп: `fa:brands:github`.
    pub fn key(&self) -> String {
        format!("fa:{}:{}", self.style, self.name)
    }

    pub fn asset_path(&self) -> String {
        format!("fa/{}/{}.svg", self.style, self.name)
    }

    pub fn svg(&self) -> Vec<u8> {
        format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {} {}"><path d="{}"/></svg>"#,
            self.width, self.height, self.path
        )
        .into_bytes()
    }

    /// Насколько хорошо значок подходит под запрос: меньше — лучше.
    fn rank(&self, query: &str) -> Option<u8> {
        if self.name.starts_with(query) {
            Some(0)
        } else if self.name.contains(query) || self.label.to_lowercase().contains(query) {
            Some(1)
        } else if self.terms.to_lowercase().contains(query) {
            Some(2)
        } else {
            None
        }
    }
}

static ICONS: LazyLock<Vec<FaIcon>> = LazyLock::new(|| {
    let mut text = String::new();
    if flate2::read::GzDecoder::new(DATA)
        .read_to_string(&mut text)
        .is_err()
    {
        return Vec::new();
    }
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split('\t');
            let mut next = || parts.next().map(str::to_owned);
            Some(FaIcon {
                style: next()?,
                name: next()?,
                width: next()?.parse().ok()?,
                height: next()?.parse().ok()?,
                label: next()?,
                terms: next()?,
                path: next()?,
            })
        })
        .collect()
});

pub fn all() -> &'static [FaIcon] {
    &ICONS
}

pub fn find(style: &str, name: &str) -> Option<&'static FaIcon> {
    all()
        .iter()
        .find(|icon| icon.style == style && icon.name == name)
}

/// Значок по ключу `fa:<стиль>:<имя>`.
pub fn from_key(key: &str) -> Option<&'static FaIcon> {
    let (style, name) = key.strip_prefix("fa:")?.split_once(':')?;
    find(style, name)
}

/// Значок по пути ассета `fa/<стиль>/<имя>.svg`.
pub fn from_asset_path(path: &str) -> Option<&'static FaIcon> {
    let (style, file) = path.strip_prefix("fa/")?.split_once('/')?;
    find(style, file.strip_suffix(".svg")?)
}

/// Значки под запрос, лучшие совпадения первыми.
pub fn search(query: &str) -> Vec<&'static FaIcon> {
    let query = query.trim().to_lowercase();
    let mut found: Vec<(u8, &FaIcon)> = all()
        .iter()
        .filter_map(|icon| icon.rank(&query).map(|rank| (rank, icon)))
        .collect();
    found.sort_by_key(|(rank, _)| *rank);
    found.into_iter().map(|(_, icon)| icon).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nabory_na_meste() {
        let count = |style: &str| all().iter().filter(|icon| icon.style == style).count();
        assert!(count("brands") > 500, "brands: {}", count("brands"));
        assert!(count("solid") > 1000, "solid: {}", count("solid"));
        assert!(count("regular") > 100, "regular: {}", count("regular"));
    }

    #[test]
    fn klyuch_i_put_vedut_k_odnomu_znachku() {
        let github = find("brands", "github").expect("github");
        assert_eq!(github.key(), "fa:brands:github");
        assert_eq!(github.asset_path(), "fa/brands/github.svg");
        assert!(std::ptr::eq(
            from_key("fa:brands:github").expect("ключ"),
            github
        ));
        assert!(std::ptr::eq(
            from_asset_path("fa/brands/github.svg").expect("путь"),
            github
        ));
        assert!(from_key("fa:brands:нет-такого").is_none());
        assert!(from_key("selfhst:github").is_none());

        let svg = String::from_utf8(github.svg()).expect("utf8");
        assert!(
            svg.starts_with("<svg") && svg.contains("viewBox=\"0 0 "),
            "{svg}"
        );
    }

    #[test]
    fn poisk_snachala_po_imeni() {
        let found = search("docker");
        assert_eq!(found.first().map(|icon| icon.name.as_str()), Some("docker"));
        // И по поисковым словам, а не только по имени.
        assert!(
            search("kubernetes")
                .iter()
                .any(|icon| icon.style == "brands")
        );
        assert!(search("zzzz-нет").is_empty());
    }
}
