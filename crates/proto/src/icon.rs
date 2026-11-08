use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Значок, скачанный из внешнего каталога, вместе с байтами — чтобы список
/// хостов выглядел так же и без сети. Хост или группа ссылаются на него
/// строкой [`IconRecord::key`], например `selfhst:github`.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IconRecord {
    /// Откуда значок: пока только `selfhst`.
    #[serde(default)]
    pub source: String,
    /// Имя значка в каталоге.
    #[serde(default)]
    pub name: String,
    /// Формат байтов: `svg` или `png`.
    #[serde(default)]
    pub format: String,
    /// Только цветной вариант, одинаковый в любой теме. Тогда светлого и
    /// тёмного в записи нет, а ключ значка оканчивается на `:color`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub colored: bool,
    /// Цветной вариант: у цветного значка — единственный, у остальных — запасной,
    /// когда светлого или тёмного в каталоге нет.
    #[serde(default, with = "base64_bytes", skip_serializing_if = "Vec::is_empty")]
    pub color: Vec<u8>,
    /// Светлый (белый) вариант для тёмной темы; пусто — его нет в каталоге.
    #[serde(default, with = "base64_bytes", skip_serializing_if = "Vec::is_empty")]
    pub light: Vec<u8>,
    /// Тёмный вариант для светлой темы; пусто — его нет.
    #[serde(default, with = "base64_bytes", skip_serializing_if = "Vec::is_empty")]
    pub dark: Vec<u8>,
}

impl core::fmt::Debug for IconRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "IconRecord({})", self.key())
    }
}

/// Какой вариант значка показать.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IconVariant {
    Color,
    Light,
    Dark,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl IconRecord {
    /// Ключ, которым на значок ссылаются хосты и группы.
    pub fn key(&self) -> String {
        Self::key_of(&self.source, &self.name, self.colored)
    }

    pub fn key_of(source: &str, name: &str, colored: bool) -> String {
        if colored {
            format!("{source}:{name}:color")
        } else {
            format!("{source}:{name}")
        }
    }

    /// Есть ли что показать в обеих темах.
    pub fn is_complete(&self) -> bool {
        let has = |bytes: &Vec<u8>| !bytes.is_empty() || !self.color.is_empty();
        if self.colored {
            !self.color.is_empty()
        } else {
            has(&self.light) && has(&self.dark)
        }
    }

    /// Байты варианта под тему: на тёмном фоне — светлый, на светлом — тёмный.
    /// Нужного нет — цветной.
    pub fn for_theme(&self, dark_theme: bool) -> (IconVariant, &[u8]) {
        if self.colored {
            return (IconVariant::Color, &self.color);
        }
        let (variant, bytes) = if dark_theme {
            (IconVariant::Light, &self.light)
        } else {
            (IconVariant::Dark, &self.dark)
        };
        if bytes.is_empty() {
            (IconVariant::Color, &self.color)
        } else {
            (variant, bytes)
        }
    }
}

mod base64_bytes {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        STANDARD.decode(text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn icon() -> IconRecord {
        IconRecord {
            source: "selfhst".into(),
            name: "github".into(),
            format: "svg".into(),
            colored: false,
            color: b"<svg color/>".to_vec(),
            light: b"<svg light/>".to_vec(),
            dark: Vec::new(),
        }
    }

    #[test]
    fn variant_vybiraetsya_po_teme() {
        let icon = icon();
        assert_eq!(icon.key(), "selfhst:github");
        assert_eq!(
            icon.for_theme(true),
            (IconVariant::Light, &b"<svg light/>"[..])
        );
        // Тёмного варианта нет — цветной.
        assert_eq!(
            icon.for_theme(false),
            (IconVariant::Color, &b"<svg color/>"[..])
        );
        assert!(icon.is_complete());

        let mut colored = icon.clone();
        colored.colored = true;
        assert_eq!(colored.key(), "selfhst:github:color");
        assert_eq!(colored.for_theme(true).0, IconVariant::Color);

        let mut half = icon;
        half.color.clear();
        assert!(!half.is_complete(), "для светлой темы показать нечего");
    }

    #[test]
    fn bayty_v_zapisi_lezhat_base64() {
        let body = crate::RecordBody::Icon(icon());
        let json = serde_json::to_string(&body).expect("сериализация");
        assert!(json.contains("PHN2ZyBjb2xvci8+"), "{json}");
        assert!(!json.contains("\"dark\""), "{json}");
        assert_eq!(
            serde_json::from_str::<crate::RecordBody>(&json).expect("разбор"),
            body
        );
    }
}
