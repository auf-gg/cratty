use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// An icon downloaded from an external catalog, stored with its bytes so the list
/// of hosts looks the same offline. A host or group references it
/// by the string [`IconRecord::key`], for example `selfhst:github`.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IconRecord {
    /// Where the icon comes from: only `selfhst` for now.
    #[serde(default)]
    pub source: String,
    /// Icon name in the catalog.
    #[serde(default)]
    pub name: String,
    /// Byte format: `svg` or `png`.
    #[serde(default)]
    pub format: String,
    /// Color variant only, identical in any theme. Then there is no light or
    /// dark variant in the record, and the icon key ends with `:color`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub colored: bool,
    /// Color variant: the only one for a color icon, a fallback for the rest
    /// when the catalog has no light or dark one.
    #[serde(default, with = "base64_bytes", skip_serializing_if = "Vec::is_empty")]
    pub color: Vec<u8>,
    /// Light (white) variant for the dark theme; empty — not in the catalog.
    #[serde(default, with = "base64_bytes", skip_serializing_if = "Vec::is_empty")]
    pub light: Vec<u8>,
    /// Dark variant for the light theme; empty — none.
    #[serde(default, with = "base64_bytes", skip_serializing_if = "Vec::is_empty")]
    pub dark: Vec<u8>,
}

impl core::fmt::Debug for IconRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "IconRecord({})", self.key())
    }
}

/// Which icon variant to show.
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
    /// Key by which hosts and groups reference the icon.
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

    /// Whether there is something to show in both themes.
    pub fn is_complete(&self) -> bool {
        let has = |bytes: &Vec<u8>| !bytes.is_empty() || !self.color.is_empty();
        if self.colored {
            !self.color.is_empty()
        } else {
            has(&self.light) && has(&self.dark)
        }
    }

    /// Variant bytes for the theme: light on a dark background, dark on a light one.
    /// If the needed one is missing, the color one.
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
    fn variant_is_chosen_by_theme() {
        let icon = icon();
        assert_eq!(icon.key(), "selfhst:github");
        assert_eq!(
            icon.for_theme(true),
            (IconVariant::Light, &b"<svg light/>"[..])
        );
        // No dark variant — use the color one.
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
        assert!(!half.is_complete(), "nothing to show for the light theme");
    }

    #[test]
    fn bytes_in_record_are_stored_as_base64() {
        let body = crate::RecordBody::Icon(icon());
        let json = serde_json::to_string(&body).expect("serialization");
        assert!(json.contains("PHN2ZyBjb2xvci8+"), "{json}");
        assert!(!json.contains("\"dark\""), "{json}");
        assert_eq!(
            serde_json::from_str::<crate::RecordBody>(&json).expect("parse"),
            body
        );
    }
}
