//! Interface language: language packs live in `locales/<lang>/*.<lang>.yml`.
//!
//! Strings are looked up with `rust_i18n::t!("area.key")`. The locale is
//! process-wide and shared with gpui-component, so its built-in widgets switch
//! language together with ours.

use std::borrow::Cow;

/// Languages with a full pack. `code` is the locale name used in file names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Language {
    English,
    Russian,
    Chinese,
}

impl Language {
    pub const ALL: [Language; 3] = [Language::English, Language::Russian, Language::Chinese];

    pub fn code(self) -> &'static str {
        match self {
            Language::English => "en",
            Language::Russian => "ru",
            Language::Chinese => "zh-CN",
        }
    }

    /// The language's own name, shown the same way in every interface language.
    pub fn native_name(self) -> &'static str {
        match self {
            Language::English => "English",
            Language::Russian => "Русский",
            Language::Chinese => "中文",
        }
    }

    pub fn from_code(code: &str) -> Option<Language> {
        Language::ALL.into_iter().find(|lang| lang.code() == code)
    }

    /// Maps a BCP 47 tag such as `ru-RU`, `zh_Hans_CN` or `en-US` to a pack.
    pub fn from_tag(tag: &str) -> Option<Language> {
        let primary = tag.split(['-', '_', '.']).next()?.to_ascii_lowercase();
        match primary.as_str() {
            "en" => Some(Language::English),
            "ru" => Some(Language::Russian),
            "zh" => Some(Language::Chinese),
            _ => None,
        }
    }
}

/// The system language if there is a pack for it, otherwise English.
pub fn system_language() -> Language {
    sys_locale::get_locales()
        .find_map(|tag| Language::from_tag(&tag))
        .unwrap_or(Language::English)
}

/// Resolves the `language` setting: empty (or unknown) means "follow the system".
pub fn resolve(setting: &str) -> Language {
    Language::from_code(setting.trim()).unwrap_or_else(system_language)
}

/// Switches the interface to the language chosen in settings.
pub fn apply(setting: &str) {
    rust_i18n::set_locale(resolve(setting).code());
}

pub fn current() -> Language {
    Language::from_code(&rust_i18n::locale()).unwrap_or(Language::English)
}

/// Plural form category of `n` in the current language, following CLDR rules.
fn plural_form(language: Language, n: u64) -> &'static str {
    match language {
        Language::Chinese => "other",
        Language::English => {
            if n == 1 {
                "one"
            } else {
                "other"
            }
        }
        Language::Russian => {
            let (rem10, rem100) = (n % 10, n % 100);
            if rem10 == 1 && rem100 != 11 {
                "one"
            } else if (2..=4).contains(&rem10) && !(12..=14).contains(&rem100) {
                "few"
            } else {
                "many"
            }
        }
    }
}

/// Translates a counted phrase: looks up `key.one`/`key.few`/`key.many`/`key.other`
/// (whichever forms the language has) and substitutes `%{count}`. Other
/// placeholders can be filled by the caller with `.replace("%{name}", ...)`.
pub fn plural(key: &str, count: u64) -> String {
    let form = plural_form(current(), count);
    let mut text: Cow<'_, str> = rust_i18n::t!(format!("{key}.{form}"));
    if text.ends_with(&format!(".{form}")) && form != "other" {
        // A pack without this form: fall back to the general one.
        text = rust_i18n::t!(format!("{key}.other"));
    }
    text.replace("%{count}", &count.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn keys(locale: &str) -> BTreeSet<String> {
        crate::_rust_i18n_backend()
            .messages_for_locale(locale)
            .unwrap_or_default()
            .into_iter()
            .map(|(key, _)| key.into_owned())
            .filter(|key| !key.starts_with('_'))
            .collect()
    }

    /// Plural forms differ between languages, so they are compared by phrase.
    fn base(key: &str) -> String {
        for form in [".one", ".few", ".many", ".other"] {
            if let Some(stem) = key.strip_suffix(form) {
                return stem.to_string();
            }
        }
        key.to_string()
    }

    #[test]
    fn every_pack_has_the_same_keys() {
        let english: BTreeSet<String> = keys("en").iter().map(|key| base(key)).collect();
        assert!(!english.is_empty(), "the English pack is empty");
        for language in Language::ALL {
            let theirs: BTreeSet<String> =
                keys(language.code()).iter().map(|key| base(key)).collect();
            let missing: Vec<_> = english.difference(&theirs).collect();
            let extra: Vec<_> = theirs.difference(&english).collect();
            assert!(
                missing.is_empty() && extra.is_empty(),
                "{}: missing {missing:?}, extra {extra:?}",
                language.code()
            );
        }
    }

    #[test]
    fn placeholders_match_english() {
        let placeholders = |text: &str| -> BTreeSet<String> {
            text.match_indices("%{")
                .filter_map(|(at, _)| {
                    let rest = &text[at + 2..];
                    rest.find('}').map(|end| rest[..end].to_string())
                })
                .collect()
        };
        let english: std::collections::BTreeMap<String, BTreeSet<String>> = crate::_rust_i18n_backend()
            .messages_for_locale("en")
            .unwrap_or_default()
            .into_iter()
            .map(|(key, text)| (base(&key), placeholders(&text)))
            .collect();
        for language in Language::ALL {
            for (key, text) in crate::_rust_i18n_backend()
                .messages_for_locale(language.code())
                .unwrap_or_default()
            {
                if let Some(expected) = english.get(&base(&key)) {
                    let mut found = placeholders(&text);
                    found.remove("count");
                    let mut expected = expected.clone();
                    expected.remove("count");
                    assert_eq!(found, expected, "{}: {key}", language.code());
                }
            }
        }
    }

    #[test]
    fn plural_forms_follow_the_language_rules() {
        let ru = |n| plural_form(Language::Russian, n);
        assert_eq!([ru(1), ru(2), ru(5), ru(11), ru(21), ru(22), ru(112)], [
            "one", "few", "many", "many", "one", "few", "many"
        ]);
        assert_eq!(plural_form(Language::English, 1), "one");
        assert_eq!(plural_form(Language::English, 0), "other");
        assert_eq!(plural_form(Language::Chinese, 1), "other");
    }

    #[test]
    fn system_tags_map_to_packs() {
        assert_eq!(Language::from_tag("ru-RU"), Some(Language::Russian));
        assert_eq!(Language::from_tag("zh_Hans_CN"), Some(Language::Chinese));
        assert_eq!(Language::from_tag("zh-TW"), Some(Language::Chinese));
        assert_eq!(Language::from_tag("en-GB"), Some(Language::English));
        assert_eq!(Language::from_tag("de-DE"), None);
        assert_eq!(resolve("ru"), Language::Russian);
    }
}
