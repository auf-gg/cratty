use gpui_kit::{App, Global, SharedString};
use std::collections::HashSet;

#[cfg(target_os = "windows")]
const CANDIDATES: &[&str] = &[
    "Cascadia Mono",
    "Cascadia Code",
    "Consolas",
    "Lucida Console",
    "Courier New",
];

#[cfg(target_os = "macos")]
const CANDIDATES: &[&str] = &["SF Mono", "Menlo", "Monaco", "Andale Mono", "Courier New"];

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
const CANDIDATES: &[&str] = &[
    "JetBrains Mono",
    "Fira Code",
    "DejaVu Sans Mono",
    "Liberation Mono",
    "Noto Sans Mono",
    "Ubuntu Mono",
    "monospace",
];

#[derive(Clone, Debug)]
pub struct MonoFont {
    pub family: SharedString,
    pub is_monospace: bool,
    /// Шрифт для значков (Nerd Font), если основной их не содержит.
    pub icons: Option<SharedString>,
}

impl Global for MonoFont {}

/// Все установленные семейства, по алфавиту, без повторов.
pub fn installed(cx: &App) -> Vec<String> {
    let mut names = cx.text_system().all_font_names();
    names.sort_by_key(|name| name.to_lowercase());
    names.dedup();
    names.retain(|name| !name.starts_with('.'));
    names
}

/// Похожие на моноширинные: по имени семейства. Точного признака текстовая
/// система не даёт, а грузить две тысячи шрифтов ради замера долго.
pub fn monospace(all: &[String]) -> Vec<String> {
    const HINTS: &[&str] = &[
        "mono",
        "code",
        "console",
        "consolas",
        "courier",
        "terminal",
        "term",
        "hack",
        "iosevka",
        "inconsolata",
        "menlo",
        "monaco",
        "cascadia",
        "fixed",
        "typewriter",
    ];
    all.iter()
        .filter(|name| {
            let lower = name.to_lowercase();
            HINTS.iter().any(|hint| lower.contains(hint))
        })
        .cloned()
        .collect()
}

/// Шрифты со значками для промптов: Nerd Font и Symbols.
pub fn icon_fonts(all: &[String]) -> Vec<String> {
    let mut fonts: Vec<String> = all
        .iter()
        .filter(|name| name.contains("Nerd Font") || name.starts_with("Symbols"))
        .cloned()
        .collect();
    // Сначала «Symbols Nerd Font», потом моноширинные варианты.
    fonts.sort_by_key(|name| {
        (
            !name.starts_with("Symbols"),
            !name.ends_with("Mono"),
            name.to_lowercase(),
        )
    });
    fonts
}

/// Значение настройки «иконки» без шрифта.
pub const NO_ICONS: &str = "none";

/// Вшитый шрифт значков: Symbols Nerd Font Mono (Nerd Fonts 3) с буквой «m»,
/// без которой gpui шрифт не загружает (см. assets/fonts/README.md). У системных
/// Nerd Font часто старая версия без значков Material.
pub const BUNDLED_ICONS: &str = "Cratty Symbols";
const BUNDLED_ICONS_TTF: &[u8] = include_bytes!("../../assets/fonts/CrattySymbols-Regular.ttf");

impl MonoFont {
    pub fn detect(cx: &App) -> Self {
        let installed: HashSet<String> = cx.text_system().all_font_names().into_iter().collect();

        for candidate in CANDIDATES {
            if installed.contains(*candidate) {
                return Self {
                    family: SharedString::new_static(candidate),
                    is_monospace: true,
                    icons: None,
                };
            }
        }

        Self {
            family: SharedString::new_static(".SystemUIFont"),
            is_monospace: false,
            icons: None,
        }
    }

    /// Шрифт терминала по настройкам: выбранный, если установлен, иначе
    /// найденный сам; значки — выбранный шрифт, сам основной (если он Nerd
    /// Font) или первый найденный Nerd Font.
    pub fn from_settings(settings: &crate::ui::settings::Settings, cx: &App) -> Self {
        let all = installed(cx);
        let chosen = settings.terminal_font.trim();
        let mut font = if !chosen.is_empty() && all.iter().any(|name| name == chosen) {
            Self {
                family: SharedString::from(chosen.to_owned()),
                is_monospace: true,
                icons: None,
            }
        } else {
            Self::detect(cx)
        };

        let wanted = settings.terminal_icons.trim();
        font.icons = match wanted {
            NO_ICONS => None,
            // Подстановка берётся только для символов, которых нет в основном
            // шрифте, поэтому вшитый набор не мешает и Nerd Font в роли основного.
            "" => Some(SharedString::new_static(BUNDLED_ICONS)),
            name if all.iter().any(|known| known == name) => {
                Some(SharedString::from(name.to_owned()))
            }
            _ => None,
        };
        font
    }

    pub fn init(cx: &mut App) {
        if let Err(error) = cx
            .text_system()
            .add_fonts(vec![std::borrow::Cow::Borrowed(BUNDLED_ICONS_TTF)])
        {
            eprintln!("не удалось загрузить шрифт значков: {error:#}");
        }
        let font = Self::detect(cx);
        if !font.is_monospace {
            eprintln!(
                "моноширинный шрифт не найден (искали: {}), откат на {}",
                CANDIDATES.join(", "),
                font.family
            );
        }
        cx.set_global(font);
    }

    pub fn apply(settings: &crate::ui::settings::Settings, cx: &mut App) {
        let font = Self::from_settings(settings, cx);
        cx.set_global(font);
    }

    pub fn get(cx: &App) -> &Self {
        cx.global::<Self>()
    }

    /// Шрифт для текста терминала: основной плюс шрифт значков в подстановке.
    pub fn font(&self) -> gpui_kit::Font {
        let mut font = gpui_kit::font(self.family.clone());
        if let Some(icons) = &self.icons {
            font.fallbacks = Some(gpui_kit::FontFallbacks::from_fonts(vec![icons.to_string()]));
        }
        font
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    #[test]
    fn otbor_monoshirinnyh_i_shriftov_znachkov() {
        let all: Vec<String> = [
            "Inter",
            "JetBrains Mono",
            "Fira Code",
            "Hack Nerd Font",
            "Hack Nerd Font Mono",
            "Symbols Nerd Font",
            "Noto Sans",
        ]
        .map(String::from)
        .to_vec();

        let mono = super::monospace(&all);
        assert!(mono.contains(&"JetBrains Mono".to_string()));
        assert!(mono.contains(&"Fira Code".to_string()));
        assert!(!mono.contains(&"Inter".to_string()));

        assert_eq!(
            super::icon_fonts(&all),
            ["Symbols Nerd Font", "Hack Nerd Font Mono", "Hack Nerd Font"]
        );
    }

    #[test]
    fn v_ishodnikah_net_literalnyh_semeystv_shrifta() {
        let needle = format!(".font_family({}", '"');
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");

        let mut offenders = Vec::new();
        for file in rust_files(&root) {
            let text = std::fs::read_to_string(&file).expect("прочитать исходник");
            for (index, line) in text.lines().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                let Some((_, tail)) = line.split_once(needle.as_str()) else {
                    continue;
                };
                let family = tail.split('"').next().unwrap_or_default();
                if family != ".SystemUIFont" {
                    offenders.push(format!(
                        "{}:{}: {family}",
                        file.strip_prefix(&root).unwrap_or(&file).display(),
                        index + 1
                    ));
                }
            }
        }

        assert!(
            offenders.is_empty(),
            "семейство шрифта задано литералом — берите его у MonoFont:\n{}",
            offenders.join("\n")
        );
    }

    fn rust_files(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let entries = std::fs::read_dir(dir).expect("обойти каталог исходников");
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(rust_files(&path));
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
        out
    }
}
