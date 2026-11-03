use gpui::{App, Global, SharedString};
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
}

impl Global for MonoFont {}

impl MonoFont {
    pub fn detect(cx: &App) -> Self {
        let installed: HashSet<String> = cx.text_system().all_font_names().into_iter().collect();

        for candidate in CANDIDATES {
            if installed.contains(*candidate) {
                return Self {
                    family: SharedString::new_static(candidate),
                    is_monospace: true,
                };
            }
        }

        Self {
            family: SharedString::new_static(".SystemUIFont"),
            is_monospace: false,
        }
    }

    pub fn init(cx: &mut App) {
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

    pub fn get(cx: &App) -> &Self {
        cx.global::<Self>()
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

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
