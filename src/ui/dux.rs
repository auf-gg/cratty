//! Палитры Dux Shell (DankMaterialShell): Material-цвета, которые оболочка
//! генерирует из обоев, плюс её 16 цветов терминала (`dank16`).
//! Файл: `~/.cache/dms/dms-colors.json`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use gpui_kit::component::ThemeConfig;
use serde_json::{Map, Value, json};

use crate::term::palette::Rgb;

pub const DARK_ID: &str = "Dux Shell Dark";
pub const LIGHT_ID: &str = "Dux Shell Light";
pub const TITLE: &str = "Dux Shell";

pub struct DuxTheme {
    pub config: ThemeConfig,
    pub ansi: [Rgb; 16],
    pub dark: bool,
}

/// Файл цветов Dux Shell, если оболочка установлена.
pub fn colors_file() -> Option<PathBuf> {
    let cache = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::home_dir().map(|home| home.join(".cache")))?;
    ["dms", "DankMaterialShell"]
        .iter()
        .map(|dir| cache.join(dir).join("dms-colors.json"))
        .find(|path| path.is_file())
}

pub fn modified(path: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
}

pub fn read(path: &Path) -> Result<Vec<DuxTheme>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("не прочитать {}", path.display()))?;
    parse(&text)
}

pub fn parse(text: &str) -> Result<Vec<DuxTheme>> {
    let root: Value = serde_json::from_str(text)?;
    let mut themes = Vec::new();
    for (mode, id) in [("dark", DARK_ID), ("light", LIGHT_ID)] {
        let Some(colors) = root["colors"][mode].as_object() else {
            continue;
        };
        let ansi = dank16(&root["dank16"], mode)?;
        let config = serde_json::from_value(theme_json(id, mode, colors, &ansi))
            .with_context(|| format!("тема {id}"))?;
        themes.push(DuxTheme {
            config,
            ansi: ansi.map(|hex| hex_rgb(&hex).unwrap_or(Rgb::new(0, 0, 0))),
            dark: mode == "dark",
        });
    }
    if themes.is_empty() {
        return Err(anyhow!("в файле нет цветов Dux Shell"));
    }
    Ok(themes)
}

fn dank16(table: &Value, mode: &str) -> Result<[String; 16]> {
    let mut out: [String; 16] = Default::default();
    for (index, slot) in out.iter_mut().enumerate() {
        let entry = &table[format!("color{index}")];
        let hex = entry[mode]
            .as_str()
            .or_else(|| entry["default"].as_str())
            .ok_or_else(|| anyhow!("нет цвета color{index}"))?;
        hex_rgb(hex).ok_or_else(|| anyhow!("цвет color{index} не hex: {hex}"))?;
        *slot = hex.to_owned();
    }
    Ok(out)
}

/// Material-роли → ключи темы gpui-kit.
fn theme_json(id: &str, mode: &str, m: &Map<String, Value>, ansi: &[String; 16]) -> Value {
    let get = |role: &str| m.get(role).and_then(Value::as_str).unwrap_or("#808080");
    let pairs: &[(&str, &str)] = &[
        ("background", "surface"),
        ("foreground", "on_surface"),
        ("border", "outline_variant"),
        ("window.border", "outline_variant"),
        ("input.border", "outline"),
        ("ring", "primary"),
        ("caret", "primary"),
        ("muted.background", "surface_container_high"),
        ("muted.foreground", "on_surface_variant"),
        ("primary.background", "primary"),
        ("primary.hover.background", "primary_fixed_dim"),
        ("primary.active.background", "primary"),
        ("primary.foreground", "on_primary"),
        ("secondary.background", "surface_container_high"),
        ("secondary.hover.background", "surface_container_highest"),
        ("secondary.active.background", "surface_container_highest"),
        ("secondary.foreground", "on_surface"),
        ("accent.background", "secondary_container"),
        ("accent.foreground", "on_secondary_container"),
        ("popover.background", "surface_container"),
        ("popover.foreground", "on_surface"),
        ("title_bar.background", "surface_container_low"),
        ("title_bar.border", "outline_variant"),
        ("sidebar.background", "surface_container_low"),
        ("sidebar.border", "outline_variant"),
        ("sidebar.foreground", "on_surface"),
        ("sidebar.accent.background", "secondary_container"),
        ("sidebar.accent.foreground", "on_secondary_container"),
        ("sidebar.primary.background", "primary"),
        ("sidebar.primary.foreground", "on_primary"),
        ("list.background", "surface"),
        ("list.even.background", "surface"),
        ("list.head.background", "surface_container"),
        ("list.hover.background", "surface_container_high"),
        ("list.active.background", "secondary_container"),
        ("list.active.border", "primary"),
        ("tab_bar.background", "surface_container_low"),
        ("tab.background", "surface_container_low"),
        ("tab.foreground", "on_surface_variant"),
        ("tab.active.background", "surface"),
        ("tab.active.foreground", "on_surface"),
        ("scrollbar.thumb.background", "outline_variant"),
        ("scrollbar.thumb.hover.background", "outline"),
        ("switch.background", "outline_variant"),
        ("progress.bar.background", "primary"),
        ("selection.background", "primary_container"),
        ("link", "primary"),
        ("link.hover", "primary_fixed_dim"),
        ("danger.background", "error"),
        ("danger.hover.background", "error"),
        ("danger.active.background", "error"),
        ("danger.foreground", "on_error"),
        ("drag.border", "primary"),
    ];
    let mut colors: Map<String, Value> = pairs
        .iter()
        .map(|(key, role)| ((*key).to_owned(), json!(get(role))))
        .collect();
    for (index, name) in ["red", "green", "yellow", "blue", "magenta", "cyan"]
        .iter()
        .enumerate()
    {
        colors.insert(format!("base.{name}"), json!(ansi[index + 1]));
        colors.insert(format!("base.{name}.light"), json!(ansi[index + 9]));
    }
    json!({ "name": id, "mode": mode, "colors": colors })
}

fn hex_rgb(hex: &str) -> Option<Rgb> {
    let hex = hex.trim().trim_start_matches('#');
    if hex.len() < 6 || !hex.is_ascii() {
        return None;
    }
    let channel = |at: usize| u8::from_str_radix(&hex[at..at + 2], 16).ok();
    Some(Rgb::new(channel(0)?, channel(2)?, channel(4)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r##"{
        "dank16": {
            "color0": {"dark": "#0c0f0a", "light": "#f9faf1"},
            "color1": {"dark": "#ee836b", "light": "#793e30"},
            "color2": {"dark": "#6ecf67", "light": "#255f21"},
            "color3": {"dark": "#ffec72", "light": "#7d7104"},
            "color4": {"dark": "#a7c48d", "light": "#4c6c37"},
            "color5": {"dark": "#425933", "light": "#cbedb0"},
            "color6": {"dark": "#b5cf9f", "light": "#4a6737"},
            "color7": {"dark": "#d1d9cc", "light": "#222322"},
            "color8": {"dark": "#3a3f37", "light": "#babcb8"},
            "color9": {"dark": "#ffb19f", "light": "#995b4c"},
            "color10": {"dark": "#a7f8a1", "light": "#438c3f"},
            "color11": {"dark": "#fff3a5", "light": "#9a8c26"},
            "color12": {"dark": "#cbe3b6", "light": "#517639"},
            "color13": {"dark": "#e8ffd5", "light": "#6b855a"},
            "color14": {"dark": "#f0ffe4", "light": "#738566"},
            "color15": {"dark": "#fbfff8", "light": "#bdbfbb"}
        },
        "mode": "dark",
        "colors": {
            "dark": {"surface": "#0c0f0a", "on_surface": "#e2e7d8", "primary": "#b5cf9f"},
            "light": {"surface": "#f9faf1", "on_surface": "#2f342a", "primary": "#4a6737"}
        }
    }"##;

    #[test]
    fn obe_temy_i_terminal_iz_dank16() {
        let themes = parse(SAMPLE).expect("разбор");
        assert_eq!(themes.len(), 2);
        let dark = themes.iter().find(|theme| theme.dark).expect("тёмная");
        assert_eq!(dark.config.name.as_ref(), DARK_ID);
        assert_eq!(dark.ansi[1], Rgb::new(0xee, 0x83, 0x6b));
        let light = themes.iter().find(|theme| !theme.dark).expect("светлая");
        assert_eq!(light.ansi[1], Rgb::new(0x79, 0x3e, 0x30));
    }

    #[test]
    fn bityy_fayl_ne_valit() {
        assert!(parse("{}").is_err());
        assert!(parse("не json").is_err());
    }
}
