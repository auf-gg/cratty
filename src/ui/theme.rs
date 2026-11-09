use std::rc::Rc;

use rust_i18n::t;

use gpui_kit::component::{Theme, ThemeColor, ThemeConfig, ThemeMode, ThemeRegistry};
use gpui_kit::{App, Global, Hsla, Window, WindowAppearance, rgb, rgba};

use crate::term::palette::{self, Palette, Rgb};

/// Appearance mode: follow the OS, always dark or always light.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Appearance {
    System,
    Dark,
    Light,
}

impl Appearance {
    pub fn parse(text: &str) -> Self {
        match text.trim() {
            "dark" => Self::Dark,
            "light" => Self::Light,
            _ => Self::System,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Dark => "dark",
            Self::Light => "light",
        }
    }

    pub fn title(self) -> String {
        match self {
            Self::System => t!("ui_theme.system"),
            Self::Dark => t!("ui_theme.dark"),
            Self::Light => t!("ui_theme.light"),
        }
        .to_string()
    }

    /// Whether the theme is currently dark, taking the OS appearance into account.
    pub fn is_dark(self, os: WindowAppearance) -> bool {
        match self {
            Self::Dark => true,
            Self::Light => false,
            Self::System => matches!(os, WindowAppearance::Dark | WindowAppearance::VibrantDark),
        }
    }
}

pub const DEFAULT_DARK: &str = "cratty";
pub const DEFAULT_LIGHT: &str = "light";

/// cratty's own themes: id, name, whether dark.
const BUILTIN: &[(&str, &str, bool)] = &[
    ("cratty", "Cratty", true),
    ("synthwave", "SynthWave '84", true),
    ("graphite", "Graphite", true),
    ("light", "Light", false),
];

/// gpui-kit themes embedded in the program (assets/themes).
const BUNDLED: &[&str] = &[
    include_str!("../../assets/themes/adventure.json"),
    include_str!("../../assets/themes/alduin.json"),
    include_str!("../../assets/themes/asciinema.json"),
    include_str!("../../assets/themes/aurora.json"),
    include_str!("../../assets/themes/ayu.json"),
    include_str!("../../assets/themes/catppuccin.json"),
    include_str!("../../assets/themes/everforest.json"),
    include_str!("../../assets/themes/fahrenheit.json"),
    include_str!("../../assets/themes/flexoki.json"),
    include_str!("../../assets/themes/gruvbox.json"),
    include_str!("../../assets/themes/harper.json"),
    include_str!("../../assets/themes/hybrid.json"),
    include_str!("../../assets/themes/jellybeans.json"),
    include_str!("../../assets/themes/kibble.json"),
    include_str!("../../assets/themes/macos-classic.json"),
    include_str!("../../assets/themes/mellifluous.json"),
    include_str!("../../assets/themes/molokai.json"),
    include_str!("../../assets/themes/solarized.json"),
    include_str!("../../assets/themes/spaceduck.json"),
    include_str!("../../assets/themes/tokyonight.json"),
    include_str!("../../assets/themes/twilight.json"),
];

/// One theme in the catalog: everything needed for selection, preview and the terminal.
#[derive(Clone)]
pub struct ThemeEntry {
    pub id: String,
    pub title: String,
    pub dark: bool,
    pub colors: ThemeColor,
    pub palette: Palette,
    config: Option<Rc<ThemeConfig>>,
}

struct Catalog(Vec<ThemeEntry>);

impl Global for Catalog {}

/// Loads the embedded themes and builds the catalog. Call after `gpui_kit::init`.
pub fn init(cx: &mut App) {
    for json in BUNDLED {
        if let Err(error) = ThemeRegistry::global_mut(cx).load_themes_from_str(json) {
            eprintln!("failed to load the theme: {error:#}");
        }
    }

    let mut entries: Vec<ThemeEntry> = BUILTIN
        .iter()
        .map(|(id, title, dark)| {
            let mut colors = if *dark {
                *ThemeColor::dark()
            } else {
                *ThemeColor::light()
            };
            builtin_colors(id, &mut colors);
            ThemeEntry {
                id: (*id).into(),
                title: (*title).into(),
                dark: *dark,
                palette: match *id {
                    "cratty" => palette::CRATTY,
                    "synthwave" => palette::SYNTHWAVE,
                    _ => palette_from(&colors, *dark),
                },
                colors,
                config: None,
            }
        })
        .collect();

    let mut registered: Vec<ThemeEntry> = ThemeRegistry::global(cx)
        .sorted_themes()
        .into_iter()
        .map(|config| {
            let mut scratch = Theme::default();
            scratch.apply_config(config);
            let dark = config.mode.is_dark();
            ThemeEntry {
                id: config.name.to_string(),
                title: config.name.to_string(),
                dark,
                palette: palette_from(&scratch.colors, dark),
                colors: scratch.colors,
                config: Some(config.clone()),
            }
        })
        .collect();
    registered.sort_by_key(|entry| entry.title.to_lowercase());
    entries.extend(dux_entries());
    entries.extend(registered);
    cx.set_global(Catalog(entries));
}

fn is_dux(id: &str) -> bool {
    id == crate::ui::dux::DARK_ID || id == crate::ui::dux::LIGHT_ID
}

/// Dux Shell palettes, if the shell is installed: its Material colors and dank16.
fn dux_entries() -> Vec<ThemeEntry> {
    let Some(path) = crate::ui::dux::colors_file() else {
        return Vec::new();
    };
    let themes = match crate::ui::dux::read(&path) {
        Ok(themes) => themes,
        Err(error) => {
            eprintln!("failed to read Dux Shell colors: {error:#}");
            return Vec::new();
        }
    };
    themes
        .into_iter()
        .map(|dux| {
            let config = Rc::new(dux.config);
            let mut scratch = Theme::default();
            scratch.apply_config(&config);
            let colors = scratch.colors;
            ThemeEntry {
                id: config.name.to_string(),
                title: crate::ui::dux::TITLE.into(),
                dark: dux.dark,
                palette: Palette::new(
                    to_rgb(colors.foreground),
                    to_rgb(colors.background),
                    to_rgb(colors.caret),
                    dux.ansi,
                ),
                colors,
                config: Some(config),
            }
        })
        .collect()
}

/// Rereads the Dux Shell colors (they change along with the wallpaper).
/// Returns `true` if the Dux palette is currently applied and must be applied again.
pub fn refresh_dux(cx: &mut App, settings: &crate::ui::settings::Settings) -> bool {
    let fresh = dux_entries();
    let Some(catalog) = cx.try_global::<Catalog>() else {
        return false;
    };
    let mut entries: Vec<ThemeEntry> = catalog
        .0
        .iter()
        .filter(|entry| !is_dux(&entry.id))
        .cloned()
        .collect();
    let at = entries
        .iter()
        .position(|entry| entry.config.is_some())
        .unwrap_or(entries.len());
    entries.splice(at..at, fresh);
    cx.set_global(Catalog(entries));

    let current = if is_dark(cx) {
        &settings.dark_theme
    } else {
        &settings.light_theme
    };
    is_dux(current)
}

/// Themes for a mode: our own first, then gpui-kit's alphabetically.
pub fn catalog(cx: &App, dark: bool) -> Vec<ThemeEntry> {
    cx.try_global::<Catalog>()
        .map(|catalog| {
            catalog
                .0
                .iter()
                .filter(|entry| entry.dark == dark)
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

pub fn find(cx: &App, id: &str) -> Option<ThemeEntry> {
    cx.try_global::<Catalog>()?
        .0
        .iter()
        .find(|entry| entry.id == id)
        .cloned()
}

/// Theme for a mode: the chosen one if it exists and has the same mode, otherwise our own.
pub fn resolve(cx: &App, id: &str, dark: bool) -> Option<ThemeEntry> {
    find(cx, id)
        .filter(|entry| entry.dark == dark)
        .or_else(|| find(cx, if dark { DEFAULT_DARK } else { DEFAULT_LIGHT }))
}

fn builtin_colors(id: &str, colors: &mut ThemeColor) {
    match id {
        "cratty" => cratty(colors),
        "synthwave" => synthwave(colors),
        "graphite" => graphite(colors),
        _ => {}
    }
}

fn to_rgb(color: Hsla) -> Rgb {
    let rgba: gpui_kit::Rgba = color.into();
    let channel = |value: f32| (value * 255.).round().clamp(0., 255.) as u8;
    Rgb::new(channel(rgba.r), channel(rgba.g), channel(rgba.b))
}

/// ANSI palette from theme colors: base.red/green/… and their light variants.
fn palette_from(colors: &ThemeColor, dark: bool) -> Palette {
    let c = |color: Hsla| to_rgb(color);
    let (black, white, bright_black, bright_white) = if dark {
        (
            c(colors.secondary),
            c(colors.muted_foreground),
            c(colors.border),
            c(colors.foreground),
        )
    } else {
        (
            c(colors.foreground),
            c(colors.border),
            c(colors.muted_foreground),
            c(colors.secondary),
        )
    };
    Palette::new(
        c(colors.foreground),
        c(colors.background),
        c(colors.caret),
        [
            black,
            c(colors.red),
            c(colors.green),
            c(colors.yellow),
            c(colors.blue),
            c(colors.magenta),
            c(colors.cyan),
            white,
            bright_black,
            c(colors.red_light),
            c(colors.green_light),
            c(colors.yellow_light),
            c(colors.blue_light),
            c(colors.magenta_light),
            c(colors.cyan_light),
            bright_white,
        ],
    )
}

pub trait MainAction {
    fn main_action(self, enabled: bool) -> Self;
}

impl MainAction for gpui_kit::component::button::Button {
    fn main_action(self, enabled: bool) -> Self {
        use gpui_kit::component::{Disableable, button::ButtonVariants};
        if enabled {
            self.primary()
        } else {
            self.disabled(true)
        }
    }
}

struct Active {
    palette: Palette,
    solid: Hsla,
    opacity: f32,
    dark: bool,
}

impl Global for Active {}

/// Whether a dark theme is currently applied.
pub fn is_dark(cx: &App) -> bool {
    cx.try_global::<Active>().is_none_or(|active| active.dark)
}

pub fn solid_background(cx: &App) -> Hsla {
    use gpui_kit::component::ActiveTheme;
    cx.try_global::<Active>()
        .map_or_else(|| cx.theme().background, |active| active.solid)
}

pub fn terminal_opacity(cx: &App) -> f32 {
    cx.try_global::<Active>()
        .map_or(1.0, |active| active.opacity)
}

pub fn window_background(
    settings: &crate::ui::settings::Settings,
) -> gpui_kit::WindowBackgroundAppearance {
    use gpui_kit::WindowBackgroundAppearance as Appearance;
    match (settings.opacity() < 1.0, settings.blur) {
        (false, _) => Appearance::Opaque,
        (true, false) => Appearance::Transparent,
        (true, true) if crate::platform::blur_supported() => Appearance::Blurred,
        (true, true) => Appearance::Transparent,
    }
}

pub fn terminal_base(cx: &App) -> Palette {
    cx.try_global::<Active>()
        .map_or(palette::CRATTY, |active| active.palette)
}

fn c(hex: u32) -> Hsla {
    rgb(hex).into()
}

fn ca(hex_with_alpha: u32) -> Hsla {
    rgba(hex_with_alpha).into()
}

pub fn apply(settings: &crate::ui::settings::Settings, window: Option<&mut Window>, cx: &mut App) {
    let os = window
        .as_ref()
        .map(|window| window.appearance())
        .unwrap_or_else(|| cx.window_appearance());
    let dark = settings.appearance().is_dark(os);
    let wanted = if dark {
        &settings.dark_theme
    } else {
        &settings.light_theme
    };
    let entry = resolve(cx, wanted, dark);
    let opacity = settings.opacity();
    Theme::change(
        if dark {
            ThemeMode::Dark
        } else {
            ThemeMode::Light
        },
        None,
        cx,
    );
    // Only through `Theme::update`: the theme stores colors twice (`colors` and
    // `tokens`), and the gpui-component window root paints `tokens.background`.
    // Editing through `global_mut` leaves the tokens from the default theme — under
    // the window then lies its opaque background, and transparency is lost.
    if let Some(config) = entry.as_ref().and_then(|entry| entry.config.clone()) {
        Theme::update(cx, |theme| theme.apply_config(&config));
    }
    let solid = Theme::update(cx, |theme| {
        if let Some(entry) = entry.as_ref().filter(|entry| entry.config.is_none()) {
            builtin_colors(&entry.id, &mut theme.colors);
        }
        let ui_font = settings.ui_font.trim();
        if !ui_font.is_empty() {
            theme.font_family = ui_font.to_owned().into();
        }
        let (background, active_line, number, active_number) = (
            theme.colors.background,
            theme.colors.secondary,
            theme.colors.muted_foreground,
            theme.colors.foreground,
        );
        let style = &mut std::sync::Arc::make_mut(&mut theme.highlight_theme).style;
        style.editor_background = Some(background);
        style.editor_active_line = Some(active_line);
        style.editor_line_number = Some(number);
        style.editor_active_line_number = Some(active_number);
        if opacity < 1.0 {
            theme.colors.background = background.opacity(opacity);
        }
        background
    });
    cx.set_global(Active {
        palette: entry.map_or(palette::CRATTY, |entry| entry.palette),
        solid,
        opacity,
        dark,
    });
    if let Some(window) = window {
        window.set_background_appearance(window_background(settings));
        window.refresh();
    }
}

struct Layers {
    frame: Hsla,
    base: Hsla,
    raised: Hsla,
    raised_hover: Hsla,
    overlay: Hsla,
    border: Hsla,
    input: Hsla,
    text: Hsla,
    text_muted: Hsla,
    accent: Hsla,
    accent_hover: Hsla,
    accent_foreground: Hsla,
    nav_active: Hsla,
    list_hover: Hsla,
    list_active: Hsla,
    caret: Hsla,
}

fn layers(t: &mut ThemeColor, l: &Layers) {
    t.background = l.base;
    t.foreground = l.text;
    t.border = l.border;
    t.window_border = l.border;
    t.input = l.input;
    t.ring = l.accent;
    t.caret = l.caret;

    t.title_bar = l.frame;
    t.title_bar_border = l.border;

    t.sidebar = l.frame;
    t.sidebar_border = l.border;
    t.sidebar_foreground = l.text;
    t.sidebar_accent = l.nav_active;
    t.sidebar_accent_foreground = l.text;
    t.sidebar_primary = l.accent;
    t.sidebar_primary_foreground = l.accent_foreground;

    t.secondary = l.raised;
    t.secondary_hover = l.raised_hover;
    t.secondary_active = l.raised_hover;
    t.secondary_foreground = l.text;

    t.muted = l.raised;
    t.muted_foreground = l.text_muted;

    t.accent = l.nav_active;
    t.accent_foreground = l.text;

    t.popover = l.overlay;
    t.popover_foreground = l.text;
    t.overlay = ca(0x0000008c);

    t.primary = l.accent;
    t.primary_hover = l.accent_hover;
    t.primary_active = l.accent;
    t.primary_foreground = l.accent_foreground;

    t.list = l.base;
    t.list_even = l.base;
    t.list_head = l.raised;
    t.list_hover = l.list_hover;
    t.list_active = l.list_active;
    t.list_active_border = l.accent;

    t.tab_bar = l.frame;
    t.tab = l.frame;
    t.tab_foreground = l.text_muted;
    t.tab_active = l.base;
    t.tab_active_foreground = l.text;

    t.drag_border = l.accent;
    t.scrollbar_thumb = l.input;
    t.scrollbar_thumb_hover = l.raised_hover;
    t.switch = l.input;
    t.progress_bar = l.accent;
}

fn cratty(t: &mut ThemeColor) {
    layers(
        t,
        &Layers {
            frame: c(0x15110e),
            base: c(0x1b1612),
            raised: c(0x231d18),
            raised_hover: c(0x2e2620),
            overlay: c(0x231d18),
            border: c(0x3a312a),
            input: c(0x5e554d),
            text: c(0xf3ede6),
            text_muted: c(0xa89f96),
            accent: c(0xe8643a),
            accent_hover: c(0xf07a53),
            accent_foreground: c(0x15110e),
            nav_active: c(0x2e2620),
            list_hover: ca(0x2e262099),
            list_active: ca(0xe8643a24),
            caret: c(0x7ee787),
        },
    );
    t.selection = ca(0xe8643a40);
    t.drop_target = ca(0xe8643a26);
    t.link = c(0xe8643a);
    t.link_hover = c(0xf07a53);
    t.success = c(0x7ee787);
    t.success_hover = c(0x9aeda1);
    t.success_active = c(0x7ee787);
    t.info = c(0x7ee787);
}

fn synthwave(t: &mut ThemeColor) {
    layers(
        t,
        &Layers {
            frame: c(0x241b2f),
            base: c(0x262335),
            raised: c(0x2a2139),
            raised_hover: c(0x37294d),
            overlay: c(0x2a2139),
            border: c(0x3d3157),
            input: c(0x495495),
            text: c(0xf4eefc),
            text_muted: c(0xa99fc4),
            accent: c(0xff7edb),
            accent_hover: c(0xff9be4),
            accent_foreground: c(0x241b2f),
            nav_active: c(0x37294d),
            list_hover: ca(0x37294d99),
            list_active: ca(0xff7edb24),
            caret: c(0x03edf9),
        },
    );
    t.selection = ca(0xffffff20);
    t.drop_target = ca(0xff7edb26);
    t.link = c(0xf97e72);
    t.link_hover = c(0xff9f95);
    t.success = c(0x72f1b8);
    t.success_hover = c(0x8ff5c8);
    t.success_active = c(0x72f1b8);
    t.danger = c(0xfe4450);
    t.danger_hover = c(0xff6670);
    t.danger_active = c(0xfe4450);
    t.warning = c(0xfede5d);
    t.info = c(0x03edf9);
}

fn graphite(t: &mut ThemeColor) {
    layers(
        t,
        &Layers {
            frame: c(0x15161b),
            base: c(0x1c1d23),
            raised: c(0x24262e),
            raised_hover: c(0x2b2d37),
            overlay: c(0x2a2c35),
            border: c(0x33353f),
            input: c(0x3d404c),
            text: c(0xe6e7ec),
            text_muted: c(0x8e91a0),
            accent: c(0x6d8cff),
            accent_hover: c(0x819cff),
            accent_foreground: c(0xffffff),
            nav_active: c(0x2c3246),
            list_hover: c(0x252731),
            list_active: c(0x2a3558),
            caret: c(0xe6e7ec),
        },
    );
    t.selection = ca(0x6d8cff55);
    t.drop_target = ca(0x6d8cff26);
    t.link = c(0x6d8cff);
    t.link_hover = c(0x819cff);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_from_settings_tolerates_typos() {
        assert_eq!(Appearance::parse("dark"), Appearance::Dark);
        assert_eq!(Appearance::parse("light"), Appearance::Light);
        assert_eq!(Appearance::parse("darkk"), Appearance::System);
        assert!(Appearance::System.is_dark(WindowAppearance::Dark));
        assert!(!Appearance::System.is_dark(WindowAppearance::Light));
        assert!(Appearance::Dark.is_dark(WindowAppearance::Light));
    }

    #[test]
    fn catalog_contains_all_themes_and_splits_by_mode() {
        let cx = gpui_kit::TestAppContext::single();
        cx.update(|cx| {
            gpui_kit::init(cx);
            init(cx);
            let (dark, light) = (catalog(cx, true), catalog(cx, false));
            for name in ["Cratty", "Tokyo Night", "Gruvbox Dark", "Catppuccin Mocha"] {
                assert!(
                    dark.iter().any(|e| e.title == name),
                    "missing dark theme {name}"
                );
            }
            for name in ["Light", "Ayu Light", "Solarized Light"] {
                assert!(
                    light.iter().any(|e| e.title == name),
                    "missing light theme {name}"
                );
            }
            assert!(dark.len() + light.len() >= 39, "not all themes loaded");
            assert_eq!(dark[0].id, DEFAULT_DARK, "own themes come first");

            // A light palette is not applied in dark mode — our own is used.
            assert_eq!(
                resolve(cx, "Ayu Light", true).expect("theme").id,
                DEFAULT_DARK
            );
            assert_eq!(
                resolve(cx, "no such theme", false).expect("theme").id,
                DEFAULT_LIGHT
            );
            assert_eq!(
                resolve(cx, "Tokyo Night", true).expect("theme").id,
                "Tokyo Night"
            );
        });
    }

    #[test]
    fn gpui_kit_theme_is_applied_with_terminal_palette() {
        let cx = gpui_kit::TestAppContext::single();
        cx.update(|cx| {
            gpui_kit::init(cx);
            init(cx);
            let settings: crate::ui::settings::Settings =
                serde_json::from_str(r#"{"appearance":"dark","dark_theme":"Gruvbox Dark"}"#)
                    .expect("parse");
            apply(&settings, None, cx);
            let entry = find(cx, "Gruvbox Dark").expect("theme");
            assert_eq!(Theme::global(cx).colors.background, entry.colors.background);
            assert_eq!(terminal_base(cx).indexed(1), entry.palette.indexed(1));
            assert!(is_dark(cx));
        });
    }

    // The gpui-component window root paints `tokens.background`, not
    // `colors.background`: without syncing, the window stays opaque.
    #[test]
    fn opacity_reaches_root_tokens() {
        let cx = gpui_kit::TestAppContext::single();
        cx.update(|cx| {
            gpui_kit::init(cx);
            let settings: crate::ui::settings::Settings =
                serde_json::from_str(r#"{"terminal_opacity":60}"#).expect("parse");
            apply(&settings, None, cx);

            let theme = Theme::global(cx);
            let token = theme
                .tokens
                .background
                .background
                .as_solid()
                .expect("solid background");
            assert!((token.a - 0.6).abs() < 0.01, "token alpha: {}", token.a);
            assert_eq!(token, theme.colors.background);
        });
    }
}
