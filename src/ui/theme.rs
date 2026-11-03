use gpui::{App, Global, Hsla, Window, rgb, rgba};
use gpui_component::{Theme, ThemeColor, ThemeMode};

use crate::term::palette::{self, Palette};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    Cratty,
    Synthwave,
    Graphite,
    Light,
}

impl Scheme {
    pub fn parse(text: &str) -> Self {
        match text.trim() {
            "synthwave" => Self::Synthwave,
            "graphite" => Self::Graphite,
            "light" => Self::Light,
            _ => Self::Cratty,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cratty => "cratty",
            Self::Synthwave => "synthwave",
            Self::Graphite => "graphite",
            Self::Light => "light",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::Cratty => "Cratty",
            Self::Synthwave => "SynthWave '84",
            Self::Graphite => "Графит",
            Self::Light => "Светлая",
        }
    }

    pub fn is_dark(self) -> bool {
        !matches!(self, Self::Light)
    }
}

pub trait MainAction {
    fn main_action(self, enabled: bool) -> Self;
}

impl MainAction for gpui_component::button::Button {
    fn main_action(self, enabled: bool) -> Self {
        use gpui_component::{Disableable, button::ButtonVariants};
        if enabled {
            self.primary()
        } else {
            self.disabled(true)
        }
    }
}

struct Active {
    scheme: Scheme,
    solid: Hsla,
    opacity: f32,
}

impl Global for Active {}

pub fn active(cx: &App) -> Scheme {
    cx.try_global::<Active>()
        .map_or(Scheme::Cratty, |active| active.scheme)
}

pub fn solid_background(cx: &App) -> Hsla {
    use gpui_component::ActiveTheme;
    cx.try_global::<Active>()
        .map_or_else(|| cx.theme().background, |active| active.solid)
}

pub fn terminal_opacity(cx: &App) -> f32 {
    cx.try_global::<Active>()
        .map_or(1.0, |active| active.opacity)
}

pub fn window_background(
    settings: &crate::ui::settings::Settings,
) -> gpui::WindowBackgroundAppearance {
    use gpui::WindowBackgroundAppearance as Appearance;
    match (settings.opacity() < 1.0, settings.blur) {
        (false, _) => Appearance::Opaque,
        (true, false) => Appearance::Transparent,
        (true, true) if crate::platform::blur_supported() => Appearance::Blurred,
        (true, true) => Appearance::Transparent,
    }
}

pub fn terminal_base(cx: &App) -> Palette {
    match active(cx) {
        Scheme::Cratty => palette::CRATTY,
        Scheme::Synthwave => palette::SYNTHWAVE,
        Scheme::Graphite | Scheme::Light => palette::DEFAULT,
    }
}

fn c(hex: u32) -> Hsla {
    rgb(hex).into()
}

fn ca(hex_with_alpha: u32) -> Hsla {
    rgba(hex_with_alpha).into()
}

pub fn apply(settings: &crate::ui::settings::Settings, window: Option<&mut Window>, cx: &mut App) {
    let scheme = settings.scheme();
    let opacity = settings.opacity();
    Theme::change(
        if scheme.is_dark() {
            ThemeMode::Dark
        } else {
            ThemeMode::Light
        },
        None,
        cx,
    );
    {
        let colors = &mut Theme::global_mut(cx).colors;
        match scheme {
            Scheme::Cratty => cratty(colors),
            Scheme::Synthwave => synthwave(colors),
            Scheme::Graphite => graphite(colors),
            Scheme::Light => {}
        }
    }
    {
        let theme = Theme::global_mut(cx);
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
    }
    let solid = Theme::global(cx).colors.background;
    if opacity < 1.0 {
        Theme::global_mut(cx).colors.background = solid.opacity(opacity);
    }
    cx.set_global(Active {
        scheme,
        solid,
        opacity,
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
    fn skhema_iz_nastroek_terpit_opechatki() {
        assert_eq!(Scheme::parse("graphite"), Scheme::Graphite);
        assert_eq!(Scheme::parse("light"), Scheme::Light);
        assert_eq!(Scheme::parse("synthwave"), Scheme::Synthwave);
        assert_eq!(Scheme::parse("synthwav"), Scheme::Cratty);
        for scheme in [
            Scheme::Cratty,
            Scheme::Synthwave,
            Scheme::Graphite,
            Scheme::Light,
        ] {
            assert_eq!(Scheme::parse(scheme.as_str()), scheme);
        }
    }
}
