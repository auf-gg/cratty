use serde::{Deserialize, Serialize};

use crate::term::predict::Policy;

pub const MIN_FONT_SIZE: f32 = 8.;
pub const MAX_FONT_SIZE: f32 = 40.;
pub const DEFAULT_FONT_SIZE: f32 = 14.;

pub const FONT_SIZE_STEP: f32 = 1.;

pub const DEFAULT_AUTOLOCK_MINUTES: u32 = 15;

pub const MIN_AUTOLOCK_MINUTES: u32 = 1;
pub const MAX_AUTOLOCK_MINUTES: u32 = 8 * 60;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default = "default_font_size")]
    pub font_size: f32,
    #[serde(default = "default_autolock_minutes")]
    pub autolock_minutes: u32,
    /// Блокировать ли хранилища самим: по бездействию и после сна.
    #[serde(default = "default_autolock")]
    pub autolock: bool,
    #[serde(default)]
    pub sync_folder: String,
    #[serde(default = "default_prediction")]
    pub prediction: String,
    /// Старое поле «текущая тема»: читается один раз для переноса, не пишется.
    #[serde(default, skip_serializing)]
    pub theme: String,
    /// «system», «dark» или «light». Пусто — старый файл, переносится из `theme`.
    #[serde(default)]
    pub appearance: String,
    #[serde(default = "default_theme")]
    pub dark_theme: String,
    #[serde(default = "default_light_theme")]
    pub light_theme: String,
    /// Шрифт терминала; пусто — подобрать самому.
    #[serde(default)]
    pub terminal_font: String,
    /// Шрифт значков в терминале: пусто — сам, «none» — без него.
    #[serde(default)]
    pub terminal_icons: String,
    /// Шрифт интерфейса; пусто — системный.
    #[serde(default)]
    pub ui_font: String,
    #[serde(default = "default_opacity")]
    pub terminal_opacity: u8,
    #[serde(default)]
    pub blur: bool,
    #[serde(default = "default_rail_width")]
    pub rail_width: f32,
    #[serde(default = "default_panel_width")]
    pub panel_width: f32,
    #[serde(default = "default_editor_width")]
    pub editor_width: f32,
    /// Закреплена ли левая панель. Откреплённая выезжает при наведении на край окна.
    #[serde(default = "default_pinned")]
    pub rail_pinned: bool,
    /// То же для правой панели сеанса.
    #[serde(default = "default_pinned")]
    pub panel_pinned: bool,
    /// Свёрнутые группы хостов в левой панели: «хранилище/группа».
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub collapsed_groups: Vec<String>,
}

fn default_pinned() -> bool {
    true
}

pub const RAIL_WIDTH: std::ops::RangeInclusive<f32> = 200.0..=480.0;
pub const PANEL_WIDTH: std::ops::RangeInclusive<f32> = 280.0..=720.0;
pub const EDITOR_WIDTH: std::ops::RangeInclusive<f32> = 280.0..=1600.0;

fn default_editor_width() -> f32 {
    560.0
}

fn default_rail_width() -> f32 {
    264.0
}

fn default_panel_width() -> f32 {
    340.0
}

pub fn fit(value: f32, range: std::ops::RangeInclusive<f32>, fallback: f32) -> f32 {
    if value.is_finite() {
        value.clamp(*range.start(), *range.end())
    } else {
        fallback
    }
}

fn default_opacity() -> u8 {
    100
}

pub const MIN_OPACITY: u8 = 40;

fn default_light_theme() -> String {
    crate::ui::theme::DEFAULT_LIGHT.into()
}

fn default_theme() -> String {
    "cratty".into()
}

fn default_prediction() -> String {
    "adaptive".into()
}

fn default_font_size() -> f32 {
    DEFAULT_FONT_SIZE
}

fn default_autolock() -> bool {
    true
}

fn default_autolock_minutes() -> u32 {
    DEFAULT_AUTOLOCK_MINUTES
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            font_size: DEFAULT_FONT_SIZE,
            autolock_minutes: DEFAULT_AUTOLOCK_MINUTES,
            autolock: true,
            sync_folder: String::new(),
            prediction: default_prediction(),
            theme: String::new(),
            appearance: "system".into(),
            dark_theme: default_theme(),
            light_theme: default_light_theme(),
            terminal_font: String::new(),
            terminal_icons: String::new(),
            ui_font: String::new(),
            terminal_opacity: default_opacity(),
            blur: false,
            rail_width: default_rail_width(),
            panel_width: default_panel_width(),
            editor_width: default_editor_width(),
            rail_pinned: true,
            panel_pinned: true,
            collapsed_groups: Vec::new(),
        }
    }
}

impl Settings {
    pub fn clamped(mut self) -> Self {
        if !self.font_size.is_finite() {
            self.font_size = DEFAULT_FONT_SIZE;
        }
        self.font_size = self.font_size.clamp(MIN_FONT_SIZE, MAX_FONT_SIZE);
        self.migrate_theme();
        self.autolock_minutes = self
            .autolock_minutes
            .clamp(MIN_AUTOLOCK_MINUTES, MAX_AUTOLOCK_MINUTES);
        self.terminal_opacity = self.terminal_opacity.clamp(MIN_OPACITY, 100);
        self.rail_width = fit(self.rail_width, RAIL_WIDTH, default_rail_width());
        self.panel_width = fit(self.panel_width, PANEL_WIDTH, default_panel_width());
        self.editor_width = fit(self.editor_width, EDITOR_WIDTH, default_editor_width());
        self
    }

    pub fn sync_folder(&self) -> Option<std::path::PathBuf> {
        let trimmed = self.sync_folder.trim();
        (!trimmed.is_empty()).then(|| std::path::PathBuf::from(trimmed))
    }

    pub fn opacity(&self) -> f32 {
        f32::from(self.terminal_opacity.clamp(MIN_OPACITY, 100)) / 100.0
    }

    pub fn nudge_opacity(&mut self, steps: i32) -> bool {
        let next =
            (i32::from(self.terminal_opacity) + steps * 5).clamp(i32::from(MIN_OPACITY), 100) as u8;
        let changed = next != self.terminal_opacity;
        self.terminal_opacity = next;
        changed
    }

    pub fn appearance(&self) -> crate::ui::theme::Appearance {
        crate::ui::theme::Appearance::parse(&self.appearance)
    }

    pub fn set_appearance(&mut self, appearance: crate::ui::theme::Appearance) {
        self.appearance = appearance.as_str().into();
    }

    /// Палитра для тёмного или светлого режима.
    pub fn set_palette(&mut self, id: &str, dark: bool) {
        if dark {
            self.dark_theme = id.into();
        } else {
            self.light_theme = id.into();
        }
    }

    /// До режимов была одна тема: светлая «light» или одна из тёмных.
    fn migrate_theme(&mut self) {
        if !self.appearance.is_empty() {
            return;
        }
        let legacy = std::mem::take(&mut self.theme);
        self.appearance = match legacy.trim() {
            "" => "system",
            "light" => "light",
            dark => {
                self.dark_theme = dark.into();
                "dark"
            }
        }
        .into();
    }

    pub fn prediction(&self) -> Policy {
        match self.prediction.trim() {
            "always" => Policy::Always,
            "never" => Policy::Never,
            _ => Policy::Adaptive,
        }
    }

    pub fn set_prediction(&mut self, policy: Policy) {
        self.prediction = match policy {
            Policy::Adaptive => "adaptive",
            Policy::Always => "always",
            Policy::Never => "never",
        }
        .into();
    }

    pub fn autolock_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(u64::from(self.autolock_minutes) * 60)
    }

    pub fn set_autolock_minutes(&mut self, minutes: u32) -> bool {
        let before = self.autolock_minutes;
        self.autolock_minutes = minutes.clamp(MIN_AUTOLOCK_MINUTES, MAX_AUTOLOCK_MINUTES);
        self.autolock_minutes != before
    }

    pub fn nudge_font_size(&mut self, steps: f32) -> bool {
        let before = self.font_size;
        self.font_size =
            (self.font_size + steps * FONT_SIZE_STEP).clamp(MIN_FONT_SIZE, MAX_FONT_SIZE);
        self.font_size != before
    }
}

pub fn directory() -> Option<std::path::PathBuf> {
    path().and_then(|file| file.parent().map(std::path::Path::to_path_buf))
}

fn path() -> Option<std::path::PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA").map(std::path::PathBuf::from)
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| home().map(|home| home.join(".config")))
    };
    Some(base.or_else(home)?.join("cratty").join("settings.json"))
}

fn home() -> Option<std::path::PathBuf> {
    #[allow(deprecated)]
    std::env::home_dir()
}

pub fn load() -> Settings {
    let Some(path) = path() else {
        return Settings::default();
    };
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Settings::default();
    };

    match serde_json::from_str::<Settings>(&text) {
        Ok(settings) => settings.clamped(),
        Err(error) => {
            eprintln!("Не удалось разобрать {}: {error}", path.display());
            Settings::default()
        }
    }
}

pub fn save(settings: &Settings) -> Result<(), String> {
    let path = path().ok_or("Не удалось определить каталог настроек.")?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("Не удалось создать {}: {error}", parent.display()))?;
    }

    let text = serde_json::to_string_pretty(settings)
        .map_err(|error| format!("Не удалось сериализовать настройки: {error}"))?;

    std::fs::write(&path, text)
        .map_err(|error| format!("Не удалось записать {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_within_the_allowed_range() {
        let settings = Settings::default();
        assert_eq!(settings.clone(), settings.clamped());
    }

    #[test]
    fn out_of_range_values_from_the_file_are_pulled_back() {
        let huge = Settings {
            font_size: 500.,
            ..Settings::default()
        }
        .clamped();
        assert_eq!(huge.font_size, MAX_FONT_SIZE);

        let tiny = Settings {
            font_size: 1.,
            ..Settings::default()
        }
        .clamped();
        assert_eq!(tiny.font_size, MIN_FONT_SIZE);
    }

    #[test]
    fn nonsense_values_fall_back_to_the_default() {
        let broken = Settings {
            font_size: f32::NAN,
            ..Settings::default()
        }
        .clamped();
        assert_eq!(broken.font_size, DEFAULT_FONT_SIZE);
    }

    #[test]
    fn nudging_stops_at_the_boundaries() {
        let mut settings = Settings {
            font_size: MAX_FONT_SIZE,
            ..Settings::default()
        };
        assert!(!settings.nudge_font_size(1.), "выше потолка расти некуда");
        assert_eq!(settings.font_size, MAX_FONT_SIZE);

        let mut settings = Settings {
            font_size: MIN_FONT_SIZE,
            ..Settings::default()
        };
        assert!(!settings.nudge_font_size(-1.));
        assert_eq!(settings.font_size, MIN_FONT_SIZE);
    }

    #[test]
    fn nudging_moves_by_one_step() {
        let mut settings = Settings {
            font_size: 14.,
            ..Settings::default()
        };
        assert!(settings.nudge_font_size(1.));
        assert_eq!(settings.font_size, 14. + FONT_SIZE_STEP);
        assert!(settings.nudge_font_size(-2.));
        assert_eq!(settings.font_size, 14. - FONT_SIZE_STEP);
    }

    #[test]
    fn an_empty_file_still_yields_working_settings() {
        let parsed: Settings = serde_json::from_str("{}").expect("не разбирается");
        assert_eq!(parsed.font_size, DEFAULT_FONT_SIZE);
        assert_eq!(parsed.autolock_minutes, DEFAULT_AUTOLOCK_MINUTES);
    }

    #[test]
    fn staraya_tema_perenositsya_v_rezhim() {
        let dark: Settings = serde_json::from_str(r#"{"theme":"synthwave"}"#).expect("разбор");
        let dark = dark.clamped();
        assert_eq!(dark.appearance, "dark");
        assert_eq!(dark.dark_theme, "synthwave");

        let light: Settings = serde_json::from_str(r#"{"theme":"light"}"#).expect("разбор");
        assert_eq!(light.clamped().appearance, "light");

        let fresh: Settings = serde_json::from_str("{}").expect("разбор");
        assert_eq!(fresh.clamped().appearance, "system");

        let text = serde_json::to_string(&dark).expect("запись");
        assert!(
            !text.contains("\"theme\""),
            "старое поле не должно писаться"
        );
    }

    #[test]
    fn the_file_round_trips() {
        let settings = Settings {
            font_size: 18.,
            autolock_minutes: 30,
            autolock: false,
            sync_folder: String::new(),
            prediction: "never".into(),
            theme: String::new(),
            appearance: "dark".into(),
            dark_theme: "graphite".into(),
            light_theme: "Ayu Light".into(),
            terminal_font: "Hack Nerd Font Mono".into(),
            terminal_icons: "none".into(),
            ui_font: "Inter".into(),
            terminal_opacity: 85,
            blur: true,
            rail_width: 300.0,
            panel_width: 400.0,
            editor_width: 600.0,
            rail_pinned: false,
            panel_pinned: true,
            collapsed_groups: vec!["vault/prod".into()],
        };
        let text = serde_json::to_string(&settings).expect("не сериализуется");
        let parsed: Settings = serde_json::from_str(&text).expect("не разбирается");
        assert_eq!(parsed, settings);
    }

    #[test]
    fn prozrachnost_v_predelah() {
        let mut settings: Settings = serde_json::from_str("{}").expect("разбор");
        assert_eq!(settings.opacity(), 1.0);
        assert!(!settings.nudge_opacity(1), "плотнее сплошного некуда");
        assert!(settings.nudge_opacity(-2));
        assert_eq!(settings.terminal_opacity, 90);
        for _ in 0..30 {
            settings.nudge_opacity(-1);
        }
        assert_eq!(settings.terminal_opacity, MIN_OPACITY);
        let wild: Settings = serde_json::from_str(r#"{"terminal_opacity":3}"#).expect("разбор");
        assert_eq!(wild.clamped().terminal_opacity, MIN_OPACITY);
    }

    #[test]
    fn rezhim_predskazaniya_terpit_opechatki() {
        let parsed: Settings =
            serde_json::from_str(r#"{"font_size":16,"prediction":"allways"}"#).expect("разбор");
        assert_eq!(parsed.font_size, 16.);
        assert_eq!(parsed.prediction(), Policy::Adaptive);

        let old: Settings = serde_json::from_str(r#"{"font_size":16}"#).expect("разбор");
        assert_eq!(old.prediction(), Policy::Adaptive);

        let mut settings = Settings::default();
        settings.set_prediction(Policy::Never);
        assert_eq!(settings.prediction(), Policy::Never);
    }

    #[test]
    fn nastroyki_i_hranilishche_lezhat_otdelno() {
        let settings = directory().expect("каталог настроек");
        let vault = crate::store::VaultStore::default_root().expect("каталог хранилища");
        assert_ne!(settings, vault);
    }

    #[test]
    fn taymaut_avtoloka_zazhat_v_granicy() {
        let too_big = Settings {
            autolock_minutes: 100_000,
            ..Settings::default()
        }
        .clamped();
        assert_eq!(too_big.autolock_minutes, MAX_AUTOLOCK_MINUTES);

        let too_small = Settings {
            autolock_minutes: 0,
            ..Settings::default()
        }
        .clamped();
        assert_eq!(too_small.autolock_minutes, MIN_AUTOLOCK_MINUTES);
    }

    #[test]
    fn taymaut_perevoditsya_v_duration() {
        let settings = Settings {
            autolock_minutes: 15,
            ..Settings::default()
        };
        assert_eq!(
            settings.autolock_timeout(),
            std::time::Duration::from_secs(900)
        );
    }

    #[test]
    fn staryy_fayl_nastroek_chitaetsya() {
        let parsed: Settings =
            serde_json::from_str(r#"{"font_size":16.0}"#).expect("не разбирается");
        assert_eq!(parsed.font_size, 16.);
        assert_eq!(parsed.autolock_minutes, DEFAULT_AUTOLOCK_MINUTES);
    }
}
