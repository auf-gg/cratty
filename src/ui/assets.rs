use std::borrow::Cow;

use anyhow::Result;
use gpui_kit::{AssetSource, SharedString};

macro_rules! icons {
    ($($name:literal),* $(,)?) => {
        &[$(
            (
                concat!("icons/", $name, ".svg"),
                include_bytes!(concat!("../../assets/icons/", $name, ".svg")).as_slice(),
            ),
        )*]
    };
}

static ICONS: &[(&str, &[u8])] = icons![
    "asterisk",
    "case-sensitive",
    "check",
    "chevron-down",
    "chevron-left",
    "chevron-right",
    "ellipsis",
    "circle-x",
    "close",
    "eye",
    "minus",
    "plus",
    "replace",
    "window-close",
    "window-maximize",
    "window-minimize",
    "window-restore",
    "delete",
    "globe",
    "lock",
    "lock-open",
    "moon",
    "panel-left-close",
    "panel-left-open",
    "route",
    "arrow-up",
    "download",
    "file",
    "folder",
    "folder-plus",
    "key-round",
    "monitor",
    "pencil",
    "pin",
    "pin-off",
    "refresh-cw",
    "server",
    "upload",
    "search",
    "settings",
    "square-terminal",
    "sun",
];

static BRAND: &[(&str, &[u8])] = &[(
    "brand/cratty.svg",
    include_bytes!("../../assets/cratty.svg"),
)];

pub struct Assets;

impl AssetSource for Assets {
    fn load(&self, path: &str) -> Result<Option<Cow<'static, [u8]>>> {
        if let Some((_, bytes)) = ICONS.iter().chain(BRAND).find(|(name, _)| *name == path) {
            return Ok(Some(Cow::Borrowed(bytes)));
        }
        // Иконки, которые рисуют сами компоненты (спиннер загрузки, стрелки
        // меню и т.п.), — из набора gpui-kit: он ровно под них и собран.
        if let Ok(Some(bytes)) = gpui_kit::assets::Assets.load(path) {
            return Ok(Some(bytes));
        }
        eprintln!("нет ассета {path} — добавьте его в assets/icons");
        Ok(None)
    }

    fn list(&self, path: &str) -> Result<Vec<SharedString>> {
        Ok(ICONS
            .iter()
            .filter(|(name, _)| name.starts_with(path))
            .map(|(name, _)| SharedString::new_static(name))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui_kit::component::{IconName, IconNamed};

    #[test]
    fn every_embedded_icon_is_valid_svg() {
        for (name, bytes) in ICONS {
            let text = std::str::from_utf8(bytes).unwrap_or_else(|_| panic!("{name} не UTF-8"));
            assert!(text.contains("<svg"), "{name} не похож на SVG");
            assert!(
                text.contains("currentColor"),
                "{name} не подхватит цвет темы: нет currentColor"
            );
        }
    }

    #[test]
    fn ikonki_komponentov_berutsya_iz_nabora_gpui_kit() {
        for path in [
            "icons/loader.svg",
            "icons/loader-circle.svg",
            "icons/chevron-up.svg",
            "icons/triangle-alert.svg",
            "icons/copy.svg",
        ] {
            let bytes = Assets.load(path).expect("загрузка").expect(path);
            assert!(bytes.starts_with(b"<svg"), "{path} не svg");
        }
        // Своя иконка не подменяется набором gpui-kit.
        let ours = Assets
            .load("icons/lock.svg")
            .expect("загрузка")
            .expect("lock");
        assert_eq!(ours.as_ref(), include_bytes!("../../assets/icons/lock.svg"));
    }

    #[test]
    fn icons_we_render_are_all_present() {
        let used = [
            IconName::Asterisk,
            IconName::Check,
            IconName::Close,
            IconName::Delete,
            IconName::Eye,
            IconName::Globe,
            IconName::Minus,
            IconName::Moon,
            IconName::PanelLeftClose,
            IconName::PanelLeftOpen,
            IconName::Plus,
            IconName::Replace,
            IconName::Search,
            IconName::Settings,
            IconName::SquareTerminal,
            IconName::Sun,
        ];

        for icon in used {
            let path = icon.path();
            assert!(
                ICONS.iter().any(|(name, _)| *name == path.as_ref()),
                "иконка {path} используется в UI, но не вшита"
            );
        }
    }

    #[test]
    fn our_own_icons_are_present() {
        for path in [
            "icons/lock.svg",
            "icons/lock-open.svg",
            "icons/pin.svg",
            "icons/pin-off.svg",
        ] {
            assert!(
                ICONS.iter().any(|(name, _)| *name == path),
                "иконка {path} используется в UI, но не вшита"
            );
        }
    }

    #[test]
    fn window_control_icons_are_present() {
        for path in [
            "icons/window-minimize.svg",
            "icons/window-maximize.svg",
            "icons/window-restore.svg",
            "icons/window-close.svg",
        ] {
            assert!(
                ICONS.iter().any(|(name, _)| *name == path),
                "нет иконки кнопки окна: {path}"
            );
        }
    }

    #[test]
    fn brand_icon_is_present() {
        assert!(
            Assets
                .load("brand/cratty.svg")
                .expect("не ошибка")
                .is_some()
        );
    }

    #[test]
    fn unknown_asset_is_reported_as_missing_not_as_empty() {
        let loaded = Assets
            .load("icons/такой-иконки-нет.svg")
            .expect("не ошибка");
        assert!(loaded.is_none());
    }
}
