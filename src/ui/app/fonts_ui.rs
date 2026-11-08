//! Выбор шрифтов: терминал, значки в терминале (Nerd Font) и интерфейс.

use super::*;
use crate::ui::font::{self, MonoFont};
use gpui_kit::component::IndexPath;
use gpui_kit::component::searchable_list::SearchableVec;
use gpui_kit::component::select::{Select, SelectEvent, SelectState};

type FontSelect = Entity<SelectState<SearchableVec<SharedString>>>;

const AUTO: &str = "Автоматически";
const NO_ICONS: &str = "Без значков";
const SYSTEM: &str = "Системный";

/// Значки Nerd Font, которые обычно рисуют промпты: стрелка powerline,
/// ветка git, папка, терминал, замок.
const ICON_SAMPLE: &str = "\u{e0b0} \u{e0a0} \u{f418} \u{f07b} \u{f489} \u{f023}";

pub(super) struct FontPickers {
    terminal: FontSelect,
    icons: FontSelect,
    ui: FontSelect,
    _subscriptions: Vec<Subscription>,
}

#[derive(Clone, Copy)]
enum Slot {
    Terminal,
    Icons,
    Ui,
}

impl FontPickers {
    pub(super) fn new(settings: &Settings, window: &mut Window, cx: &mut Context<AppView>) -> Self {
        let all = font::installed(cx);
        let mut make = |first: &[&str], fonts: Vec<String>, current: &str| {
            let mut items: Vec<SharedString> = first
                .iter()
                .map(|label| SharedString::from(*label))
                .collect();
            items.extend(fonts.into_iter().map(SharedString::from));
            let selected = items
                .iter()
                .position(|item| item.as_ref() == current)
                .unwrap_or(0);
            cx.new(|cx| {
                SelectState::new(
                    SearchableVec::new(items),
                    Some(IndexPath::new(selected)),
                    window,
                    cx,
                )
                .searchable(true)
            })
        };

        let icons_current = match settings.terminal_icons.trim() {
            "" => AUTO,
            font::NO_ICONS => NO_ICONS,
            name => name,
        };
        let terminal = make(
            &[AUTO],
            font::monospace(&all),
            settings.terminal_font.trim(),
        );
        let icons = make(&[AUTO, NO_ICONS], font::icon_fonts(&all), icons_current);
        let ui = make(&[SYSTEM], all, settings.ui_font.trim());

        let mut subscribe = |state: &FontSelect, slot: Slot| {
            cx.subscribe_in(
                state,
                window,
                move |this, _, event: &SelectEvent<SearchableVec<SharedString>>, window, cx| {
                    let SelectEvent::Confirm(Some(value)) = event else {
                        return;
                    };
                    this.set_font(slot, value, window, cx);
                },
            )
        };
        let subscriptions = vec![
            subscribe(&terminal, Slot::Terminal),
            subscribe(&icons, Slot::Icons),
            subscribe(&ui, Slot::Ui),
        ];

        Self {
            terminal,
            icons,
            ui,
            _subscriptions: subscriptions,
        }
    }
}

impl AppView {
    fn set_font(
        &mut self,
        slot: Slot,
        value: &SharedString,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let value = value.as_ref();
        match slot {
            Slot::Terminal => {
                self.settings.terminal_font = if value == AUTO { "" } else { value }.into();
            }
            Slot::Icons => {
                self.settings.terminal_icons = match value {
                    AUTO => "",
                    NO_ICONS => font::NO_ICONS,
                    name => name,
                }
                .into();
            }
            Slot::Ui => {
                self.settings.ui_font = if value == SYSTEM { "" } else { value }.into();
            }
        }
        self.error = settings::save(&self.settings).err().map(SharedString::from);
        MonoFont::apply(&self.settings, cx);
        crate::ui::theme::apply(&self.settings, Some(window), cx);
        self.apply_appearance(cx);
    }

    pub(super) fn fonts_block(&self, cx: &mut Context<Self>) -> AnyElement {
        let pickers = &self.font_pickers;
        let mono = MonoFont::get(cx).clone();
        let theme = cx.theme().clone();
        let field = |title: &'static str| {
            Label::new(title)
                .text_xs()
                .text_color(theme.muted_foreground)
        };
        let select = |state: &FontSelect| {
            Select::new(state)
                .small()
                .menu_max_h(px(320.))
                .search_placeholder("Найти шрифт")
        };

        let icons_note: SharedString = match &mono.icons {
            Some(name) if name.as_ref() == font::BUNDLED_ICONS => {
                "Значки из встроенного набора Nerd Fonts 3 (как в kitty).".into()
            }
            Some(name) => format!("Значки берутся из «{name}».").into(),
            None if mono.family.contains("Nerd Font") => {
                "Значки — только те, что есть в шрифте терминала.".into()
            }
            None => "Значков нет: промпты с Nerd Font будут показывать пустые квадраты.".into(),
        };

        Self::section("Шрифты", cx)
            .child(field("Терминал"))
            .child(select(&pickers.terminal))
            .child(field("Значки в терминале"))
            .child(select(&pickers.icons))
            .child(
                v_flex()
                    .p_2()
                    .gap_1()
                    .rounded_md()
                    .bg(crate::ui::theme::solid_background(cx))
                    .border_1()
                    .border_color(theme.border)
                    .font(mono.font())
                    .text_size(px(self.settings.font_size))
                    .child(SharedString::from("user@host ~/src $ git status"))
                    .child(SharedString::from("0O 1lI {} [] => != ~ Ёё Жж"))
                    .child(div().text_color(theme.primary).child(ICON_SAMPLE)),
            )
            .child(Self::hint(icons_note, cx))
            .child(field("Интерфейс"))
            .child(select(&pickers.ui))
            .into_any_element()
    }
}
