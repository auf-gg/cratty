//! Font picker: terminal, terminal icons (Nerd Font) and interface.

use super::*;
use crate::ui::font::{self, MonoFont};
use gpui_kit::component::IndexPath;
use gpui_kit::component::searchable_list::SearchableVec;
use gpui_kit::component::select::{Select, SelectEvent, SelectState};

type FontSelect = Entity<SelectState<SearchableVec<SharedString>>>;

fn auto() -> String {
    t!("fonts.auto").to_string()
}

fn no_icons() -> String {
    t!("fonts.no_icons").to_string()
}

fn system() -> String {
    t!("fonts.system").to_string()
}

/// Nerd Font icons that prompts usually draw: powerline arrow,
/// git branch, folder, terminal, lock.
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
        let mut make = |first: &[String], fonts: Vec<String>, current: &str| {
            let mut items: Vec<SharedString> = first
                .iter()
                .map(|label| SharedString::from(label.clone()))
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
            "" => auto(),
            font::NO_ICONS => no_icons(),
            name => name.to_string(),
        };
        let terminal = make(
            &[auto()],
            font::monospace(&all),
            settings.terminal_font.trim(),
        );
        let icons = make(&[auto(), no_icons()], font::icon_fonts(&all), &icons_current);
        let ui = make(&[system()], all, settings.ui_font.trim());

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
                self.settings.terminal_font = if value == auto() { "" } else { value }.into();
            }
            Slot::Icons => {
                self.settings.terminal_icons = if value == auto() {
                    ""
                } else if value == no_icons() {
                    font::NO_ICONS
                } else {
                    value
                }
                .into();
            }
            Slot::Ui => {
                self.settings.ui_font = if value == system() { "" } else { value }.into();
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
        let field = |title: String| {
            Label::new(title)
                .text_xs()
                .text_color(theme.muted_foreground)
        };
        let select = |state: &FontSelect| {
            Select::new(state)
                .small()
                .menu_max_h(px(320.))
                .search_placeholder(t!("fonts.search"))
        };

        let icons_note: SharedString = match &mono.icons {
            Some(name) if name.as_ref() == font::BUNDLED_ICONS => {
                t!("fonts.icons_bundled").into()
            }
            Some(name) => t!("fonts.icons_from", name = name.to_string()).into(),
            None if mono.family.contains("Nerd Font") => {
                t!("fonts.icons_in_font").into()
            }
            None => t!("fonts.icons_none").into(),
        };

        Self::section(t!("fonts.title"), cx)
            .child(field(t!("fonts.terminal").to_string()))
            .child(select(&pickers.terminal))
            .child(field(t!("fonts.terminal_icons").to_string()))
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
                    .child(SharedString::from("0O 1lI {} [] => != ~ Zz Qq"))
                    .child(div().text_color(theme.primary).child(ICON_SAMPLE)),
            )
            .child(Self::hint(icons_note, cx))
            .child(field(t!("fonts.interface").to_string()))
            .child(select(&pickers.ui))
            .into_any_element()
    }
}
