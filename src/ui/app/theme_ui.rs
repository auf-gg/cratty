//! Выбор оформления: режим (системный, тёмный, светлый), палитры для каждого
//! режима и схематичное окно-превью палитры.

use super::*;
use crate::ui::theme::{self, Appearance, ThemeEntry};
use gpui_kit::Hsla;

impl AppView {
    fn set_appearance(
        &mut self,
        appearance: Appearance,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.settings.set_appearance(appearance);
        self.save_theme(window, cx);
    }

    fn set_palette(&mut self, id: &str, dark: bool, window: &mut Window, cx: &mut Context<Self>) {
        self.settings.set_palette(id, dark);
        self.save_theme(window, cx);
    }

    fn save_theme(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.error = settings::save(&self.settings).err().map(SharedString::from);
        theme::apply(&self.settings, Some(window), cx);
        self.apply_appearance(cx);
    }

    pub(super) fn theme_block(&self, cx: &mut Context<Self>) -> AnyElement {
        let appearance = self.settings.appearance();
        let dark_now = theme::is_dark(cx);
        let current = if dark_now {
            &self.settings.dark_theme
        } else {
            &self.settings.light_theme
        };
        let shown = self
            .theme_preview
            .as_deref()
            .and_then(|id| theme::find(cx, id))
            .or_else(|| theme::resolve(cx, current, dark_now));

        let modes =
            h_flex().gap_1().children(
                [Appearance::System, Appearance::Dark, Appearance::Light].map(|mode| {
                    Button::new(SharedString::from(format!("appearance-{}", mode.as_str())))
                        .ghost()
                        .small()
                        .selected(appearance == mode)
                        .label(mode.title())
                        .on_click(cx.listener(move |this, _, window, cx| {
                            this.set_appearance(mode, window, cx)
                        }))
                }),
            );

        let mut section = Self::section("Оформление", cx)
            .child(modes)
            .children(shown.map(|entry| Self::theme_preview_window(&entry)));

        if appearance != Appearance::Light {
            section = section.child(self.palette_group(true, cx));
        }
        if appearance != Appearance::Dark {
            section = section.child(self.palette_group(false, cx));
        }
        section.into_any_element()
    }

    fn palette_group(&self, dark: bool, cx: &mut Context<Self>) -> AnyElement {
        let selected = if dark {
            &self.settings.dark_theme
        } else {
            &self.settings.light_theme
        };
        let selected = theme::resolve(cx, selected, dark).map(|entry| entry.id);
        let chips = theme::catalog(cx, dark)
            .into_iter()
            .map(|entry| {
                let chosen = selected.as_deref() == Some(entry.id.as_str());
                self.palette_chip(entry, dark, chosen, cx)
            })
            .collect::<Vec<_>>();

        v_flex()
            .gap_2()
            .pt_2()
            .child(Self::hint(
                if dark {
                    "Палитра тёмного режима"
                } else {
                    "Палитра светлого режима"
                },
                cx,
            ))
            .child(h_flex().flex_wrap().gap_1p5().children(chips))
            .into_any_element()
    }

    /// Плашка темы, нарисованная её же цветами: фон, текст и три акцента.
    fn palette_chip(
        &self,
        entry: ThemeEntry,
        dark: bool,
        chosen: bool,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let colors = &entry.colors;
        let ring = cx.theme().ring;
        let dot = |color: Hsla| div().size(px(8.)).rounded_full().bg(color);
        let (hover_id, click_id) = (entry.id.clone(), entry.id.clone());

        h_flex()
            .id(SharedString::from(format!("palette-{}", entry.id)))
            .h(px(28.))
            .px_2()
            .gap_1p5()
            .items_center()
            .rounded_md()
            .cursor_pointer()
            .bg(colors.background)
            .border_1()
            .border_color(if chosen { ring } else { colors.border })
            .when(chosen, |this| this.border_2())
            .child(dot(colors.primary))
            .child(dot(colors.red))
            .child(dot(colors.green))
            .child(dot(colors.blue))
            .child(
                Label::new(SharedString::from(entry.title.clone()))
                    .text_xs()
                    .text_color(colors.foreground),
            )
            .on_hover(cx.listener(move |this, hovered: &bool, _window, cx| {
                if *hovered {
                    this.theme_preview = Some(hover_id.clone());
                } else if this.theme_preview.as_deref() == Some(hover_id.as_str()) {
                    this.theme_preview = None;
                }
                cx.notify();
            }))
            .on_click(
                cx.listener(move |this, _, window, cx| {
                    this.set_palette(&click_id, dark, window, cx)
                }),
            )
            .into_any_element()
    }

    /// Схематичное окно в цветах темы: заголовок, боковая панель со списком,
    /// терминал с цветным выводом и кнопка акцента.
    fn theme_preview_window(entry: &ThemeEntry) -> AnyElement {
        let colors = &entry.colors;
        let ansi = |index: u8| {
            let rgb = entry.palette.indexed(index);
            gpui_kit::Hsla::from(gpui_kit::rgb(rgb.to_hex()))
        };
        let bar = |width: f32, color: Hsla| div().h(px(5.)).w(px(width)).rounded_sm().bg(color);
        let line = |parts: Vec<(f32, Hsla)>| {
            h_flex()
                .gap_1()
                .children(parts.into_iter().map(|(width, color)| bar(width, color)))
        };

        let title_bar = h_flex()
            .h(px(18.))
            .px_2()
            .gap_1()
            .items_center()
            .bg(colors.title_bar)
            .border_b_1()
            .border_color(colors.border)
            .child(div().size(px(6.)).rounded_full().bg(colors.red))
            .child(div().size(px(6.)).rounded_full().bg(colors.yellow))
            .child(div().size(px(6.)).rounded_full().bg(colors.green))
            .child(div().flex_1())
            .child(bar(40., colors.muted_foreground));

        let row = |active: bool, width: f32| {
            h_flex()
                .h(px(14.))
                .px_1p5()
                .rounded_sm()
                .items_center()
                .when(active, |this| this.bg(colors.list_active))
                .child(bar(
                    width,
                    if active {
                        colors.foreground
                    } else {
                        colors.muted_foreground
                    },
                ))
        };
        let sidebar = v_flex()
            .w(px(88.))
            .h_full()
            .p_1p5()
            .gap_1()
            .bg(colors.sidebar)
            .border_r_1()
            .border_color(colors.border)
            .child(
                div()
                    .h(px(12.))
                    .rounded_sm()
                    .border_1()
                    .border_color(colors.input),
            )
            .child(row(true, 52.))
            .child(row(false, 40.))
            .child(row(false, 60.))
            .child(row(false, 34.))
            .child(div().flex_1())
            .child(
                div()
                    .h(px(14.))
                    .rounded_sm()
                    .bg(colors.primary)
                    .flex()
                    .items_center()
                    .justify_center()
                    .child(bar(36., colors.primary_foreground)),
            );

        let terminal = v_flex()
            .flex_1()
            .h_full()
            .p_2()
            .gap_1p5()
            .bg(colors.background)
            .child(line(vec![(18., ansi(2)), (40., colors.foreground)]))
            .child(line(vec![(30., ansi(4)), (22., ansi(6)), (28., ansi(5))]))
            .child(line(vec![(46., ansi(3)), (20., colors.foreground)]))
            .child(line(vec![(24., ansi(1)), (54., colors.muted_foreground)]))
            .child(line(vec![(18., ansi(2)), (6., colors.caret)]));

        v_flex()
            .w(px(320.))
            .h(px(150.))
            .rounded_lg()
            .overflow_hidden()
            .border_1()
            .border_color(colors.border)
            .child(title_bar)
            .child(h_flex().flex_1().child(sidebar).child(terminal))
            .child(
                div()
                    .px_2()
                    .py_0p5()
                    .bg(colors.title_bar)
                    .border_t_1()
                    .border_color(colors.border)
                    .child(
                        Label::new(SharedString::from(entry.title.clone()))
                            .text_xs()
                            .text_color(colors.muted_foreground),
                    ),
            )
            .into_any_element()
    }
}
