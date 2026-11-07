use gpui_kit::component::{
    ActiveTheme, Disableable, Icon, IconName, Sizable, StyledExt, button::Button, h_flex,
    label::Label, v_flex,
};
use gpui_kit::{AnyElement, App, Context, Div, Pixels, SharedString, Window, div, prelude::*, px};

use super::AppView;

type Step = Box<dyn Fn(&mut AppView, &mut Window, &mut Context<AppView>) + 'static>;

impl AppView {
    pub(super) fn section(title: &'static str, cx: &App) -> Div {
        v_flex().px_5().py_4().gap_2().child(
            Label::new(title)
                .text_sm()
                .font_semibold()
                .text_color(cx.theme().foreground),
        )
    }

    pub(super) fn hint(text: impl Into<SharedString>, cx: &App) -> Label {
        Label::new(text.into())
            .text_xs()
            .text_color(cx.theme().muted_foreground)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn stepper(
        id: &'static str,
        value: String,
        can_less: bool,
        can_more: bool,
        less: Step,
        more: Step,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        h_flex()
            .gap_1()
            .items_center()
            .child(
                Button::new(SharedString::from(format!("{id}-less")))
                    .outline()
                    .small()
                    .icon(Icon::new(IconName::Minus))
                    .disabled(!can_less)
                    .on_click(cx.listener(move |this, _, window, cx| less(this, window, cx))),
            )
            .child(
                div()
                    .w(px(76.))
                    .flex()
                    .justify_center()
                    .child(Label::new(SharedString::from(value)).text_sm()),
            )
            .child(
                Button::new(SharedString::from(format!("{id}-more")))
                    .outline()
                    .small()
                    .icon(Icon::new(IconName::Plus))
                    .disabled(!can_more)
                    .on_click(cx.listener(move |this, _, window, cx| more(this, window, cx))),
            )
            .into_any_element()
    }

    pub(super) fn popover(title: &'static str, width: Pixels, cx: &App) -> Div {
        let theme = cx.theme();
        v_flex()
            .absolute()
            .occlude()
            .top(px(8.))
            .right(px(12.))
            .w(width)
            .max_w(gpui_kit::relative(0.9))
            .p_2()
            .gap_1()
            .rounded_lg()
            .border_1()
            .border_color(theme.border)
            .bg(theme.popover)
            .shadow_lg()
            .child(
                div().px_2().pt_1().pb_1().child(
                    Label::new(title)
                        .text_xs()
                        .font_semibold()
                        .text_color(theme.muted_foreground),
                ),
            )
    }

    pub(super) fn drawer_group(
        title: &'static str,
        body: impl IntoElement,
        cx: &App,
    ) -> AnyElement {
        v_flex()
            .gap_2()
            .pt_3()
            .border_t_1()
            .border_color(cx.theme().border)
            .child(Label::new(title).text_sm().font_semibold())
            .child(body)
            .into_any_element()
    }
}
