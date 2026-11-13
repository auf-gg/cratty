use gpui_kit::component::{
    ActiveTheme, Icon, IconName, Selectable, Sizable,
    button::{Button, ButtonVariants},
    checkbox::Checkbox,
    h_flex,
    input::{Input, InputState},
    label::Label,
    v_flex,
};
use rust_i18n::t;
use gpui_kit::{AnyElement, Context, Entity, SharedString, Window, prelude::*};
use proto::{ForwardKind, PortForward};

use super::AppView;
use crate::ui::{connect, route};

pub(super) struct ForwardDraft {
    pub kind: ForwardKind,
    pub listen: Entity<InputState>,
    pub target: Entity<InputState>,
}

impl ForwardDraft {
    pub fn new(window: &mut Window, cx: &mut Context<AppView>) -> Self {
        Self {
            kind: ForwardKind::Local,
            listen: cx.new(|cx| InputState::new(window, cx).placeholder(t!("ports.port_placeholder"))),
            target: cx.new(|cx| InputState::new(window, cx).placeholder(t!("ports.target_placeholder"))),
        }
    }
}

fn parse_rule(kind: ForwardKind, listen: &str, target: &str) -> Result<PortForward, String> {
    let listen_port = match listen.trim().parse::<u16>() {
        Ok(port) if port != 0 => port,
        _ => {
            return Err(t!("ports.err_port", port = listen.trim()).to_string());
        }
    };
    let mut rule = PortForward {
        kind,
        listen_port,
        enabled: true,
        ..Default::default()
    };
    if kind != ForwardKind::Dynamic {
        let request = connect::parse_target(target.trim())
            .map_err(|error| t!("ports.err_target", error = error.to_string()).to_string())?;
        if request.user.is_some() {
            return Err(t!("ports.err_user").to_string());
        }
        rule.target_host = request.alias;
        rule.target_port = request
            .port
            .ok_or_else(|| t!("ports.err_target_port").to_string())?;
    }
    Ok(rule)
}

impl AppView {
    fn forward_add(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let draft = &self.form.forward_draft;
        let listen = draft.listen.read(cx).value().to_string();
        let target = draft.target.read(cx).value().to_string();
        match parse_rule(draft.kind, &listen, &target) {
            Ok(rule) => {
                self.form.forwards.push(rule);
                self.error = None;
                for input in [
                    &self.form.forward_draft.listen,
                    &self.form.forward_draft.target,
                ] {
                    input.update(cx, |state, cx| state.set_value("", window, cx));
                }
            }
            Err(error) => self.error = Some(error.into()),
        }
        cx.notify();
    }

    pub(super) fn forwards_block(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let theme = cx.theme().clone();
        let muted = theme.muted_foreground;
        let kind = self.form.forward_draft.kind;
        let server = self.form.host.read(cx).value().trim().to_string();

        let rows: Vec<AnyElement> = self
            .form
            .forwards
            .iter()
            .enumerate()
            .map(|(index, rule)| {
                v_flex()
                    .gap_1()
                    .p_2()
                    .rounded_md()
                    .border_1()
                    .border_color(theme.border)
                    .bg(theme.secondary)
                    .child(
                        h_flex()
                            .items_center()
                            .gap_1()
                            .child(
                                Label::new(SharedString::from(format!(
                                    "{} · {}",
                                    route::kind_title(rule.kind),
                                    rule.kind.flag()
                                )))
                                .text_xs()
                                .text_color(muted)
                                .flex_grow_1(),
                            )
                            .child(
                                Checkbox::new(SharedString::from(format!("forward-auto-{index}")))
                                    .xsmall()
                                    .checked(rule.enabled)
                                    .label(t!("ports.autostart").to_string())
                                    .tooltip(t!("ports.autostart_tooltip"))
                                    .on_click(cx.listener(move |this, checked: &bool, _window, cx| {
                                        if let Some(rule) = this.form.forwards.get_mut(index) {
                                            rule.enabled = *checked;
                                        }
                                        cx.notify();
                                    })),
                            )
                            .child(
                                Button::new(SharedString::from(format!("forward-remove-{index}")))
                                    .ghost()
                                    .xsmall()
                                    .icon(Icon::new(IconName::Close))
                                    .tooltip(t!("ports.delete"))
                                    .on_click(cx.listener(move |this, _, _window, cx| {
                                        if index < this.form.forwards.len() {
                                            this.form.forwards.remove(index);
                                        }
                                        cx.notify();
                                    })),
                            ),
                    )
                    .child(route::forward(rule, &server, cx))
                    .into_any_element()
            })
            .collect();

        let kind_button = |id: &'static str, value: ForwardKind| {
            Button::new(id)
                .ghost()
                .small()
                .selected(kind == value)
                .label(SharedString::from(format!(
                    "{} {}",
                    route::kind_title(value),
                    value.flag()
                )))
                .on_click(cx.listener(move |this, _, _window, cx| {
                    this.form.forward_draft.kind = value;
                    cx.notify();
                }))
        };
        let hint = match kind {
            ForwardKind::Local => t!("ports.hint_local"),
            ForwardKind::Remote => t!("ports.hint_remote"),
            _ => t!("ports.hint_dynamic"),
        };

        let draft = &self.form.forward_draft;
        let typed = parse_rule(
            kind,
            draft.listen.read(cx).value().as_ref(),
            draft.target.read(cx).value().as_ref(),
        );
        let (preview_title, preview) = match typed {
            Ok(rule) => (t!("ports.preview"), rule),
            Err(_) => (
                t!("ports.example"),
                PortForward {
                    kind,
                    listen_port: 8080,
                    target_host: "localhost".into(),
                    target_port: if kind == ForwardKind::Remote {
                        3000
                    } else {
                        5432
                    },
                    enabled: true,
                },
            ),
        };

        Some(
            v_flex()
                .gap_2()
                .when(rows.is_empty(), |this| {
                    this.child(
                        Label::new(t!("ports.empty"))
                            .text_xs()
                            .text_color(muted),
                    )
                })
                .children(rows)
                .child(
                    v_flex()
                        .gap_2()
                        .p_2()
                        .rounded_md()
                        .border_1()
                        .border_dashed()
                        .border_color(theme.border)
                        .child(
                            h_flex()
                                .flex_wrap()
                                .gap_1()
                                .child(kind_button("forward-kind-l", ForwardKind::Local))
                                .child(kind_button("forward-kind-r", ForwardKind::Remote))
                                .child(kind_button("forward-kind-d", ForwardKind::Dynamic)),
                        )
                        .child(Label::new(hint).text_xs().text_color(muted))
                        .child(
                            h_flex()
                                .gap_1()
                                .items_center()
                                .child(
                                    Input::new(&self.form.forward_draft.listen)
                                        .small()
                                        .w(gpui_kit::px(90.)),
                                )
                                .when(kind != ForwardKind::Dynamic, |this| {
                                    this.child(Label::new("→").text_sm().text_color(muted))
                                        .child(
                                            Input::new(&self.form.forward_draft.target)
                                                .small()
                                                .flex_grow_1(),
                                        )
                                })
                                .child(
                                    Button::new("forward-add")
                                        .outline()
                                        .small()
                                        .icon(Icon::new(IconName::Plus))
                                        .label(t!("ports.add"))
                                        .on_click(cx.listener(|this, _, window, cx| {
                                            this.forward_add(window, cx)
                                        })),
                                ),
                        )
                        .child(Label::new(preview_title).text_xs().text_color(muted))
                        .child(route::forward(&preview, &server, cx)),
                )
                .into_any_element(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_from_form_fields() {
        let rule = parse_rule(ForwardKind::Local, " 8080 ", "db.internal:5432").expect("rule");
        assert_eq!(rule.summary(), "-L 8080 → db.internal:5432");
        let rule = parse_rule(ForwardKind::Remote, "9000", "[::1]:3000").expect("rule");
        assert_eq!((rule.target_host.as_str(), rule.target_port), ("::1", 3000));
        assert!(parse_rule(ForwardKind::Dynamic, "1080", "junk").is_ok());

        assert!(parse_rule(ForwardKind::Local, "0", "db:1").is_err());
        assert!(
            parse_rule(ForwardKind::Local, "80", "db").is_err(),
            "without a target port"
        );
        assert!(parse_rule(ForwardKind::Local, "80", "root@db:22").is_err());
    }
}
