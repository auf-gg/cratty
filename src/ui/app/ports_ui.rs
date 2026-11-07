use gpui_kit::component::{
    ActiveTheme, Icon, IconName, Selectable, Sizable,
    button::{Button, ButtonVariants},
    h_flex,
    input::{Input, InputState},
    label::Label,
    v_flex,
};
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
            listen: cx.new(|cx| InputState::new(window, cx).placeholder("Порт")),
            target: cx.new(|cx| InputState::new(window, cx).placeholder("хост:порт")),
        }
    }
}

fn parse_rule(kind: ForwardKind, listen: &str, target: &str) -> Result<PortForward, String> {
    let listen_port = match listen.trim().parse::<u16>() {
        Ok(port) if port != 0 => port,
        _ => {
            return Err(format!(
                "Порт «{}» должен быть числом от 1 до 65535.",
                listen.trim()
            ));
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
            .map_err(|error| format!("Адрес назначения: {error}"))?;
        if request.user.is_some() {
            return Err("Адрес назначения указывается без имени пользователя.".into());
        }
        rule.target_host = request.alias;
        rule.target_port = request
            .port
            .ok_or("Укажите порт назначения в формате хост:порт.")?;
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
                                Button::new(SharedString::from(format!("forward-auto-{index}")))
                                    .ghost()
                                    .xsmall()
                                    .selected(rule.enabled)
                                    .label("Автозапуск")
                                    .tooltip(
                                        "Включать при подключении. Иначе правило включается вручную в панели сеанса.",
                                    )
                                    .on_click(cx.listener(move |this, _, _window, cx| {
                                        if let Some(rule) = this.form.forwards.get_mut(index) {
                                            rule.enabled = !rule.enabled;
                                        }
                                        cx.notify();
                                    })),
                            )
                            .child(
                                Button::new(SharedString::from(format!("forward-remove-{index}")))
                                    .ghost()
                                    .xsmall()
                                    .icon(Icon::new(IconName::Close))
                                    .tooltip("Удалить правило")
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
            ForwardKind::Local => {
                "Доступ с этого компьютера к сервису в сети сервера: базе данных, панели управления, внутреннему API."
            }
            ForwardKind::Remote => {
                "Доступ с сервера к сервису, запущенному на этом компьютере, например к локальному веб-серверу."
            }
            _ => "SOCKS-прокси на этом компьютере: трафик приложений передаётся через сервер.",
        };

        let draft = &self.form.forward_draft;
        let typed = parse_rule(
            kind,
            draft.listen.read(cx).value().as_ref(),
            draft.target.read(cx).value().as_ref(),
        );
        let (preview_title, preview) = match typed {
            Ok(rule) => ("Предпросмотр", rule),
            Err(_) => (
                "Пример",
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
                        Label::new("Правила переадресации не заданы.")
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
                                        .label("Добавить")
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
    fn pravilo_iz_poley_formy() {
        let rule = parse_rule(ForwardKind::Local, " 8080 ", "db.internal:5432").expect("правило");
        assert_eq!(rule.summary(), "-L 8080 → db.internal:5432");
        let rule = parse_rule(ForwardKind::Remote, "9000", "[::1]:3000").expect("правило");
        assert_eq!((rule.target_host.as_str(), rule.target_port), ("::1", 3000));
        assert!(parse_rule(ForwardKind::Dynamic, "1080", "мусор").is_ok());

        assert!(parse_rule(ForwardKind::Local, "0", "db:1").is_err());
        assert!(
            parse_rule(ForwardKind::Local, "80", "db").is_err(),
            "без порта цели"
        );
        assert!(parse_rule(ForwardKind::Local, "80", "root@db:22").is_err());
    }
}
