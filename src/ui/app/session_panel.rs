use super::*;
use crate::ssh::forward::ForwardState;
use crate::ui::route;
use crate::ui::terminal::Status;
use crate::vault_session::ViaItem;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum InfoTab {
    Info,
    Files,
}

pub(super) fn address(request: &connect::Request) -> String {
    let mut text = String::new();
    if let Some(user) = &request.user {
        text.push_str(user);
        text.push('@');
    }
    text.push_str(&request.alias);
    if let Some(port) = request.port.filter(|port| *port != 22) {
        text.push_str(&format!(":{port}"));
    }
    text
}

impl AppView {
    pub(super) fn session_panel(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        if !self.info_open || self.showing_page {
            return None;
        }
        let index = self.active?;
        let tab = self.tabs.get(index)?;
        let TabKind::Terminal { view, files, .. } = &tab.kind else {
            return None;
        };
        let theme = cx.theme().clone();

        let body = match self.info_tab {
            InfoTab::Info => self.session_info(tab, view, cx),
            InfoTab::Files => match files {
                Some(panel) => div()
                    .size_full()
                    .child(panel.view.clone())
                    .into_any_element(),
                None => v_flex()
                    .p_4()
                    .gap_2()
                    .child(
                        Label::new("Файловый менеджер использует текущее SSH-соединение.")
                            .text_xs()
                            .text_color(theme.muted_foreground),
                    )
                    .child(
                        Button::new("panel-open-files")
                            .outline()
                            .small()
                            .label("Открыть файлы")
                            .disabled(tab.is_closed(cx))
                            .on_click(cx.listener(move |this, _, _window, cx| {
                                this.ensure_files_panel(index, cx)
                            })),
                    )
                    .into_any_element(),
            },
        };

        let tab_label = |id: &'static str, label: &'static str, value: InfoTab| {
            let current = self.info_tab == value;
            div()
                .id(id)
                .h_full()
                .flex()
                .items_center()
                .child(
                    Label::new(label)
                        .text_sm()
                        .when(current, |this| this.font_medium())
                        .text_color(if current {
                            theme.foreground
                        } else {
                            theme.muted_foreground
                        }),
                )
                .on_click(cx.listener(move |this, _, _window, cx| {
                    this.info_tab = value;
                    if value == InfoTab::Files {
                        this.ensure_files_panel(index, cx);
                    }
                    cx.notify();
                }))
        };

        Some(
            v_flex()
                .w(px(self.settings.panel_width))
                .h_full()
                .flex_shrink_0()
                .border_l_1()
                .border_color(theme.border)
                .bg(crate::ui::theme::solid_background(cx))
                .child(
                    h_flex()
                        .h(px(40.))
                        .flex_shrink_0()
                        .px_4()
                        .gap_4()
                        .items_center()
                        .child(tab_label("panel-tab-info", "Сведения", InfoTab::Info))
                        .child(tab_label("panel-tab-files", "Файлы", InfoTab::Files))
                        .child(div().flex_grow_1())
                        .child(
                            Button::new("panel-close")
                                .ghost()
                                .xsmall()
                                .icon(Icon::new(IconName::Close))
                                .tooltip("Скрыть панель")
                                .on_click(cx.listener(|this, _, _window, cx| {
                                    this.info_open = false;
                                    cx.notify();
                                })),
                        ),
                )
                .child(div().flex_grow_1().min_h(px(0.)).child(body))
                .into_any_element(),
        )
    }

    fn ensure_files_panel(&mut self, index: usize, cx: &mut Context<Self>) {
        let missing = matches!(
            self.tabs.get(index).map(|tab| &tab.kind),
            Some(TabKind::Terminal { files: None, .. })
        );
        if missing {
            self.toggle_files_panel(index, cx);
        }
    }

    fn info_section(title: &'static str, cx: &App) -> gpui_kit::Div {
        v_flex().gap_1().child(
            div().h(px(28.)).flex().items_center().child(
                Label::new(title)
                    .text_xs()
                    .font_medium()
                    .text_color(cx.theme().muted_foreground),
            ),
        )
    }

    fn info_row(label: &'static str, value: AnyElement, cx: &App) -> AnyElement {
        h_flex()
            .min_h(px(28.))
            .gap_3()
            .items_center()
            .child(
                div().w(px(76.)).flex_shrink_0().child(
                    Label::new(label)
                        .text_sm()
                        .text_color(cx.theme().muted_foreground),
                ),
            )
            .child(div().flex_1().min_w(px(0.)).child(value))
            .into_any_element()
    }

    fn session_info(
        &self,
        tab: &SessionTab,
        view: &Entity<TerminalView>,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = cx.theme().clone();
        let terminal = view.read(cx);
        let (connected, status_text, status_color) = match terminal.status() {
            Status::Connecting { .. } => (false, "Подключение…".to_string(), theme.warning),
            Status::Connected { .. } => (true, "Подключено".to_string(), theme.success),
            Status::Closed { message, failed } => (
                false,
                if message.is_empty() {
                    "Отключено".to_string()
                } else {
                    message.to_string()
                },
                if *failed {
                    theme.danger
                } else {
                    theme.muted_foreground
                },
            ),
        };
        let forwards: Vec<(proto::PortForward, ForwardState)> = terminal.forwards().to_vec();
        let server = tab.request.alias.clone();
        let target = address(&tab.request);
        let saved_target = self
            .find_host(tab.vault.as_deref(), &target)
            .map(|(vault, entry)| (vault, entry.host.target()));

        let status = h_flex()
            .gap_2()
            .items_center()
            .child(Self::dot(status_color))
            .child(Label::new(SharedString::from(status_text)).text_sm())
            .into_any_element();
        let auth = match tab.credentials.auth {
            HostAuth::Auto => "Автоматически",
            HostAuth::Password => "Пароль",
            HostAuth::Key { .. } => "Файл ключа",
        };

        let mut steps =
            vec![route::node(route::Place::You, "Этот компьютер", "", cx).into_any_element()];
        for item in &tab.credentials.via {
            let (place, detail) = match item {
                ViaItem::Proxy(_) => (route::Place::Hop, "Прокси-сервер"),
                ViaItem::Host(_) => (route::Place::Server, "Промежуточный хост"),
            };
            steps.push(
                route::node(place, shorten(&item.title(), ROW_TITLE_CHARS), detail, cx)
                    .into_any_element(),
            );
        }
        steps.push(
            route::node(
                route::Place::Server,
                shorten(&server, ROW_TITLE_CHARS),
                "Целевой сервер",
                cx,
            )
            .into_any_element(),
        );

        let port_rows: Vec<AnyElement> = forwards
            .iter()
            .enumerate()
            .map(|(index, (rule, state))| {
                let (text, color) = match state {
                    ForwardState::Active => ("Активно".to_string(), theme.success),
                    ForwardState::Off => ("Выключено".to_string(), theme.muted_foreground),
                    ForwardState::Failed(error) => (error.clone(), theme.danger),
                };
                let active = *state == ForwardState::Active;
                let terminal = view.clone();
                v_flex()
                    .gap_1()
                    .py_2()
                    .child(
                        h_flex()
                            .gap_2()
                            .items_center()
                            .child(Self::dot(color))
                            .child(
                                Label::new(SharedString::from(format!(
                                    "{} · {}",
                                    route::kind_title(rule.kind),
                                    text
                                )))
                                .text_xs()
                                .text_color(theme.muted_foreground)
                                .flex_grow_1(),
                            )
                            .child(
                                Button::new(SharedString::from(format!("panel-forward-{index}")))
                                    .xsmall()
                                    .ghost()
                                    .label(if active {
                                        "Выключить"
                                    } else {
                                        "Включить"
                                    })
                                    .disabled(!connected)
                                    .on_click(cx.listener(move |_, _, _window, cx| {
                                        terminal.read(cx).set_forward(index, !active);
                                    })),
                            ),
                    )
                    .child(route::forward_line(rule, &server, cx))
                    .into_any_element()
            })
            .collect();

        v_flex()
            .id("session-info")
            .size_full()
            .overflow_y_scrollbar()
            .px_4()
            .pb_4()
            .gap_4()
            .child(
                Self::info_section("Сеанс", cx)
                    .child(Self::info_row(
                        "Адрес",
                        Label::new(SharedString::from(target.clone()))
                            .text_sm()
                            .into_any_element(),
                        cx,
                    ))
                    .child(Self::info_row("Состояние", status, cx))
                    .child(Self::info_row(
                        "Вход",
                        Label::new(auth).text_sm().into_any_element(),
                        cx,
                    )),
            )
            .child(
                Self::info_section("Маршрут", cx)
                    .child(route::flow(steps, cx))
                    .children(tab.credentials.proxy_error.clone().map(|error| {
                        Label::new(SharedString::from(error))
                            .text_xs()
                            .text_color(theme.danger)
                    })),
            )
            .child(
                Self::info_section("Переадресация портов", cx)
                    .when(port_rows.is_empty(), |this| {
                        this.child(
                            Label::new("Правила переадресации не заданы.")
                                .text_xs()
                                .text_color(theme.muted_foreground),
                        )
                    })
                    .children(port_rows)
                    .children(saved_target.map(|(vault, target)| {
                        h_flex().child(
                            Button::new("panel-edit-host")
                                .ghost()
                                .xsmall()
                                .icon(Icon::empty().path("icons/pencil.svg"))
                                .label("Изменить маршрут и переадресацию")
                                .on_click(cx.listener(move |this, _, window, cx| {
                                    this.edit(&vault, &target, window, cx)
                                })),
                        )
                    })),
            )
            .into_any_element()
    }
}

#[cfg(test)]
mod tests {
    use super::address;
    use crate::ui::connect::Request;

    #[test]
    fn adres_bez_standartnogo_porta() {
        let request = Request {
            alias: "prod-01".into(),
            user: Some("root".into()),
            port: Some(22),
        };
        assert_eq!(address(&request), "root@prod-01");
        let request = Request {
            alias: "db".into(),
            user: None,
            port: Some(2222),
        };
        assert_eq!(address(&request), "db:2222");
    }
}
