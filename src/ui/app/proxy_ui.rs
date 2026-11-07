use crate::ui::route;
use crate::vault_session::ViaItem;
use gpui_kit::component::{
    ActiveTheme, Disableable, Icon, IconName, Sizable, StyledExt,
    button::{Button, ButtonVariants},
    h_flex,
    input::{Input, InputState},
    label::Label,
    scroll::ScrollableElement,
    v_flex,
};
use gpui_kit::{AnyElement, Context, Entity, SharedString, Window, div, prelude::*, px};
use proto::{ProxyKind, ProxyRecord, RecordId, SOCKS_PORT};

use super::{AppView, ROW_TITLE_CHARS, Section, shorten};

pub(super) struct ProxyForm {
    pub label: Entity<InputState>,
    pub host: Entity<InputState>,
    pub port: Entity<InputState>,
    pub user: Entity<InputState>,
    pub password: Entity<InputState>,
    pub editing: Option<RecordId>,
    pub open: bool,
}

impl ProxyForm {
    pub(super) fn new(
        label: Entity<InputState>,
        host: Entity<InputState>,
        port: Entity<InputState>,
        user: Entity<InputState>,
        password: Entity<InputState>,
    ) -> Self {
        Self {
            label,
            host,
            port,
            user,
            password,
            editing: None,
            open: false,
        }
    }
}

impl AppView {
    pub(super) fn resolve_chain(
        &self,
        vault: &str,
        via: &[RecordId],
    ) -> (Vec<crate::vault_session::ViaItem>, Option<String>) {
        if via.is_empty() {
            return (Vec::new(), None);
        }
        let Some(unlocked) = self.unlocked_of(vault) else {
            return (
                Vec::new(),
                Some("Хранилище заблокировано: цепочку прокси невозможно построить. Разблокируйте хранилище.".into()),
            );
        };
        let resolved = crate::vault_session::resolve_via_in(via, |id| unlocked.via_item(id));
        match resolved {
            Ok(via) => (via, None),
            Err(error) => (Vec::new(), Some(error)),
        }
    }

    pub(super) fn proxy_save(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let label = self.proxy_form.label.read(cx).value().trim().to_string();
        let host = self.proxy_form.host.read(cx).value().trim().to_string();
        let port_text = self.proxy_form.port.read(cx).value().trim().to_string();
        let user = self.proxy_form.user.read(cx).value().trim().to_string();

        let port = if port_text.is_empty() {
            SOCKS_PORT
        } else {
            match port_text.parse::<u16>() {
                Ok(port) if port != 0 => port,
                _ => {
                    self.error = Some(
                        format!("Порт «{port_text}» должен быть числом от 1 до 65535.").into(),
                    );
                    cx.notify();
                    return;
                }
            }
        };
        if host.is_empty() {
            self.error = Some("Укажите адрес прокси-сервера.".into());
            cx.notify();
            return;
        }

        let editing = self.proxy_form.editing.clone();
        let existing = editing
            .as_ref()
            .and_then(|id| {
                self.current_unlocked()
                    .and_then(|unlocked| unlocked.proxy(id))
            })
            .map(|entry| entry.proxy);
        if existing
            .as_ref()
            .is_some_and(|proxy| proxy.kind == ProxyKind::Unsupported)
        {
            self.error = Some(
                "Прокси создан более новой версией приложения и не может быть изменён.".into(),
            );
            cx.notify();
            return;
        }

        let mut record = existing.unwrap_or_else(|| ProxyRecord::new(ProxyKind::Socks5, "", port));
        record.label = label;
        record.host = host;
        record.port = port;
        record.user = user;

        let password = Self::take_password(&self.proxy_form.password, window, cx);
        if !password.is_empty() {
            record.set_password(proto::Secret::new(password));
        }
        if record.user.is_empty() {
            record.forget_password();
        }

        self.persist_current(cx, move |unlocked, store| {
            unlocked.upsert_proxy(store, editing, record).map(|_| ())
        });
        if self.error.is_none() {
            self.proxy_clear(window, cx);
        }
    }

    pub(super) fn proxy_edit(
        &mut self,
        id: &RecordId,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(entry) = self
            .current_unlocked()
            .and_then(|unlocked| unlocked.proxy(id))
        else {
            return;
        };
        let proxy = entry.proxy;
        let port = proxy.port.to_string();
        let form = &self.proxy_form;
        form.label.update(cx, |state, cx| {
            state.set_value(proxy.label.clone(), window, cx)
        });
        form.host.update(cx, |state, cx| {
            state.set_value(proxy.host.clone(), window, cx)
        });
        form.port
            .update(cx, |state, cx| state.set_value(port, window, cx));
        form.user.update(cx, |state, cx| {
            state.set_value(proxy.user.clone(), window, cx)
        });
        form.password
            .update(cx, |state, cx| state.set_value("", window, cx));
        self.proxy_form.editing = Some(id.clone());
        self.proxy_form.open = true;
        self.error = None;
        cx.notify();
    }

    fn proxy_new(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.proxy_clear(window, cx);
        self.proxy_form.open = true;
        self.error = None;
        cx.notify();
    }

    pub(super) fn proxy_clear(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let form = &self.proxy_form;
        for input in [
            &form.label,
            &form.host,
            &form.port,
            &form.user,
            &form.password,
        ] {
            input.update(cx, |state, cx| state.set_value("", window, cx));
        }
        self.proxy_form.editing = None;
        self.proxy_form.open = false;
        cx.notify();
    }

    fn proxy_forget_password(&mut self, cx: &mut Context<Self>) {
        let Some(id) = self.proxy_form.editing.clone() else {
            return;
        };
        let Some(mut proxy) = self
            .current_unlocked()
            .and_then(|unlocked| unlocked.proxy(&id))
            .map(|entry| entry.proxy)
        else {
            return;
        };
        if !proxy.forget_password() {
            return;
        }
        self.persist_current(cx, move |unlocked, store| {
            unlocked.upsert_proxy(store, Some(id), proxy).map(|_| ())
        });
    }

    fn proxy_remove(&mut self, id: &RecordId, window: &mut Window, cx: &mut Context<Self>) {
        let id = id.clone();
        let was_editing = self.proxy_form.editing.as_ref() == Some(&id);
        self.persist_current(cx, move |unlocked, store| unlocked.remove_proxy(store, &id));
        if was_editing && self.error.is_none() {
            self.proxy_clear(window, cx);
        }
    }

    fn chain_push(&mut self, id: RecordId, cx: &mut Context<Self>) {
        if !self.form.via.contains(&id) {
            self.form.via.push(id);
        }
        cx.notify();
    }

    fn chain_remove(&mut self, index: usize, cx: &mut Context<Self>) {
        if index < self.form.via.len() {
            self.form.via.remove(index);
        }
        cx.notify();
    }

    pub(super) fn chain_block(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let unlocked = self.unlocked_of(&self.form.vault)?;
        let muted = cx.theme().muted_foreground;
        let danger = cx.theme().danger;
        let proxies = unlocked.proxies();
        let editing_host = self.form.host.read(cx).value().trim().to_string();
        let hosts: Vec<_> = unlocked
            .hosts()
            .into_iter()
            .filter(|entry| self.form.editing.as_deref() != Some(entry.host.target().as_str()))
            .collect();

        let links: Vec<AnyElement> = self
            .form
            .via
            .iter()
            .enumerate()
            .map(|(index, id)| {
                let (place, title, detail) = match unlocked.via_item(id) {
                    Some(ViaItem::Proxy(proxy)) => {
                        (route::Place::Hop, proxy.title(), "Прокси-сервер")
                    }
                    Some(ViaItem::Host(host)) => {
                        (route::Place::Server, host.title(), "Промежуточный хост")
                    }
                    None => (route::Place::Hop, "Звено удалено".to_string(), ""),
                };
                let broken = detail.is_empty();
                route::node(place, shorten(&title, ROW_TITLE_CHARS), detail, cx)
                    .when(broken, |this| this.border_color(danger))
                    .child(
                        Button::new(SharedString::from(format!("chain-remove-{index}")))
                            .ghost()
                            .xsmall()
                            .icon(Icon::new(IconName::Close))
                            .tooltip("Удалить из цепочки")
                            .on_click(cx.listener(move |this, _, _window, cx| {
                                this.chain_remove(index, cx)
                            })),
                    )
                    .into_any_element()
            })
            .collect();
        let direct = links.is_empty();

        let mut steps =
            vec![route::node(route::Place::You, "Этот компьютер", "", cx).into_any_element()];
        steps.extend(links);
        steps.push(
            route::node(
                route::Place::Server,
                if editing_host.is_empty() {
                    "Сервер".to_string()
                } else {
                    shorten(&editing_host, ROW_TITLE_CHARS)
                },
                "Целевой сервер",
                cx,
            )
            .into_any_element(),
        );

        let available: Vec<(RecordId, String)> = proxies
            .into_iter()
            .filter(|entry| entry.proxy.is_usable())
            .map(|entry| (entry.id, entry.proxy.title()))
            .chain(
                hosts
                    .into_iter()
                    .map(|entry| (entry.id, format!("Хост {}", entry.host.title()))),
            )
            .filter(|(id, _)| !self.form.via.contains(id))
            .collect();

        Some(
            v_flex()
                .gap_2()
                .child(route::flow(steps, cx))
                .child(
                    Label::new(if direct {
                        "Прямое подключение. Добавьте звенья, если сервер доступен только через бастион или прокси-сервер."
                    } else {
                        "Подключение выполняется слева направо. Сохранённый хост используется со своими учётными данными (аналог ssh -J)."
                    })
                    .text_xs()
                    .text_color(muted),
                )
                .when(available.is_empty(), |this| {
                    this.child(h_flex().child(
                        Button::new("chain-go-proxies")
                            .ghost()
                            .xsmall()
                            .icon(Icon::new(IconName::Plus))
                            .label("Добавить прокси-сервер")
                            .tooltip("Звеном цепочки может быть SOCKS-прокси или другой сохранённый хост.")
                            .on_click(cx.listener(|this, _, _window, cx| this.go(Section::Proxies, cx))),
                    ))
                })
                .when(!available.is_empty(), |this| {
                    this.child(
                        h_flex()
                            .flex_wrap()
                            .items_center()
                            .gap_1()
                            .child(Label::new("Добавить звено:").text_xs().text_color(muted))
                            .children(available.into_iter().map(|(id, title)| {
                                Button::new(SharedString::from(format!("chain-add-{id}")))
                                    .ghost()
                                    .xsmall()
                                    .icon(Icon::new(IconName::Plus))
                                    .label(SharedString::from(shorten(&title, ROW_TITLE_CHARS)))
                                    .tooltip("Добавить звено перед целевым сервером")
                                    .on_click(cx.listener(move |this, _, _window, cx| {
                                        this.chain_push(id.clone(), cx)
                                    }))
                            })),
                    )
                })
                .into_any_element(),
        )
    }

    pub(super) fn proxies_page(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let muted = theme.muted_foreground;
        let Some(unlocked) = self.current_unlocked() else {
            return div().into_any_element();
        };
        let proxies = unlocked.proxies();

        let header = h_flex()
            .px_6()
            .pt_5()
            .pb_3()
            .justify_between()
            .items_center()
            .child(Label::new("Прокси").text_xl().font_semibold())
            .child(
                Button::new("new-proxy")
                    .primary()
                    .icon(Icon::new(IconName::Plus))
                    .label("Новый прокси")
                    .on_click(cx.listener(|this, _, window, cx| this.proxy_new(window, cx))),
            );

        let cards: Vec<AnyElement> = proxies
            .into_iter()
            .map(|entry| {
                let edit_id = entry.id.clone();
                let used_by = unlocked.hosts_via(&entry.id).len();
                let unsupported = entry.proxy.kind == ProxyKind::Unsupported;
                let usage = match used_by {
                    0 => "Не используется".to_string(),
                    count => format!("Используется в цепочках: {count}"),
                };
                v_flex()
                    .id(SharedString::from(format!("proxy-card-{}", entry.id)))
                    .w(px(280.))
                    .p_3()
                    .gap_1()
                    .rounded_lg()
                    .border_1()
                    .border_color(theme.border)
                    .bg(theme.secondary)
                    .hover(|style| style.bg(theme.secondary_hover))
                    .child(
                        h_flex()
                            .gap_2()
                            .items_center()
                            .child(
                                Icon::empty()
                                    .path("icons/route.svg")
                                    .small()
                                    .text_color(theme.primary),
                            )
                            .child(
                                Label::new(SharedString::from(shorten(
                                    &entry.proxy.title(),
                                    ROW_TITLE_CHARS,
                                )))
                                .font_semibold(),
                            ),
                    )
                    .child(
                        Label::new(SharedString::from(shorten(&entry.proxy.summary(), 40)))
                            .text_xs()
                            .text_color(if unsupported { theme.warning } else { muted }),
                    )
                    .child(
                        Label::new(SharedString::from(usage))
                            .text_xs()
                            .text_color(muted),
                    )
                    .when(!unsupported, |this| {
                        this.on_click(cx.listener(move |this, _, window, cx| {
                            this.proxy_edit(&edit_id, window, cx)
                        }))
                    })
                    .into_any_element()
            })
            .collect();
        let empty = cards.is_empty();

        div()
            .relative()
            .size_full()
            .child(
                v_flex().size_full().child(header).children(self.vault_picker(cx)).child(
                    v_flex()
                        .id("proxies-grid")
                        .flex_grow_1()
                        .min_h(px(0.))
                        .overflow_y_scrollbar()
                        .px_6()
                        .pb_6()
                        .gap_3()
                        .child(
                            Label::new(
                                "Прокси-серверы задаются здесь и подключаются к хосту в разделе «Маршрут» его настроек.",
                            )
                            .text_sm()
                            .text_color(muted),
                        )
                        .when(empty, |this| {
                            this.child(
                                v_flex()
                                    .py_10()
                                    .items_center()
                                    .gap_2()
                                    .child(
                                        Icon::empty()
                                            .path("icons/route.svg")
                                            .size(px(36.))
                                            .text_color(muted),
                                    )
                                    .child(Label::new("Прокси-серверы не добавлены"))
                                    .child(
                                        Label::new(
                                            "Нажмите «Новый прокси», чтобы добавить SOCKS5-прокси.",
                                        )
                                        .text_sm()
                                        .text_color(muted),
                                    ),
                            )
                        })
                        .child(h_flex().flex_wrap().gap_3().children(cards)),
                ),
            )
            .when(self.proxy_form.open, |this| {
                this.child(self.proxy_drawer(cx))
            })
            .into_any_element()
    }

    fn proxy_drawer(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let muted = theme.muted_foreground;
        let editing = self.proxy_form.editing.as_ref().and_then(|id| {
            self.current_unlocked()
                .and_then(|unlocked| unlocked.proxy(id))
        });
        let has_password = editing
            .as_ref()
            .is_some_and(|entry| entry.proxy.password().is_some());
        let used_by: Vec<String> = editing
            .as_ref()
            .and_then(|entry| {
                self.current_unlocked().map(|unlocked| {
                    unlocked
                        .hosts_via(&entry.id)
                        .into_iter()
                        .map(|h| h.host.title())
                        .collect()
                })
            })
            .unwrap_or_default();
        let remove_id = editing.as_ref().map(|entry| entry.id.clone());
        let form = &self.proxy_form;

        let field = |label: &'static str, input: &Entity<InputState>| {
            v_flex()
                .gap_1()
                .child(Self::field_label(label, muted))
                .child(Input::new(input))
        };

        div()
            .absolute()
            .occlude()
            .top_0()
            .right_0()
            .h_full()
            .w(px(420.))
            .max_w_full()
            .bg(crate::ui::theme::solid_background(cx))
            .border_l_1()
            .border_color(theme.border)
            .shadow_lg()
            .child(
                v_flex()
                    .size_full()
                    .child(
                        h_flex()
                            .px_4()
                            .py_3()
                            .justify_between()
                            .items_center()
                            .border_b_1()
                            .border_color(theme.border)
                            .child(
                                Label::new(if editing.is_some() {
                                    "Изменить прокси"
                                } else {
                                    "Новый прокси"
                                })
                                .text_lg()
                                .font_semibold(),
                            )
                            .child(
                                Button::new("proxy-close")
                                    .ghost()
                                    .small()
                                    .icon(Icon::new(IconName::Close))
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.proxy_clear(window, cx)
                                    })),
                            ),
                    )
                    .child(
                        v_flex()
                            .id("proxy-editor-body")
                            .flex_grow_1()
                            .min_h(px(0.))
                            .overflow_y_scrollbar()
                            .px_4()
                            .py_3()
                            .gap_3()
                            .child(
                                Label::new("Протокол SOCKS5. Имена хостов разрешаются на стороне прокси-сервера.")
                                    .text_xs()
                                    .text_color(muted),
                            )
                            .child(field("Название", &form.label))
                            .child(
                                h_flex()
                                    .gap_2()
                                    .items_end()
                                    .child(div().flex_grow_1().child(field("Адрес", &form.host)))
                                    .child(div().w(px(80.)).child(field("Порт", &form.port))),
                            )
                            .child(field("Имя пользователя", &form.user))
                            .child(
                                v_flex()
                                    .gap_1()
                                    .child(field("Пароль", &form.password))
                                    .child(
                                        Label::new(if has_password {
                                            "Пароль сохранён. Оставьте поле пустым, чтобы не изменять его."
                                        } else {
                                            "Требуется, только если указано имя пользователя."
                                        })
                                        .text_xs()
                                        .text_color(muted),
                                    ),
                            )
                            .when(has_password, |this| {
                                this.child(
                                    Button::new("proxy-forget-password")
                                        .ghost()
                                        .small()
                                        .label("Удалить сохранённый пароль")
                                        .on_click(cx.listener(|this, _, _window, cx| {
                                            this.proxy_forget_password(cx)
                                        })),
                                )
                            })
                            .when(!used_by.is_empty(), |this| {
                                this.child(
                                    Label::new(SharedString::from(format!(
                                        "Используется в цепочках: {}",
                                        used_by.join(", ")
                                    )))
                                    .text_xs()
                                    .text_color(muted),
                                )
                            })
                            .children(
                                self.error.clone().map(|error| {
                                    Label::new(error).text_sm().text_color(theme.danger)
                                }),
                            ),
                    )
                    .child(
                        h_flex()
                            .px_4()
                            .py_3()
                            .gap_2()
                            .border_t_1()
                            .border_color(theme.border)
                            .child(
                                Button::new("proxy-save")
                                    .primary()
                                    .label("Сохранить")
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.proxy_save(window, cx)
                                    })),
                            )
                            .child(div().flex_grow_1())
                            .children(remove_id.map(|id| {
                                Button::new("proxy-remove")
                                    .ghost()
                                    .icon(Icon::new(IconName::Delete))
                                    .label("Удалить")
                                    .disabled(!used_by.is_empty())
                                    .tooltip(if used_by.is_empty() {
                                        "Удалить из хранилища"
                                    } else {
                                        "Прокси используется в цепочках хостов. Сначала удалите его из них."
                                    })
                                    .on_click(cx.listener(move |this, _, window, cx| {
                                        this.proxy_remove(&id, window, cx)
                                    }))
                            })),
                    ),
            )
            .into_any_element()
    }
}
