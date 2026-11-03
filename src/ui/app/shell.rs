use super::*;

impl AppView {
    pub(super) fn go(&mut self, section: Section, cx: &mut Context<Self>) {
        self.section = section;
        self.showing_page = true;
        cx.notify();
    }

    pub(super) fn workspace(&self, cx: &mut Context<Self>) -> AnyElement {
        let solid = crate::ui::theme::solid_background(cx);
        let content = match self.active {
            Some(index) if !self.showing_page => {
                let tab = &self.tabs[index];
                match &tab.kind {
                    TabKind::Terminal {
                        editor: Some(editor),
                        ..
                    } if editor.expanded => div()
                        .size_full()
                        .bg(solid)
                        .child(editor.view.clone())
                        .into_any_element(),
                    TabKind::Terminal { editor, split, .. } => {
                        let closed = tab.is_closed(cx);
                        let reconnect = closed.then(|| self.reconnect_bar(index, cx));
                        let theme = cx.theme().clone();
                        v_flex()
                            .size_full()
                            .children(reconnect)
                            .child(
                                h_flex()
                                    .h(px(36.))
                                    .flex_shrink_0()
                                    .px_3()
                                    .gap_1()
                                    .items_center()
                                    .border_b_1()
                                    .border_color(theme.border)
                                    .child(div().flex_1())
                                    .when(!split.panes.is_empty(), |this| {
                                        let on = split.broadcast;
                                        this.child(
                                            Button::new("toggle-broadcast")
                                                .small()
                                                .when(on, |button| button.danger())
                                                .when(!on, |button| button.ghost())
                                                .icon(Icon::empty().path("icons/monitor.svg"))
                                                .label(if on { "Ввод во все панели: вкл." } else { "Ввод во все панели" })
                                                .tooltip("Ввод с клавиатуры передаётся во все панели вкладки")
                                                .on_click(cx.listener(move |this, _, _window, cx| {
                                                    this.toggle_broadcast(index, cx)
                                                })),
                                        )
                                    })
                                    .child(
                                        Button::new("toggle-snippets")
                                            .ghost()
                                            .small()
                                            .selected(self.snippets_open)
                                            .icon(Icon::empty().path("icons/square-terminal.svg"))
                                            .label("Сниппеты")
                                            .disabled(closed)
                                            .on_click(cx.listener(|this, _, _window, cx| {
                                                this.snippets_open = !this.snippets_open;
                                                this.split_menu = false;
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        Button::new("toggle-split")
                                            .ghost()
                                            .small()
                                            .selected(self.split_menu)
                                            .icon(Icon::empty().path("icons/panel-left-open.svg"))
                                            .label("Разделить")
                                            .on_click(cx.listener(|this, _, _window, cx| {
                                                this.split_menu = !this.split_menu;
                                                this.snippets_open = false;
                                                cx.notify();
                                            })),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_row()
                                    .flex_grow()
                                    .min_h(px(0.))
                                    .child(
                                        div()
                                            .flex()
                                            .flex_1()
                                            .min_w(px(240.))
                                            .h_full()
                                            .child(self.pane_group(index, cx)),
                                    )
                                    .when(editor.is_some(), |this| {
                                        this.child(self.edge_handle("edge-editor", Edge::Editor, cx))
                                    })
                                    .children(editor.as_ref().map(|editor| {
                                        div()
                                            .w(px(self.settings.editor_width))
                                            .min_w(px(*settings::EDITOR_WIDTH.start()))
                                            .h_full()
                                            .border_l_1()
                                            .border_color(theme.border)
                                            .bg(solid)
                                            .child(editor.view.clone())
                                    })),
                            )
                            .into_any_element()
                    }
                    TabKind::Files { view, .. } => div()
                        .size_full()
                        .bg(solid)
                        .child(view.clone())
                        .into_any_element(),
                    TabKind::Editor { view, .. } => div()
                        .size_full()
                        .bg(solid)
                        .child(view.clone())
                        .into_any_element(),
                }
            }
            _ => div()
                .size_full()
                .bg(solid)
                .child(self.page(cx))
                .into_any_element(),
        };

        v_flex()
            .size_full()
            .child(
                div()
                    .flex_grow()
                    .min_h(px(0.))
                    .overflow_hidden()
                    .child(content),
            )
            .into_any_element()
    }

    fn page(&self, cx: &mut Context<Self>) -> AnyElement {
        let locked = self.stage.is_some();
        match self.section {
            Section::Hosts => self.hosts_page(cx),
            Section::Keys if locked => self.vault_screen(cx),
            Section::Keys => self.keys_page(cx),
            Section::Proxies if locked => self.vault_screen(cx),
            Section::Proxies => self.proxies_page(cx),
            Section::Snippets if locked => self.vault_screen(cx),
            Section::Snippets => self.snippets_page(cx),
            Section::Settings => self.settings_page(cx),
        }
    }

    fn page_frame(
        title: &'static str,
        actions: Option<AnyElement>,
        body: AnyElement,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = cx.theme().clone();
        v_flex()
            .size_full()
            .child(
                h_flex()
                    .px_6()
                    .pt_5()
                    .pb_3()
                    .justify_between()
                    .items_center()
                    .child(Label::new(title).text_xl().font_semibold())
                    .children(actions),
            )
            .child(
                div()
                    .id(SharedString::from(format!("page-{title}")))
                    .flex_grow()
                    .min_h(px(0.))
                    .overflow_y_scrollbar()
                    .px_6()
                    .pb_6()
                    .child(
                        div()
                            .max_w(px(720.))
                            .rounded_lg()
                            .border_1()
                            .border_color(theme.border)
                            .bg(theme.secondary)
                            .overflow_hidden()
                            .child(body),
                    ),
            )
            .into_any_element()
    }

    fn vault_screen(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        v_flex()
            .size_full()
            .items_center()
            .justify_center()
            .p_6()
            .child(
                v_flex()
                    .w(px(460.))
                    .max_w_full()
                    .py_3()
                    .rounded_xl()
                    .border_1()
                    .border_color(theme.border)
                    .bg(theme.secondary)
                    .child(self.vault_panel(cx)),
            )
            .into_any_element()
    }

    pub(super) fn quick_connect(&mut self, cx: &mut Context<Self>) {
        let raw = self.form.line.read(cx).value().trim().to_string();
        if raw.is_empty() {
            self.error = Some("Введите адрес в формате пользователь@хост:порт.".into());
            cx.notify();
            return;
        }
        self.open(&raw, &connect::Credentials::default(), cx);
    }

    fn quick_files(&mut self, cx: &mut Context<Self>) {
        let raw = self.form.line.read(cx).value().trim().to_string();
        if raw.is_empty() {
            self.error = Some("Введите адрес в формате пользователь@хост:порт.".into());
            cx.notify();
            return;
        }
        self.open_files(&raw, connect::Credentials::default(), cx);
    }

    pub(super) fn new_host(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        for input in [
            &self.form.label,
            &self.form.host,
            &self.form.port,
            &self.form.user,
            &self.form.password,
            &self.form.key_path,
        ] {
            input.update(cx, |state, cx| state.set_value("", window, cx));
        }
        self.form.editing = None;
        self.form.auth = HostAuth::Auto;
        self.form.via.clear();
        self.form.forwards.clear();
        self.section = Section::Hosts;
        self.showing_page = true;
        self.editor_open = true;
        self.error = None;
        cx.notify();
    }

    fn close_editor(&mut self, cx: &mut Context<Self>) {
        self.editor_open = false;
        self.error = None;
        cx.notify();
    }

    fn hosts_page(&self, cx: &mut Context<Self>) -> AnyElement {
        if self.editor_open {
            return self.editor_drawer(cx);
        }
        if self.stage.is_some() {
            return self.vault_screen(cx);
        }
        let theme = cx.theme().clone();

        let action = |id: &'static str, icon: Icon, label: &'static str, hint: &'static str| {
            h_flex()
                .id(id)
                .h(px(32.))
                .px_2()
                .gap_3()
                .items_center()
                .rounded(px(7.))
                .hover(|style| style.bg(theme.secondary_hover))
                .child(icon.small().text_color(theme.muted_foreground))
                .child(Label::new(label).text_sm().flex_grow())
                .child(
                    Label::new(hint)
                        .text_xs()
                        .text_color(theme.muted_foreground),
                )
        };

        v_flex()
            .size_full()
            .items_center()
            .justify_center()
            .p_6()
            .child(
                v_flex()
                    .w(px(360.))
                    .max_w_full()
                    .gap_4()
                    .child(
                        h_flex()
                            .gap_3()
                            .items_center()
                            .child(img("brand/cratty.svg").size(px(40.)))
                            .child(
                                v_flex()
                                    .child(Label::new("cratty").text_lg().font_semibold())
                                    .child(
                                        Label::new("SSH-клиент")
                                            .text_xs()
                                            .text_color(theme.muted_foreground),
                                    ),
                            ),
                    )
                    .child(
                        Label::new(
                            "Выберите хост в списке слева или введите адрес в формате user@host:port и нажмите Enter.",
                        )
                        .text_sm()
                        .text_color(theme.muted_foreground),
                    )
                    .child(
                        v_flex()
                            .gap_px()
                            .child(
                                action(
                                    "home-new-host",
                                    Icon::new(IconName::Plus),
                                    "Новый хост",
                                    "Сохранить подключение",
                                )
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.new_host(window, cx)
                                })),
                            )
                            .child(
                                action(
                                    "home-files",
                                    Icon::empty().path("icons/folder.svg"),
                                    "Открыть файлы по адресу",
                                    "SFTP",
                                )
                                .on_click(cx.listener(|this, _, _window, cx| this.quick_files(cx))),
                            )
                            .child(
                                action(
                                    "home-proxies",
                                    Icon::empty().path("icons/route.svg"),
                                    "Прокси-серверы",
                                    "Цепочки подключений",
                                )
                                .on_click(cx.listener(|this, _, _window, cx| {
                                    this.go(Section::Proxies, cx)
                                })),
                            )
                            .child(
                                action(
                                    "home-keys",
                                    Icon::empty().path("icons/key-round.svg"),
                                    "Ключи",
                                    "SSH-агент и импорт",
                                )
                                .on_click(cx.listener(|this, _, _window, cx| {
                                    this.go(Section::Keys, cx)
                                })),
                            ),
                    )
                    .children(
                        self.error
                            .clone()
                            .map(|error| Label::new(error).text_sm().text_color(theme.danger)),
                    ),
            )
            .into_any_element()
    }

    pub(super) fn saved_credentials(&self, target: &str) -> connect::Credentials {
        self.vault
            .unlocked()
            .and_then(|unlocked| unlocked.find_by_target(target))
            .map(|entry| {
                let (via, proxy_error) = self.resolve_chain(&entry.host.via);
                connect::Credentials {
                    auth: entry.host.auth.clone(),
                    password: None,
                    stored: entry.host.password().cloned(),
                    via,
                    proxy_error,
                    forward_agent: entry.host.forward_agent,
                    forwards: entry.host.forwards.clone(),
                }
            })
            .unwrap_or_default()
    }

    fn editor_drawer(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let existing = self.form.editing.clone();
        let editing = existing.is_some();

        let form_fields = self.form_fields(cx);
        let auth_switch = self.auth_switch(cx);
        let auth_fields = self.auth_fields(cx);

        div()
            .size_full()
            .flex()
            .justify_center()
            .child(
                v_flex()
                    .h_full()
                    .w(px(620.))
                    .max_w_full()
                    .child(
                        h_flex()
                            .px_4()
                            .py_3()
                            .justify_between()
                            .items_center()
                            .border_b_1()
                            .border_color(theme.border)
                            .child(
                                Label::new(if editing {
                                    "Изменить хост"
                                } else {
                                    "Новый хост"
                                })
                                .text_lg()
                                .font_semibold(),
                            )
                            .child(
                                Button::new("editor-close")
                                    .ghost()
                                    .small()
                                    .icon(Icon::new(IconName::Close))
                                    .on_click(
                                        cx.listener(|this, _, _window, cx| this.close_editor(cx)),
                                    ),
                            ),
                    )
                    .child(
                        v_flex()
                            .id("editor-body")
                            .flex_grow()
                            .min_h(px(0.))
                            .overflow_y_scrollbar()
                            .px_4()
                            .py_3()
                            .gap_3()
                            .child(Label::new("Сервер").text_sm().font_semibold())
                            .child(form_fields)
                            .child(Self::drawer_group(
                                "Аутентификация",
                                v_flex().gap_2().child(auth_switch).child(auth_fields),
                                cx,
                            ))
                            .children(
                                self.chain_block(cx)
                                    .map(|block| Self::drawer_group("Маршрут", block, cx)),
                            )
                            .children(
                                self.forwards_block(cx).map(|block| {
                                    Self::drawer_group("Переадресация портов", block, cx)
                                }),
                            )
                            .children(self.stored_rejected_notice(cx))
                            .children(
                                self.record_controls(cx)
                                    .map(|block| Self::drawer_group("Параметры записи", block, cx)),
                            )
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
                                Button::new("editor-save")
                                    .primary()
                                    .label("Сохранить")
                                    .on_click(
                                        cx.listener(|this, _, _window, cx| this.save_current(cx)),
                                    ),
                            )
                            .child(
                                Button::new("editor-connect")
                                    .outline()
                                    .label("Подключиться")
                                    .on_click(cx.listener(|this, _, _window, cx| {
                                        this.connect_from_form(cx);
                                        if this.error.is_none() {
                                            this.editor_open = false;
                                        }
                                    })),
                            )
                            .child(div().flex_grow())
                            .children(existing.map(|target| {
                                Button::new("editor-delete")
                                    .ghost()
                                    .icon(Icon::new(IconName::Delete))
                                    .label("Удалить")
                                    .on_click(cx.listener(move |this, _, _window, cx| {
                                        this.forget(&target, cx);
                                        if this.error.is_none() {
                                            this.editor_open = false;
                                        }
                                    }))
                            })),
                    ),
            )
            .into_any_element()
    }

    fn settings_page(&self, cx: &mut Context<Self>) -> AnyElement {
        let tabs = [
            (SettingsTab::General, "Общие"),
            (SettingsTab::Security, "Безопасность"),
            (SettingsTab::Sync, "Синхронизация"),
        ];
        let current = self.settings_tab;
        let nav = h_flex()
            .gap_1()
            .children(tabs.into_iter().map(|(tab, label)| {
                Button::new(SharedString::from(format!("settings-{label}")))
                    .ghost()
                    .small()
                    .selected(current == tab)
                    .label(label)
                    .on_click(cx.listener(move |this, _, _window, cx| {
                        this.settings_tab = tab;
                        cx.notify();
                    }))
            }));
        let body = self.settings_panel(current, cx);
        Self::page_frame("Настройки", Some(nav.into_any_element()), body, cx)
    }
}
