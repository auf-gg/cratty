use super::*;
use std::borrow::Cow;

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
                            .when(!split.panes.is_empty(), |this| this.child(
                                h_flex()
                                    .h(px(36.))
                                    .flex_shrink_0()
                                    .px_3()
                                    .gap_1()
                                    .items_center()
                                    .border_b_1()
                                    .border_color(theme.border)
                                    .child(div().flex_1())
                                    .child({
                                        let on = split.broadcast;
                                        Button::new("toggle-broadcast")
                                            .small()
                                            .when(on, |button| button.danger())
                                            .when(!on, |button| button.ghost())
                                            .icon(Icon::empty().path("icons/monitor.svg"))
                                            .label(if on { t!("shell.broadcast_on") } else { t!("shell.broadcast") })
                                            .tooltip(t!("shell.broadcast_tip"))
                                            .on_click(cx.listener(move |this, _, _window, cx| {
                                                this.toggle_broadcast(index, cx)
                                            }))
                                    }),
                            ))
                            .child(
                                div()
                                    .relative()
                                    .flex()
                                    .flex_row()
                                    .flex_grow_1()
                                    .min_h(px(0.))
                                    .child(
                                        div()
                                            .flex()
                                            .flex_1()
                                            .min_w(px(240.))
                                            .h_full()
                                            .child(self.pane_group(index, cx)),
                                    )
                                    .children(editor.as_ref().map(|editor| {
                                        div()
                                            .w(px(self.settings.editor_width))
                                            .min_w(px(*settings::EDITOR_WIDTH.start()))
                                            .h_full()
                                            .border_l_1()
                                            .border_color(theme.border)
                                            .bg(solid)
                                            .child(editor.view.clone())
                                    }))
                                    .when(editor.is_some(), |this| {
                                        this.child(self.edge_handle(
                                            "edge-editor",
                                            Edge::Editor,
                                            self.settings.editor_width,
                                            cx,
                                        ))
                                    }),
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
                    .flex_grow_1()
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
        title: impl Into<SharedString>,
        actions: Option<AnyElement>,
        body: AnyElement,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let title: SharedString = title.into();
        let theme = cx.theme().clone();
        // The header with tabs and the content block share one width, centered.
        const WIDTH: f32 = 720.;
        v_flex()
            .size_full()
            .items_center()
            .child(
                h_flex()
                    .w_full()
                    .max_w(px(WIDTH + 48.))
                    .px_6()
                    .pt_5()
                    .pb_3()
                    .justify_between()
                    .items_center()
                    .child(Label::new(title.clone()).text_xl().font_semibold())
                    .children(actions),
            )
            .child(
                v_flex()
                    .id(SharedString::from(format!("page-{title}")))
                    .w_full()
                    .flex_grow_1()
                    .min_h(px(0.))
                    .overflow_y_scrollbar()
                    .items_center()
                    .px_6()
                    .pb_6()
                    .child(
                        div()
                            .w_full()
                            .max_w(px(WIDTH))
                            .flex_shrink_0()
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
            .gap_3()
            .p_6()
            .children(self.vault_picker(cx))
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
            self.error = Some(t!("shell.enter_address").into());
            cx.notify();
            return;
        }
        self.open(&raw, &connect::Credentials::default(), None, cx);
    }

    fn quick_files(&mut self, cx: &mut Context<Self>) {
        let raw = self.form.line.read(cx).value().trim().to_string();
        if raw.is_empty() {
            self.error = Some(t!("shell.enter_address").into());
            cx.notify();
            return;
        }
        self.open_files(&raw, connect::Credentials::default(), None, cx);
    }

    pub(super) fn new_host(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.key_notice = None;
        for input in [
            &self.form.label,
            &self.form.group,
            &self.form.host,
            &self.form.port,
            &self.form.user,
            &self.form.password,
            &self.form.key_path,
        ] {
            input.update(cx, |state, cx| state.set_value("", window, cx));
        }
        self.form.vault = if self.vault().state().is_unlocked() {
            self.current_id()
        } else {
            self.unlocked_slots()
                .next()
                .map(|slot| slot.id.clone())
                .unwrap_or_else(|| self.current_id())
        };
        self.form.editing = None;
        self.form.auth = HostAuth::Auto;
        self.form.via.clear();
        self.form.forwards.clear();
        self.form.icon.clear();
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

        let action = |id: &'static str, icon: Icon, label: Cow<'static, str>, hint: Cow<'static, str>| {
            h_flex()
                .id(id)
                .h(px(32.))
                .px_2()
                .gap_3()
                .items_center()
                .rounded(px(7.))
                .hover(|style| style.bg(theme.secondary_hover))
                .child(icon.small().text_color(theme.muted_foreground))
                .child(Label::new(label).text_sm().flex_grow_1())
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
                                        Label::new(t!("shell.ssh_client"))
                                            .text_xs()
                                            .text_color(theme.muted_foreground),
                                    ),
                            ),
                    )
                    .child(
                        Label::new(t!("shell.home_intro"))
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
                                    t!("shell.home_new_host"),
                                    t!("shell.home_new_host_hint"),
                                )
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.new_host(window, cx)
                                })),
                            )
                            .child(
                                action(
                                    "home-files",
                                    Icon::empty().path("icons/folder.svg"),
                                    t!("shell.home_files"),
                                    "SFTP".into(),
                                )
                                .on_click(cx.listener(|this, _, _window, cx| this.quick_files(cx))),
                            )
                            .child(
                                action(
                                    "home-proxies",
                                    Icon::empty().path("icons/route.svg"),
                                    t!("shell.home_proxies"),
                                    t!("shell.home_proxies_hint"),
                                )
                                .on_click(cx.listener(|this, _, _window, cx| {
                                    this.go(Section::Proxies, cx)
                                })),
                            )
                            .child(
                                action(
                                    "home-keys",
                                    Icon::empty().path("icons/key-round.svg"),
                                    t!("shell.home_keys"),
                                    t!("shell.home_keys_hint"),
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

    pub(super) fn saved_credentials(&self, vault: &str, target: &str) -> connect::Credentials {
        self.unlocked_of(vault)
            .and_then(|unlocked| unlocked.find_by_target(target))
            .map(|entry| {
                let (via, proxy_error) = self.resolve_chain(vault, &entry.host.via);
                connect::Credentials {
                    auth: entry.host.auth.clone(),
                    password: None,
                    stored: entry.host.password().cloned(),
                    via,
                    proxy_error,
                    forward_agent: entry.host.forward_agent,
                    forwards: entry.host.forwards.clone(),
                    command: None,
                }
            })
            .unwrap_or_default()
    }

    fn form_vault_block(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let muted = cx.theme().muted_foreground;
        let unlocked: Vec<(String, String)> = self
            .unlocked_slots()
            .map(|slot| (slot.id.clone(), slot.name.clone()))
            .collect();
        if unlocked.len() < 2 && self.listed().count() < 2 {
            return None;
        }

        let editing = self.form.editing.is_some();
        Some(
            v_flex()
                .gap_1()
                .child(Self::field_label(t!("shell.field_vault"), muted))
                .child(if editing {
                    Label::new(SharedString::from(self.vault_name(&self.form.vault)))
                        .text_sm()
                        .into_any_element()
                } else {
                    h_flex()
                        .gap_1()
                        .flex_wrap()
                        .children(unlocked.into_iter().map(|(id, name)| {
                            let selected = self.form.vault == id;
                            let pick = id.clone();
                            Button::new(SharedString::from(format!("form-vault-{id}")))
                                .ghost()
                                .small()
                                .selected(selected)
                                .label(SharedString::from(shorten(&name, ROW_TITLE_CHARS)))
                                .on_click(cx.listener(move |this, _, _window, cx| {
                                    this.form.via.clear();
                                    this.form.vault = pick.clone();
                                    cx.notify();
                                }))
                        }))
                        .into_any_element()
                })
                .into_any_element(),
        )
    }

    fn editor_drawer(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let existing = self.form.editing.clone();
        let editing = existing.is_some();

        let vault_pick = self.form_vault_block(cx);
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
                                    t!("shell.edit_host")
                                } else {
                                    t!("shell.new_host")
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
                            .flex_grow_1()
                            .min_h(px(0.))
                            .overflow_y_scrollbar()
                            .px_4()
                            .py_3()
                            .gap_3()
                            .children(vault_pick)
                            .child(Label::new(t!("shell.server")).text_sm().font_semibold())
                            .child(form_fields)
                            .child(Self::drawer_group(
                                t!("shell.authentication"),
                                v_flex().gap_2().child(auth_switch).child(auth_fields),
                                cx,
                            ))
                            .children(
                                self.chain_block(cx)
                                    .map(|block| Self::drawer_group(t!("shell.route"), block, cx)),
                            )
                            .children(
                                self.forwards_block(cx).map(|block| {
                                    Self::drawer_group(t!("shell.port_forwarding"), block, cx)
                                }),
                            )
                            .children(self.stored_rejected_notice(cx))
                            .children(
                                self.record_controls(cx)
                                    .map(|block| Self::drawer_group(t!("shell.entry_options"), block, cx)),
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
                                    .label(t!("shell.save"))
                                    .on_click(
                                        cx.listener(|this, _, window, cx| this.save_current(window, cx)),
                                    ),
                            )
                            .child(
                                Button::new("editor-connect")
                                    .outline()
                                    .label(t!("shell.connect"))
                                    .on_click(cx.listener(|this, _, _window, cx| {
                                        this.connect_from_form(cx);
                                        if this.error.is_none() {
                                            this.editor_open = false;
                                        }
                                    })),
                            )
                            .child(div().flex_grow_1())
                            .children(existing.map(|target| {
                                let vault = self.form.vault.clone();
                                Button::new("editor-delete")
                                    .ghost()
                                    .icon(Icon::new(IconName::Delete))
                                    .label(t!("shell.delete"))
                                    .on_click(cx.listener(move |this, _, _window, cx| {
                                        this.forget(&vault, &target, cx);
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
            (SettingsTab::General, t!("shell.tab_general")),
            (SettingsTab::Security, t!("shell.tab_security")),
            (SettingsTab::Sync, t!("shell.tab_sync")),
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
        Self::page_frame(t!("shell.settings"), Some(nav.into_any_element()), body, cx)
    }
}
