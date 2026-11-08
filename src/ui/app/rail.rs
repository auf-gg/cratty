use super::*;
use gpui_kit::component::menu::{ContextMenuExt as _, PopupMenuItem};

impl AppView {
    pub(super) fn rail(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let theme = cx.theme().clone();
        let locked = !self.any_unlocked();
        let query = self.form.line.read(cx).value().trim().to_string();

        let sessions: Vec<AnyElement> = self
            .tabs
            .iter()
            .enumerate()
            .map(|(index, tab)| self.session_row(index, tab, cx))
            .collect();

        let vault_groups: Vec<AnyElement> = self
            .listed()
            .map(|(ix, _)| ix)
            .collect::<Vec<_>>()
            .into_iter()
            .map(|ix| self.vault_group(ix, &query, cx))
            .collect();

        let looks_like_address = !query.is_empty() && connect::parse_target(&query).is_ok();

        Some(
            v_flex()
                .w(px(self.settings.rail_width))
                .h_full()
                .flex_shrink_0()
                .bg(theme.sidebar)
                .border_r_1()
                .border_color(theme.border)
                .child(
                    h_flex()
                        .px_3()
                        .pt_3()
                        .pb_2()
                        .gap_1()
                        .items_center()
                        .child(div().flex_1().child(Input::new(&self.form.line).small()))
                        .child(
                            Button::new("rail-local-terminal")
                                .ghost()
                                .small()
                                .icon(Icon::empty().path("icons/square-terminal.svg"))
                                .tooltip(if cfg!(unix) {
                                    "Локальный терминал (без хранилища)"
                                } else {
                                    "Локальный терминал поддерживается только на Unix"
                                })
                                .disabled(!cfg!(unix))
                                .on_click(
                                    cx.listener(|this, _, _window, cx| this.spawn_local_tab(cx)),
                                ),
                        )
                        .child(
                            Button::new("rail-new-host")
                                .ghost()
                                .small()
                                .icon(Icon::new(IconName::Plus))
                                .tooltip(if locked {
                                    "Новый хост (требуется разблокировать хранилище)"
                                } else {
                                    "Новый хост"
                                })
                                .disabled(locked)
                                .on_click(
                                    cx.listener(|this, _, window, cx| this.new_host(window, cx)),
                                ),
                        )
                        .child(self.pin_button(Edge::Rail, cx)),
                )
                .child(
                    v_flex()
                        .id("rail-scroll")
                        .flex_grow_1()
                        .min_h(px(0.))
                        .overflow_y_scrollbar()
                        .px_2()
                        .pb_2()
                        .gap_4()
                        .when(looks_like_address, |this| {
                            this.child(self.rail_group(
                                "Подключиться",
                                vec![self.address_row(&query, cx)],
                                cx,
                            ))
                        })
                        .when(!sessions.is_empty(), |this| {
                            this.child(self.rail_group("Сеансы", sessions, cx))
                        })
                        .children(self.import_notice_box(cx))
                        .children(vault_groups)
                        .child(self.new_vault_row(cx)),
                )
                .child(self.rail_footer(cx))
                .into_any_element(),
        )
    }

    fn vault_group(&self, ix: usize, query: &str, cx: &mut Context<Self>) -> AnyElement {
        let slot = &self.vaults[ix];
        let id = slot.id.clone();
        let rows: Vec<AnyElement> = match slot.session.unlocked() {
            None => vec![self.locked_row(ix, cx)],
            Some(unlocked) => {
                let saved: Vec<HostRecord> = unlocked
                    .hosts()
                    .into_iter()
                    .map(|entry| entry.host)
                    .filter(|host| host.matches(query))
                    .collect();
                if saved.is_empty() {
                    vec![self.empty_row(
                        if query.is_empty() {
                            "Хосты не добавлены"
                        } else {
                            "Ничего не нашлось"
                        },
                        cx,
                    )]
                } else {
                    let mut rows = Vec::new();
                    // Сначала группы по алфавиту, за ними хосты без группы.
                    for group in unlocked.groups() {
                        let key = proto::GroupRecord::key(&group.name);
                        let members: Vec<&HostRecord> = saved
                            .iter()
                            .filter(|host| proto::GroupRecord::key(&host.group) == key)
                            .collect();
                        if members.is_empty() {
                            continue;
                        }
                        // При поиске группы раскрыты: иначе найденное не видно.
                        let collapsed =
                            query.is_empty() && self.is_group_collapsed(&id, &group.name);
                        rows.push(self.group_row(&id, &group, members.len(), collapsed, cx));
                        if !collapsed {
                            rows.extend(
                                members
                                    .into_iter()
                                    .map(|host| self.saved_row(&id, host.clone(), true, cx)),
                            );
                        }
                    }
                    rows.extend(
                        saved
                            .iter()
                            .filter(|host| host.group.trim().is_empty())
                            .map(|host| self.saved_row(&id, host.clone(), false, cx)),
                    );
                    rows
                }
            }
        };

        v_flex()
            .gap_px()
            .child(self.vault_header(ix, cx))
            .children(rows)
            .into_any_element()
    }

    fn rail_group(&self, title: &'static str, rows: Vec<AnyElement>, cx: &App) -> AnyElement {
        v_flex()
            .gap_px()
            .child(
                div().h(px(22.)).px_2().flex().items_center().child(
                    Label::new(title)
                        .text_xs()
                        .font_medium()
                        .text_color(cx.theme().muted_foreground),
                ),
            )
            .children(rows)
            .into_any_element()
    }

    pub(super) fn rail_row(
        id: SharedString,
        selected: bool,
        cx: &App,
    ) -> gpui_kit::Stateful<gpui_kit::Div> {
        let theme = cx.theme();
        let (selected_bg, hover_bg) = (theme.secondary_active, theme.secondary_hover);
        h_flex()
            .id(id)
            .px_2()
            .gap_2()
            .items_center()
            .rounded(px(7.))
            .when(selected, |this| this.bg(selected_bg))
            .when(!selected, |this| {
                this.hover(move |style| style.bg(hover_bg))
            })
    }

    fn session_row(&self, index: usize, tab: &SessionTab, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let selected = !self.showing_page && self.active == Some(index);
        let marker = if tab.is_files() {
            Icon::empty()
                .path("icons/folder.svg")
                .small()
                .text_color(theme.muted_foreground)
                .into_any_element()
        } else if let Some(editor) = tab.editor() {
            if editor.read(cx).is_dirty() {
                Self::dot(theme.warning)
            } else {
                Icon::empty()
                    .path("icons/file.svg")
                    .small()
                    .text_color(theme.muted_foreground)
                    .into_any_element()
            }
        } else if tab.is_closed(cx) {
            Self::dot(theme.danger)
        } else if tab.terminal().is_some_and(|view| {
            matches!(
                view.read(cx).status(),
                crate::ui::terminal::Status::Connecting { .. }
            )
        }) {
            Self::dot(theme.warning)
        } else {
            Self::dot(theme.success)
        };

        Self::rail_row(
            SharedString::from(format!("rail-tab-{index}")),
            selected,
            cx,
        )
        .h(px(30.))
        .child(div().w(px(16.)).flex().justify_center().child(marker))
        .child(
            div().flex_1().min_w(px(0.)).overflow_hidden().child(
                Label::new(tab.title.clone())
                    .text_sm()
                    .when(selected, |this| this.font_medium())
                    .line_clamp(1)
                    .text_ellipsis(),
            ),
        )
        .child(
            Button::new(SharedString::from(format!("rail-close-{index}")))
                .ghost()
                .xsmall()
                .icon(Icon::new(IconName::Close))
                .tooltip("Закрыть")
                .on_click(cx.listener(move |this, _, _window, cx| {
                    cx.stop_propagation();
                    this.close_tab(index, cx)
                })),
        )
        .on_mouse_down(
            MouseButton::Middle,
            cx.listener(move |this, _, _window, cx| this.close_tab(index, cx)),
        )
        .on_click(cx.listener(move |this, _, _window, cx| this.select(index, cx)))
        .into_any_element()
    }

    pub(super) fn dot(color: gpui_kit::Hsla) -> AnyElement {
        div()
            .size(px(7.))
            .rounded_full()
            .bg(color)
            .into_any_element()
    }

    fn saved_row(
        &self,
        vault: &str,
        host: HostRecord,
        in_group: bool,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = cx.theme().clone();
        let target = host.target();
        let title = host.title();
        let view = cx.entity();
        let (vault, open_target) = (vault.to_owned(), target.clone());
        let menu_vault = vault.clone();
        let menu_target = target.clone();

        Self::rail_row(
            SharedString::from(format!("rail-host-{vault}-{target}")),
            false,
            cx,
        )
        .h(px(42.))
        .when(in_group, |this| this.pl(px(26.)))
        .child(self.icon_view(&vault, &host.icon, "server", px(20.), cx))
        .child(
            v_flex()
                .flex_1()
                .min_w(px(0.))
                .overflow_hidden()
                .child(
                    Label::new(SharedString::from(shorten(&title, ROW_TITLE_CHARS + 6)))
                        .text_sm()
                        .line_clamp(1)
                        .text_ellipsis(),
                )
                .child(
                    Label::new(SharedString::from(target))
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .line_clamp(1)
                        .text_ellipsis(),
                ),
        )
        .on_click(
            cx.listener(move |this, _, _window, cx| this.open_saved(&vault, &open_target, cx)),
        )
        .context_menu(move |menu, _window, _cx| {
            let item = |label: &'static str, icon: &'static str| {
                PopupMenuItem::new(label).icon(Icon::empty().path(icon))
            };
            let files = {
                let (view, vault, target) = (view.clone(), menu_vault.clone(), menu_target.clone());
                item("Файлы (SFTP)", "icons/folder.svg").on_click(move |_, _window, cx| {
                    view.update(cx, |this, cx| {
                        let credentials = this.saved_credentials(&vault, &target);
                        this.open_files(&target, credentials, Some(vault.clone()), cx);
                    });
                })
            };
            let edit = {
                let (view, vault, target) = (view.clone(), menu_vault.clone(), menu_target.clone());
                item("Изменить", "icons/pencil.svg").on_click(move |_, window, cx| {
                    view.update(cx, |this, cx| this.edit(&vault, &target, window, cx));
                })
            };
            let delete = {
                let (view, vault, target) = (view.clone(), menu_vault.clone(), menu_target.clone());
                item("Удалить…", "icons/delete.svg").on_click(move |_, _window, cx| {
                    view.update(cx, |this, cx| {
                        this.confirm_forget = Some((vault.clone(), target.clone()));
                        cx.notify();
                    });
                })
            };
            menu.item(files)
                .item(edit)
                .item(PopupMenuItem::separator())
                .item(delete)
        })
        .into_any_element()
    }

    /// Подтверждение удаления хоста из контекстного меню.
    pub(super) fn forget_host_dialog(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let (vault, target) = self.confirm_forget.clone()?;
        let theme = cx.theme().clone();

        Some(
            div()
                .absolute()
                .occlude()
                .top_0()
                .left_0()
                .size_full()
                .flex()
                .items_center()
                .justify_center()
                .bg(gpui_kit::hsla(0., 0., 0., 0.5))
                .on_mouse_down(MouseButton::Left, |_, _, _| {})
                .child(
                    v_flex()
                        .w(px(420.))
                        .p_4()
                        .gap_3()
                        .rounded_lg()
                        .bg(theme.background)
                        .border_1()
                        .border_color(theme.danger)
                        .child(
                            Label::new(SharedString::from(format!("Удалить хост «{target}»?")))
                                .font_semibold(),
                        )
                        .child(
                            Label::new(
                                "Запись и сохранённые для неё пароли будут удалены из хранилища. Открытые сеансы останутся подключёнными.",
                            )
                            .text_sm()
                            .text_color(theme.muted_foreground),
                        )
                        .child(
                            h_flex()
                                .gap_2()
                                .child(
                                    Button::new("host-delete-confirm")
                                        .danger()
                                        .label("Удалить")
                                        .on_click(cx.listener(move |this, _, _window, cx| {
                                            this.confirm_forget = None;
                                            this.forget(&vault, &target, cx);
                                            cx.notify();
                                        })),
                                )
                                .child(
                                    Button::new("host-delete-cancel")
                                        .outline()
                                        .label("Отмена")
                                        .on_click(cx.listener(|this, _, _window, cx| {
                                            this.confirm_forget = None;
                                            cx.notify();
                                        })),
                                ),
                        ),
                )
                .into_any_element(),
        )
    }

    fn address_row(&self, query: &str, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        Self::rail_row("rail-address".into(), false, cx)
            .h(px(30.))
            .child(
                Icon::empty()
                    .path("icons/square-terminal.svg")
                    .small()
                    .text_color(theme.primary),
            )
            .child(
                div().flex_1().min_w(px(0.)).overflow_hidden().child(
                    Label::new(SharedString::from(format!("ssh {query}")))
                        .text_sm()
                        .line_clamp(1)
                        .text_ellipsis(),
                ),
            )
            .child(
                Label::new("Enter")
                    .text_xs()
                    .text_color(theme.muted_foreground),
            )
            .on_click(cx.listener(|this, _, _window, cx| this.quick_connect(cx)))
            .into_any_element()
    }

    fn locked_row(&self, ix: usize, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let id = self.vaults[ix].id.clone();
        let (title, hint) = if self.vaults[ix].session.state().is_absent() {
            ("Хранилище не создано", "Создать хранилище")
        } else {
            ("Хранилище заблокировано", "Разблокировать")
        };
        Self::rail_row(SharedString::from(format!("rail-locked-{id}")), false, cx)
            .h(px(42.))
            .child(
                Icon::empty()
                    .path("icons/lock.svg")
                    .small()
                    .text_color(theme.muted_foreground),
            )
            .child(
                v_flex().child(Label::new(title).text_sm()).child(
                    Label::new(hint)
                        .text_xs()
                        .text_color(theme.muted_foreground),
                ),
            )
            .on_click(
                cx.listener(move |this, _, window, cx| this.open_vault_screen(&id, window, cx)),
            )
            .into_any_element()
    }

    fn empty_row(&self, text: &'static str, cx: &App) -> AnyElement {
        div()
            .px_2()
            .h(px(28.))
            .flex()
            .items_center()
            .child(
                Label::new(text)
                    .text_xs()
                    .text_color(cx.theme().muted_foreground),
            )
            .into_any_element()
    }

    fn rail_footer(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let unlocked = self.any_unlocked();
        let nav = |id: &'static str, icon: Icon, tip: &'static str, section: Section| {
            Button::new(id)
                .ghost()
                .small()
                .icon(icon)
                .tooltip(tip)
                .selected(self.showing_page && self.section == section)
                .on_click(cx.listener(move |this, _, _window, cx| this.go(section, cx)))
        };
        h_flex()
            .px_2()
            .py_2()
            .gap_1()
            .items_center()
            .border_t_1()
            .border_color(theme.border)
            .child(nav(
                "rail-keys",
                Icon::empty().path("icons/key-round.svg"),
                "Ключи",
                Section::Keys,
            ))
            .child(nav(
                "rail-proxies",
                Icon::empty().path("icons/route.svg"),
                "Прокси",
                Section::Proxies,
            ))
            .child(nav(
                "rail-snippets",
                Icon::empty().path("icons/square-terminal.svg"),
                "Сниппеты",
                Section::Snippets,
            ))
            .child(nav(
                "rail-settings",
                Icon::new(IconName::Settings),
                "Настройки",
                Section::Settings,
            ))
            .child(div().flex_grow_1())
            .child(
                Button::new("rail-vault")
                    .ghost()
                    .small()
                    .icon(
                        Icon::empty()
                            .path(if unlocked {
                                "icons/lock-open.svg"
                            } else {
                                "icons/lock.svg"
                            })
                            .text_color(if unlocked {
                                theme.success
                            } else {
                                theme.muted_foreground
                            }),
                    )
                    .tooltip(if unlocked {
                        "Заблокировать все хранилища"
                    } else {
                        "Разблокировать хранилище"
                    })
                    .on_click(cx.listener(move |this, _, window, cx| {
                        if unlocked {
                            this.lock_all(cx);
                        } else {
                            let id = this.current_id();
                            this.open_vault_screen(&id, window, cx);
                        }
                    })),
            )
            .into_any_element()
    }
}
