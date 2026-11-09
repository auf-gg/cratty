use super::*;
use gpui_kit::component::menu::{ContextMenuExt as _, PopupMenuItem};
use std::borrow::Cow;

/// Host being dragged across the left panel into another group.
#[derive(Clone)]
pub(super) struct HostDrag {
    vault: String,
    target: String,
    group: String,
    title: SharedString,
}

struct HostDragPreview(SharedString);

impl Render for HostDragPreview {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .px_2()
            .py_1()
            .rounded_md()
            .bg(cx.theme().popover)
            .border_1()
            .border_color(cx.theme().border)
            .text_sm()
            .child(self.0.clone())
    }
}

impl AppView {
    /// Makes the element a drop target for a host from the same vault:
    /// it moves into group `group` (empty name means no group). With `anchor`
    /// the host takes that host's place, which also reorders within a group.
    pub(super) fn host_drop_target<E: InteractiveElement>(
        element: E,
        vault: &str,
        group: &str,
        anchor: Option<String>,
        cx: &mut Context<Self>,
    ) -> E {
        let bg = cx.theme().drop_target;
        let check_vault = vault.to_owned();
        let check_group = proto::GroupRecord::key(group);
        let check_anchor = anchor.clone();
        let (drop_vault, drop_group) = (vault.to_owned(), group.trim().to_owned());
        element
            .can_drop(move |value, _window, _cx| {
                value.downcast_ref::<HostDrag>().is_some_and(|drag| {
                    drag.vault == check_vault
                        && match &check_anchor {
                            Some(anchor) => *anchor != drag.target,
                            None => proto::GroupRecord::key(&drag.group) != check_group,
                        }
                })
            })
            .drag_over::<HostDrag>(move |style, _, _, _| style.bg(bg))
            .on_drop(cx.listener(move |this, drag: &HostDrag, _window, cx| {
                this.dragging_host = None;
                let (target, group, anchor) =
                    (drag.target.clone(), drop_group.clone(), anchor.clone());
                this.persist(&drop_vault, cx, |unlocked, store| {
                    unlocked.move_host(store, &target, &group, anchor.as_deref())
                });
            }))
    }

    /// The "No group" drop spot at the end of the vault while a host is dragged out of a group.
    fn ungroup_zone(&self, vault: &str, cx: &mut Context<Self>) -> Option<AnyElement> {
        if self.dragging_host.as_ref() != Some(&(vault.to_owned(), true)) {
            return None;
        }
        let theme = cx.theme().clone();
        let zone = Self::rail_row(
            SharedString::from(format!("rail-ungroup-{vault}")),
            false,
            cx,
        )
        .h(px(30.))
        .mt_1()
        .justify_center()
        .border_1()
        .border_color(theme.border)
        .child(
            Label::new(t!("rail.no_group"))
                .text_xs()
                .text_color(theme.muted_foreground),
        );
        Some(Self::host_drop_target(zone, vault, "", None, cx).into_any_element())
    }

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
                // Dropped where it is not accepted (for example, onto
                // itself), the host is removed by gpui without a redraw — and the
                // drag hint freezes. We redraw ourselves.
                .on_mouse_up(
                    MouseButton::Left,
                    cx.listener(|this, _, _window, cx| {
                        if this.dragging_host.take().is_some() {
                            cx.notify();
                        }
                    }),
                )
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
                                    t!("rail.local_terminal")
                                } else {
                                    t!("rail.local_terminal_unix_only")
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
                                    t!("rail.new_host_locked")
                                } else {
                                    t!("rail.new_host")
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
                                t!("rail.group_connect"),
                                vec![self.address_row(&query, cx)],
                                cx,
                            ))
                        })
                        .when(!sessions.is_empty(), |this| {
                            this.child(self.rail_group(t!("rail.group_sessions"), sessions, cx))
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
                            t!("rail.no_hosts")
                        } else {
                            t!("rail.nothing_found")
                        },
                        cx,
                    )]
                } else {
                    let mut rows = Vec::new();
                    // Groups first, alphabetically, then hosts without a group.
                    for group in unlocked.groups() {
                        let key = proto::GroupRecord::key(&group.name);
                        let members: Vec<&HostRecord> = saved
                            .iter()
                            .filter(|host| proto::GroupRecord::key(&host.group) == key)
                            .collect();
                        if members.is_empty() {
                            continue;
                        }
                        // While searching, groups are expanded: otherwise matches are not visible.
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
            .child(Self::host_drop_target(
                div().rounded(px(7.)).child(self.vault_header(ix, cx)),
                &id,
                "",
                None,
                cx,
            ))
            .children(rows)
            .children(self.ungroup_zone(&id, cx))
            .into_any_element()
    }

    fn rail_group(&self, title: impl Into<SharedString>, rows: Vec<AnyElement>, cx: &App) -> AnyElement {
        v_flex()
            .gap_px()
            .child(
                div().h(px(22.)).px_2().flex().items_center().child(
                    Label::new(title.into())
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
                .tooltip(t!("rail.close"))
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
        let drag = HostDrag {
            vault: vault.clone(),
            target: target.clone(),
            group: host.group.trim().to_owned(),
            title: SharedString::from(title.clone()),
        };
        let drop_group = if in_group {
            host.group.clone()
        } else {
            String::new()
        };

        let row = Self::rail_row(
            SharedString::from(format!("rail-host-{vault}-{target}")),
            false,
            cx,
        );
        Self::host_drop_target(row, &vault, &drop_group, Some(target.clone()), cx)
            .on_drag(drag, {
                let view = view.clone();
                move |drag: &HostDrag, _, _window, cx| {
                    let grouped = !drag.group.is_empty();
                    let vault = drag.vault.clone();
                    view.update(cx, |this, _| this.dragging_host = Some((vault, grouped)));
                    cx.new(|_| HostDragPreview(drag.title.clone()))
                }
            })
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
                let item = |label: Cow<'static, str>, icon: &'static str| {
                    PopupMenuItem::new(label).icon(Icon::empty().path(icon))
                };
                let files = {
                    let (view, vault, target) =
                        (view.clone(), menu_vault.clone(), menu_target.clone());
                    item(t!("rail.menu_files"), "icons/folder.svg").on_click(move |_, _window, cx| {
                        view.update(cx, |this, cx| {
                            let credentials = this.saved_credentials(&vault, &target);
                            this.open_files(&target, credentials, Some(vault.clone()), cx);
                        });
                    })
                };
                let edit = {
                    let (view, vault, target) =
                        (view.clone(), menu_vault.clone(), menu_target.clone());
                    item(t!("rail.menu_edit"), "icons/pencil.svg").on_click(move |_, window, cx| {
                        view.update(cx, |this, cx| this.edit(&vault, &target, window, cx));
                    })
                };
                let delete = {
                    let (view, vault, target) =
                        (view.clone(), menu_vault.clone(), menu_target.clone());
                    item(t!("rail.menu_delete"), "icons/delete.svg").on_click(move |_, _window, cx| {
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

    /// Confirmation of host deletion from the context menu.
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
                            Label::new(t!("rail.delete_host_title", target = target))
                                .font_semibold(),
                        )
                        .child(
                            Label::new(t!("rail.delete_host_body"))
                            .text_sm()
                            .text_color(theme.muted_foreground),
                        )
                        .child(
                            h_flex()
                                .gap_2()
                                .child(
                                    Button::new("host-delete-confirm")
                                        .danger()
                                        .label(t!("rail.delete"))
                                        .on_click(cx.listener(move |this, _, _window, cx| {
                                            this.confirm_forget = None;
                                            this.forget(&vault, &target, cx);
                                            cx.notify();
                                        })),
                                )
                                .child(
                                    Button::new("host-delete-cancel")
                                        .outline()
                                        .label(t!("rail.cancel"))
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
            (t!("rail.no_vault_created"), t!("rail.create_vault"))
        } else {
            (t!("rail.vault_locked"), t!("rail.unlock"))
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

    fn empty_row(&self, text: impl Into<SharedString>, cx: &App) -> AnyElement {
        div()
            .px_2()
            .h(px(28.))
            .flex()
            .items_center()
            .child(
                Label::new(text.into())
                    .text_xs()
                    .text_color(cx.theme().muted_foreground),
            )
            .into_any_element()
    }

    fn rail_footer(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let unlocked = self.any_unlocked();
        let nav = |id: &'static str, icon: Icon, tip: Cow<'static, str>, section: Section| {
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
                t!("rail.keys"),
                Section::Keys,
            ))
            .child(nav(
                "rail-proxies",
                Icon::empty().path("icons/route.svg"),
                t!("rail.proxies"),
                Section::Proxies,
            ))
            .child(nav(
                "rail-snippets",
                Icon::empty().path("icons/square-terminal.svg"),
                t!("rail.snippets"),
                Section::Snippets,
            ))
            .child(nav(
                "rail-settings",
                Icon::new(IconName::Settings),
                t!("rail.settings"),
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
                        t!("rail.lock_all")
                    } else {
                        t!("rail.unlock_vault")
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
