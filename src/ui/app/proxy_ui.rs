use crate::ui::route;
use rust_i18n::t;
use crate::vault_session::ViaItem;
use gpui_kit::component::{
    ActiveTheme, Disableable, Icon, IconName, IndexPath, Selectable, Sizable, StyledExt,
    button::{Button, ButtonRounded, ButtonVariants},
    h_flex,
    input::{Input, InputState},
    label::Label,
    list::{List, ListDelegate, ListEvent, ListItem, ListState},
    popover::Popover,
    scroll::ScrollableElement,
    v_flex,
};
use gpui_kit::{
    AnyElement, App, Context, Entity, Focusable, SharedString, Subscription, Task, Window, div,
    prelude::*, px,
};
use proto::{ProxyKind, ProxyRecord, RecordId, SOCKS_PORT};

use super::{AppView, ROW_TITLE_CHARS, Section, shorten};

/// A proxy or a saved host that can become a chain hop.
struct HopOption {
    id: RecordId,
    proxy: bool,
    title: String,
    detail: String,
}

/// The "+" menu on a route arrow: a searchable list, rendered only where visible.
#[derive(Default)]
pub(super) struct HopPicker {
    /// Where in `via` the picked hop goes.
    at: usize,
    options: Vec<HopOption>,
    shown: Vec<usize>,
}

impl HopPicker {
    fn filter(&mut self, query: &str) {
        let query = query.trim().to_lowercase();
        self.shown = (0..self.options.len())
            .filter(|&index| {
                let option = &self.options[index];
                query.is_empty()
                    || option.title.to_lowercase().contains(&query)
                    || option.detail.to_lowercase().contains(&query)
            })
            .collect();
    }

    fn option(&self, ix: IndexPath) -> Option<&HopOption> {
        self.options.get(*self.shown.get(ix.row)?)
    }
}

impl ListDelegate for HopPicker {
    type Item = ListItem;

    fn perform_search(
        &mut self,
        query: &str,
        _window: &mut Window,
        cx: &mut Context<ListState<Self>>,
    ) -> Task<()> {
        self.filter(query);
        cx.notify();
        Task::ready(())
    }

    fn items_count(&self, _section: usize, _cx: &App) -> usize {
        self.shown.len()
    }

    fn render_item(
        &mut self,
        ix: IndexPath,
        _window: &mut Window,
        cx: &mut Context<ListState<Self>>,
    ) -> Option<ListItem> {
        let option = self.option(ix)?;
        let theme = cx.theme();
        let (icon, color) = if option.proxy {
            ("icons/route.svg", theme.muted_foreground)
        } else {
            ("icons/server.svg", theme.primary)
        };
        Some(
            ListItem::new(SharedString::from(format!("hop-{ix}"))).child(
                h_flex()
                    .gap_2()
                    .items_center()
                    .child(Icon::empty().path(icon).small().text_color(color))
                    .child(
                        v_flex()
                            .child(
                                Label::new(SharedString::from(shorten(&option.title, ROW_TITLE_CHARS)))
                                    .text_sm(),
                            )
                            .child(
                                Label::new(SharedString::from(shorten(&option.detail, 40)))
                                    .text_xs()
                                    .text_color(theme.muted_foreground),
                            ),
                    ),
            ),
        )
    }

    fn render_empty(
        &mut self,
        _window: &mut Window,
        cx: &mut Context<ListState<Self>>,
    ) -> impl IntoElement {
        div()
            .px_3()
            .py_4()
            .text_sm()
            .text_color(cx.theme().muted_foreground)
            .child(t!("proxy.hop_none").to_string())
    }

    fn set_selected_index(
        &mut self,
        _ix: Option<IndexPath>,
        _window: &mut Window,
        _cx: &mut Context<ListState<Self>>,
    ) {
    }
}

pub(super) struct HopMenu {
    list: Entity<ListState<HopPicker>>,
    /// The arrow whose menu is open.
    open: Option<usize>,
    _events: Subscription,
}

impl HopMenu {
    pub(super) fn new(window: &mut Window, cx: &mut Context<AppView>) -> Self {
        let list = cx.new(|cx| ListState::new(HopPicker::default(), window, cx).searchable(true));
        let _events = cx.subscribe(&list, |this, list, event: &ListEvent, cx| {
            let ListEvent::Confirm(ix) = event else {
                return;
            };
            let picker = list.read(cx).delegate();
            if let Some(option) = picker.option(*ix) {
                let (at, id) = (picker.at, option.id.clone());
                this.chain_insert(at, id, cx);
            }
        });
        Self {
            list,
            open: None,
            _events,
        }
    }
}

pub(super) struct ProxyForm {
    pub label: Entity<InputState>,
    pub host: Entity<InputState>,
    pub port: Entity<InputState>,
    pub user: Entity<InputState>,
    pub password: Entity<InputState>,
    /// The vault the proxy is (or will be) stored in.
    pub vault: String,
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
            vault: String::new(),
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
                Some(t!("proxy.err_locked").to_string()),
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
                    self.error = Some(t!("proxy.err_port", port = port_text).to_string().into());
                    cx.notify();
                    return;
                }
            }
        };
        if host.is_empty() {
            self.error = Some(t!("proxy.err_host").to_string().into());
            cx.notify();
            return;
        }

        let vault = self.proxy_form.vault.clone();
        let editing = self.proxy_form.editing.clone();
        let existing = editing
            .as_ref()
            .and_then(|id| self.unlocked_of(&vault).and_then(|unlocked| unlocked.proxy(id)))
            .map(|entry| entry.proxy);
        if existing
            .as_ref()
            .is_some_and(|proxy| proxy.kind == ProxyKind::Unsupported)
        {
            self.error = Some(t!("proxy.err_unsupported").to_string().into());
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

        self.persist(&vault, cx, move |unlocked, store| {
            unlocked.upsert_proxy(store, editing, record).map(|_| ())
        });
        if self.error.is_none() {
            self.proxy_clear(window, cx);
        }
    }

    fn proxy_edit(&mut self, vault: &str, id: &RecordId, window: &mut Window, cx: &mut Context<Self>) {
        let Some(entry) = self.unlocked_of(vault).and_then(|unlocked| unlocked.proxy(id)) else {
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
        self.proxy_form.vault = vault.to_owned();
        self.proxy_form.editing = Some(id.clone());
        self.proxy_form.open = true;
        self.error = None;
        cx.notify();
    }

    /// New proxy form; `vault` preselects where it is saved.
    fn proxy_new(&mut self, vault: Option<String>, window: &mut Window, cx: &mut Context<Self>) {
        self.proxy_clear(window, cx);
        self.proxy_form.vault = vault
            .filter(|id| self.unlocked_of(id).is_some())
            .or_else(|| self.current_unlocked().map(|_| self.current_id()))
            .or_else(|| self.unlocked_slots().next().map(|slot| slot.id.clone()))
            .unwrap_or_default();
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
        let vault = self.proxy_form.vault.clone();
        let Some(mut proxy) = self
            .unlocked_of(&vault)
            .and_then(|unlocked| unlocked.proxy(&id))
            .map(|entry| entry.proxy)
        else {
            return;
        };
        if !proxy.forget_password() {
            return;
        }
        self.persist(&vault, cx, move |unlocked, store| {
            unlocked.upsert_proxy(store, Some(id), proxy).map(|_| ())
        });
    }

    fn proxy_remove(&mut self, id: &RecordId, window: &mut Window, cx: &mut Context<Self>) {
        let id = id.clone();
        let vault = self.proxy_form.vault.clone();
        let was_editing = self.proxy_form.editing.as_ref() == Some(&id);
        self.persist(&vault, cx, move |unlocked, store| unlocked.remove_proxy(store, &id));
        if was_editing && self.error.is_none() {
            self.proxy_clear(window, cx);
        }
    }

    fn chain_insert(&mut self, at: usize, id: RecordId, cx: &mut Context<Self>) {
        if !self.form.via.contains(&id) {
            self.form.via.insert(at.min(self.form.via.len()), id);
        }
        self.hop_menu.open = None;
        cx.notify();
    }

    /// Proxies and hosts not yet in the chain, except the host being edited.
    fn hop_options(&self) -> Vec<HopOption> {
        let Some(unlocked) = self.unlocked_of(&self.form.vault) else {
            return Vec::new();
        };
        let proxies = unlocked
            .proxies()
            .into_iter()
            .filter(|entry| entry.proxy.is_usable())
            .map(|entry| HopOption {
                proxy: true,
                title: entry.proxy.title(),
                detail: entry.proxy.address(),
                id: entry.id,
            });
        let hosts = unlocked
            .hosts()
            .into_iter()
            .filter(|entry| self.form.editing.as_deref() != Some(entry.host.target().as_str()))
            .map(|entry| HopOption {
                proxy: false,
                title: entry.host.title(),
                detail: entry.host.target(),
                id: entry.id,
            });
        proxies
            .chain(hosts)
            .filter(|option| !self.form.via.contains(&option.id))
            .collect()
    }

    fn hop_menu_toggle(&mut self, at: usize, open: bool, window: &mut Window, cx: &mut Context<Self>) {
        if !open {
            // Another arrow's menu may already be open.
            if self.hop_menu.open == Some(at) {
                self.hop_menu.open = None;
            }
            cx.notify();
            return;
        }
        let options = self.hop_options();
        self.hop_menu.open = Some(at);
        self.hop_menu.list.update(cx, |list, cx| {
            let picker = list.delegate_mut();
            picker.at = at;
            picker.options = options;
            picker.filter("");
            list.set_query("", window, cx);
        });
        cx.notify();
    }

    /// Route arrow with a "+" in the middle: adds a hop at this place of the chain.
    fn hop_arrow(&self, at: usize, cx: &mut Context<Self>) -> AnyElement {
        let muted = cx.theme().muted_foreground;
        let list = self.hop_menu.list.clone();
        let view = cx.entity().downgrade();
        let toggle = view.clone();
        h_flex()
            .items_center()
            .child(div().w(px(6.)).h(px(1.)).bg(muted))
            .child(
                Popover::new(SharedString::from(format!("chain-add-{at}")))
                    .open(self.hop_menu.open == Some(at))
                    .track_focus(&list.focus_handle(cx))
                    .p_0()
                    .trigger(
                        Button::new(SharedString::from(format!("chain-add-button-{at}")))
                            .outline()
                            .xsmall()
                            .rounded(ButtonRounded::Size(px(999.)))
                            .icon(Icon::new(IconName::Plus))
                            .tooltip(t!("proxy.add_hop_tooltip")),
                    )
                    .on_open_change(move |open, window, cx| {
                        let _ = toggle.update(cx, |this, cx| this.hop_menu_toggle(at, *open, window, cx));
                    })
                    .content(move |_, _, cx| {
                        let view = view.clone();
                        v_flex()
                            .w(px(300.))
                            .child(
                                List::new(&list)
                                    .search_placeholder(t!("proxy.hop_search"))
                                    .max_h(px(280.))
                                    .py_1(),
                            )
                            .child(
                                div().p_1().border_t_1().border_color(cx.theme().border).child(
                                    Button::new("chain-go-proxies")
                                        .ghost()
                                        .small()
                                        .w_full()
                                        .icon(Icon::new(IconName::Plus))
                                        .label(t!("proxy.add_server"))
                                        .tooltip(t!("proxy.add_server_tooltip"))
                                        .on_click(move |_, window, cx| {
                                            let _ = view.update(cx, |this, cx| {
                                                this.hop_menu.open = None;
                                                this.go(Section::Proxies, cx);
                                                // A hop must come from the host's own vault.
                                                let vault = this.form.vault.clone();
                                                this.proxy_new(Some(vault), window, cx);
                                            });
                                        }),
                                ),
                            )
                    }),
            )
            .child(Label::new("→").text_sm().text_color(muted))
            .into_any_element()
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
        let editing_host = self.form.host.read(cx).value().trim().to_string();

        let links: Vec<AnyElement> = self
            .form
            .via
            .iter()
            .enumerate()
            .map(|(index, id)| {
                let (place, title, detail) = match unlocked.via_item(id) {
                    Some(ViaItem::Proxy(proxy)) => {
                        (route::Place::Hop, proxy.title(), t!("proxy.node_proxy").to_string())
                    }
                    Some(ViaItem::Host(host)) => {
                        (route::Place::Server, host.title(), t!("proxy.node_host").to_string())
                    }
                    None => (route::Place::Hop, t!("proxy.hop_deleted").to_string(), String::new()),
                };
                let broken = detail.is_empty();
                route::node(place, shorten(&title, ROW_TITLE_CHARS), detail, cx)
                    .when(broken, |this| this.border_color(danger))
                    .child(
                        Button::new(SharedString::from(format!("chain-remove-{index}")))
                            .ghost()
                            .xsmall()
                            .icon(Icon::new(IconName::Close))
                            .tooltip(t!("proxy.remove_hop"))
                            .on_click(cx.listener(move |this, _, _window, cx| {
                                this.chain_remove(index, cx)
                            })),
                    )
                    .into_any_element()
            })
            .collect();
        let direct = links.is_empty();

        let mut steps =
            vec![route::node(route::Place::You, t!("proxy.this_computer").to_string(), "", cx).into_any_element()];
        steps.extend(links);
        steps.push(
            route::node(
                route::Place::Server,
                if editing_host.is_empty() {
                    t!("proxy.server").to_string()
                } else {
                    shorten(&editing_host, ROW_TITLE_CHARS)
                },
                t!("proxy.target_server").to_string(),
                cx,
            )
            .into_any_element(),
        );

        // The arrow before step `index` inserts a hop that becomes that step.
        let mut flow = h_flex().flex_wrap().items_center().gap_1();
        for (index, step) in steps.into_iter().enumerate() {
            if index > 0 {
                flow = flow.child(self.hop_arrow(index - 1, cx));
            }
            flow = flow.child(step);
        }

        Some(
            v_flex()
                .gap_2()
                .child(flow)
                .child(
                    Label::new(if direct {
                        t!("proxy.chain_direct")
                    } else {
                        t!("proxy.chain_note")
                    })
                    .text_xs()
                    .text_color(muted),
                )
                .into_any_element(),
        )
    }

    pub(super) fn proxies_page(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let muted = theme.muted_foreground;

        let header = h_flex()
            .px_6()
            .pt_5()
            .pb_3()
            .justify_between()
            .items_center()
            .child(Label::new(t!("proxy.title")).text_xl().font_semibold())
            .child(
                Button::new("new-proxy")
                    .primary()
                    .icon(Icon::new(IconName::Plus))
                    .label(t!("proxy.new"))
                    .on_click(cx.listener(|this, _, window, cx| this.proxy_new(None, window, cx))),
            );

        let slots: Vec<(String, String)> = self
            .listed()
            .map(|(_, slot)| (slot.id.clone(), slot.name.clone()))
            .collect();
        let groups: Vec<AnyElement> = slots
            .into_iter()
            .map(|(vault, name)| self.proxy_group(vault, name, cx))
            .collect();

        div()
            .relative()
            .size_full()
            .child(
                v_flex().size_full().child(header).child(
                    v_flex()
                        .id("proxies-grid")
                        .flex_grow_1()
                        .min_h(px(0.))
                        .overflow_y_scrollbar()
                        .px_6()
                        .pb_6()
                        .gap_5()
                        .child(Label::new(t!("proxy.intro")).text_sm().text_color(muted))
                        .children(groups),
                ),
            )
            .when(self.proxy_form.open, |this| {
                this.child(self.proxy_drawer(cx))
            })
            .into_any_element()
    }

    /// One vault on the proxies page: its proxies, or why they are not shown.
    fn proxy_group(&self, vault: String, name: String, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let muted = theme.muted_foreground;
        let unlocked = self.unlocked_of(&vault);

        let heading = h_flex()
            .gap_2()
            .items_center()
            .child(
                Icon::empty()
                    .path(if unlocked.is_some() {
                        "icons/lock-open.svg"
                    } else {
                        "icons/lock.svg"
                    })
                    .small()
                    .text_color(muted),
            )
            .child(Label::new(SharedString::from(shorten(&name, ROW_TITLE_CHARS))).font_semibold());

        let Some(unlocked) = unlocked else {
            return v_flex()
                .gap_2()
                .child(heading.child(
                    Button::new(SharedString::from(format!("proxy-unlock-{vault}")))
                        .ghost()
                        .xsmall()
                        .label(t!("proxy.unlock"))
                        .on_click(cx.listener(move |this, _, window, cx| {
                            this.select_vault(&vault, window, cx)
                        })),
                ))
                .into_any_element();
        };

        let cards: Vec<AnyElement> = unlocked
            .proxies()
            .into_iter()
            .map(|entry| {
                let edit_id = entry.id.clone();
                let edit_vault = vault.clone();
                let used_by = unlocked.hosts_via(&entry.id).len();
                let unsupported = entry.proxy.kind == ProxyKind::Unsupported;
                let usage = match used_by {
                    0 => t!("proxy.not_used").to_string(),
                    count => t!("proxy.used_in_chains", used = count).to_string(),
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
                            this.proxy_edit(&edit_vault, &edit_id, window, cx)
                        }))
                    })
                    .into_any_element()
            })
            .collect();

        v_flex()
            .gap_2()
            .child(heading)
            .child(if cards.is_empty() {
                Label::new(t!("proxy.empty_title"))
                    .text_sm()
                    .text_color(muted)
                    .into_any_element()
            } else {
                h_flex().flex_wrap().gap_3().children(cards).into_any_element()
            })
            .into_any_element()
    }

    /// Where the proxy is stored. Chosen on creation; an existing proxy stays put,
    /// since hosts of its vault may use it in their chains.
    fn proxy_vault_field(&self, editing: bool, cx: &mut Context<Self>) -> AnyElement {
        let muted = cx.theme().muted_foreground;
        let unlocked: Vec<(String, String)> = self
            .unlocked_slots()
            .map(|slot| (slot.id.clone(), slot.name.clone()))
            .collect();
        let choice = if editing || unlocked.len() < 2 {
            Label::new(SharedString::from(self.vault_name(&self.proxy_form.vault)))
                .text_sm()
                .into_any_element()
        } else {
            h_flex()
                .gap_1()
                .flex_wrap()
                .children(unlocked.into_iter().map(|(id, name)| {
                    let selected = self.proxy_form.vault == id;
                    Button::new(SharedString::from(format!("proxy-vault-{id}")))
                        .ghost()
                        .small()
                        .selected(selected)
                        .label(SharedString::from(shorten(&name, ROW_TITLE_CHARS)))
                        .on_click(cx.listener(move |this, _, _window, cx| {
                            this.proxy_form.vault = id.clone();
                            cx.notify();
                        }))
                }))
                .into_any_element()
        };
        v_flex()
            .gap_1()
            .child(Self::field_label(t!("proxy.vault").to_string(), muted))
            .child(choice)
            .child(Label::new(t!("proxy.vault_note")).text_xs().text_color(muted))
            .into_any_element()
    }

    fn proxy_drawer(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let muted = theme.muted_foreground;
        let unlocked = self.unlocked_of(&self.proxy_form.vault);
        let editing = self
            .proxy_form
            .editing
            .as_ref()
            .and_then(|id| unlocked.and_then(|unlocked| unlocked.proxy(id)));
        let has_password = editing
            .as_ref()
            .is_some_and(|entry| entry.proxy.password().is_some());
        let used_by: Vec<String> = editing
            .as_ref()
            .and_then(|entry| {
                unlocked.map(|unlocked| {
                    unlocked
                        .hosts_via(&entry.id)
                        .into_iter()
                        .map(|h| h.host.title())
                        .collect()
                })
            })
            .unwrap_or_default();
        let vault_field = self.proxy_vault_field(editing.is_some(), cx);
        let remove_id = editing.as_ref().map(|entry| entry.id.clone());
        let form = &self.proxy_form;

        let field = |label: String, input: &Entity<InputState>| {
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
                                    t!("proxy.edit_title")
                                } else {
                                    t!("proxy.new_title")
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
                                Label::new(t!("proxy.protocol_note"))
                                    .text_xs()
                                    .text_color(muted),
                            )
                            .child(vault_field)
                            .child(field(t!("proxy.name").to_string(), &form.label))
                            .child(
                                h_flex()
                                    .gap_2()
                                    .items_end()
                                    .child(div().flex_grow_1().child(field(t!("proxy.address").to_string(), &form.host)))
                                    .child(div().w(px(80.)).child(field(t!("proxy.port").to_string(), &form.port))),
                            )
                            .child(field(t!("proxy.username").to_string(), &form.user))
                            .child(
                                v_flex()
                                    .gap_1()
                                    .child(field(t!("proxy.password").to_string(), &form.password))
                                    .child(
                                        Label::new(if has_password {
                                            t!("proxy.password_saved")
                                        } else {
                                            t!("proxy.password_required")
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
                                        .label(t!("proxy.forget_password"))
                                        .on_click(cx.listener(|this, _, _window, cx| {
                                            this.proxy_forget_password(cx)
                                        })),
                                )
                            })
                            .when(!used_by.is_empty(), |this| {
                                this.child(
                                    Label::new(t!("proxy.used_in_chains", used = used_by.join(", ")))
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
                                    .label(t!("proxy.save"))
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.proxy_save(window, cx)
                                    })),
                            )
                            .child(div().flex_grow_1())
                            .children(remove_id.map(|id| {
                                Button::new("proxy-remove")
                                    .ghost()
                                    .icon(Icon::new(IconName::Delete))
                                    .label(t!("proxy.delete"))
                                    .disabled(!used_by.is_empty())
                                    .tooltip(if used_by.is_empty() {
                                        t!("proxy.delete_tooltip")
                                    } else {
                                        t!("proxy.delete_blocked")
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
