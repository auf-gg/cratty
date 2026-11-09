use gpui_kit::component::{
    ActiveTheme, Icon, IconName, Sizable,
    button::{Button, ButtonVariants},
    h_flex,
    label::Label,
    scroll::ScrollableElement,
    v_flex,
};
use gpui_kit::{
    AnyElement, Context, Entity, EntityId, MouseDownEvent, SharedString, Subscription, div,
    prelude::*, px,
};

use rust_i18n::t;

use super::{AppView, ROW_TITLE_CHARS, SessionTab, TabKind, shorten};
use crate::ui::connect;
use crate::ui::terminal::{TerminalEvent, TerminalView};

pub(super) struct Pane {
    pub title: SharedString,
    pub vault: Option<String>,
    pub view: Entity<TerminalView>,
    pub _events: Subscription,
    pub request: connect::Request,
    pub credentials: connect::Credentials,
}

#[derive(Default)]
pub(super) struct Split {
    pub panes: Vec<Pane>,
    pub broadcast: bool,
    pub focused: usize,
}

impl SessionTab {
    pub(super) fn terminals(&self) -> Vec<Entity<TerminalView>> {
        match &self.kind {
            TabKind::Terminal { view, split, .. } => std::iter::once(view.clone())
                .chain(split.panes.iter().map(|pane| pane.view.clone()))
                .collect(),
            _ => Vec::new(),
        }
    }

    pub(super) fn focused_terminal(&self) -> Option<Entity<TerminalView>> {
        match &self.kind {
            TabKind::Terminal { view, split, .. } => Some(match split.focused {
                0 => view.clone(),
                at => split
                    .panes
                    .get(at - 1)
                    .map_or_else(|| view.clone(), |pane| pane.view.clone()),
            }),
            _ => None,
        }
    }

    fn split(&self) -> Option<&Split> {
        match &self.kind {
            TabKind::Terminal { split, .. } => Some(split),
            _ => None,
        }
    }

    fn split_mut(&mut self) -> Option<&mut Split> {
        match &mut self.kind {
            TabKind::Terminal { split, .. } => Some(split),
            _ => None,
        }
    }
}

impl AppView {
    pub(super) fn subscribe_terminal(
        &mut self,
        view: &Entity<TerminalView>,
        vault: Option<String>,
        target: String,
        cx: &mut Context<Self>,
    ) -> Subscription {
        cx.subscribe(
            view,
            move |this, emitter, event: &TerminalEvent, cx| match event {
                TerminalEvent::Typed(bytes) => this.broadcast_from(emitter.entity_id(), bytes, cx),
                _ => this.on_terminal_event(vault.as_deref(), &target, event, cx),
            },
        )
    }

    fn broadcast_from(&mut self, source: EntityId, bytes: &bytes::Bytes, cx: &mut Context<Self>) {
        let Some(tab) = self.tabs.iter().find(|tab| {
            tab.terminals()
                .iter()
                .any(|view| view.entity_id() == source)
        }) else {
            return;
        };
        if !tab.split().is_some_and(|split| split.broadcast) {
            return;
        }
        for view in tab.terminals() {
            if view.entity_id() != source {
                view.update(cx, |view, _| view.receive_broadcast(bytes.clone()));
            }
        }
    }

    fn split_tab(&mut self, index: usize, pick: Option<(String, String)>, cx: &mut Context<Self>) {
        let Some(tab) = self.tabs.get(index) else {
            return;
        };
        let (request, mut credentials, title, vault) = match &pick {
            None => (
                tab.request.clone(),
                tab.credentials.clone(),
                tab.title.clone(),
                tab.vault.clone(),
            ),
            Some((vault, raw)) => {
                let request = match connect::parse_target(raw) {
                    Ok(request) => request,
                    Err(error) => {
                        self.error = Some(error.into());
                        cx.notify();
                        return;
                    }
                };
                let title = self
                    .unlocked_of(vault)
                    .and_then(|unlocked| unlocked.find_by_target(raw))
                    .map_or_else(|| raw.clone(), |entry| entry.host.title());
                (
                    request,
                    self.saved_credentials(vault, raw),
                    title.into(),
                    Some(vault.clone()),
                )
            }
        };
        credentials.forwards.clear();

        let Some((view, events)) = self.start_pane(&request, &credentials, vault.clone(), cx)
        else {
            return;
        };
        if let Some(split) = self.tabs.get_mut(index).and_then(SessionTab::split_mut) {
            let broadcast = split.broadcast;
            split.panes.push(Pane {
                title,
                vault,
                view: view.clone(),
                _events: events,
                request,
                credentials,
            });
            split.focused = split.panes.len();
            view.update(cx, |view, cx| {
                view.set_broadcast(broadcast);
                view.request_focus(cx);
            });
        }
        self.split_menu = false;
        self.apply_appearance(cx);
        cx.notify();
    }

    fn start_pane(
        &mut self,
        request: &connect::Request,
        credentials: &connect::Credentials,
        vault: Option<String>,
        cx: &mut Context<Self>,
    ) -> Option<(Entity<TerminalView>, Subscription)> {
        let settings = connect::read_ssh_config(&request.alias);
        let target = connect::resolve(request, &settings);
        let agent = self.agent_address();
        let Some(view) = Self::start_session(&target, &settings, credentials, agent, cx) else {
            self.error = Some(t!("panes.session_start_failed").into());
            cx.notify();
            return None;
        };
        let can_save = self.can_save_for(vault.as_deref());
        view.update(cx, |view, cx| view.set_can_save_secrets(can_save, cx));
        let events = self.subscribe_terminal(&view, vault, target.to_string(), cx);
        Some((view, events))
    }

    fn reconnect_pane(&mut self, index: usize, pane: usize, cx: &mut Context<Self>) {
        let Some(old) = self
            .tabs
            .get(index)
            .and_then(SessionTab::split)
            .and_then(|split| split.panes.get(pane))
        else {
            return;
        };
        let (request, credentials, vault) = (
            old.request.clone(),
            old.credentials.clone(),
            old.vault.clone(),
        );
        let Some((view, events)) = self.start_pane(&request, &credentials, vault, cx) else {
            return;
        };
        if let Some(split) = self.tabs.get_mut(index).and_then(SessionTab::split_mut)
            && let Some(slot) = split.panes.get_mut(pane)
        {
            let broadcast = split.broadcast;
            slot.view = view.clone();
            slot._events = events;
            view.update(cx, |view, cx| {
                view.set_broadcast(broadcast);
                view.request_focus(cx);
            });
        }
        self.apply_appearance(cx);
        cx.notify();
    }

    fn close_pane(&mut self, index: usize, pane: usize, cx: &mut Context<Self>) {
        if let Some(split) = self.tabs.get_mut(index).and_then(SessionTab::split_mut)
            && pane < split.panes.len()
        {
            split.panes.remove(pane);
            split.focused = 0;
            if split.panes.is_empty() {
                split.broadcast = false;
            }
        }
        let broadcast = self
            .tabs
            .get(index)
            .and_then(SessionTab::split)
            .is_some_and(|split| split.broadcast);
        for view in self
            .tabs
            .get(index)
            .map(SessionTab::terminals)
            .unwrap_or_default()
        {
            view.update(cx, |view, _| view.set_broadcast(broadcast));
        }
        self.focus_active(cx);
    }

    pub(super) fn toggle_broadcast(&mut self, index: usize, cx: &mut Context<Self>) {
        let Some(split) = self.tabs.get_mut(index).and_then(SessionTab::split_mut) else {
            return;
        };
        split.broadcast = !split.broadcast;
        let broadcast = split.broadcast;
        for view in self.tabs[index].terminals() {
            view.update(cx, |view, _| view.set_broadcast(broadcast));
        }
        cx.notify();
    }

    pub(super) fn track_pane_focus(&mut self, window: &gpui_kit::Window, cx: &gpui_kit::App) {
        let Some(tab) = self.active.and_then(|index| self.tabs.get_mut(index)) else {
            return;
        };
        let focused = tab.terminals().iter().position(|view| {
            gpui_kit::Focusable::focus_handle(view.read(cx), cx).contains_focused(window, cx)
        });
        if let (Some(focused), Some(split)) = (focused, tab.split_mut()) {
            split.focused = focused;
        }
    }

    fn focus_pane(&mut self, index: usize, pane: usize, cx: &mut Context<Self>) {
        if let Some(split) = self.tabs.get_mut(index).and_then(SessionTab::split_mut)
            && split.focused != pane
        {
            split.focused = pane;
            cx.notify();
        }
    }

    pub(super) fn pane_group(&self, index: usize, cx: &mut Context<Self>) -> AnyElement {
        let tab = &self.tabs[index];
        let TabKind::Terminal { view, split, .. } = &tab.kind else {
            return div().into_any_element();
        };
        let multi = !split.panes.is_empty();
        let count = split.panes.len() + 1;
        let columns = grid_columns(count);

        let mut cells = vec![self.pane_cell(
            index,
            0,
            columns,
            view,
            &tab.title,
            multi,
            split.focused == 0,
            cx,
        )];
        for (at, pane) in split.panes.iter().enumerate() {
            cells.push(self.pane_cell(
                index,
                at + 1,
                columns,
                &pane.view,
                &pane.title,
                multi,
                split.focused == at + 1,
                cx,
            ));
        }
        let mut rows = Vec::new();
        let mut cells = cells.into_iter().peekable();
        while cells.peek().is_some() {
            rows.push(
                div()
                    .flex_1()
                    .min_h(px(0.))
                    .flex()
                    .flex_row()
                    .children(cells.by_ref().take(columns)),
            );
        }

        div()
            .relative()
            .flex_1()
            .min_w(px(0.))
            .min_h(px(0.))
            .flex()
            .flex_col()
            .children(rows)
            .into_any_element()
    }

    #[allow(clippy::too_many_arguments)]
    fn pane_cell(
        &self,
        index: usize,
        position: usize,
        columns: usize,
        view: &Entity<TerminalView>,
        title: &SharedString,
        multi: bool,
        focused: bool,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = cx.theme().clone();
        let closed = view.read(cx).is_closed();
        let header = multi.then(|| {
            h_flex()
                .h(px(28.))
                .px_2()
                .gap_1()
                .items_center()
                .flex_shrink_0()
                .bg(if focused {
                    theme.list_active
                } else {
                    theme.secondary
                })
                .border_b_1()
                .border_color(theme.border)
                .child(
                    Label::new(SharedString::from(shorten(title, ROW_TITLE_CHARS)))
                        .text_xs()
                        .flex_grow_1()
                        .text_color(if focused {
                            theme.foreground
                        } else {
                            theme.muted_foreground
                        }),
                )
                .when(closed, |this| {
                    this.child(Label::new(t!("panes.disconnected")).text_xs().text_color(theme.danger))
                })
                .when(position > 0 && closed, |this| {
                    this.child(
                        Button::new(SharedString::from(format!("pane-reconnect-{position}")))
                            .ghost()
                            .xsmall()
                            .icon(Icon::empty().path("icons/refresh-cw.svg"))
                            .tooltip(t!("panes.reconnect"))
                            .on_click(cx.listener(move |this, _, _window, cx| {
                                this.reconnect_pane(index, position - 1, cx)
                            })),
                    )
                })
                .when(position > 0, |this| {
                    this.child(
                        Button::new(SharedString::from(format!("pane-close-{position}")))
                            .ghost()
                            .xsmall()
                            .icon(Icon::new(IconName::Close))
                            .tooltip(t!("panes.close_pane"))
                            .on_click(cx.listener(move |this, _, _window, cx| {
                                this.close_pane(index, position - 1, cx)
                            })),
                    )
                })
        });
        div()
            .flex_1()
            .min_w(px(0.))
            .min_h(px(0.))
            .flex()
            .flex_col()
            .when(!position.is_multiple_of(columns), |this| {
                this.border_l_1().border_color(theme.border)
            })
            .when(position >= columns, |this| {
                this.border_t_1().border_color(theme.border)
            })
            .capture_any_mouse_down(cx.listener(move |this, _: &MouseDownEvent, _window, cx| {
                this.focus_pane(index, position, cx)
            }))
            .children(header)
            .child(
                div()
                    .flex_1()
                    .min_h(px(0.))
                    .overflow_hidden()
                    .child(view.clone()),
            )
            .into_any_element()
    }

    pub(super) fn split_popover(&self, index: usize, cx: &mut Context<Self>) -> Option<AnyElement> {
        if !self.split_menu {
            return None;
        }
        let theme = cx.theme().clone();
        let many = self.unlocked_slots().count() > 1;
        let hosts: Vec<(String, String, proto::RecordId, String)> = self
            .unlocked_slots()
            .filter_map(|slot| {
                slot.session.unlocked().map(|unlocked| {
                    unlocked
                        .hosts()
                        .into_iter()
                        .map(|entry| {
                            let title = if many {
                                format!("{} · {}", slot.name, entry.host.title())
                            } else {
                                entry.host.title()
                            };
                            (slot.id.clone(), title, entry.id, entry.host.target())
                        })
                        .collect::<Vec<_>>()
                })
            })
            .flatten()
            .collect();
        let host_row = |id: SharedString, title: String, pick: Option<(String, String)>| {
            div()
                .id(id)
                .px_2()
                .py_1()
                .rounded_md()
                .hover(|style| style.bg(theme.secondary_hover))
                .child(Label::new(SharedString::from(shorten(&title, ROW_TITLE_CHARS))).text_sm())
                .on_click(
                    cx.listener(move |this, _, _window, cx| {
                        this.split_tab(index, pick.clone(), cx)
                    }),
                )
        };
        Some(
            Self::popover(t!("panes.connection_for_new_pane"), px(300.), cx)
                .child(host_row("split-same".into(), t!("panes.current_host").to_string(), None))
                .child(
                    v_flex()
                        .id("split-hosts")
                        .max_h(px(300.))
                        .overflow_y_scrollbar()
                        .children(hosts.into_iter().map(|(vault, title, id, target)| {
                            host_row(
                                SharedString::from(format!("split-host-{vault}-{id}")),
                                title,
                                Some((vault, target)),
                            )
                        })),
                )
                .into_any_element(),
        )
    }
}

fn grid_columns(count: usize) -> usize {
    (1..=count)
        .find(|columns| columns * columns >= count)
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::grid_columns;

    #[test]
    fn grid_is_almost_square() {
        let got: Vec<usize> = (1..=9).map(grid_columns).collect();
        assert_eq!(got, vec![1, 2, 2, 2, 3, 3, 3, 3, 3]);
    }
}
