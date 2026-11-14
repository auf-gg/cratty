//! Tabs: reopening them at the next start, renaming them.

use super::*;
use crate::ui::settings::{SavedTab, SavedTabKind};

/// A tab title being edited in the left panel.
pub(super) struct Renaming {
    pub index: usize,
    pub input: Entity<InputState>,
    _events: Subscription,
}

impl SessionTab {
    /// What is needed to open the tab again; `None` for tabs that cannot be
    /// reopened: a file editor, a one-off command.
    fn saved(&self, active: bool) -> Option<SavedTab> {
        let kind = match &self.kind {
            TabKind::Terminal { .. } if self.local => SavedTabKind::Local,
            TabKind::Terminal { .. } if self.credentials.command.is_none() => SavedTabKind::Ssh,
            TabKind::Files { .. } => SavedTabKind::Files,
            _ => return None,
        };
        Some(SavedTab {
            kind,
            target: if self.local {
                String::new()
            } else {
                self.request.to_string()
            },
            vault: self.vault.clone(),
            name: self.default_title.is_some().then(|| self.title.to_string()),
            active,
        })
    }
}

impl AppView {
    /// Open tabs followed by those still waiting for their vault.
    fn tabs_snapshot(&self) -> Vec<SavedTab> {
        let mut tabs: Vec<SavedTab> = self
            .tabs
            .iter()
            .enumerate()
            .filter_map(|(index, tab)| tab.saved(self.active == Some(index)))
            .collect();
        let shown = tabs.iter().any(|tab| tab.active);
        tabs.extend(self.pending_tabs.iter().cloned().map(|mut tab| {
            tab.active &= !shown;
            tab
        }));
        tabs
    }

    /// Writes the open tabs to the settings when they are to be reopened.
    pub(super) fn remember_tabs(&mut self) {
        if !self.settings.restore_tabs || self.reopening {
            return;
        }
        let tabs = self.tabs_snapshot();
        if tabs != self.settings.open_tabs {
            self.settings.open_tabs = tabs;
            self.save_settings_quietly();
        }
    }

    pub(super) fn set_restore_tabs(&mut self, on: bool, cx: &mut Context<Self>) {
        self.settings.restore_tabs = on;
        if !on {
            self.pending_tabs.clear();
        }
        self.settings.open_tabs = if on { self.tabs_snapshot() } else { Vec::new() };
        self.save_settings_quietly();
        cx.notify();
    }

    /// Unlike the settings page, tab changes must not wipe an unrelated error.
    fn save_settings_quietly(&mut self) {
        if let Err(error) = settings::save(&self.settings) {
            self.error = Some(error.into());
        }
    }

    /// At startup: reopens the tabs of the previous run. Tabs of a locked vault wait
    /// until it is unlocked; tabs of a vault that no longer exists are dropped.
    pub(super) fn restore_tabs(&mut self, cx: &mut Context<Self>) {
        if !self.settings.restore_tabs {
            return;
        }
        let saved = std::mem::take(&mut self.settings.open_tabs);
        self.pending_tabs = saved
            .into_iter()
            .filter(|tab| tab.vault.as_deref().is_none_or(|id| self.vault_ix(id).is_some()))
            .collect();
        self.reopen_ready_tabs(cx);
    }

    /// Opens the waiting tabs that need no vault or whose vault is unlocked now.
    pub(super) fn reopen_ready_tabs(&mut self, cx: &mut Context<Self>) {
        if self.pending_tabs.is_empty() {
            return;
        }
        let (ready, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending_tabs)
            .into_iter()
            .partition(|tab| {
                tab.vault
                    .as_deref()
                    .is_none_or(|id| self.unlocked_of(id).is_some())
            });
        self.pending_tabs = waiting;

        self.reopening = true;
        let mut active = None;
        for saved in ready {
            if self.reopen(&saved, cx) && saved.active {
                active = Some(self.tabs.len() - 1);
            }
        }
        self.reopening = false;

        if let Some(index) = active {
            self.select(index, cx);
        }
        self.remember_tabs();
    }

    /// Opens one saved tab; `false` when it could not be opened.
    fn reopen(&mut self, saved: &SavedTab, cx: &mut Context<Self>) -> bool {
        let before = self.tabs.len();
        match saved.kind {
            SavedTabKind::Local => self.spawn_local_tab(cx),
            SavedTabKind::Ssh => match &saved.vault {
                Some(vault) => self.open_saved(vault, &saved.target, cx),
                None => self.open(&saved.target, &connect::Credentials::default(), None, cx),
            },
            SavedTabKind::Files => {
                let credentials = saved
                    .vault
                    .as_deref()
                    .map(|vault| self.saved_credentials(vault, &saved.target))
                    .unwrap_or_default();
                self.open_files(&saved.target, credentials, saved.vault.clone(), cx);
            }
        }
        if self.tabs.len() == before {
            return false;
        }
        if let Some(name) = &saved.name
            && let Some(tab) = self.tabs.last_mut()
        {
            tab.default_title = Some(std::mem::replace(&mut tab.title, name.clone().into()));
        }
        true
    }

    pub(super) fn start_rename(&mut self, index: usize, window: &mut Window, cx: &mut Context<Self>) {
        let Some(tab) = self.tabs.get(index) else {
            return;
        };
        let title = tab.title.clone();
        let input = cx.new(|cx| InputState::new(window, cx).default_value(title));
        let events = cx.subscribe_in(
            &input,
            window,
            |this, _, event: &InputEvent, _window, cx| match event {
                InputEvent::PressEnter { .. } => this.finish_rename(true, true, cx),
                // Focus went elsewhere: keep the name, do not pull focus back.
                InputEvent::Blur => this.finish_rename(true, false, cx),
                _ => {}
            },
        );
        input.update(cx, |state, cx| {
            state.focus(window, cx);
            state.select_all(window, cx);
        });
        self.renaming = Some(Renaming {
            index,
            input,
            _events: events,
        });
        cx.notify();
    }

    /// An empty name, or the default one, gives the tab its default title back.
    pub(super) fn finish_rename(&mut self, save: bool, refocus: bool, cx: &mut Context<Self>) {
        let Some(renaming) = self.renaming.take() else {
            return;
        };
        if save {
            let typed = renaming.input.read(cx).value().trim().to_string();
            if let Some(tab) = self.tabs.get_mut(renaming.index) {
                let default = tab.default_title.clone().unwrap_or_else(|| tab.title.clone());
                if typed.is_empty() || typed == default.as_ref() {
                    tab.title = default;
                    tab.default_title = None;
                } else {
                    tab.title = typed.into();
                    tab.default_title = Some(default);
                }
            }
            self.remember_tabs();
        }
        if refocus {
            self.focus_active(cx);
        }
        cx.notify();
    }

    pub(super) fn tabs_block(&self, cx: &mut Context<Self>) -> AnyElement {
        Self::section(t!("settings.tabs.title"), cx)
            .child(
                gpui_kit::component::checkbox::Checkbox::new("restore-tabs")
                    .small()
                    .label(t!("settings.tabs.restore").to_string())
                    .checked(self.settings.restore_tabs)
                    .on_click(cx.listener(|this, checked: &bool, _window, cx| {
                        this.set_restore_tabs(*checked, cx)
                    })),
            )
            .child(Self::hint(t!("settings.tabs.restore_note"), cx))
            .child(Self::hint(t!("settings.tabs.rename_note"), cx))
            .into_any_element()
    }
}
