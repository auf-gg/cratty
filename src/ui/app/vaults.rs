use super::*;
use crate::store::registry::{self, Registry, VaultEntry};
use crate::ui::ssh_import::{self, HostBook};
use crate::vault_session::{HostEntry, Unlocked};
use gpui_kit::component::menu::{DropdownMenu as _, PopupMenuItem};
use std::path::PathBuf;

/// Vault open in the app: its registry entry and its session.
///
/// `draft` — the vault has not been created yet and is not in the registry; it lives only
/// while the creation screen is open.
pub(super) struct VaultSlot {
    pub id: String,
    pub name: String,
    pub sync_folder: String,
    pub draft: bool,
    pub session: VaultSession,
}

impl VaultSlot {
    pub fn root(&self) -> PathBuf {
        self.session.store().root().to_path_buf()
    }

    pub fn entry(&self) -> VaultEntry {
        VaultEntry {
            id: self.id.clone(),
            name: self.name.clone(),
            path: self.root(),
            sync_folder: self.sync_folder.clone(),
        }
    }

    pub fn sync_path(&self) -> Option<PathBuf> {
        self.entry().sync_folder()
    }
}

impl AppView {
    pub(super) fn load_registry(
        file: Option<&std::path::Path>,
        legacy_root: &std::path::Path,
        settings: &mut Settings,
        warnings: &mut Vec<SharedString>,
    ) -> Vec<VaultEntry> {
        let path = file.unwrap_or_else(|| std::path::Path::new(""));
        let mut attempt = Registry::load(path, legacy_root, &settings.sync_folder);

        if let (Err(error), Some(file)) = (&attempt, file) {
            warnings.push(SharedString::from(format!("{error:#}")));
            let backup = file.with_extension("json.bad");
            match std::fs::rename(file, &backup) {
                Ok(()) => {
                    warnings.push(SharedString::from(
                        t!(
                            "vaults.list_corrupted_saved",
                            path = backup.display().to_string()
                        )
                        .to_string(),
                    ));
                    attempt = Registry::load(path, legacy_root, &settings.sync_folder);
                }
                Err(error) => warnings.push(SharedString::from(
                    t!("vaults.list_set_aside_failed", error = error.to_string()).to_string(),
                )),
            }
        }

        let loaded = match attempt {
            Ok(loaded) => loaded,
            Err(_) => return Vec::new(),
        };

        if loaded.dirty
            && let Some(file) = file
        {
            match loaded.registry.save(file) {
                Ok(()) => {
                    if !settings.sync_folder.trim().is_empty() {
                        settings.sync_folder.clear();
                        if let Err(error) = settings::save(settings) {
                            warnings.push(SharedString::from(format!("{error:#}")));
                        }
                    }
                }
                Err(error) => warnings.push(SharedString::from(
                    t!("vaults.list_write_failed", error = format!("{error:#}")).to_string(),
                )),
            }
        }
        loaded.registry.vaults
    }

    pub(super) fn vault(&self) -> &VaultSession {
        &self.vaults[self.current].session
    }

    pub(super) fn current_id(&self) -> String {
        self.vaults[self.current].id.clone()
    }

    pub(super) fn vault_ix(&self, id: &str) -> Option<usize> {
        self.vaults.iter().position(|slot| slot.id == id)
    }

    pub(super) fn vault_name(&self, id: &str) -> String {
        self.vault_ix(id)
            .map(|ix| self.vaults[ix].name.clone())
            .unwrap_or_default()
    }

    pub(super) fn unlocked_of(&self, id: &str) -> Option<&Unlocked> {
        self.vault_ix(id)
            .and_then(|ix| self.vaults[ix].session.unlocked())
    }

    pub(super) fn current_unlocked(&self) -> Option<&Unlocked> {
        self.vault().unlocked()
    }

    pub(super) fn any_unlocked(&self) -> bool {
        self.vaults
            .iter()
            .any(|slot| slot.session.state().is_unlocked())
    }

    pub(super) fn unlocked_slots(&self) -> impl Iterator<Item = &VaultSlot> {
        self.vaults
            .iter()
            .filter(|slot| slot.session.state().is_unlocked())
    }

    pub(super) fn listed(&self) -> impl Iterator<Item = (usize, &VaultSlot)> {
        self.vaults
            .iter()
            .enumerate()
            .filter(|(_, slot)| !slot.draft)
    }

    fn search_order(&self) -> impl Iterator<Item = usize> + '_ {
        std::iter::once(self.current).chain((0..self.vaults.len()).filter(|ix| *ix != self.current))
    }

    pub(super) fn touch_all(&mut self) {
        let now = std::time::Instant::now();
        for slot in &mut self.vaults {
            slot.session.touch(now);
        }
    }

    /// Looks up a saved host. With `origin`, only in that vault; without it,
    /// in all open ones, starting from the selected one.
    pub(super) fn find_host(
        &self,
        origin: Option<&str>,
        target: &str,
    ) -> Option<(String, HostEntry)> {
        if let Some(id) = origin
            && let Some(ix) = self.vault_ix(id)
        {
            return self.vaults[ix]
                .session
                .unlocked()?
                .find_by_target(target)
                .map(|entry| (id.to_owned(), entry));
        }
        self.search_order().find_map(|ix| {
            let slot = &self.vaults[ix];
            slot.session
                .unlocked()?
                .find_by_target(target)
                .map(|entry| (slot.id.clone(), entry))
        })
    }

    /// The vault where this host's entry should be written.
    pub(super) fn vault_for_write(&self, origin: Option<&str>, target: &str) -> Option<String> {
        if let Some((id, _)) = self.find_host(origin, target) {
            return Some(id);
        }
        if let Some(id) = origin
            && self.unlocked_of(id).is_some()
        {
            return Some(id.to_owned());
        }
        if self.vault().state().is_unlocked() {
            return Some(self.current_id());
        }
        self.unlocked_slots().next().map(|slot| slot.id.clone())
    }

    pub(super) fn can_save_for(&self, origin: Option<&str>) -> bool {
        match origin.and_then(|id| self.vault_ix(id)) {
            Some(ix) => self.vaults[ix].session.state().is_unlocked(),
            None => self.any_unlocked(),
        }
    }

    pub(super) fn persist<F>(&mut self, id: &str, cx: &mut Context<Self>, edit: F)
    where
        F: FnOnce(&mut Unlocked, &VaultStore) -> anyhow::Result<()>,
    {
        let Some(ix) = self.vault_ix(id) else {
            self.error = Some(t!("vaults.not_found").to_string().into());
            cx.notify();
            return;
        };
        let store = VaultStore::new(self.vaults[ix].root());
        let slot = &mut self.vaults[ix];
        let Some(unlocked) = slot.session.unlocked_mut() else {
            self.error = Some(t!("vaults.locked").to_string().into());
            cx.notify();
            return;
        };

        self.error = edit(unlocked, &store)
            .err()
            .map(|error| SharedString::from(format!("{error:#}")));
        slot.session.touch(std::time::Instant::now());
        cx.notify();
    }

    pub(super) fn persist_current<F>(&mut self, cx: &mut Context<Self>, edit: F)
    where
        F: FnOnce(&mut Unlocked, &VaultStore) -> anyhow::Result<()>,
    {
        let id = self.current_id();
        self.persist(&id, cx, edit);
    }

    pub(super) fn stage_for(&self, ix: usize) -> Option<Stage> {
        let state = self.vaults[ix].session.state();
        if state.is_unlocked() {
            None
        } else if state.is_absent() {
            Some(Stage::Create)
        } else {
            Some(Stage::Unlock)
        }
    }

    fn recovery_pending(&self) -> bool {
        matches!(self.stage, Some(Stage::Recovery { .. }))
    }

    fn warn_recovery_pending(&mut self, cx: &mut Context<Self>) {
        self.vault_error = Some(t!("vaults.recovery_pending").to_string().into());
        self.showing_page = true;
        self.section = Section::Hosts;
        self.editor_open = false;
        cx.notify();
    }

    pub(super) fn select_vault(&mut self, id: &str, window: &mut Window, cx: &mut Context<Self>) {
        let Some(ix) = self.vault_ix(id) else {
            return;
        };
        if ix != self.current && self.recovery_pending() {
            self.warn_recovery_pending(cx);
            return;
        }

        self.current = ix;
        self.stage = self.stage_for(ix);
        self.vault_error = None;
        self.reveal = None;
        self.importing = None;
        self.proxy_form.editing = None;
        self.proxy_form.open = false;
        self.snippet_form.editing = None;
        self.snippet_form.open = false;
        self.sync_status = None;
        self.sync_error = None;

        let folder = self.vaults[ix].sync_folder.clone();
        self.sync_input
            .update(cx, |state, cx| state.set_value(folder, window, cx));

        if !self.vault_busy {
            let keep = self.current_id();
            self.vaults.retain(|slot| !slot.draft || slot.id == keep);
            self.current = self.vault_ix(&keep).unwrap_or(0);
        }
        cx.notify();
    }

    pub(super) fn open_vault_screen(
        &mut self,
        id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.select_vault(id, window, cx);
        if self.current_id() == id {
            self.section = Section::Hosts;
            self.showing_page = true;
            self.editor_open = false;
        }
        cx.notify();
    }

    pub(super) fn make_draft(&self, name: &str) -> VaultSlot {
        let base = self.base_dir.clone().unwrap_or_else(|| PathBuf::from("."));
        let entry = Registry::new_entry(&base, name).unwrap_or_else(|_| VaultEntry {
            id: "draft".into(),
            name: name.to_owned(),
            path: base.join(registry::VAULTS_DIR).join("draft"),
            sync_folder: String::new(),
        });
        VaultSlot {
            id: entry.id,
            name: entry.name,
            sync_folder: String::new(),
            draft: true,
            session: VaultSession::open(
                VaultStore::new(entry.path),
                self.settings.autolock_timeout(),
            ),
        }
    }

    pub(super) fn begin_new_vault(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.vault_busy {
            return;
        }
        if self.recovery_pending() {
            self.warn_recovery_pending(cx);
            return;
        }

        let first = self.vaults.iter().all(|slot| slot.draft);
        let existing = self
            .vaults
            .iter()
            .find(|slot| slot.draft)
            .map(|s| s.id.clone());
        let id = match existing {
            Some(id) => id,
            None => {
                let name = if first {
                    registry::first_vault_name()
                } else {
                    let taken: Vec<String> =
                        self.vaults.iter().map(|slot| slot.name.clone()).collect();
                    registry::default_name(&taken)
                };
                let draft = self.make_draft(&name);
                let id = draft.id.clone();
                self.vaults.push(draft);
                id
            }
        };

        self.select_vault(&id, window, cx);
        let name = self.vault_name(&id);
        self.vault_form
            .name
            .update(cx, |state, cx| state.set_value(name, window, cx));
        for input in [&self.vault_form.password, &self.vault_form.repeat] {
            input.update(cx, |state, cx| state.set_value("", window, cx));
        }
        self.vault_form.import = !self.import_pending().is_empty();
        self.section = Section::Hosts;
        self.showing_page = true;
        self.editor_open = false;
        cx.notify();
    }

    pub(super) fn cancel_new_vault(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.vault_busy {
            return;
        }
        let Some(id) = self.listed().next().map(|(_, slot)| slot.id.clone()) else {
            return;
        };
        self.select_vault(&id, window, cx);
    }

    /// Offer to import the old hosts.json — only while there is no
    /// created vault yet.
    pub(super) fn import_pending(&self) -> &[HostRecord] {
        if self.vaults.iter().all(|slot| slot.draft) {
            &self.pending_import
        } else {
            &[]
        }
    }

    /// Reconciles the name from the registry with the encrypted name entry. The entry wins:
    /// it comes from other devices. No entry: create it from the registry,
    /// so the name propagates to other devices.
    pub(super) fn reconcile_vault_name(&mut self, id: &str) {
        let Some(ix) = self.vault_ix(id) else {
            return;
        };
        let store = VaultStore::new(self.vaults[ix].root());
        let local = self.vaults[ix].name.clone();
        let Some(unlocked) = self.vaults[ix].session.unlocked_mut() else {
            return;
        };
        match unlocked.vault_name() {
            Some(name) if name != local => {
                self.vaults[ix].name = name;
                self.save_registry();
            }
            Some(_) => {}
            None => {
                if let Err(error) = unlocked.set_vault_name(&store, &local) {
                    self.vault_error = Some(SharedString::from(
                        t!("vaults.name_save_failed", error = format!("{error:#}")).to_string(),
                    ));
                }
            }
        }
    }

    pub(super) fn save_registry(&mut self) {
        let Some(file) = self.registry_file.clone() else {
            return;
        };
        let registry = Registry {
            vaults: self.listed().map(|(_, slot)| slot.entry()).collect(),
        };
        if let Err(error) = registry.save(&file) {
            self.vault_error = Some(SharedString::from(
                t!("vaults.list_write_failed", error = format!("{error:#}")).to_string(),
            ));
        }
    }

    pub(super) fn lock_vault_by_id(&mut self, id: &str, cx: &mut Context<Self>) {
        let Some(ix) = self.vault_ix(id) else {
            return;
        };
        self.reveal = None;
        self.sync_watches.remove(id);
        self.refuse_all_signs();
        if ix == self.current {
            self.proxy_form.editing = None;
            self.vault_error = None;
        }
        self.vaults[ix].session.lock(None);
        if ix == self.current {
            self.stage = self.stage_for(ix);
        }
        self.sync_can_save_secrets(cx);
        cx.notify();
    }

    pub(super) fn lock_all(&mut self, cx: &mut Context<Self>) {
        let ids: Vec<String> = self.unlocked_slots().map(|slot| slot.id.clone()).collect();
        for id in ids {
            self.lock_vault_by_id(&id, cx);
        }
    }

    pub(super) fn ask_delete_vault(&mut self, id: &str, cx: &mut Context<Self>) {
        if self.vault_ix(id).is_some() {
            self.confirm_delete = Some(id.to_owned());
            cx.notify();
        }
    }

    pub(super) fn cancel_delete_vault(&mut self, cx: &mut Context<Self>) {
        if self.confirm_delete.take().is_some() {
            cx.notify();
        }
    }

    pub(super) fn delete_vault(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(id) = self.confirm_delete.take() else {
            return;
        };
        let Some(ix) = self.vault_ix(&id) else {
            return;
        };

        let root = self.vaults[ix].root();
        let keychain_id = self.vaults[ix]
            .session
            .store()
            .read_account()
            .ok()
            .map(|account| account.vault_id.as_str().to_owned());

        self.lock_vault_by_id(&id, cx);
        self.sync_tasks.remove(&id);
        self.syncing.remove(&id);
        self.os_unlocking.retain(|known| *known != id);

        if let Err(error) = crate::store::remove_vault(&root) {
            self.error = Some(SharedString::from(format!("{error:#}")));
            self.vault_error = self.error.clone();
            cx.notify();
            return;
        }

        let mut leftover = None;
        if let Some(keychain_id) = keychain_id {
            use crate::keychain::KeyStash as _;
            if let Err(error) = OsKeychain.delete(&keychain_id) {
                leftover = Some(
                    t!("vaults.deleted_key_remains", error = format!("{error:#}")).to_string(),
                );
            }
        }

        let was_current = ix == self.current;
        self.vaults.remove(ix);
        self.save_registry();

        if self.vaults.is_empty() {
            let draft = self.make_draft(&registry::first_vault_name());
            self.vaults.push(draft);
        }
        if ix < self.current {
            self.current -= 1;
        }

        if self.form.vault == id {
            self.form.vault = String::new();
            self.form.editing = None;
            self.editor_open = false;
        }
        if was_current || self.current >= self.vaults.len() {
            let target = self
                .listed()
                .next()
                .map(|(_, slot)| slot.id.clone())
                .unwrap_or_else(|| self.vaults[0].id.clone());
            self.current = self.vault_ix(&target).unwrap_or(0);
            self.select_vault(&target, window, cx);
        }
        if self.vaults[self.current].draft {
            self.begin_new_vault(window, cx);
        }

        self.vault_error = leftover.map(SharedString::from);
        cx.notify();
    }

    pub(super) fn import_ssh_config(&mut self, id: &str, cx: &mut Context<Self>) {
        struct Book<'a> {
            unlocked: &'a mut Unlocked,
            store: &'a VaultStore,
        }

        impl HostBook for Book<'_> {
            fn find(&self, target: &str) -> Option<proto::RecordId> {
                self.unlocked.find_by_target(target).map(|entry| entry.id)
            }

            fn put(&mut self, host: HostRecord) -> anyhow::Result<proto::RecordId> {
                self.unlocked.upsert_host(self.store, host)
            }
        }

        let Some(ix) = self.vault_ix(id) else {
            return;
        };
        let name = self.vaults[ix].name.clone();
        let text = connect::ssh_config_path()
            .ok_or_else(|| t!("vaults.ssh_dir_unknown").to_string())
            .and_then(|path| {
                std::fs::read_to_string(&path)
                    .map_err(|error| {
                        t!(
                            "vaults.read_failed",
                            path = path.display().to_string(),
                            error = error.to_string()
                        )
                        .to_string()
                    })
            });
        let text = match text {
            Ok(text) => text,
            Err(error) => {
                self.import_notice = Some(SharedString::from(
                    t!("vaults.import_error", name = name, error = error).to_string(),
                ));
                cx.notify();
                return;
            }
        };

        let store = VaultStore::new(self.vaults[ix].root());
        let slot = &mut self.vaults[ix];
        let Some(unlocked) = slot.session.unlocked_mut() else {
            self.import_notice = Some(SharedString::from(
                t!("vaults.import_locked", name = name).to_string(),
            ));
            cx.notify();
            return;
        };

        let report = ssh_import::import(
            &text,
            &mut Book {
                unlocked,
                store: &store,
            },
        );
        slot.session.touch(std::time::Instant::now());
        self.import_notice = Some(SharedString::from(
            t!("vaults.import_summary", name = name, summary = report.summary()).to_string(),
        ));
        cx.notify();
    }

    pub(super) fn vault_picker(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        if self.listed().count() < 2 {
            return None;
        }
        let muted = cx.theme().muted_foreground;
        Some(
            h_flex()
                .px_6()
                .pb_2()
                .gap_1()
                .flex_wrap()
                .items_center()
                .child(Label::new(t!("vaults.picker_label").to_string()).text_xs().text_color(muted))
                .children(self.listed().map(|(ix, slot)| {
                    let id = slot.id.clone();
                    let unlocked = slot.session.state().is_unlocked();
                    Button::new(SharedString::from(format!("vault-pick-{}", slot.id)))
                        .ghost()
                        .small()
                        .selected(ix == self.current)
                        .icon(
                            Icon::empty()
                                .path(if unlocked {
                                    "icons/lock-open.svg"
                                } else {
                                    "icons/lock.svg"
                                })
                                .text_color(muted),
                        )
                        .label(SharedString::from(shorten(&slot.name, ROW_TITLE_CHARS)))
                        .on_click(cx.listener(move |this, _, window, cx| {
                            this.select_vault(&id, window, cx)
                        }))
                }))
                .into_any_element(),
        )
    }

    pub(super) fn vault_header(&self, ix: usize, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let slot = &self.vaults[ix];
        let id = slot.id.clone();
        let unlocked = slot.session.state().is_unlocked();
        let view = cx.entity();

        let (lock_id, name_id, menu_id) = (id.clone(), id.clone(), id.clone());
        h_flex()
            .h(px(26.))
            .px_1()
            .gap_1()
            .items_center()
            .child(
                Button::new(SharedString::from(format!("vault-lock-{id}")))
                    .ghost()
                    .xsmall()
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
                        t!("vaults.lock_tooltip").to_string()
                    } else {
                        t!("vaults.unlock_tooltip").to_string()
                    })
                    .on_click(cx.listener(move |this, _, window, cx| {
                        if unlocked {
                            this.lock_vault_by_id(&lock_id, cx);
                        } else {
                            this.open_vault_screen(&lock_id, window, cx);
                        }
                    })),
            )
            .child(
                div()
                    .id(SharedString::from(format!("vault-name-{id}")))
                    .flex_1()
                    .min_w(px(0.))
                    .overflow_hidden()
                    .cursor_pointer()
                    .child(
                        Label::new(SharedString::from(slot.name.clone()))
                            .text_xs()
                            .font_medium()
                            .text_color(theme.muted_foreground)
                            .line_clamp(1)
                            .text_ellipsis(),
                    )
                    .on_click(cx.listener(move |this, _, window, cx| {
                        if unlocked {
                            this.select_vault(&name_id, window, cx);
                        } else {
                            this.open_vault_screen(&name_id, window, cx);
                        }
                    })),
            )
            .child(
                Button::new(SharedString::from(format!("vault-menu-{id}")))
                    .ghost()
                    .xsmall()
                    .icon(Icon::empty().path("icons/ellipsis.svg"))
                    .tooltip(t!("vaults.actions_tooltip").to_string())
                    .dropdown_menu(move |menu, _window, _cx| {
                        let import = {
                            let (view, id) = (view.clone(), menu_id.clone());
                            PopupMenuItem::new(t!("vaults.menu_import").to_string())
                                .disabled(!unlocked)
                                .on_click(move |_, _window, cx| {
                                    view.update(cx, |this, cx| this.import_ssh_config(&id, cx));
                                })
                        };
                        let toggle = {
                            let (view, id) = (view.clone(), menu_id.clone());
                            PopupMenuItem::new(if unlocked {
                                t!("vaults.menu_lock").to_string()
                            } else {
                                t!("vaults.menu_unlock").to_string()
                            })
                            .on_click(move |_, window, cx| {
                                view.update(cx, |this, cx| {
                                    if unlocked {
                                        this.lock_vault_by_id(&id, cx);
                                    } else {
                                        this.open_vault_screen(&id, window, cx);
                                    }
                                });
                            })
                        };
                        let edit = {
                            let (view, id) = (view.clone(), menu_id.clone());
                            PopupMenuItem::new(t!("vaults.menu_settings").to_string()).on_click(
                                move |_, window, cx| {
                                    view.update(cx, |this, cx| {
                                        this.open_vault_editor(&id, window, cx)
                                    });
                                },
                            )
                        };
                        let delete = {
                            let (view, id) = (view.clone(), menu_id.clone());
                            PopupMenuItem::new(t!("vaults.menu_delete").to_string()).on_click(
                                move |_, _window, cx| {
                                    view.update(cx, |this, cx| this.ask_delete_vault(&id, cx));
                                },
                            )
                        };
                        menu.item(edit)
                            .item(import)
                            .item(toggle)
                            .item(PopupMenuItem::separator())
                            .item(delete)
                    }),
            )
            .into_any_element()
    }

    pub(super) fn new_vault_row(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        Self::rail_row("rail-new-vault".into(), false, cx)
            .h(px(30.))
            .child(
                Icon::new(IconName::Plus)
                    .small()
                    .text_color(theme.muted_foreground),
            )
            .child(Label::new(t!("vaults.new_vault").to_string()).text_sm())
            .on_click(cx.listener(|this, _, window, cx| this.begin_new_vault(window, cx)))
            .into_any_element()
    }

    pub(super) fn import_notice_box(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let notice = self.import_notice.clone()?;
        let theme = cx.theme().clone();
        Some(
            v_flex()
                .p_2()
                .gap_1()
                .rounded_md()
                .border_1()
                .border_color(theme.border)
                .child(
                    Label::new(notice)
                        .text_xs()
                        .text_color(theme.muted_foreground),
                )
                .child(
                    h_flex().child(
                        Button::new("import-notice-close")
                            .ghost()
                            .xsmall()
                            .label(t!("vaults.close").to_string())
                            .on_click(cx.listener(|this, _, _window, cx| {
                                this.import_notice = None;
                                cx.notify();
                            })),
                    ),
                )
                .into_any_element(),
        )
    }

    pub(super) fn delete_vault_dialog(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let id = self.confirm_delete.clone()?;
        let name = self.vault_name(&id);
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
                            Label::new(SharedString::from(
                                t!("vaults.delete_title", name = name).to_string(),
                            ))
                            .font_semibold(),
                        )
                        .child(
                            Label::new(t!("vaults.delete_warning").to_string())
                            .text_sm()
                            .text_color(theme.danger),
                        )
                        .child(
                            Label::new(t!("vaults.delete_sessions").to_string())
                                .text_xs()
                                .text_color(theme.muted_foreground),
                        )
                        .child(
                            h_flex()
                                .gap_2()
                                .child(
                                    Button::new("vault-delete-confirm")
                                        .danger()
                                        .label(t!("vaults.delete_confirm").to_string())
                                        .on_click(cx.listener(|this, _, window, cx| {
                                            this.delete_vault(window, cx)
                                        })),
                                )
                                .child(
                                    Button::new("vault-delete-cancel")
                                        .outline()
                                        .label(t!("vaults.cancel").to_string())
                                        .on_click(cx.listener(|this, _, _window, cx| {
                                            this.cancel_delete_vault(cx)
                                        })),
                                ),
                        ),
                )
                .into_any_element(),
        )
    }
}
