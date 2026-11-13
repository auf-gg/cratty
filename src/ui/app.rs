use gpui_kit::component::{
    ActiveTheme, Disableable, Icon, IconName, Selectable, Sizable, StyledExt, TitleBar,
    button::{Button, ButtonVariants},
    h_flex,
    input::{Input, InputEvent, InputState},
    label::Label,
    scroll::ScrollableElement,
    v_flex,
};
use gpui_kit::{
    AnyElement, App, Bounds, Context, Entity, Focusable, KeyBinding, MouseButton, NoAction, Render,
    Result, SharedString, Subscription, Window, WindowBounds, WindowOptions, actions, div, img,
    prelude::*, px, size,
};

mod ai_ui;
mod fonts_ui;
mod groups_ui;
mod icons_ui;
mod key_backup;
mod key_tools;
mod keys_ui;
mod kit;
mod panes_ui;
mod ports_ui;
mod proxy_ui;
mod rail;
mod session_panel;
mod settings_ui;
mod shell;
mod snippets_ui;
mod sync_ui;
mod tabs_ui;
mod theme_ui;
mod update_ui;
mod vault_edit;
mod vault_flow;
mod vaults;

use rust_i18n::t;
use crate::agent as ssh_agent;
use crate::keychain::OsKeychain;
use crate::ssh::{PtySize, spawn_local, spawn_ssh};
use crate::store::registry;
use crate::store::{VaultStore, migrate};
use crate::ui::connect::{self, HostSettings, KeyEntry, Target};
use crate::ui::settings::{self, Settings};
use crate::ui::terminal::{TerminalEvent, TerminalView};
use crate::ui::vault_ui::{self, Stage};
use crate::vault_session::StoredKey;
use crate::vault_session::VaultSession;
use futures::StreamExt;
use proto::{HostAuth, HostRecord};
use vaults::VaultSlot;
use zeroize::Zeroize;

actions!(app, [Quit, NewTab, CloseTab, NextTab, PrevTab, TogglePanel]);

const DEFAULT_PTY: PtySize = PtySize {
    cols: 100,
    rows: 30,
    pixel_width: 0,
    pixel_height: 0,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Section {
    Hosts,
    Keys,
    Proxies,
    Snippets,
    Settings,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SettingsTab {
    General,
    Security,
    Sync,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Edge {
    Rail,
    Panel,
    Editor,
}

/// Width of the resize handle over a panel border.
const EDGE_HANDLE: f32 = 6.0;

struct EdgeDrag;

impl Render for EdgeDrag {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        gpui_kit::Empty
    }
}

struct SessionTab {
    title: SharedString,
    /// Title before the user renamed the tab; `None` while it has its own.
    default_title: Option<SharedString>,
    vault: Option<String>,
    kind: TabKind,
    request: connect::Request,
    credentials: connect::Credentials,
    /// Local tab without a vault: reconnects into a new PTY,
    /// rather than to the SSH address from `request`.
    local: bool,
    /// AI agents may use this tab's connection (see `crate::mcp`). Kept on reconnect.
    agents: Option<ai_ui::AgentAccess>,
    /// The conversation of the AI tab. Kept on reconnect, like the access it uses.
    chat: Option<ai_ui::ChatPanel>,
}

enum TabKind {
    Terminal {
        view: Entity<TerminalView>,
        _events: Subscription,
        files: Option<FilesPanel>,
        editor: Option<DockedEditor>,
        split: panes_ui::Split,
    },
    Files {
        view: Entity<crate::ui::files::FilesView>,
        _events: Subscription,
    },
    Editor {
        view: Entity<crate::ui::editor::EditorView>,
        _events: Subscription,
    },
}

struct FilesPanel {
    view: Entity<crate::ui::files::FilesView>,
    _events: Subscription,
    visible: bool,
}

struct DockedEditor {
    view: Entity<crate::ui::editor::EditorView>,
    _events: Subscription,
    expanded: bool,
}

impl SessionTab {
    fn terminal(&self) -> Option<&Entity<TerminalView>> {
        match &self.kind {
            TabKind::Terminal { view, .. } => Some(view),
            _ => None,
        }
    }

    fn is_closed(&self, cx: &App) -> bool {
        match &self.kind {
            TabKind::Terminal { view, .. } => view.read(cx).is_closed(),
            TabKind::Files { view, .. } => view.read(cx).is_closed(),
            TabKind::Editor { .. } => false,
        }
    }

    fn editor(&self) -> Option<&Entity<crate::ui::editor::EditorView>> {
        match &self.kind {
            TabKind::Editor { view, .. } => Some(view),
            _ => None,
        }
    }

    fn is_files(&self) -> bool {
        matches!(self.kind, TabKind::Files { .. })
    }
}

pub struct AppView {
    tabs: Vec<SessionTab>,
    active: Option<usize>,
    /// Tabs of the previous run waiting for their vault to be unlocked.
    pending_tabs: Vec<settings::SavedTab>,
    /// Tabs of the previous run are being opened: do not write the list halfway.
    reopening: bool,
    renaming: Option<tabs_ui::Renaming>,

    section: Section,
    /// The unpinned panel is slid out because the mouse is at the window edge.
    rail_peek: bool,
    panel_peek: bool,
    /// Tiling WM: we don't draw our own top bar.
    tiling: bool,
    info_tab: session_panel::InfoTab,
    showing_page: bool,
    editor_open: bool,
    settings_tab: SettingsTab,

    form: Form,
    proxy_form: proxy_ui::ProxyForm,
    snippet_form: snippets_ui::SnippetForm,
    snippets_open: bool,
    split_menu: bool,
    _subscriptions: Vec<Subscription>,

    vaults: Vec<VaultSlot>,
    current: usize,
    registry_file: Option<std::path::PathBuf>,
    base_dir: Option<std::path::PathBuf>,
    os_unlocking: Vec<String>,
    os_tasks: Vec<gpui_kit::Task<()>>,
    confirm_delete: Option<String>,
    /// Host (vault, address) whose deletion is awaiting confirmation.
    confirm_forget: Option<(String, String)>,
    /// Host currently being dragged in the left panel: its vault and whether it has a group.
    dragging_host: Option<(String, bool)>,
    vault_editor: Option<vault_edit::VaultEditor>,
    /// "Edit group" dialog opened from the group menu in the left panel.
    group_editor: Option<groups_ui::GroupEditor>,
    /// Host or group icon picker dialog.
    icon_picker: Option<icons_ui::IconPicker>,
    /// selfh.st catalog: from cache and from the server.
    selfhst: icons_ui::SelfhstState,
    icon_images: icons_ui::IconImages,
    pending_icons: icons_ui::PendingIcons,
    /// Theme under the cursor in settings: shown in the preview.
    theme_preview: Option<String>,
    /// Outcome of key actions in the host form (created, error, install tab).
    key_notice: Option<SharedString>,
    font_pickers: fonts_ui::FontPickers,
    /// Watches the Dux Shell colors file: when the wallpaper changes, so does the palette.
    _dux_watch: Option<gpui_kit::Task<()>>,
    import_notice: Option<SharedString>,
    stage: Option<Stage>,
    vault_form: VaultForm,
    pending_import: Vec<HostRecord>,
    vault_warnings: Vec<SharedString>,
    autolock_task: Option<gpui_kit::Task<()>>,
    vault_error: Option<SharedString>,
    reveal: Option<Reveal>,
    stored_rejected: Option<Rejected>,
    vault_busy: bool,
    vault_task: Option<gpui_kit::Task<()>>,
    keys: Vec<KeyEntry>,
    agent: Option<ssh_agent::Running>,
    agent_task: Option<gpui_kit::Task<()>>,
    agent_error: Option<SharedString>,
    sign_queue: std::collections::VecDeque<PendingSign>,
    /// MCP server for AI agents: started when agent access is first allowed on a tab.
    mcp: Option<crate::mcp::Running>,
    mcp_task: Option<gpui_kit::Task<()>>,
    mcp_error: Option<SharedString>,
    /// Agent calls waiting for the user's approval, oldest first.
    agent_queue: std::collections::VecDeque<ai_ui::PendingCall>,
    /// Agents found on this computer for the AI tab: looked for once, in the background.
    agent_kinds: Option<Vec<(crate::acp::AgentKind, Result<crate::acp::AgentCommand, crate::acp::agents::Missing>)>>,
    agent_scan: Option<gpui_kit::Task<()>>,
    importing: Option<PendingImport>,
    sync_input: Entity<InputState>,
    sync_status: Option<SharedString>,
    sync_error: Option<SharedString>,
    syncing: std::collections::HashSet<String>,
    sync_tasks: std::collections::HashMap<String, gpui_kit::Task<()>>,
    sync_watches: std::collections::HashMap<String, gpui_kit::Task<()>>,
    settings: Settings,
    error: Option<SharedString>,
    updater: update_ui::UpdateState,
}

struct PendingSign {
    ask: Box<ssh_agent::SignAsk>,
    key_title: SharedString,
    target: SignTarget,
}

enum SignTarget {
    Proven {
        name: Option<SharedString>,
        fingerprint: SharedString,
        forwarding: bool,
    },
    Unknown,
}

struct PendingImport {
    path: std::path::PathBuf,
    name: SharedString,
    encrypted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Reveal {
    Confirming {
        vault: String,
        target: String,
        copy: bool,
    },
    Showing {
        vault: String,
        target: String,
        text: SharedString,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Rejected {
    vault: Option<String>,
    target: String,
}

struct VaultForm {
    name: Entity<InputState>,
    password: Entity<InputState>,
    repeat: Entity<InputState>,
    code: Entity<InputState>,
    passphrase: Entity<InputState>,
    import: bool,
    remember: bool,
    notice: Option<SharedString>,
}

struct Form {
    vault: String,
    editing: Option<String>,
    line: Entity<InputState>,
    label: Entity<InputState>,
    group: Entity<InputState>,
    /// Host icon: built-in or `selfhst:<name>`; empty means default.
    icon: String,
    host: Entity<InputState>,
    port: Entity<InputState>,
    user: Entity<InputState>,
    password: Entity<InputState>,
    key_path: Entity<InputState>,
    auth: HostAuth,
    via: Vec<proto::RecordId>,
    forwards: Vec<proto::PortForward>,
    forward_draft: ports_ui::ForwardDraft,
}

impl AppView {
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let field = |placeholder: SharedString, cx: &mut Context<Self>, window: &mut Window| {
            cx.new(|cx| InputState::new(window, cx).placeholder(placeholder))
        };

        let line = field(t!("app.search_or_address").into(), cx, window);
        let label = field(t!("app.label_example").into(), cx, window);
        let group = field(t!("app.no_group").into(), cx, window);
        let host = field(t!("app.host_placeholder").into(), cx, window);
        let port = field("22".into(), cx, window);
        let user = field(t!("app.username").into(), cx, window);
        let password = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder(t!("app.password"))
                .masked(true)
        });
        let key_path = field(t!("app.key_path").into(), cx, window);
        let forward_draft = ports_ui::ForwardDraft::new(window, cx);
        let snippet_form = snippets_ui::SnippetForm::new(window, cx);
        let proxy_form = proxy_ui::ProxyForm::new(
            field(t!("app.proxy_label_example").into(), cx, window),
            field(t!("app.host_placeholder").into(), cx, window),
            field("1080".into(), cx, window),
            field(t!("app.optional").into(), cx, window),
            cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder(t!("app.password"))
                    .masked(true)
            }),
        );

        let mut subscriptions: Vec<Subscription> = vec![
            cx.subscribe(&line, |this, _, event: &InputEvent, cx| match event {
                InputEvent::PressEnter { .. } => this.quick_connect(cx),
                InputEvent::Change => cx.notify(),
                _ => {}
            }),
            // "System" mode: the OS switched between light and dark appearance.
            cx.observe_window_appearance(window, |this, window, cx| {
                if this.settings.appearance() == crate::ui::theme::Appearance::System {
                    crate::ui::theme::apply(&this.settings, Some(window), cx);
                    this.apply_appearance(cx);
                }
            }),
        ];

        let vault_password = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder(t!("app.master_password"))
                .masked(true)
        });
        let vault_repeat = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder(t!("app.repeat_master_password"))
                .masked(true)
        });
        let vault_code = field(t!("app.vault_code").into(), cx, window);
        let vault_name = field(t!("app.vault_name_example").into(), cx, window);
        let sync_input = field(t!("app.shared_folder").into(), cx, window);
        let key_passphrase = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder(t!("app.key_passphrase"))
                .masked(true)
        });

        for input in [&vault_password, &vault_repeat, &vault_code, &vault_name] {
            subscriptions.push(cx.subscribe_in(
                input,
                window,
                |this, _, event: &InputEvent, window, cx| {
                    if matches!(event, InputEvent::PressEnter { .. }) {
                        this.vault_submit(window, cx);
                    }
                },
            ));
        }

        let mut settings = settings::load();
        let (legacy_path, pending_import) = VaultSession::legacy_hosts();
        let _ = legacy_path;

        let mut vault_warnings: Vec<SharedString> = crate::platform::harden_process()
            .into_iter()
            .map(SharedString::from)
            .collect();

        let base_dir = VaultStore::default_base();
        let registry_file = base_dir.as_ref().map(|base| base.join(registry::FILE_NAME));
        let legacy_root =
            VaultStore::default_root().unwrap_or_else(|| std::path::PathBuf::from("vault"));
        let entries = Self::load_registry(
            registry_file.as_deref(),
            &legacy_root,
            &mut settings,
            &mut vault_warnings,
        );

        let timeout = settings.autolock_timeout();
        let mut vaults: Vec<VaultSlot> = entries
            .into_iter()
            .map(|entry| VaultSlot {
                id: entry.id,
                name: entry.name,
                sync_folder: entry.sync_folder,
                draft: false,
                session: VaultSession::open(VaultStore::new(entry.path), timeout),
            })
            .collect();

        let mut this = Self {
            tabs: Vec::new(),
            active: None,
            pending_tabs: Vec::new(),
            reopening: false,
            renaming: None,
            section: Section::Hosts,
            rail_peek: false,
            panel_peek: false,
            tiling: crate::platform::tiling_wm(),
            info_tab: session_panel::InfoTab::Info,
            showing_page: true,
            editor_open: false,
            settings_tab: SettingsTab::General,
            form: Form {
                vault: String::new(),
                editing: None,
                line,
                label,
                group,
                icon: String::new(),
                host,
                port,
                user,
                password,
                key_path,
                auth: HostAuth::Auto,
                via: Vec::new(),
                forwards: Vec::new(),
                forward_draft,
            },
            proxy_form,
            snippet_form,
            snippets_open: false,
            split_menu: false,
            _subscriptions: subscriptions,
            vaults: Vec::new(),
            current: 0,
            registry_file,
            base_dir,
            os_unlocking: Vec::new(),
            os_tasks: Vec::new(),
            confirm_delete: None,
            confirm_forget: None,
            dragging_host: None,
            vault_editor: None,
            group_editor: None,
            icon_picker: None,
            selfhst: Default::default(),
            icon_images: Default::default(),
            pending_icons: Default::default(),
            theme_preview: None,
            key_notice: None,
            font_pickers: fonts_ui::FontPickers::new(&settings, window, cx),
            _dux_watch: Self::watch_dux(window, cx),
            import_notice: None,
            stage: None,
            vault_form: VaultForm {
                name: vault_name,
                password: vault_password,
                repeat: vault_repeat,
                code: vault_code,
                passphrase: key_passphrase,
                import: false,
                remember: false,
                notice: None,
            },
            pending_import,
            vault_warnings,
            autolock_task: None,
            vault_error: None,
            reveal: None,
            stored_rejected: None,
            vault_busy: false,
            vault_task: None,
            keys: connect::list_keys(),
            agent: None,
            agent_task: None,
            agent_error: None,
            sign_queue: std::collections::VecDeque::new(),
            mcp: None,
            mcp_task: None,
            mcp_error: None,
            agent_queue: std::collections::VecDeque::new(),
            agent_kinds: None,
            agent_scan: None,
            importing: None,
            sync_input,
            sync_status: None,
            sync_error: None,
            syncing: std::collections::HashSet::new(),
            sync_tasks: std::collections::HashMap::new(),
            sync_watches: std::collections::HashMap::new(),
            settings,
            error: None,
            updater: update_ui::UpdateState::default(),
        };

        if vaults.is_empty() {
            vaults.push(this.make_draft(&registry::first_vault_name()));
        }
        this.vaults = vaults;
        this.form.vault = this.vaults[0].id.clone();
        this.stage = this.stage_for(0);
        this.vault_form.import = !this.import_pending().is_empty();
        if this.vaults[0].draft {
            let name = this.vaults[0].name.clone();
            this.vault_form
                .name
                .update(cx, |state, cx| state.set_value(name, window, cx));
        }
        let folder = this.vaults[0].sync_folder.clone();
        if !folder.is_empty() {
            this.sync_input
                .update(cx, |state, cx| state.set_value(&folder, window, cx));
        }

        this.autolock_task = Some(cx.spawn(async move |this: gpui_kit::WeakEntity<Self>, cx| {
            loop {
                cx.background_executor()
                    .timer(std::time::Duration::from_secs(30))
                    .await;
                if this.update(cx, |this, cx| this.check_autolock(cx)).is_err() {
                    return;
                }
            }
        }));

        let startup: Vec<String> = this
            .vaults
            .iter()
            .filter(|slot| slot.session.account().is_some() && slot.session.has_os_key())
            .map(|slot| slot.id.clone())
            .collect();
        for id in startup {
            this.unlock_with_os_key_for(&id, false, cx);
        }

        this.restore_tabs(cx);
        let args: Vec<String> = std::env::args().skip(1).collect();
        this.open_from_command_line(&args, cx);

        this.start_update_checks(cx);

        this
    }

    /// `cratty user@host:2222` connects right away: at startup, or when a later copy
    /// hands its command line over to this one.
    fn open_from_command_line(&mut self, args: &[String], cx: &mut Context<Self>) {
        if let Some(raw) = args.first() {
            self.open(raw, &connect::Credentials::default(), None, cx);
        }
    }

    fn read_form(
        &self,
        cx: &Context<Self>,
    ) -> std::result::Result<(String, connect::Credentials), String> {
        let auth = match &self.form.auth {
            HostAuth::Key { .. } => {
                let path = self.form.key_path.read(cx).value().trim().to_string();
                if path.is_empty() {
                    return Err(t!("app.enter_key_path").into());
                }
                HostAuth::Key { path }
            }
            other => other.clone(),
        };

        let password = match self.form.auth {
            HostAuth::Password => {
                let typed = self.form.password.read(cx).value().to_string();
                (!typed.is_empty()).then(|| proto::Secret::new(typed.into_bytes()))
            }
            _ => None,
        };

        let host = self.form.host.read(cx).value().trim().to_string();
        if host.is_empty() {
            return Err(t!("app.enter_server_address").into());
        }
        let user = self.form.user.read(cx).value().trim().to_string();
        let port = self.form.port.read(cx).value().trim().to_string();

        let mut target = String::new();
        if !user.is_empty() {
            target.push_str(&user);
            target.push('@');
        }
        target.push_str(&host);
        if !port.is_empty() && port != "22" {
            target.push(':');
            target.push_str(&port);
        }

        let (via, proxy_error) = self.resolve_chain(&self.form.vault, &self.form.via);
        Ok((
            target,
            connect::Credentials {
                auth,
                password,
                stored: None,
                via,
                proxy_error,
                forward_agent: false,
                forwards: self.form.forwards.clone(),
                command: None,
            },
        ))
    }

    fn connect_from_form(&mut self, cx: &mut Context<Self>) {
        match self.read_form(cx) {
            Ok((target, credentials)) => {
                let vault = Some(self.form.vault.clone()).filter(|id| !id.is_empty());
                self.open(&target, &credentials, vault, cx)
            }
            Err(error) => {
                self.error = Some(error.into());
                cx.notify();
            }
        }
    }

    fn save_current(&mut self, cx: &mut Context<Self>) {
        let (target, credentials) = match self.read_form(cx) {
            Ok(parts) => parts,
            Err(error) => {
                self.error = Some(error.into());
                cx.notify();
                return;
            }
        };

        let request = match connect::parse_target(&target) {
            Ok(request) => request,
            Err(error) => {
                self.error = Some(error.into());
                cx.notify();
                return;
            }
        };

        let mut host = HostRecord::new(request.alias);
        host.user = request.user.unwrap_or_default();
        host.port = request.port.unwrap_or(22);

        let original = self.form.editing.clone().unwrap_or_else(|| host.target());
        let vault_id = self.form.vault.clone();
        let existing = self
            .unlocked_of(&vault_id)
            .and_then(|unlocked| unlocked.find_by_target(&original));
        let device_only = existing.as_ref().is_some_and(|entry| entry.device_only);
        let old_icon = existing
            .as_ref()
            .map(|entry| entry.host.icon.clone())
            .unwrap_or_default();
        if let Some(existing) = &existing {
            host.secrets = existing.host.secrets.clone();
            host.forward_agent = existing.host.forward_agent;
            host.order = existing.host.order;
        }
        let old_group = existing
            .as_ref()
            .map(|entry| entry.host.group.clone())
            .unwrap_or_default();
        let renamed = existing
            .map(|entry| entry.id)
            .filter(|_| original != host.target());

        host.label = self.form.label.read(cx).value().trim().to_string();
        host.icon = self.form.icon.clone();
        let group = self.form.group.read(cx).value().trim().to_string();
        host.group = self
            .unlocked_of(&vault_id)
            .map(|unlocked| unlocked.group_name(&group))
            .unwrap_or(group);
        // In a different group the previous position means nothing.
        if proto::GroupRecord::key(&host.group) != proto::GroupRecord::key(&old_group) {
            host.order = 0;
        }
        host.auth = credentials.auth;
        host.via = self.form.via.clone();
        host.forwards = self.form.forwards.clone();
        let saved_target = host.target();
        let new_icon = self.icon_to_store(&vault_id, &host.icon);

        self.persist(&vault_id, cx, |unlocked, store| {
            if let Some(icon) = new_icon {
                unlocked.store_icon(store, icon)?;
            }
            unlocked.upsert_host_with(store, host, device_only)?;
            if let Some(old) = renamed {
                unlocked.remove_host(store, &old)?;
            }
            unlocked.release_icon(store, &old_icon)
        });
        if self.error.is_none() {
            self.form.editing = Some(saved_target);
            // The host's key file goes straight into the vault.
            self.sync_key_files(&vault_id);
        }
        if self.error.is_none() {
            self.editor_open = false;
        }
    }

    fn edit(&mut self, vault: &str, target: &str, window: &mut Window, cx: &mut Context<Self>) {
        let Some(host) = self
            .unlocked_of(vault)
            .and_then(|unlocked| unlocked.find_by_target(target))
            .map(|entry| entry.host)
        else {
            return;
        };
        self.fill_form(vault, host, window, cx);
    }

    fn fill_form(
        &mut self,
        vault: &str,
        host: HostRecord,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.form.vault = vault.to_owned();
        self.form.editing = Some(host.target());
        self.key_notice = None;
        self.form.auth = host.auth.clone();
        self.form.via = host.via.clone();
        self.form.forwards = host.forwards.clone();
        self.form.icon = host.icon.clone();
        self.section = Section::Hosts;
        self.showing_page = true;
        self.editor_open = true;
        self.rail_peek = !self.settings.rail_pinned;

        let port = host.port.to_string();
        let key = match &host.auth {
            HostAuth::Key { path } => path.clone(),
            _ => String::new(),
        };
        self.form
            .label
            .update(cx, |state, cx| state.set_value(host.label, window, cx));
        self.form
            .group
            .update(cx, |state, cx| state.set_value(host.group, window, cx));
        self.form
            .host
            .update(cx, |state, cx| state.set_value(host.host, window, cx));
        self.form
            .port
            .update(cx, |state, cx| state.set_value(port, window, cx));
        self.form
            .user
            .update(cx, |state, cx| state.set_value(host.user, window, cx));
        self.form
            .key_path
            .update(cx, |state, cx| state.set_value(key, window, cx));

        self.error = None;
        cx.notify();
    }

    fn forget(&mut self, vault: &str, target: &str, cx: &mut Context<Self>) {
        let Some((id, icon)) = self
            .unlocked_of(vault)
            .and_then(|unlocked| unlocked.find_by_target(target))
            .map(|entry| (entry.id, entry.host.icon))
        else {
            return;
        };
        self.persist(vault, cx, move |unlocked, store| {
            unlocked.remove_host(store, &id)?;
            unlocked.release_icon(store, &icon)
        });
    }

    fn on_terminal_event(
        &mut self,
        vault: Option<&str>,
        target: &str,
        event: &TerminalEvent,
        cx: &mut Context<Self>,
    ) {
        match event {
            TerminalEvent::SaveSecret { purpose, secret } => {
                self.remember_secret(vault, target, *purpose, secret.clone(), cx);
            }
            TerminalEvent::StoredPasswordRejected => {
                self.stored_rejected = Some(Rejected {
                    vault: vault.map(str::to_owned),
                    target: target.to_owned(),
                });
                cx.notify();
            }
            TerminalEvent::Typed(_) => {}
        }
    }

    fn remember_secret(
        &mut self,
        vault: Option<&str>,
        target: &str,
        purpose: proto::SecretPurpose,
        secret: proto::Secret,
        cx: &mut Context<Self>,
    ) {
        let Some(vault_id) = self.vault_for_write(vault, target) else {
            self.error = Some(t!("app.vault_locked_not_saved").into());
            cx.notify();
            return;
        };
        let Some(unlocked) = self.unlocked_of(&vault_id) else {
            self.error = Some(t!("app.vault_locked_not_saved").into());
            cx.notify();
            return;
        };

        let mut host = match unlocked.find_by_target(target) {
            Some(entry) => entry.host,
            None => match connect::parse_target(target) {
                Ok(request) => {
                    let mut host = HostRecord::new(request.alias);
                    host.user = request.user.unwrap_or_default();
                    host.port = request.port.unwrap_or(22);
                    host
                }
                Err(error) => {
                    self.error = Some(
                        t!("app.save_password_failed", error = error.to_string()).into(),
                    );
                    cx.notify();
                    return;
                }
            },
        };
        host.secrets.set(purpose, secret);

        self.persist(&vault_id, cx, |unlocked, store| {
            unlocked.upsert_host(store, host).map(|_| ())
        });
    }

    fn forget_secret(
        &mut self,
        vault: Option<&str>,
        target: &str,
        purpose: proto::SecretPurpose,
        cx: &mut Context<Self>,
    ) {
        let Some((vault_id, entry)) = self.find_host(vault, target) else {
            return;
        };
        let mut host = entry.host;
        if !host.secrets.remove(purpose) {
            return;
        }
        self.persist(&vault_id, cx, |unlocked, store| {
            unlocked.upsert_host(store, host).map(|_| ())
        });
    }

    fn toggle_device_only(&mut self, vault: &str, target: &str, cx: &mut Context<Self>) {
        let Some((_, entry)) = self.find_host(Some(vault), target) else {
            return;
        };
        let host = entry.host;
        let device_only = !entry.device_only;
        self.persist(vault, cx, move |unlocked, store| {
            unlocked
                .upsert_host_with(store, host, device_only)
                .map(|_| ())
        });
    }

    fn toggle_forward_agent(&mut self, vault: &str, target: &str, cx: &mut Context<Self>) {
        let Some((_, entry)) = self.find_host(Some(vault), target) else {
            return;
        };
        let mut host = entry.host;
        host.forward_agent = !host.forward_agent;
        self.persist(vault, cx, move |unlocked, store| {
            unlocked.upsert_host(store, host).map(|_| ())
        });
    }

    fn ask_reveal(&mut self, vault: &str, target: &str, copy: bool, cx: &mut Context<Self>) {
        self.reveal = Some(Reveal::Confirming {
            vault: vault.to_owned(),
            target: target.to_owned(),
            copy,
        });
        cx.notify();
    }

    fn confirm_reveal(&mut self, cx: &mut Context<Self>) {
        let Some(Reveal::Confirming {
            vault,
            target,
            copy,
        }) = self.reveal.clone()
        else {
            return;
        };

        let Some(secret) = self
            .unlocked_of(&vault)
            .and_then(|unlocked| unlocked.find_by_target(&target))
            .and_then(|entry| entry.host.password().cloned())
        else {
            self.reveal = None;
            self.error = Some(t!("app.no_saved_password").into());
            cx.notify();
            return;
        };

        let Ok(text) = std::str::from_utf8(secret.expose()) else {
            self.reveal = None;
            self.error = Some(t!("app.password_invalid_chars").into());
            cx.notify();
            return;
        };

        if copy {
            cx.write_to_clipboard(gpui_kit::ClipboardItem::new_string(text.to_owned()));
            self.reveal = None;
            self.error = Some(t!("app.password_copied").into());
        } else {
            self.reveal = Some(Reveal::Showing {
                vault,
                target,
                text: SharedString::from(text.to_owned()),
            });
        }
        cx.notify();
    }

    fn hide_reveal(&mut self, cx: &mut Context<Self>) {
        if self.reveal.take().is_some() {
            cx.notify();
        }
    }

    fn sync_can_save_secrets(&mut self, cx: &mut Context<Self>) {
        let tabs: Vec<(bool, Vec<Entity<TerminalView>>)> = self
            .tabs
            .iter()
            .map(|tab| (self.can_save_for(tab.vault.as_deref()), tab.terminals()))
            .collect();
        for (can, views) in tabs {
            for view in views {
                view.update(cx, |view, cx| view.set_can_save_secrets(can, cx));
            }
        }
    }

    fn check_autolock(&mut self, cx: &mut Context<Self>) {
        if !self.settings.autolock {
            return;
        }
        let now = std::time::Instant::now();
        let wall = crate::store::now_ms();
        let mut locked = false;
        for (ix, slot) in self.vaults.iter_mut().enumerate() {
            if let Some(reason) = slot.session.tick(now, wall) {
                locked = true;
                if ix == self.current {
                    self.stage = Some(Stage::Unlock);
                    self.vault_error = Some(reason.into());
                }
            }
        }
        if !locked {
            return;
        }
        self.reveal = None;
        self.sync_can_save_secrets(cx);
        cx.notify();
    }

    fn open(
        &mut self,
        raw: &str,
        credentials: &connect::Credentials,
        vault: Option<String>,
        cx: &mut Context<Self>,
    ) {
        self.touch_all();
        match connect::parse_target(raw) {
            Ok(request) => {
                self.error = None;
                self.spawn_tab(request, credentials.clone(), vault, cx);
            }
            Err(error) => {
                self.error = Some(error.into());
                cx.notify();
            }
        }
    }

    fn open_saved(&mut self, vault: &str, target: &str, cx: &mut Context<Self>) {
        let credentials = self
            .find_host(Some(vault), target)
            .map(|(_, entry)| {
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
            .unwrap_or_default();
        let target = target.to_string();
        self.open(&target, &credentials, Some(vault.to_owned()), cx);
    }

    fn spawn_tab(
        &mut self,
        request: connect::Request,
        credentials: connect::Credentials,
        vault: Option<String>,
        cx: &mut Context<Self>,
    ) {
        let settings = connect::read_ssh_config(&request.alias);
        let target = connect::resolve(&request, &settings);

        let agent = self.agent_address();
        let Some(view) = Self::start_session(&target, &settings, &credentials, agent, cx) else {
            self.error = Some(t!("app.session_start_failed").into());
            cx.notify();
            return;
        };

        let found = self.find_host(vault.as_deref(), &target.to_string());
        let title = found
            .as_ref()
            .map(|(_, entry)| entry.host.title())
            .unwrap_or_else(|| target.to_string());
        let vault = vault.or_else(|| found.map(|(id, _)| id));

        let can_save = self.can_save_for(vault.as_deref());
        view.update(cx, |view, cx| view.set_can_save_secrets(can_save, cx));

        let events = self.subscribe_terminal(&view, vault.clone(), target.to_string(), cx);

        self.tabs.push(SessionTab {
            title: title.into(),
            default_title: None,
            vault,
            kind: TabKind::Terminal {
                view,
                _events: events,
                files: None,
                editor: None,
                split: Default::default(),
            },
            request,
            credentials,
            local: false,
            agents: None,
            chat: None,
        });
        self.active = Some(self.tabs.len() - 1);
        self.showing_page = false;
        self.remember_tabs();
        self.apply_appearance(cx);
        self.focus_active(cx);
    }

    fn open_files(
        &mut self,
        raw: &str,
        credentials: connect::Credentials,
        vault: Option<String>,
        cx: &mut Context<Self>,
    ) {
        self.touch_all();
        let request = match connect::parse_target(raw) {
            Ok(request) => request,
            Err(error) => {
                self.error = Some(error.into());
                cx.notify();
                return;
            }
        };
        let settings = connect::read_ssh_config(&request.alias);
        let target = connect::resolve(&request, &settings);
        let agent = self.agent_address();
        let config = connect::config_for(&target, &settings, &credentials, DEFAULT_PTY, agent);

        let found = self.find_host(vault.as_deref(), &target.to_string());
        let name = found
            .as_ref()
            .map(|(_, entry)| entry.host.title())
            .unwrap_or_else(|| target.to_string());
        let vault = vault.or_else(|| found.map(|(id, _)| id));
        let title = t!("app.files_title", name = name).to_string();
        let view_title = title.clone();
        let view = cx.new(|cx| crate::ui::files::FilesView::new(view_title, config, cx));
        let events = cx.subscribe(
            &view,
            |this, _, event: &crate::ui::files::FilesEvent, cx| {
                this.on_files_event(None, event, cx)
            },
        );

        self.tabs.push(SessionTab {
            title: title.into(),
            default_title: None,
            vault,
            kind: TabKind::Files {
                view,
                _events: events,
            },
            request,
            credentials,
            local: false,
            agents: None,
            chat: None,
        });
        self.active = Some(self.tabs.len() - 1);
        self.showing_page = false;
        self.remember_tabs();
        cx.notify();
    }

    fn start_session(
        target: &Target,
        settings: &HostSettings,
        credentials: &connect::Credentials,
        agent: Option<ssh_agent::Address>,
        cx: &mut Context<Self>,
    ) -> Option<Entity<TerminalView>> {
        let config = connect::config_for(target, settings, credentials, DEFAULT_PTY, agent);
        let forwards = config.forwards.clone();
        let session = spawn_ssh(config).ok()?;
        let label = target.to_string();
        Some(
            cx.new(|cx| TerminalView::new(label, DEFAULT_PTY, session, cx).with_forwards(forwards)),
        )
    }

    fn start_local_session(&mut self, cx: &mut Context<Self>) -> Option<Entity<TerminalView>> {
        let session = spawn_local(DEFAULT_PTY, "xterm-256color").map_err(|err| {
            self.error = Some(t!("app.local_terminal_error", error = err.to_string()).into());
        });
        let session = session.ok()?;
        Some(cx.new(|cx| TerminalView::new(t!("app.local_tab").to_string(), DEFAULT_PTY, session, cx)))
    }

    /// Local shell tab: no SSH and no vault, available even
    /// on the lock screen.
    fn spawn_local_tab(&mut self, cx: &mut Context<Self>) {
        let Some(view) = self.start_local_session(cx) else {
            cx.notify();
            return;
        };
        let events = self.subscribe_terminal(&view, None, t!("app.local_tab").to_string(), cx);

        self.tabs.push(SessionTab {
            title: t!("app.local_tab").into(),
            default_title: None,
            vault: None,
            kind: TabKind::Terminal {
                view,
                _events: events,
                files: None,
                editor: None,
                split: Default::default(),
            },
            request: connect::Request {
                alias: String::new(),
                user: None,
                port: None,
            },
            credentials: connect::Credentials::default(),
            local: true,
            agents: None,
            chat: None,
        });
        self.active = Some(self.tabs.len() - 1);
        self.showing_page = false;
        self.remember_tabs();
        self.apply_appearance(cx);
        self.focus_active(cx);
    }

    fn reconnect(&mut self, index: usize, cx: &mut Context<Self>) {
        let Some(tab) = self.tabs.get(index) else {
            return;
        };
        if tab.is_files() {
            return;
        }
        let request = tab.request.clone();
        let credentials = tab.credentials.clone();
        let vault = tab.vault.clone();
        let local = tab.local;

        let agent = self.agent_address();
        let (target_text, started) = if local {
            (t!("app.local_tab").to_string(), self.start_local_session(cx))
        } else {
            let settings = connect::read_ssh_config(&request.alias);
            let target = connect::resolve(&request, &settings);
            let text = target.to_string();
            let started = Self::start_session(&target, &settings, &credentials, agent, cx);
            (text, started)
        };
        if let Some(view) = started {
            let can_save = self.can_save_for(vault.as_deref());
            view.update(cx, |view, cx| view.set_can_save_secrets(can_save, cx));

            let events = self.subscribe_terminal(&view, vault, target_text, cx);

            if let Some(tab) = self.tabs.get_mut(index) {
                let (editor, split) = match &mut tab.kind {
                    TabKind::Terminal { editor, split, .. } => {
                        (editor.take(), std::mem::take(split))
                    }
                    _ => (None, Default::default()),
                };
                view.update(cx, |view, _| view.set_broadcast(split.broadcast));
                tab.kind = TabKind::Terminal {
                    view,
                    _events: events,
                    files: None,
                    editor,
                    split,
                };
            }
            self.apply_appearance(cx);
            self.focus_active(cx);
        }
    }

    fn toggle_files_panel(&mut self, index: usize, cx: &mut Context<Self>) {
        if let Some(SessionTab {
            kind: TabKind::Terminal {
                files: Some(panel), ..
            },
            ..
        }) = self.tabs.get_mut(index)
            && (panel.visible || !panel.view.read(cx).is_closed())
        {
            panel.visible = !panel.visible;
            cx.notify();
            return;
        }
        let Some(tab) = self.tabs.get(index) else {
            return;
        };
        let TabKind::Terminal { view, .. } = &tab.kind else {
            return;
        };
        let panel = {
            let Some(handle) = view.read(cx).open_sftp() else {
                return;
            };
            let title = tab.title.clone();
            let files_view = cx.new(|cx| crate::ui::files::FilesView::attached(title, handle, cx));
            let events = cx.subscribe(
                &files_view,
                |this, emitter, event: &crate::ui::files::FilesEvent, cx| {
                    this.on_files_event(Some(emitter), event, cx)
                },
            );
            Some(FilesPanel {
                view: files_view,
                _events: events,
                visible: true,
            })
        };
        if let Some(SessionTab {
            kind: TabKind::Terminal { files, .. },
            ..
        }) = self.tabs.get_mut(index)
        {
            *files = panel;
        }
        cx.notify();
    }

    fn on_files_event(
        &mut self,
        panel: Option<Entity<crate::ui::files::FilesView>>,
        event: &crate::ui::files::FilesEvent,
        cx: &mut Context<Self>,
    ) {
        let crate::ui::files::FilesEvent::OpenFile {
            path,
            name,
            content,
            commands,
        } = event;

        if let Some(panel) = panel {
            let Some(index) = self.tabs.iter().position(|tab| {
                matches!(&tab.kind, TabKind::Terminal { files: Some(files), .. } if files.view == panel)
            }) else {
                return;
            };
            if let TabKind::Terminal {
                editor: Some(open), ..
            } = &self.tabs[index].kind
            {
                let open = open.view.clone();
                if open.read(cx).path() == path {
                    return;
                }
                if open.read(cx).is_dirty() {
                    open.update(cx, |view, cx| view.ask_close(cx));
                    return;
                }
            }
            let view = cx.new(|_| {
                crate::ui::editor::EditorView::new(
                    path.clone(),
                    name.clone(),
                    content.clone(),
                    commands.clone(),
                )
                .docked()
            });
            let id = view.entity_id();
            let events = cx.subscribe(
                &view,
                move |this, _, event: &crate::ui::editor::EditorEvent, cx| {
                    for tab in &mut this.tabs {
                        if let TabKind::Terminal { editor, .. } = &mut tab.kind
                            && let Some(open) = editor
                            && open.view.entity_id() == id
                        {
                            match event {
                                crate::ui::editor::EditorEvent::Close => *editor = None,
                                crate::ui::editor::EditorEvent::Expand(expanded) => {
                                    open.expanded = *expanded
                                }
                            }
                            cx.notify();
                            return;
                        }
                    }
                },
            );
            if let TabKind::Terminal { editor, .. } = &mut self.tabs[index].kind {
                *editor = Some(DockedEditor {
                    view,
                    _events: events,
                    expanded: false,
                });
            }
            cx.notify();
            return;
        }

        if let Some(index) = self.tabs.iter().position(|tab| {
            tab.editor()
                .is_some_and(|view| view.read(cx).path() == path)
        }) {
            self.select(index, cx);
            return;
        }

        let view = cx.new(|_| {
            crate::ui::editor::EditorView::new(
                path.clone(),
                name.clone(),
                content.clone(),
                commands.clone(),
            )
        });
        let id = view.entity_id();
        let events = cx.subscribe(
            &view,
            move |this, _, event: &crate::ui::editor::EditorEvent, cx| {
                if !matches!(event, crate::ui::editor::EditorEvent::Close) {
                    return;
                }
                if let Some(index) = this
                    .tabs
                    .iter()
                    .position(|tab| tab.editor().is_some_and(|view| view.entity_id() == id))
                {
                    this.remove_tab(index, cx);
                }
            },
        );
        self.tabs.push(SessionTab {
            title: name.clone().into(),
            default_title: None,
            vault: None,
            kind: TabKind::Editor {
                view,
                _events: events,
            },
            request: connect::Request {
                alias: String::new(),
                user: None,
                port: None,
            },
            credentials: connect::Credentials::default(),
            local: false,
            agents: None,
            chat: None,
        });
        self.active = Some(self.tabs.len() - 1);
        self.showing_page = false;
        self.remember_tabs();
        cx.notify();
    }

    fn close_tab(&mut self, index: usize, cx: &mut Context<Self>) {
        let editor = self.tabs.get(index).and_then(|tab| match &tab.kind {
            TabKind::Terminal {
                editor: Some(docked),
                ..
            } => Some(&docked.view),
            _ => tab.editor(),
        });
        if let Some(view) = editor.cloned()
            && view.read(cx).is_dirty()
        {
            view.update(cx, |view, cx| view.ask_close(cx));
            self.select(index, cx);
            return;
        }
        self.remove_tab(index, cx);
    }

    fn remove_tab(&mut self, index: usize, cx: &mut Context<Self>) {
        if index >= self.tabs.len() {
            return;
        }
        let tab = self.tabs.remove(index);
        if let Some(access) = tab.agents {
            self.drop_agent_calls(&access.token);
        }
        // Indices after the removed tab have shifted.
        self.renaming = None;
        self.active = match self.tabs.len() {
            0 => None,
            len => Some(index.min(len - 1)),
        };
        if self.active.is_none() {
            self.showing_page = true;
        }
        self.remember_tabs();
        self.focus_active(cx);
    }

    fn select(&mut self, index: usize, cx: &mut Context<Self>) {
        if index < self.tabs.len() {
            self.active = Some(index);
            self.showing_page = false;
            self.remember_tabs();
            self.focus_active(cx);
        }
    }

    fn focus_active(&mut self, cx: &mut Context<Self>) {
        if !self.showing_page
            && let Some(index) = self.active
            && let Some(view) = self.tabs.get(index).and_then(SessionTab::focused_terminal)
        {
            view.update(cx, |view, cx| view.request_focus(cx));
        }
        cx.notify();
    }

    fn cycle(&mut self, forward: bool, cx: &mut Context<Self>) {
        let count = self.tabs.len();
        if count == 0 {
            return;
        }
        let current = self.active.unwrap_or(0);
        let next = if forward {
            (current + 1) % count
        } else {
            (current + count - 1) % count
        };
        self.select(next, cx);
    }

    fn on_new_tab(&mut self, _: &NewTab, window: &mut Window, cx: &mut Context<Self>) {
        self.rail_peek = !self.settings.rail_pinned;
        self.section = Section::Hosts;
        self.form.line.read(cx).focus_handle(cx).focus(window, cx);
        cx.notify();
    }

    fn on_close_tab(&mut self, _: &CloseTab, _window: &mut Window, cx: &mut Context<Self>) {
        if let Some(index) = self.active {
            self.close_tab(index, cx);
        }
    }

    fn on_next_tab(&mut self, _: &NextTab, _window: &mut Window, cx: &mut Context<Self>) {
        self.cycle(true, cx);
    }

    fn on_prev_tab(&mut self, _: &PrevTab, _window: &mut Window, cx: &mut Context<Self>) {
        self.cycle(false, cx);
    }

    fn watch_dux(window: &mut Window, cx: &mut Context<Self>) -> Option<gpui_kit::Task<()>> {
        let path = crate::ui::dux::colors_file()?;
        let mut seen = crate::ui::dux::modified(&path);
        Some(
            cx.spawn_in(window, async move |this: gpui_kit::WeakEntity<Self>, cx| {
                loop {
                    cx.background_executor()
                        .timer(std::time::Duration::from_secs(3))
                        .await;
                    let now = crate::ui::dux::modified(&path);
                    if now == seen {
                        continue;
                    }
                    seen = now;
                    let alive = this.update_in(cx, |this, window, cx| {
                        if crate::ui::theme::refresh_dux(cx, &this.settings) {
                            crate::ui::theme::apply(&this.settings, Some(window), cx);
                            this.apply_appearance(cx);
                        }
                        cx.notify();
                    });
                    if alive.is_err() {
                        return;
                    }
                }
            }),
        )
    }

    fn on_toggle_panel(&mut self, _: &TogglePanel, _window: &mut Window, cx: &mut Context<Self>) {
        self.toggle_pin(Edge::Rail, cx);
    }

    /// Pin or unpin the side panel. The choice is remembered in settings.
    fn toggle_pin(&mut self, edge: Edge, cx: &mut Context<Self>) {
        let pinned = match edge {
            Edge::Rail => &mut self.settings.rail_pinned,
            Edge::Panel => &mut self.settings.panel_pinned,
            Edge::Editor => return,
        };
        *pinned = !*pinned;
        self.rail_peek = false;
        self.panel_peek = false;
        self.error = settings::save(&self.settings).err().map(SharedString::from);
        cx.notify();
    }

    fn pin_button(&self, edge: Edge, cx: &mut Context<Self>) -> AnyElement {
        let pinned = match edge {
            Edge::Rail => self.settings.rail_pinned,
            _ => self.settings.panel_pinned,
        };
        Button::new(match edge {
            Edge::Rail => "pin-rail",
            _ => "pin-panel",
        })
        .ghost()
        .small()
        .icon(Icon::empty().path(if pinned {
            "icons/pin.svg"
        } else {
            "icons/pin-off.svg"
        }))
        .tooltip(if pinned {
            t!("app.pin_unpin_tip")
        } else {
            t!("app.pin_tip")
        })
        .on_click(cx.listener(move |this, _, _window, cx| this.toggle_pin(edge, cx)))
        .into_any_element()
    }

    /// Narrow strip at the window edge: hovering slides out the unpinned panel.
    fn peek_zone(&self, edge: Edge, cx: &mut Context<Self>) -> AnyElement {
        div()
            .id(match edge {
                Edge::Rail => "peek-rail",
                _ => "peek-panel",
            })
            .absolute()
            .top_0()
            .h_full()
            .w(px(6.))
            .map(|this| match edge {
                Edge::Rail => this.left_0(),
                _ => this.right_0(),
            })
            .on_hover(cx.listener(move |this, hovered: &bool, _window, cx| {
                if *hovered {
                    match edge {
                        Edge::Rail => this.rail_peek = true,
                        _ => this.panel_peek = true,
                    }
                    cx.notify();
                }
            }))
            .into_any_element()
    }

    /// Panel slid out over the content; hides when the mouse leaves.
    fn peek_overlay(&self, edge: Edge, panel: AnyElement, cx: &mut Context<Self>) -> AnyElement {
        div()
            .id(match edge {
                Edge::Rail => "overlay-rail",
                _ => "overlay-panel",
            })
            .absolute()
            .top_0()
            .h_full()
            .flex()
            .occlude()
            .shadow_lg()
            .map(|this| match edge {
                Edge::Rail => this.left_0(),
                _ => this.right_0(),
            })
            .on_hover(cx.listener(move |this, hovered: &bool, _window, cx| {
                if !*hovered {
                    match edge {
                        Edge::Rail => this.rail_peek = false,
                        _ => {
                            // Menus live in the panel: when the panel goes away, close them too.
                            this.panel_peek = false;
                            this.snippets_open = false;
                            this.split_menu = false;
                        }
                    }
                    cx.notify();
                }
            }))
            .child(panel)
            .into_any_element()
    }

    fn title_bar(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        if self.tiling {
            return None;
        }
        let dark = cx.theme().mode.is_dark();
        let muted = cx.theme().muted_foreground;
        let active_tab = self
            .active
            .filter(|_| !self.showing_page)
            .and_then(|index| self.tabs.get(index));
        let current_title = active_tab.map(|tab| tab.title.clone());

        TitleBar::new()
            .child(
                h_flex()
                    .gap_2()
                    .items_center()
                    .child(img("brand/cratty.svg").size_4())
                    .child(Label::new("cratty").font_semibold()),
            )
            .child(
                div()
                    .flex_1()
                    .flex()
                    .justify_center()
                    .children(current_title.map(|title| {
                        Label::new(title)
                            .text_xs()
                            .text_color(muted)
                            .whitespace_nowrap()
                    })),
            )
            .child(
                // `occlude`: the whole title bar is a window drag area, and on
                // Windows the OS would take the click as a window move — the
                // button would never get it.
                h_flex().occlude().justify_end().pr_2().gap_1().child(
                    Button::new("theme")
                        .ghost()
                        .xsmall()
                        .icon(Icon::new(if dark { IconName::Sun } else { IconName::Moon }))
                        .tooltip(t!("app.switch_theme"))
                        .on_click(cx.listener(|this, _, window, cx| {
                            let next = if crate::ui::theme::is_dark(cx) {
                                crate::ui::theme::Appearance::Light
                            } else {
                                crate::ui::theme::Appearance::Dark
                            };
                            this.settings.set_appearance(next);
                            this.error =
                                settings::save(&this.settings).err().map(SharedString::from);
                            crate::ui::theme::apply(&this.settings, Some(window), cx);
                            this.apply_appearance(cx);
                        })),
                ),
            )
            .into_any_element()
            .into()
    }

    /// Resize handle laid over the panel border, taking no room in the layout
    /// (otherwise it shows as a gap). `offset` is the border's distance from the
    /// left edge (rail) or the right edge (panel, editor) of the parent; the
    /// parent must be `relative()` and the handle added after the content.
    fn edge_handle(
        &self,
        id: &'static str,
        edge: Edge,
        offset: f32,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let accent = cx.theme().primary;
        let start = px(offset - EDGE_HANDLE / 2.0);
        div()
            .id(id)
            .absolute()
            .top_0()
            .bottom_0()
            .w(px(EDGE_HANDLE))
            .map(|this| match edge {
                Edge::Rail => this.left(start),
                _ => this.right(start),
            })
            .cursor_col_resize()
            .hover(move |style| style.bg(accent))
            .on_drag(edge, |_, _, _, cx| cx.new(|_| EdgeDrag))
            .into_any_element()
    }

    fn panel_title(text: impl Into<SharedString>, muted: gpui_kit::Hsla) -> AnyElement {
        div()
            .px_3()
            .pt_3()
            .pb_2()
            .child(Label::new(text.into()).text_sm().font_semibold().text_color(muted))
            .into_any_element()
    }

    fn field_label(text: impl Into<SharedString>, muted: gpui_kit::Hsla) -> AnyElement {
        Label::new(text.into())
            .text_xs()
            .text_color(muted)
            .into_any_element()
    }

    fn auth_switch(&self, cx: &mut Context<Self>) -> AnyElement {
        let auth = self.form.auth.clone();
        let is = |kind: &HostAuth| std::mem::discriminant(&auth) == std::mem::discriminant(kind);

        h_flex()
            .gap_1()
            .child(
                Button::new("auth-auto")
                    .ghost()
                    .small()
                    .selected(is(&HostAuth::Auto))
                    .label(t!("app.auth_auto"))
                    .tooltip(t!("app.auth_auto_tip"))
                    .on_click(cx.listener(|this, _, _window, cx| {
                        this.form.auth = HostAuth::Auto;
                        cx.notify();
                    })),
            )
            .child(
                Button::new("auth-password")
                    .ghost()
                    .small()
                    .selected(is(&HostAuth::Password))
                    .label(t!("app.auth_password"))
                    .tooltip(t!("app.auth_password_tip"))
                    .on_click(cx.listener(|this, _, _window, cx| {
                        this.form.auth = HostAuth::Password;
                        cx.notify();
                    })),
            )
            .child(
                Button::new("auth-key")
                    .ghost()
                    .small()
                    .selected(is(&HostAuth::Key {
                        path: Default::default(),
                    }))
                    .label(t!("app.auth_key"))
                    .tooltip(t!("app.auth_key_tip"))
                    .on_click(cx.listener(|this, _, _window, cx| {
                        this.form.auth = HostAuth::Key {
                            path: Default::default(),
                        };
                        cx.notify();
                    })),
            )
            .into_any_element()
    }

    fn form_fields(&self, cx: &mut Context<Self>) -> AnyElement {
        let muted = cx.theme().muted_foreground;

        v_flex()
            .gap_2()
            .child(
                v_flex()
                    .gap_1()
                    .child(Self::field_label(t!("app.field_icon_name"), muted))
                    .child(
                        h_flex()
                            .gap_2()
                            .items_center()
                            .child(self.icon_button(
                                "host-icon",
                                icons_ui::IconTarget::Host,
                                &self.form.vault,
                                &self.form.icon,
                                "server",
                                cx,
                            ))
                            .child(div().flex_1().child(Input::new(&self.form.label))),
                    ),
            )
            .child(self.group_field(cx))
            .child(
                h_flex()
                    .gap_2()
                    .items_end()
                    .child(
                        v_flex()
                            .flex_grow_1()
                            .gap_1()
                            .child(Self::field_label(t!("app.field_address"), muted))
                            .child(Input::new(&self.form.host)),
                    )
                    .child(
                        v_flex()
                            .w(px(72.))
                            .gap_1()
                            .child(Self::field_label(t!("app.field_port"), muted))
                            .child(Input::new(&self.form.port)),
                    ),
            )
            .child(
                v_flex()
                    .gap_1()
                    .child(Self::field_label(t!("app.field_user"), muted))
                    .child(Input::new(&self.form.user)),
            )
            .into_any_element()
    }

    fn auth_fields(&self, cx: &mut Context<Self>) -> AnyElement {
        let muted = cx.theme().muted_foreground;

        match self.form.auth {
            HostAuth::Auto => Label::new(t!("app.auth_auto_hint"))
            .text_xs()
            .text_color(muted)
            .into_any_element(),
            HostAuth::Password => v_flex()
                .gap_1()
                .child(Input::new(&self.form.password))
                .child(
                    Label::new(t!("app.auth_password_hint"))
                    .text_xs()
                    .text_color(muted),
                )
                .into_any_element(),
            HostAuth::Key { .. } => self.key_fields(cx),
        }
    }

    fn record_controls(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let muted = cx.theme().muted_foreground;
        let warning = cx.theme().warning;
        let border = cx.theme().border;

        let target = self.form.editing.clone()?;
        let vault = self.form.vault.clone();
        let entry = self.unlocked_of(&vault)?.find_by_target(&target)?;

        let has_password = entry.host.has_password();
        let device_only = entry.device_only;
        let forward_agent = entry.host.forward_agent;
        let for_forward = target.clone();
        let for_forget = target.clone();
        let for_show = target.clone();
        let for_copy = target.clone();
        let for_bind = target.clone();
        let (v_forward, v_forget, v_show, v_copy, v_bind) = (
            vault.clone(),
            vault.clone(),
            vault.clone(),
            vault.clone(),
            vault.clone(),
        );

        let showing = match &self.reveal {
            Some(Reveal::Showing {
                vault: shown_vault,
                target: shown,
                text,
            }) if *shown == target && *shown_vault == vault => Some(text.clone()),
            _ => None,
        };
        let confirming = matches!(
            &self.reveal,
            Some(Reveal::Confirming { vault: asked_vault, target: asked, .. })
                if *asked == target && *asked_vault == vault
        );

        Some(
            v_flex()
                .gap_2()
                .child(
                    h_flex()
                        .flex_wrap()
                        .gap_1()
                        .child(
                            Button::new("record-device-only")
                                .ghost()
                                .small()
                                .selected(device_only)
                                .label(t!("app.dont_sync"))
                                .tooltip(t!("app.dont_sync_tip"))
                                .on_click(cx.listener(move |this, _, _window, cx| {
                                    let target = for_bind.clone();
                                    this.toggle_device_only(&v_bind, &target, cx);
                                })),
                        )
                        .child(
                            Button::new("record-forward-agent")
                                .ghost()
                                .small()
                                .selected(forward_agent)
                                .label(t!("app.forward_agent"))
                                .tooltip(t!("app.forward_agent_tip"))
                                .on_click(cx.listener(move |this, _, _window, cx| {
                                    let target = for_forward.clone();
                                    this.toggle_forward_agent(&v_forward, &target, cx);
                                })),
                        ),
                )
                .when(has_password, |this| {
                    this.child(
                        h_flex()
                            .gap_1()
                            .child(Label::new(t!("app.password_saved")).text_xs().text_color(muted))
                            .child(
                                Button::new("record-show-password")
                                    .ghost()
                                    .small()
                                    .label(t!("app.show"))
                                    .on_click(cx.listener(move |this, _, _window, cx| {
                                        let target = for_show.clone();
                                        this.ask_reveal(&v_show, &target, false, cx);
                                    })),
                            )
                            .child(
                                Button::new("record-copy-password")
                                    .ghost()
                                    .small()
                                    .label(t!("app.copy"))
                                    .on_click(cx.listener(move |this, _, _window, cx| {
                                        let target = for_copy.clone();
                                        this.ask_reveal(&v_copy, &target, true, cx);
                                    })),
                            )
                            .child(
                                Button::new("record-forget-password")
                                    .ghost()
                                    .small()
                                    .label(t!("app.delete"))
                                    .on_click(cx.listener(move |this, _, _window, cx| {
                                        let target = for_forget.clone();
                                        this.forget_secret(
                                            Some(&v_forget),
                                            &target,
                                            proto::SecretPurpose::Password,
                                            cx,
                                        );
                                    })),
                            ),
                    )
                })
                .when(confirming, |this| {
                    this.child(
                        v_flex()
                            .p_2()
                            .gap_1()
                            .rounded_md()
                            .border_1()
                            .border_color(border)
                            .child(
                                Label::new(t!("app.reveal_warning"))
                                .text_xs()
                                .text_color(warning),
                            )
                            .child(
                                h_flex()
                                    .gap_1()
                                    .child(
                                        Button::new("reveal-yes")
                                            .primary()
                                            .small()
                                            .label(t!("app.continue"))
                                            .on_click(cx.listener(|this, _, _window, cx| {
                                                this.confirm_reveal(cx)
                                            })),
                                    )
                                    .child(
                                        Button::new("reveal-no")
                                            .ghost()
                                            .small()
                                            .label(t!("app.cancel"))
                                            .on_click(cx.listener(|this, _, _window, cx| {
                                                this.hide_reveal(cx)
                                            })),
                                    ),
                            ),
                    )
                })
                .children(showing.map(|text| {
                    v_flex()
                        .p_2()
                        .gap_1()
                        .rounded_md()
                        .border_1()
                        .border_color(border)
                        .child(Label::new(text).text_sm().font_family(mono_family(cx)))
                        .child(
                            Button::new("reveal-hide")
                                .ghost()
                                .small()
                                .label(t!("app.hide"))
                                .on_click(cx.listener(|this, _, _window, cx| this.hide_reveal(cx))),
                        )
                }))
                .into_any_element(),
        )
    }

    fn stored_rejected_notice(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let danger = cx.theme().danger;
        let border = cx.theme().border;
        let Rejected { vault, target } = self.stored_rejected.clone()?;
        let for_forget = target.clone();

        Some(
            v_flex()
                .p_2()
                .gap_1()
                .rounded_md()
                .border_1()
                .border_color(danger)
                .child(
                    Label::new(t!("app.rejected_notice", target = target))
                    .text_xs()
                    .text_color(danger),
                )
                .child(
                    h_flex()
                        .gap_1()
                        .child(
                            Button::new("stored-rejected-forget")
                                .primary()
                                .xsmall()
                                .label(t!("app.rejected_forget"))
                                .on_click(cx.listener(move |this, _, _window, cx| {
                                    let target = for_forget.clone();
                                    this.forget_secret(vault.as_deref(), &target, proto::SecretPurpose::Password, cx);
                                    this.stored_rejected = None;
                                    cx.notify();
                                })),
                        )
                        .child(
                            Button::new("stored-rejected-dismiss")
                                .ghost()
                                .xsmall()
                                .label(t!("app.close"))
                                .on_click(cx.listener(|this, _, _window, cx| {
                                    this.stored_rejected = None;
                                    cx.notify();
                                })),
                        ),
                )
                .border_color(border)
                .into_any_element(),
        )
    }

    fn reconnect_bar(&self, index: usize, cx: &mut Context<Self>) -> AnyElement {
        let muted_bg = cx.theme().muted;
        let muted = cx.theme().muted_foreground;
        let border = cx.theme().border;

        h_flex()
            .items_center()
            .justify_between()
            .gap_2()
            .px_3()
            .py_2()
            .bg(muted_bg)
            .border_b_1()
            .border_color(border)
            .child(Label::new(t!("app.session_ended")).text_sm().text_color(muted))
            .child(
                Button::new("reconnect")
                    .primary()
                    .small()
                    .icon(Icon::new(IconName::Replace))
                    .label(t!("app.reconnect"))
                    .on_click(cx.listener(move |this, _, _window, cx| this.reconnect(index, cx))),
            )
            .into_any_element()
    }
}

impl Render for AppView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.track_pane_focus(window, cx);
        if !cx.has_active_drag() {
            self.dragging_host = None;
        }
        let title_bar = self.title_bar(cx);
        let rail = self.rail(cx);
        let workspace = self.workspace(cx);
        let session_panel = self.session_panel(cx);
        let foreground = cx.theme().foreground;

        // Unpinned panel: a hover strip at the window edge; on hover,
        // the panel over the content.
        let rail_pinned = self.settings.rail_pinned;
        let panel_pinned = self.settings.panel_pinned;
        let has_rail = rail.is_some();
        let has_panel = session_panel.is_some();
        let (rail, rail_overlay) = match (rail_pinned, rail) {
            (true, rail) => (rail, None),
            (false, Some(rail)) if self.rail_peek => {
                (None, Some(self.peek_overlay(Edge::Rail, rail, cx)))
            }
            (false, _) => (None, Some(self.peek_zone(Edge::Rail, cx))),
        };
        let (session_panel, panel_overlay) = match (panel_pinned, session_panel) {
            (true, panel) => (panel, None),
            (false, Some(panel)) if self.panel_peek => {
                (None, Some(self.peek_overlay(Edge::Panel, panel, cx)))
            }
            (false, Some(_)) => (None, Some(self.peek_zone(Edge::Panel, cx))),
            (false, None) => (None, None),
        };

        let sign_dialog = self.sign_dialog(cx);
        let agent_dialog = self.agent_dialog(cx);
        let delete_dialog = self.delete_vault_dialog(cx);
        let forget_dialog = self.forget_host_dialog(cx);
        let vault_editor = self.vault_editor_dialog(cx);
        let group_editor = self.group_editor_dialog(cx);
        let icon_picker = self.icon_picker_dialog(cx);
        let update_dialog = self.update_dialog(cx);

        div()
            .relative()
            .size_full()
            .child(
                v_flex()
                    .size_full()
                    .text_color(foreground)
                    .on_action(cx.listener(Self::on_new_tab))
                    .on_action(cx.listener(Self::on_close_tab))
                    .on_action(cx.listener(Self::on_next_tab))
                    .on_action(cx.listener(Self::on_prev_tab))
                    .on_action(cx.listener(Self::on_toggle_panel))
                    .on_action(|_: &Quit, window, _| window.remove_window())
                    .children(title_bar)
                    .child(
                        div()
                            .relative()
                            .flex()
                            .flex_row()
                            .flex_grow_1()
                            .overflow_hidden()
                            .when(rail_pinned, |this| this.children(rail))
                            .child(div().flex_grow_1().overflow_hidden().child(workspace))
                            .when(panel_pinned, |this| this.children(session_panel))
                            .when(rail_pinned && has_rail, |this| {
                                this.child(self.edge_handle(
                                    "edge-rail",
                                    Edge::Rail,
                                    self.settings.rail_width,
                                    cx,
                                ))
                            })
                            .when(panel_pinned && has_panel, |this| {
                                this.child(self.edge_handle(
                                    "edge-panel",
                                    Edge::Panel,
                                    self.settings.panel_width,
                                    cx,
                                ))
                            })
                            .children(rail_overlay)
                            .children(panel_overlay)
                            .on_drag_move(cx.listener(
                                |this, event: &gpui_kit::DragMoveEvent<Edge>, window, cx| {
                                    let x = f32::from(event.event.position.x);
                                    match *event.drag(cx) {
                                        Edge::Rail => {
                                            this.settings.rail_width = settings::fit(
                                                x,
                                                settings::RAIL_WIDTH,
                                                this.settings.rail_width,
                                            )
                                        }
                                        Edge::Panel => {
                                            let right = f32::from(window.viewport_size().width);
                                            this.settings.panel_width = settings::fit(
                                                right - x,
                                                settings::PANEL_WIDTH,
                                                this.settings.panel_width,
                                            )
                                        }
                                        Edge::Editor => {
                                            let mut right = f32::from(window.viewport_size().width);
                                            if this.settings.panel_pinned && !this.showing_page {
                                                right -= this.settings.panel_width;
                                            }
                                            let left = if this.settings.rail_pinned {
                                                this.settings.rail_width
                                            } else {
                                                0.0
                                            };
                                            let min = *settings::EDITOR_WIDTH.start();
                                            let max = (right - left - 240.0)
                                                .clamp(min, *settings::EDITOR_WIDTH.end());
                                            this.settings.editor_width = settings::fit(
                                                right - x,
                                                min..=max,
                                                this.settings.editor_width,
                                            )
                                        }
                                    }
                                    cx.notify();
                                },
                            ))
                            .on_drop(cx.listener(|this, _: &Edge, _window, cx| {
                                this.error =
                                    settings::save(&this.settings).err().map(SharedString::from);
                                cx.notify();
                            })),
                    ),
            )
            .children(sign_dialog)
            .children(agent_dialog)
            .children(delete_dialog)
            .children(forget_dialog)
            .children(vault_editor)
            .children(group_editor)
            .children(icon_picker)
            .children(update_dialog)
    }
}

/// `primary` is set when this copy owns the single-instance address: later copies
/// hand their command line to it.
pub fn open_main_window(
    primary: Option<(
        crate::instance::Primary,
        futures::channel::mpsc::UnboundedReceiver<crate::instance::Request>,
    )>,
    cx: &mut App,
) -> Result<()> {
    crate::ui::font::MonoFont::init(cx);
    gpui_kit::init(cx);
    crate::ui::theme::init(cx);

    let startup = settings::load();
    crate::i18n::apply(&startup.language);
    crate::ui::font::MonoFont::apply(&startup, cx);
    crate::ui::theme::apply(&startup, None, cx);

    let bind = |keys: &str, action: Box<dyn gpui_kit::Action>| {
        KeyBinding::load(keys, action, None, false, None, cx).expect("valid key binding")
    };
    cx.bind_keys([
        KeyBinding::new(
            if cfg!(target_os = "macos") {
                "cmd-q"
            } else {
                "ctrl-shift-q"
            },
            Quit,
            None,
        ),
        bind(&shortcut("t"), Box::new(NewTab)),
        bind(&shortcut("w"), Box::new(CloseTab)),
        bind(&shortcut("]"), Box::new(NextTab)),
        bind(&shortcut("["), Box::new(PrevTab)),
        bind(&shortcut("b"), Box::new(TogglePanel)),
        KeyBinding::new("tab", NoAction, Some("Terminal")),
        KeyBinding::new("shift-tab", NoAction, Some("Terminal")),
    ]);

    cx.on_window_closed(|cx, _| {
        if cx.windows().is_empty() {
            cx.quit();
        }
    })
    .detach();

    let bounds = Bounds::centered(None, size(px(1180.), px(760.)), cx);
    let (handle, view) = gpui_kit::open_window(
        WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(bounds)),
            window_min_size: Some(size(px(640.), px(400.))),
            // The system title: taskbar, Alt+Tab, window list.
            titlebar: Some(gpui_kit::TitlebarOptions {
                title: Some("Cratty".into()),
                ..TitleBar::title_bar_options()
            }),
            window_decorations: Some(gpui_kit::WindowDecorations::Client),
            app_id: Some("cratty".into()),
            window_background: crate::ui::theme::window_background(&startup),
            ..Default::default()
        },
        cx,
        |window, cx| cx.new(|cx| AppView::new(window, cx)),
    )?;

    if let Some((primary, mut requests)) = primary {
        cx.spawn(async move |cx| {
            // Listening stops together with this task, when the app quits.
            let _primary = primary;
            while let Some(args) = requests.next().await {
                let shown = handle.update(cx, |_, window, cx| {
                    window.activate_window();
                    cx.activate(true);
                    view.update(cx, |view, cx| view.open_from_command_line(&args, cx));
                });
                if shown.is_err() {
                    return;
                }
            }
        })
        .detach();
    }

    Ok(())
}

fn to_rgb(color: gpui_kit::Hsla) -> crate::term::Rgb {
    let rgba: gpui_kit::Rgba = color.into();
    crate::term::Rgb::new(
        (rgba.r * 255.).round().clamp(0., 255.) as u8,
        (rgba.g * 255.).round().clamp(0., 255.) as u8,
        (rgba.b * 255.).round().clamp(0., 255.) as u8,
    )
}

fn shortcut(key: &str) -> String {
    if cfg!(target_os = "macos") {
        format!("cmd-{key}")
    } else {
        format!("ctrl-shift-{key}")
    }
}

const ROW_TITLE_CHARS: usize = 22;

fn shorten(text: &str, max_chars: usize) -> String {
    let mut chars = text.chars();
    let head: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_none() {
        head
    } else {
        format!("{head}…")
    }
}

pub(crate) fn mono_family(cx: &App) -> SharedString {
    crate::ui::font::MonoFont::get(cx).family.clone()
}

#[derive(Default)]
struct SyncOutcome {
    records: Vec<proto::EncryptedRecord>,
    broken: Vec<String>,
    errors: Vec<String>,
}

async fn folder_exchange(
    path: std::path::PathBuf,
    vault_id: &proto::VaultId,
    records: Vec<proto::EncryptedRecord>,
) -> anyhow::Result<sync::Pulled> {
    use sync::VaultBackend as _;

    let backend = sync::FolderBackend::open(path, vault_id)?;
    backend.push(records).await?;
    backend.pull(sync::Cursor::BEGINNING).await
}

#[cfg(test)]
mod tests {
    use super::{ROW_TITLE_CHARS, shorten};

    const ROW_DETAIL_CHARS: usize = 30;

    #[test]
    fn short_string_is_unchanged_and_long_one_is_truncated() {
        assert_eq!(shorten("prod-01", ROW_TITLE_CHARS), "prod-01");

        let long = "administrator@very-long-hostname.production.example.com";
        let short = shorten(long, ROW_TITLE_CHARS);
        assert_eq!(short.chars().count(), ROW_TITLE_CHARS + 1, "{short}");
        assert!(short.ends_with('…'));
        assert!(long.starts_with(short.trim_end_matches('…')));
    }

    #[test]
    fn cyrillic_is_not_cut_in_the_middle_of_a_letter() {
        let text = "prod sérvér in the Zürich dätäcéntér — 東京 is the backup";
        let short = shorten(text, ROW_DETAIL_CHARS);
        assert_eq!(short.chars().count(), ROW_DETAIL_CHARS + 1);
        assert!(text.starts_with(short.trim_end_matches('…')));
    }
}
