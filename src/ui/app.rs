use gpui::{
    AnyElement, App, Bounds, Context, Entity, Focusable, KeyBinding, MouseButton, NoAction, Render,
    Result, SharedString, Subscription, Window, WindowBounds, WindowOptions, actions, div, img,
    prelude::*, px, size,
};
use gpui_component::{
    ActiveTheme, Disableable, Icon, IconName, Selectable, Sizable, StyledExt, TitleBar,
    button::{Button, ButtonVariants},
    h_flex,
    input::{Input, InputEvent, InputState},
    label::Label,
    scroll::ScrollableElement,
    v_flex,
};

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
mod vault_flow;

use crate::agent as ssh_agent;
use crate::keychain::OsKeychain;
use crate::ssh::{PtySize, spawn_ssh};
use crate::store::{VaultStore, migrate};
use crate::ui::connect::{self, HostSettings, KeyEntry, KnownHost, Target};
use crate::ui::settings::{self, Settings};
use crate::ui::terminal::{TerminalEvent, TerminalView};
use crate::ui::vault_ui::{self, Stage};
use crate::vault_session::StoredKey;
use crate::vault_session::VaultSession;
use futures::StreamExt;
use proto::{HostAuth, HostRecord};
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

struct EdgeDrag;

impl Render for EdgeDrag {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        gpui::Empty
    }
}

struct SessionTab {
    title: SharedString,
    kind: TabKind,
    request: connect::Request,
    credentials: connect::Credentials,
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

    section: Section,
    panel_open: bool,
    info_open: bool,
    info_tab: session_panel::InfoTab,
    showing_page: bool,
    editor_open: bool,
    settings_tab: SettingsTab,

    form: Form,
    proxy_form: proxy_ui::ProxyForm,
    snippet_form: snippets_ui::SnippetForm,
    snippets_open: bool,
    split_menu: bool,
    auto_unlock: bool,
    _subscriptions: Vec<Subscription>,

    vault: VaultSession,
    stage: Option<Stage>,
    vault_form: VaultForm,
    pending_import: Vec<HostRecord>,
    vault_warnings: Vec<SharedString>,
    autolock_task: Option<gpui::Task<()>>,
    vault_error: Option<SharedString>,
    reveal: Option<Reveal>,
    stored_rejected: Option<String>,
    vault_busy: bool,
    vault_task: Option<gpui::Task<()>>,
    hosts: Vec<KnownHost>,
    keys: Vec<KeyEntry>,
    agent: Option<ssh_agent::Running>,
    agent_task: Option<gpui::Task<()>>,
    agent_error: Option<SharedString>,
    sign_queue: std::collections::VecDeque<PendingSign>,
    importing: Option<PendingImport>,
    sync_input: Entity<InputState>,
    sync_status: Option<SharedString>,
    sync_error: Option<SharedString>,
    syncing: bool,
    sync_task: Option<gpui::Task<()>>,
    sync_watch: Option<gpui::Task<()>>,
    settings: Settings,
    error: Option<SharedString>,
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
    Confirming { target: String, copy: bool },
    Showing { target: String, text: SharedString },
}

struct VaultForm {
    password: Entity<InputState>,
    repeat: Entity<InputState>,
    code: Entity<InputState>,
    passphrase: Entity<InputState>,
    import: bool,
    notice: Option<SharedString>,
}

struct Form {
    editing: Option<String>,
    line: Entity<InputState>,
    label: Entity<InputState>,
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
        let field = |placeholder: &'static str, cx: &mut Context<Self>, window: &mut Window| {
            cx.new(|cx| InputState::new(window, cx).placeholder(placeholder))
        };

        let line = field("Поиск или user@host:port", cx, window);
        let label = field("Например, Production", cx, window);
        let host = field("Доменное имя или IP-адрес", cx, window);
        let port = field("22", cx, window);
        let user = field("Имя пользователя", cx, window);
        let password = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Пароль")
                .masked(true)
        });
        let key_path = field("Путь к файлу ключа", cx, window);
        let forward_draft = ports_ui::ForwardDraft::new(window, cx);
        let snippet_form = snippets_ui::SnippetForm::new(window, cx);
        let proxy_form = proxy_ui::ProxyForm::new(
            field("Например, Офис", cx, window),
            field("Доменное имя или IP-адрес", cx, window),
            field("1080", cx, window),
            field("Необязательно", cx, window),
            cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("Пароль")
                    .masked(true)
            }),
        );

        let mut subscriptions: Vec<Subscription> =
            vec![
                cx.subscribe(&line, |this, _, event: &InputEvent, cx| match event {
                    InputEvent::PressEnter { .. } => this.quick_connect(cx),
                    InputEvent::Change => cx.notify(),
                    _ => {}
                }),
            ];

        let vault_password = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Мастер-пароль")
                .masked(true)
        });
        let vault_repeat = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Повторите мастер-пароль")
                .masked(true)
        });
        let vault_code = field("XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-X", cx, window);
        let sync_input = field("Путь к общей папке", cx, window);
        let key_passphrase = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Парольная фраза ключа")
                .masked(true)
        });

        for input in [&vault_password, &vault_repeat, &vault_code] {
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

        let settings = settings::load();
        let (legacy_path, pending_import) = VaultSession::legacy_hosts();
        let _ = legacy_path;

        let vault_warnings: Vec<SharedString> = crate::platform::harden_process()
            .into_iter()
            .map(SharedString::from)
            .collect();

        let store = VaultStore::new(
            VaultStore::default_root().unwrap_or_else(|| std::path::PathBuf::from("vault")),
        );
        let vault = VaultSession::open(store, settings.autolock_timeout());

        let stage = if vault.state().is_absent() {
            Some(Stage::Create)
        } else {
            Some(Stage::Unlock)
        };

        let mut this = Self {
            tabs: Vec::new(),
            active: None,
            section: Section::Hosts,
            panel_open: true,
            info_open: true,
            info_tab: session_panel::InfoTab::Info,
            showing_page: true,
            editor_open: false,
            settings_tab: SettingsTab::General,
            form: Form {
                editing: None,
                line,
                label,
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
            auto_unlock: false,
            _subscriptions: subscriptions,
            vault,
            stage,
            vault_form: VaultForm {
                password: vault_password,
                repeat: vault_repeat,
                code: vault_code,
                passphrase: key_passphrase,
                import: !pending_import.is_empty(),
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
            hosts: connect::list_known_hosts(),
            keys: connect::list_keys(),
            agent: None,
            agent_task: None,
            agent_error: None,
            sign_queue: std::collections::VecDeque::new(),
            importing: None,
            sync_input,
            sync_status: None,
            sync_error: None,
            syncing: false,
            sync_task: None,
            sync_watch: None,
            settings,
            error: None,
        };

        let folder = this.settings.sync_folder.clone();
        if !folder.is_empty() {
            this.sync_input
                .update(cx, |state, cx| state.set_value(&folder, window, cx));
        }

        this.autolock_task = Some(cx.spawn(async move |this: gpui::WeakEntity<Self>, cx| {
            loop {
                cx.background_executor()
                    .timer(std::time::Duration::from_secs(30))
                    .await;
                if this.update(cx, |this, cx| this.check_autolock(cx)).is_err() {
                    return;
                }
            }
        }));

        if matches!(this.stage, Some(Stage::Unlock)) && this.vault.has_os_key() {
            this.auto_unlock = true;
            this.unlock_with_os_key(cx);
        }

        if let Some(raw) = std::env::args().nth(1) {
            this.open(&raw, &connect::Credentials::default(), cx);
        }

        this
    }

    fn read_form(
        &self,
        cx: &Context<Self>,
    ) -> std::result::Result<(String, connect::Credentials), String> {
        let auth = match &self.form.auth {
            HostAuth::Key { .. } => {
                let path = self.form.key_path.read(cx).value().trim().to_string();
                if path.is_empty() {
                    return Err("Укажите путь к файлу ключа.".into());
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
            return Err("Укажите адрес сервера.".into());
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

        let (via, proxy_error) = self.resolve_chain(&self.form.via);
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
            },
        ))
    }

    fn connect_from_form(&mut self, cx: &mut Context<Self>) {
        match self.read_form(cx) {
            Ok((target, credentials)) => self.open(&target, &credentials, cx),
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
        let existing = self
            .vault
            .unlocked()
            .and_then(|unlocked| unlocked.find_by_target(&original));
        let device_only = existing.as_ref().is_some_and(|entry| entry.device_only);
        if let Some(existing) = &existing {
            host.secrets = existing.host.secrets.clone();
            host.forward_agent = existing.host.forward_agent;
        }
        let renamed = existing
            .map(|entry| entry.id)
            .filter(|_| original != host.target());

        host.label = self.form.label.read(cx).value().trim().to_string();
        host.auth = credentials.auth;
        host.via = self.form.via.clone();
        host.forwards = self.form.forwards.clone();
        let saved_target = host.target();

        self.persist(cx, |unlocked, store| {
            unlocked.upsert_host_with(store, host, device_only)?;
            if let Some(old) = renamed {
                unlocked.remove_host(store, &old)?;
            }
            Ok(())
        });
        if self.error.is_none() {
            self.form.editing = Some(saved_target);
        }
        if self.error.is_none() {
            self.editor_open = false;
        }
    }

    fn edit(&mut self, target: &str, window: &mut Window, cx: &mut Context<Self>) {
        let Some(host) = self
            .vault
            .unlocked()
            .and_then(|unlocked| unlocked.find_by_target(target))
            .map(|entry| entry.host)
        else {
            return;
        };
        self.fill_form(host, window, cx);
    }

    fn fill_form(&mut self, host: HostRecord, window: &mut Window, cx: &mut Context<Self>) {
        self.form.editing = Some(host.target());
        self.form.auth = host.auth.clone();
        self.form.via = host.via.clone();
        self.form.forwards = host.forwards.clone();
        self.section = Section::Hosts;
        self.showing_page = true;
        self.editor_open = true;
        self.panel_open = true;

        let port = host.port.to_string();
        let key = match &host.auth {
            HostAuth::Key { path } => path.clone(),
            _ => String::new(),
        };
        self.form
            .label
            .update(cx, |state, cx| state.set_value(host.label, window, cx));
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

    fn forget(&mut self, target: &str, cx: &mut Context<Self>) {
        let Some(id) = self
            .vault
            .unlocked()
            .and_then(|unlocked| unlocked.find_by_target(target))
            .map(|entry| entry.id)
        else {
            return;
        };
        self.persist(cx, move |unlocked, store| unlocked.remove_host(store, &id));
    }

    fn persist<F>(&mut self, cx: &mut Context<Self>, edit: F)
    where
        F: FnOnce(&mut crate::vault_session::Unlocked, &VaultStore) -> anyhow::Result<()>,
    {
        let store = VaultStore::new(self.vault.store().root().to_path_buf());
        let Some(unlocked) = self.vault.unlocked_mut() else {
            self.error = Some("Хранилище заблокировано.".into());
            cx.notify();
            return;
        };

        self.error = edit(unlocked, &store)
            .err()
            .map(|error| SharedString::from(format!("{error:#}")));
        self.vault.touch(std::time::Instant::now());
        cx.notify();
    }

    fn on_terminal_event(&mut self, target: &str, event: &TerminalEvent, cx: &mut Context<Self>) {
        match event {
            TerminalEvent::SaveSecret { purpose, secret } => {
                self.remember_secret(target, *purpose, secret.clone(), cx);
            }
            TerminalEvent::StoredPasswordRejected => {
                self.stored_rejected = Some(target.to_owned());
                cx.notify();
            }
            TerminalEvent::Typed(_) => {}
        }
    }

    fn remember_secret(
        &mut self,
        target: &str,
        purpose: proto::SecretPurpose,
        secret: proto::Secret,
        cx: &mut Context<Self>,
    ) {
        let Some(unlocked) = self.vault.unlocked() else {
            self.error = Some("Хранилище заблокировано. Пароль не сохранён.".into());
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
                    self.error = Some(SharedString::from(format!(
                        "Не удалось сохранить пароль: {error}"
                    )));
                    cx.notify();
                    return;
                }
            },
        };
        host.secrets.set(purpose, secret);

        self.persist(cx, |unlocked, store| {
            unlocked.upsert_host(store, host).map(|_| ())
        });
    }

    fn forget_secret(
        &mut self,
        target: &str,
        purpose: proto::SecretPurpose,
        cx: &mut Context<Self>,
    ) {
        let Some(mut host) = self
            .vault
            .unlocked()
            .and_then(|unlocked| unlocked.find_by_target(target))
            .map(|entry| entry.host)
        else {
            return;
        };
        if !host.secrets.remove(purpose) {
            return;
        }
        self.persist(cx, |unlocked, store| {
            unlocked.upsert_host(store, host).map(|_| ())
        });
    }

    fn toggle_device_only(&mut self, target: &str, cx: &mut Context<Self>) {
        let Some(entry) = self
            .vault
            .unlocked()
            .and_then(|unlocked| unlocked.find_by_target(target))
        else {
            return;
        };
        let host = entry.host;
        let device_only = !entry.device_only;
        self.persist(cx, move |unlocked, store| {
            unlocked
                .upsert_host_with(store, host, device_only)
                .map(|_| ())
        });
    }

    fn toggle_forward_agent(&mut self, target: &str, cx: &mut Context<Self>) {
        let Some(entry) = self
            .vault
            .unlocked()
            .and_then(|unlocked| unlocked.find_by_target(target))
        else {
            return;
        };
        let mut host = entry.host;
        host.forward_agent = !host.forward_agent;
        self.persist(cx, move |unlocked, store| {
            unlocked.upsert_host(store, host).map(|_| ())
        });
    }

    fn ask_reveal(&mut self, target: &str, copy: bool, cx: &mut Context<Self>) {
        self.reveal = Some(Reveal::Confirming {
            target: target.to_owned(),
            copy,
        });
        cx.notify();
    }

    fn confirm_reveal(&mut self, cx: &mut Context<Self>) {
        let Some(Reveal::Confirming { target, copy }) = self.reveal.clone() else {
            return;
        };

        let Some(secret) = self
            .vault
            .unlocked()
            .and_then(|unlocked| unlocked.find_by_target(&target))
            .and_then(|entry| entry.host.password().cloned())
        else {
            self.reveal = None;
            self.error = Some("Сохранённый пароль отсутствует.".into());
            cx.notify();
            return;
        };

        let Ok(text) = std::str::from_utf8(secret.expose()) else {
            self.reveal = None;
            self.error = Some(
                "Сохранённый пароль содержит недопустимые символы и не может быть показан.".into(),
            );
            cx.notify();
            return;
        };

        if copy {
            cx.write_to_clipboard(gpui::ClipboardItem::new_string(text.to_owned()));
            self.reveal = None;
            self.error = Some("Пароль скопирован в буфер обмена.".into());
        } else {
            self.reveal = Some(Reveal::Showing {
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
        let can = self.vault.state().is_unlocked();
        for view in self.tabs.iter().flat_map(SessionTab::terminals) {
            view.update(cx, |view, cx| view.set_can_save_secrets(can, cx));
        }
    }

    fn check_autolock(&mut self, cx: &mut Context<Self>) {
        let Some(reason) = self
            .vault
            .tick(std::time::Instant::now(), crate::store::now_ms())
        else {
            return;
        };
        self.stage = Some(Stage::Unlock);
        self.vault_error = Some(reason.into());
        self.reveal = None;
        self.sync_can_save_secrets(cx);
        cx.notify();
    }

    fn open(&mut self, raw: &str, credentials: &connect::Credentials, cx: &mut Context<Self>) {
        self.vault.touch(std::time::Instant::now());
        match connect::parse_target(raw) {
            Ok(request) => {
                self.error = None;
                self.spawn_tab(request, credentials.clone(), cx);
            }
            Err(error) => {
                self.error = Some(error.into());
                cx.notify();
            }
        }
    }

    fn open_saved(&mut self, target: &str, cx: &mut Context<Self>) {
        let credentials = self
            .vault
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
            .unwrap_or_default();
        let target = target.to_string();
        self.open(&target, &credentials, cx);
    }

    fn spawn_tab(
        &mut self,
        request: connect::Request,
        credentials: connect::Credentials,
        cx: &mut Context<Self>,
    ) {
        let settings = connect::read_ssh_config(&request.alias);
        let target = connect::resolve(&request, &settings);

        let agent = self.agent_address();
        let Some(view) = Self::start_session(&target, &settings, &credentials, agent, cx) else {
            self.error = Some("Не удалось запустить сеанс.".into());
            cx.notify();
            return;
        };

        let title = self
            .vault
            .unlocked()
            .and_then(|unlocked| unlocked.find_by_target(&target.to_string()))
            .map(|entry| entry.host.title())
            .unwrap_or_else(|| target.to_string());

        let can_save = self.vault.state().is_unlocked();
        view.update(cx, |view, cx| view.set_can_save_secrets(can_save, cx));

        let events = self.subscribe_terminal(&view, target.to_string(), cx);

        self.tabs.push(SessionTab {
            title: title.into(),
            kind: TabKind::Terminal {
                view,
                _events: events,
                files: None,
                editor: None,
                split: Default::default(),
            },
            request,
            credentials,
        });
        self.active = Some(self.tabs.len() - 1);
        self.showing_page = false;
        self.apply_appearance(cx);
        self.focus_active(cx);
    }

    fn open_files(&mut self, raw: &str, credentials: connect::Credentials, cx: &mut Context<Self>) {
        self.vault.touch(std::time::Instant::now());
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

        let name = self
            .vault
            .unlocked()
            .and_then(|unlocked| unlocked.find_by_target(&target.to_string()))
            .map(|entry| entry.host.title())
            .unwrap_or_else(|| target.to_string());
        let title = format!("Файлы: {name}");
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
            kind: TabKind::Files {
                view,
                _events: events,
            },
            request,
            credentials,
        });
        self.active = Some(self.tabs.len() - 1);
        self.showing_page = false;
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

    fn reconnect(&mut self, index: usize, cx: &mut Context<Self>) {
        let Some(tab) = self.tabs.get(index) else {
            return;
        };
        if tab.is_files() {
            return;
        }
        let request = tab.request.clone();
        let credentials = tab.credentials.clone();
        let settings = connect::read_ssh_config(&request.alias);
        let target = connect::resolve(&request, &settings);

        let agent = self.agent_address();
        if let Some(view) = Self::start_session(&target, &settings, &credentials, agent, cx) {
            let can_save = self.vault.state().is_unlocked();
            view.update(cx, |view, cx| view.set_can_save_secrets(can_save, cx));

            let events = self.subscribe_terminal(&view, target.to_string(), cx);

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
        });
        self.active = Some(self.tabs.len() - 1);
        self.showing_page = false;
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
        self.tabs.remove(index);
        self.active = match self.tabs.len() {
            0 => None,
            len => Some(index.min(len - 1)),
        };
        if self.active.is_none() {
            self.showing_page = true;
        }
        self.focus_active(cx);
    }

    fn select(&mut self, index: usize, cx: &mut Context<Self>) {
        if index < self.tabs.len() {
            self.active = Some(index);
            self.showing_page = false;
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
        self.panel_open = true;
        self.section = Section::Hosts;
        self.form.line.read(cx).focus_handle(cx).focus(window);
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

    fn on_toggle_panel(&mut self, _: &TogglePanel, _window: &mut Window, cx: &mut Context<Self>) {
        self.panel_open = !self.panel_open;
        cx.notify();
    }

    fn title_bar(&self, cx: &mut Context<Self>) -> AnyElement {
        let dark = cx.theme().mode.is_dark();
        let muted = cx.theme().muted_foreground;
        let panel_open = self.panel_open;
        let info_open = self.info_open;
        let active_tab = self
            .active
            .filter(|_| !self.showing_page)
            .and_then(|index| self.tabs.get(index));
        let has_terminal = active_tab.is_some_and(|tab| tab.terminal().is_some());
        let current_title = active_tab.map(|tab| tab.title.clone());

        TitleBar::new()
            .child(
                h_flex()
                    .gap_2()
                    .items_center()
                    .child(img("brand/cratty.svg").size_4())
                    .child(Label::new("cratty").font_semibold())
                    .child(
                        Button::new("toggle-panel")
                            .ghost()
                            .xsmall()
                            .icon(Icon::new(if panel_open {
                                IconName::PanelLeftClose
                            } else {
                                IconName::PanelLeftOpen
                            }))
                            .tooltip("Показать или скрыть боковую панель")
                            .on_click(cx.listener(|this, _, _window, cx| {
                                this.panel_open = !this.panel_open;
                                cx.notify();
                            })),
                    ),
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
                h_flex()
                    .justify_end()
                    .pr_2()
                    .gap_1()
                    .when(has_terminal, |this| {
                        this.child(
                            Button::new("toggle-info")
                                .ghost()
                                .xsmall()
                                .selected(info_open)
                                .icon(Icon::empty().path("icons/panel-left-open.svg"))
                                .tooltip("Показать или скрыть панель сеанса")
                                .on_click(cx.listener(|this, _, _window, cx| {
                                    this.info_open = !this.info_open;
                                    cx.notify();
                                })),
                        )
                    })
                    .child(
                        Button::new("theme")
                            .ghost()
                            .xsmall()
                            .icon(Icon::new(if dark { IconName::Sun } else { IconName::Moon }))
                            .tooltip("Переключить тему оформления")
                            .on_click(cx.listener(|this, _, window, cx| {
                                let next = this.settings.toggled_scheme();
                                this.settings.set_scheme(next);
                                this.error =
                                    settings::save(&this.settings).err().map(SharedString::from);
                                crate::ui::theme::apply(&this.settings, Some(window), cx);
                                this.apply_appearance(cx);
                            })),
                    ),
            )
            .into_any_element()
    }

    fn edge_handle(&self, id: &'static str, edge: Edge, cx: &mut Context<Self>) -> AnyElement {
        let accent = cx.theme().primary;
        div()
            .id(id)
            .w(px(4.))
            .h_full()
            .flex_shrink_0()
            .cursor_col_resize()
            .hover(move |style| style.bg(accent))
            .on_drag(edge, |_, _, _, cx| cx.new(|_| EdgeDrag))
            .into_any_element()
    }

    fn panel_title(text: &'static str, muted: gpui::Hsla) -> AnyElement {
        div()
            .px_3()
            .pt_3()
            .pb_2()
            .child(Label::new(text).text_sm().font_semibold().text_color(muted))
            .into_any_element()
    }

    fn field_label(text: &'static str, muted: gpui::Hsla) -> AnyElement {
        Label::new(text)
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
                    .label("Автоматически")
                    .tooltip("Ключи SSH-агента, затем ключи из ~/.ssh")
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
                    .label("Пароль")
                    .tooltip("Аутентификация по паролю учётной записи")
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
                    .label("Файл ключа")
                    .tooltip("Аутентификация по указанному файлу ключа")
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
                    .child(Self::field_label("Название", muted))
                    .child(Input::new(&self.form.label)),
            )
            .child(
                h_flex()
                    .gap_2()
                    .items_end()
                    .child(
                        v_flex()
                            .flex_grow()
                            .gap_1()
                            .child(Self::field_label("Адрес", muted))
                            .child(Input::new(&self.form.host)),
                    )
                    .child(
                        v_flex()
                            .w(px(72.))
                            .gap_1()
                            .child(Self::field_label("Порт", muted))
                            .child(Input::new(&self.form.port)),
                    ),
            )
            .child(
                v_flex()
                    .gap_1()
                    .child(Self::field_label("Пользователь", muted))
                    .child(Input::new(&self.form.user)),
            )
            .into_any_element()
    }

    fn auth_fields(&self, cx: &mut Context<Self>) -> AnyElement {
        let muted = cx.theme().muted_foreground;

        match self.form.auth {
            HostAuth::Auto => Label::new(
                "Используются ключи SSH-агента, затем ключи из каталога ~/.ssh.",
            )
            .text_xs()
            .text_color(muted)
            .into_any_element(),
            HostAuth::Password => v_flex()
                .gap_1()
                .child(Input::new(&self.form.password))
                .child(
                    Label::new(
                        "Пароль передаётся только на этот сервер. Чтобы не вводить его при каждом подключении, сохраните хост.",
                    )
                    .text_xs()
                    .text_color(muted),
                )
                .into_any_element(),
            HostAuth::Key { .. } => v_flex()
                .gap_1()
                .child(Input::new(&self.form.key_path))
                .child(
                    Label::new(
                        "Укажите путь к закрытому ключу, например ~/.ssh/id_ed25519. Парольная фраза зашифрованного ключа будет запрошена при подключении.",
                    )
                    .text_xs()
                    .text_color(muted),
                )
                .into_any_element(),
        }
    }

    fn record_controls(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let muted = cx.theme().muted_foreground;
        let warning = cx.theme().warning;
        let border = cx.theme().border;

        let target = self.form.editing.clone()?;
        let entry = self.vault.unlocked()?.find_by_target(&target)?;

        let has_password = entry.host.has_password();
        let device_only = entry.device_only;
        let forward_agent = entry.host.forward_agent;
        let for_forward = target.clone();
        let for_forget = target.clone();
        let for_show = target.clone();
        let for_copy = target.clone();
        let for_bind = target.clone();

        let showing = match &self.reveal {
            Some(Reveal::Showing {
                target: shown,
                text,
            }) if *shown == target => Some(text.clone()),
            _ => None,
        };
        let confirming = matches!(
            &self.reveal,
            Some(Reveal::Confirming { target: asked, .. }) if *asked == target
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
                                .label("Не синхронизировать")
                                .tooltip(
                                    "Запись хранится только на этом устройстве и не синхронизируется.",
                                )
                                .on_click(cx.listener(move |this, _, _window, cx| {
                                    let target = for_bind.clone();
                                    this.toggle_device_only(&target, cx);
                                })),
                        )
                        .child(
                            Button::new("record-forward-agent")
                                .ghost()
                                .small()
                                .selected(forward_agent)
                                .label("Переадресация SSH-агента")
                                .tooltip(
                                    "Аналог ssh -A. Сервер сможет запрашивать подписи вашими ключами на время сеанса; каждый запрос требует подтверждения.",
                                )
                                .on_click(cx.listener(move |this, _, _window, cx| {
                                    let target = for_forward.clone();
                                    this.toggle_forward_agent(&target, cx);
                                })),
                        ),
                )
                .when(has_password, |this| {
                    this.child(
                        h_flex()
                            .gap_1()
                            .child(Label::new("Пароль сохранён").text_xs().text_color(muted))
                            .child(
                                Button::new("record-show-password")
                                    .ghost()
                                    .small()
                                    .label("Показать")
                                    .on_click(cx.listener(move |this, _, _window, cx| {
                                        let target = for_show.clone();
                                        this.ask_reveal(&target, false, cx);
                                    })),
                            )
                            .child(
                                Button::new("record-copy-password")
                                    .ghost()
                                    .small()
                                    .label("Скопировать")
                                    .on_click(cx.listener(move |this, _, _window, cx| {
                                        let target = for_copy.clone();
                                        this.ask_reveal(&target, true, cx);
                                    })),
                            )
                            .child(
                                Button::new("record-forget-password")
                                    .ghost()
                                    .small()
                                    .label("Удалить")
                                    .on_click(cx.listener(move |this, _, _window, cx| {
                                        let target = for_forget.clone();
                                        this.forget_secret(
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
                                Label::new(
                                    "Пароль будет показан на экране или помещён в буфер обмена, доступный другим программам. Продолжить?",
                                )
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
                                            .label("Продолжить")
                                            .on_click(cx.listener(|this, _, _window, cx| {
                                                this.confirm_reveal(cx)
                                            })),
                                    )
                                    .child(
                                        Button::new("reveal-no")
                                            .ghost()
                                            .small()
                                            .label("Отмена")
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
                                .label("Скрыть")
                                .on_click(cx.listener(|this, _, _window, cx| this.hide_reveal(cx))),
                        )
                }))
                .into_any_element(),
        )
    }

    fn stored_rejected_notice(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let danger = cx.theme().danger;
        let border = cx.theme().border;
        let target = self.stored_rejected.clone()?;
        let for_forget = target.clone();

        Some(
            v_flex()
                .p_2()
                .gap_1()
                .rounded_md()
                .border_1()
                .border_color(danger)
                .child(
                    Label::new(SharedString::from(format!(
                        "Сервер отклонил сохранённый пароль для {target}. Повторные попытки прекращены во избежание блокировки."
                    )))
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
                                .label("Удалить пароль и запросить заново")
                                .on_click(cx.listener(move |this, _, _window, cx| {
                                    let target = for_forget.clone();
                                    this.forget_secret(&target, proto::SecretPurpose::Password, cx);
                                    this.stored_rejected = None;
                                    cx.notify();
                                })),
                        )
                        .child(
                            Button::new("stored-rejected-dismiss")
                                .ghost()
                                .xsmall()
                                .label("Закрыть")
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
            .child(Label::new("Сеанс завершён").text_sm().text_color(muted))
            .child(
                Button::new("reconnect")
                    .primary()
                    .small()
                    .icon(Icon::new(IconName::Replace))
                    .label("Переподключиться")
                    .on_click(cx.listener(move |this, _, _window, cx| this.reconnect(index, cx))),
            )
            .into_any_element()
    }
}

impl Render for AppView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.track_pane_focus(window, cx);
        let title_bar = self.title_bar(cx);
        let rail = self.rail(cx);
        let workspace = self.workspace(cx);
        let session_panel = self.session_panel(cx);
        let foreground = cx.theme().foreground;

        let sign_dialog = self.sign_dialog(cx);

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
                    .child(title_bar)
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .flex_grow()
                            .overflow_hidden()
                            .when(rail.is_some(), |this| {
                                this.children(rail).child(self.edge_handle(
                                    "edge-rail",
                                    Edge::Rail,
                                    cx,
                                ))
                            })
                            .child(div().flex_grow().overflow_hidden().child(workspace))
                            .when(session_panel.is_some(), |this| {
                                this.child(self.edge_handle("edge-panel", Edge::Panel, cx))
                                    .children(session_panel)
                            })
                            .on_drag_move(cx.listener(
                                |this, event: &gpui::DragMoveEvent<Edge>, window, cx| {
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
                                            if this.info_open && !this.showing_page {
                                                right -= this.settings.panel_width + 4.0;
                                            }
                                            let left = if this.panel_open {
                                                this.settings.rail_width + 4.0
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
    }
}

pub fn open_main_window(cx: &mut App) -> Result<()> {
    crate::ui::font::MonoFont::init(cx);
    gpui_component::init(cx);

    let startup = settings::load();
    crate::ui::theme::apply(&startup, None, cx);

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
        KeyBinding::new(&shortcut("t"), NewTab, None),
        KeyBinding::new(&shortcut("w"), CloseTab, None),
        KeyBinding::new(&shortcut("]"), NextTab, None),
        KeyBinding::new(&shortcut("["), PrevTab, None),
        KeyBinding::new(&shortcut("b"), TogglePanel, None),
        KeyBinding::new("tab", NoAction, Some("Terminal")),
        KeyBinding::new("shift-tab", NoAction, Some("Terminal")),
    ]);

    cx.on_window_closed(|cx| {
        if cx.windows().is_empty() {
            cx.quit();
        }
    })
    .detach();

    let bounds = Bounds::centered(None, size(px(1180.), px(760.)), cx);
    cx.open_window(
        WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(bounds)),
            window_min_size: Some(size(px(640.), px(400.))),
            titlebar: Some(TitleBar::title_bar_options()),
            window_decorations: Some(gpui::WindowDecorations::Client),
            app_id: Some("cratty".into()),
            window_background: crate::ui::theme::window_background(&startup),
            ..Default::default()
        },
        |window, cx| {
            let app: Entity<AppView> = cx.new(|cx| AppView::new(window, cx));
            let view: gpui::AnyView = app.into();
            cx.new(|cx| gpui_component::Root::new(view, window, cx))
        },
    )?;

    Ok(())
}

fn to_rgb(color: gpui::Hsla) -> crate::term::Rgb {
    let rgba: gpui::Rgba = color.into();
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
    fn korotkaya_stroka_ne_menyaetsya_a_dlinnaya_obrezaetsya() {
        assert_eq!(shorten("prod-01", ROW_TITLE_CHARS), "prod-01");

        let long = "administrator@very-long-hostname.production.example.com";
        let short = shorten(long, ROW_TITLE_CHARS);
        assert_eq!(short.chars().count(), ROW_TITLE_CHARS + 1, "{short}");
        assert!(short.ends_with('…'));
        assert!(long.starts_with(short.trim_end_matches('…')));
    }

    #[test]
    fn kirillica_ne_ryvetsya_poseredine_bukvy() {
        let text = "боевой сервер в московском датацентре, тот самый";
        let short = shorten(text, ROW_DETAIL_CHARS);
        assert_eq!(short.chars().count(), ROW_DETAIL_CHARS + 1);
        assert!(text.starts_with(short.trim_end_matches('…')));
    }
}
