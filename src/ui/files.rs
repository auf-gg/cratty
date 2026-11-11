use rust_i18n::t;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use gpui_kit::component::{
    ActiveTheme, Disableable, Icon, IconName, Selectable, Sizable,
    button::{Button, ButtonVariants},
    h_flex,
    input::{Input, InputEvent, InputState},
    label::Label,
    menu::{ContextMenuExt as _, PopupMenu, PopupMenuItem},
    scroll::ScrollableElement,
    v_flex,
};
use gpui_kit::{
    AnyElement, Context, Entity, ExternalPaths, FocusHandle, Focusable, IntoElement, Modifiers,
    MouseButton, MouseDownEvent, Render, SharedString, Subscription, WeakEntity, Window, div,
    prelude::*, px,
};

use crate::ssh::sftp::{self, FromSftp, RemoteEntry, SftpHandle, ToSftp, TransferId};
use crate::ssh::{Answer, CloseReason, FromSsh, HostKeyDecision, SshConfig};

#[derive(Clone, Debug)]
struct LocalEntry {
    name: String,
    path: PathBuf,
    is_dir: bool,
    hidden: bool,
    size: u64,
    modified: Option<SystemTime>,
}

#[derive(Clone, Debug)]
enum Dragged {
    Local(Vec<PathBuf>),
    Remote(Vec<RemoteEntry>),
}

struct DragPreview(SharedString);

impl Render for DragPreview {
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

#[derive(Default)]
struct Selection {
    rows: BTreeSet<usize>,
    anchor: Option<usize>,
}

impl Selection {
    fn click(&mut self, index: usize, modifiers: &Modifiers) {
        let add = modifiers.control || modifiers.platform;
        if modifiers.shift {
            let anchor = self.anchor.unwrap_or(index);
            let (from, to) = if anchor <= index {
                (anchor, index)
            } else {
                (index, anchor)
            };
            if !add {
                self.rows.clear();
            }
            self.rows.extend(from..=to);
        } else if add {
            if !self.rows.remove(&index) {
                self.rows.insert(index);
            }
            self.anchor = Some(index);
        } else {
            self.rows.clear();
            self.rows.insert(index);
            self.anchor = Some(index);
        }
    }

    fn clear(&mut self) {
        self.rows.clear();
        self.anchor = None;
    }

    fn contains(&self, index: usize) -> bool {
        self.rows.contains(&index)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direction {
    Upload,
    Download,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TransferState {
    Running,
    Done,
    Failed(String),
}

struct Transfer {
    id: TransferId,
    name: String,
    direction: Direction,
    done: u64,
    total: u64,
    state: TransferState,
    target_dir: String,
}

#[derive(Clone, Debug)]
enum Pending {
    Upload(Vec<(PathBuf, String)>),
    Download(Vec<(String, PathBuf)>),
    Remove(Vec<String>),
}

enum Dialog {
    Confirm {
        message: SharedString,
        action: Pending,
    },
    Name {
        rename_from: Option<String>,
        initial: String,
        input: Option<Entity<InputState>>,
    },
    Secret {
        label: SharedString,
        input: Option<Entity<InputState>>,
    },
    HostKey {
        message: SharedString,
        fingerprint: SharedString,
        changed: bool,
    },
}

enum Status {
    Connecting,
    Ready,
    Closed { message: SharedString, failed: bool },
}

/// Path of a pane: breadcrumbs, and on a click an input to type the path.
#[derive(Default)]
struct PathBar {
    input: Option<Entity<InputState>>,
    stale: bool,
    /// The input is shown instead of the breadcrumbs.
    editing: bool,
    /// Focus the input on the next render (it has just been shown).
    focus: bool,
    _subscription: Option<Subscription>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    Local,
    Remote,
}

pub enum FilesEvent {
    OpenFile {
        path: String,
        name: String,
        content: String,
        commands: futures::channel::mpsc::UnboundedSender<ToSftp>,
    },
}

impl gpui_kit::EventEmitter<FilesEvent> for FilesView {}

pub struct FilesView {
    _pump: gpui_kit::Task<()>,
    handle: Option<SftpHandle>,
    config: Option<SshConfig>,
    compact: bool,
    title: SharedString,
    status: Status,
    local_path: PathBuf,
    local: Vec<LocalEntry>,
    local_error: Option<SharedString>,
    local_selection: Selection,
    local_bar: PathBar,
    local_hidden: bool,
    local_focus: FocusHandle,
    remote_path: String,
    remote: Vec<RemoteEntry>,
    remote_selection: Selection,
    remote_error: Option<SharedString>,
    remote_bar: PathBar,
    remote_hidden: bool,
    remote_focus: FocusHandle,
    transfers: Vec<Transfer>,
    next_id: TransferId,
    dialog: Option<Dialog>,
    _dialog_subscription: Option<Subscription>,
}

impl FilesView {
    pub fn new(title: impl Into<SharedString>, config: SshConfig, cx: &mut Context<Self>) -> Self {
        let mut this = Self::blank(title.into(), Some(config), false, cx);
        this.connect(cx);
        this
    }

    pub fn attached(
        title: impl Into<SharedString>,
        handle: SftpHandle,
        cx: &mut Context<Self>,
    ) -> Self {
        let mut this = Self::blank(title.into(), None, true, cx);
        this.attach_handle(handle, cx);
        this
    }

    fn blank(
        title: SharedString,
        config: Option<SshConfig>,
        compact: bool,
        cx: &mut Context<Self>,
    ) -> Self {
        let local_path = home_dir();
        let mut this = Self {
            _pump: gpui_kit::Task::ready(()),
            handle: None,
            config,
            compact,
            title,
            status: Status::Connecting,
            local_path: local_path.clone(),
            local: Vec::new(),
            local_error: None,
            local_selection: Selection::default(),
            local_bar: PathBar::default(),
            local_hidden: false,
            local_focus: cx.focus_handle(),
            remote_path: String::new(),
            remote: Vec::new(),
            remote_selection: Selection::default(),
            remote_error: None,
            remote_bar: PathBar::default(),
            remote_hidden: false,
            remote_focus: cx.focus_handle(),
            transfers: Vec::new(),
            next_id: 1,
            dialog: None,
            _dialog_subscription: None,
        };
        this.open_local(local_path);
        this
    }

    pub fn title(&self) -> SharedString {
        self.title.clone()
    }

    pub fn is_closed(&self) -> bool {
        matches!(self.status, Status::Closed { .. })
    }

    fn connect(&mut self, cx: &mut Context<Self>) {
        let Some(config) = self.config.clone() else {
            return;
        };
        match sftp::spawn_sftp(config) {
            Ok(handle) => self.attach_handle(handle, cx),
            Err(error) => {
                self.status = Status::Closed {
                    message: t!("files.stream_failed", error = error).into(),
                    failed: true,
                };
            }
        }
    }

    fn attach_handle(&mut self, mut handle: SftpHandle, cx: &mut Context<Self>) {
        self.status = Status::Connecting;
        let mut events =
            std::mem::replace(&mut handle.events, futures::channel::mpsc::channel(0).1);
        self.handle = Some(handle);

        self._pump = cx.spawn(async move |this: gpui_kit::WeakEntity<Self>, cx| {
            use futures::StreamExt;
            while let Some(event) = events.next().await {
                let mut batch = vec![event];
                while let Ok(more) = events.try_recv() {
                    batch.push(more);
                }
                let alive = this.update(cx, |this, cx| {
                    for event in batch {
                        this.apply(event);
                    }
                    cx.notify();
                });
                if alive.is_err() {
                    return;
                }
            }
            let _ = this.update(cx, |this, cx| {
                if !this.is_closed() {
                    this.handle = None;
                    this.status = Status::Closed {
                        message: t!("files.closed").into(),
                        failed: false,
                    };
                    cx.notify();
                }
            });
        });
    }

    fn open_remote_file(&mut self, entry: RemoteEntry, cx: &mut Context<Self>) {
        let Some(handle) = &self.handle else {
            return;
        };
        if entry.size > sftp::MAX_EDIT_BYTES {
            self.remote_error = Some(
                t!(
                    "files.too_large",
                    name = entry.name,
                    mb = sftp::MAX_EDIT_BYTES / 1024 / 1024
                )
                .into(),
            );
            cx.notify();
            return;
        }
        let commands = handle.commands.clone();
        let (reply, answer) = futures::channel::oneshot::channel();
        self.send(ToSftp::ReadFile {
            path: entry.path.clone(),
            reply,
        });
        self.remote_error = None;
        cx.spawn(async move |this: gpui_kit::WeakEntity<Self>, cx| {
            let result = answer.await;
            let _ = this.update(cx, |this, cx| {
                match result {
                    Ok(Ok(bytes)) => match String::from_utf8(bytes) {
                        Ok(content) => cx.emit(FilesEvent::OpenFile {
                            path: entry.path.clone(),
                            name: entry.name.clone(),
                            content,
                            commands,
                        }),
                        Err(_) => {
                            this.remote_error = Some(
                                t!("files.not_text", name = entry.name).into(),
                            )
                        }
                    },
                    Ok(Err(error)) => this.remote_error = Some(error.into()),
                    Err(_) => this.remote_error = Some(t!("files.closed").into()),
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn download_to_chosen(&mut self, entries: Vec<RemoteEntry>, cx: &mut Context<Self>) {
        if entries.is_empty() {
            return;
        }
        let receiver = cx.prompt_for_paths(gpui_kit::PathPromptOptions {
            files: false,
            directories: true,
            multiple: false,
            prompt: Some(t!("files.download_here").into()),
        });
        cx.spawn(async move |this: gpui_kit::WeakEntity<Self>, cx| {
            if let Ok(Ok(Some(paths))) = receiver.await
                && let Some(dir) = paths.into_iter().next()
            {
                let _ = this.update(cx, |this, cx| {
                    this.open_local(dir);
                    this.download(entries, cx);
                });
            }
        })
        .detach();
    }

    fn send(&self, command: ToSftp) {
        if let Some(handle) = &self.handle {
            let _ = handle.commands.unbounded_send(command);
        }
    }

    fn answer(&self, answer: Answer) {
        if let Some(handle) = &self.handle {
            let _ = handle.answers.unbounded_send(answer);
        }
    }

    fn apply(&mut self, event: FromSftp) {
        match event {
            FromSftp::Ssh(FromSsh::NeedSecret { prompt, .. }) => {
                self.dialog = Some(Dialog::Secret {
                    label: prompt.into(),
                    input: None,
                });
            }
            FromSftp::Ssh(FromSsh::NeedHostKey {
                message,
                fingerprint,
                changed,
                ..
            }) => {
                self.dialog = Some(Dialog::HostKey {
                    message: message.into(),
                    fingerprint: fingerprint.into(),
                    changed,
                });
            }
            FromSftp::Ssh(FromSsh::Closed(reason)) => {
                self.handle = None;
                self.status = match reason {
                    CloseReason::Error(text) => Status::Closed {
                        message: text.into(),
                        failed: true,
                    },
                    _ => Status::Closed {
                        message: t!("files.closed").into(),
                        failed: false,
                    },
                };
                for transfer in &mut self.transfers {
                    if transfer.state == TransferState::Running {
                        transfer.state = TransferState::Failed(t!("files.interrupted").into());
                    }
                }
            }
            FromSftp::Ssh(_) => {}
            FromSftp::Ready { home } => {
                self.status = Status::Ready;
                self.send(ToSftp::List { path: home });
            }
            FromSftp::Listing { path, entries } => {
                if path != self.remote_path {
                    self.remote_selection.clear();
                }
                self.remote_path = path;
                self.remote = entries;
                self.remote_error = None;
                self.remote_bar.stale = true;
            }
            FromSftp::Progress { id, done, total } => {
                if let Some(transfer) = self.transfers.iter_mut().find(|t| t.id == id) {
                    transfer.done = done;
                    transfer.total = total;
                }
            }
            FromSftp::Finished { id, result } => {
                let Some(transfer) = self.transfers.iter_mut().find(|t| t.id == id) else {
                    return;
                };
                transfer.state = match result {
                    Ok(()) => TransferState::Done,
                    Err(error) => TransferState::Failed(error),
                };
                let (direction, target) = (transfer.direction, transfer.target_dir.clone());
                match direction {
                    Direction::Upload if target == self.remote_path => {
                        self.send(ToSftp::List { path: target });
                    }
                    Direction::Download if Path::new(&target) == self.local_path => {
                        let path = self.local_path.clone();
                        self.reload_local(path);
                    }
                    _ => {}
                }
            }
            FromSftp::Changed { path } => {
                if path == self.remote_path || path == "." {
                    self.send(ToSftp::List {
                        path: self.remote_path.clone(),
                    });
                }
            }
            FromSftp::Failed(error) => self.remote_error = Some(error.into()),
        }
    }

    fn visible_local(&self) -> Vec<&LocalEntry> {
        self.local
            .iter()
            .filter(|entry| self.local_hidden || !entry.hidden)
            .collect()
    }

    fn visible_remote(&self) -> Vec<&RemoteEntry> {
        self.remote
            .iter()
            .filter(|entry| self.remote_hidden || !entry.name.starts_with('.'))
            .collect()
    }

    fn selected_local(&self) -> Vec<LocalEntry> {
        let visible = self.visible_local();
        self.local_selection
            .rows
            .iter()
            .filter_map(|&index| visible.get(index).map(|entry| (*entry).clone()))
            .collect()
    }

    fn selected_remote(&self) -> Vec<RemoteEntry> {
        let visible = self.visible_remote();
        self.remote_selection
            .rows
            .iter()
            .filter_map(|&index| visible.get(index).map(|entry| (*entry).clone()))
            .collect()
    }

    fn toggle_hidden(&mut self, side: Side, cx: &mut Context<Self>) {
        match side {
            Side::Local => {
                self.local_hidden = !self.local_hidden;
                self.local_selection.clear();
            }
            Side::Remote => {
                self.remote_hidden = !self.remote_hidden;
                self.remote_selection.clear();
            }
        }
        cx.notify();
    }

    fn refresh_side(&mut self, side: Side, cx: &mut Context<Self>) {
        match side {
            Side::Local => {
                let path = self.local_path.clone();
                self.reload_local(path);
            }
            Side::Remote => self.send(ToSftp::List {
                path: self.remote_path.clone(),
            }),
        }
        cx.notify();
    }

    fn go_up(&mut self, side: Side, cx: &mut Context<Self>) {
        match side {
            Side::Local => self.local_up(),
            Side::Remote if matches!(self.status, Status::Ready) => self.remote_up(),
            Side::Remote => {}
        }
        cx.notify();
    }

    fn open_remote_entry(&mut self, entry: RemoteEntry, cx: &mut Context<Self>) {
        if entry.is_dir {
            self.send(ToSftp::List { path: entry.path });
            cx.notify();
        } else {
            self.open_remote_file(entry, cx);
        }
    }

    /// Download: into the open local folder, or (compact mode, no local pane)
    /// into a folder the user picks.
    fn download_entries(&mut self, entries: Vec<RemoteEntry>, cx: &mut Context<Self>) {
        if self.compact {
            self.download_to_chosen(entries, cx);
        } else {
            self.download(entries, cx);
        }
    }

    /// Keys of a focused pane: Backspace — up, Enter — open, F2 — rename,
    /// Delete — delete.
    fn on_pane_key(&mut self, side: Side, event: &gpui_kit::KeyDownEvent, cx: &mut Context<Self>) {
        let keystroke = &event.keystroke;
        if keystroke.modifiers.control || keystroke.modifiers.alt || keystroke.modifiers.platform {
            return;
        }
        let handled = match (side, keystroke.key.as_str()) {
            (_, "backspace") => {
                self.go_up(side, cx);
                true
            }
            (Side::Local, "enter") => {
                if let [entry] = self.selected_local().as_slice()
                    && entry.is_dir
                {
                    self.open_local(entry.path.clone());
                    cx.notify();
                }
                true
            }
            (Side::Remote, "enter") => {
                if let [entry] = self.selected_remote().as_slice() {
                    self.open_remote_entry(entry.clone(), cx);
                }
                true
            }
            (Side::Remote, "f2") => {
                if let [entry] = self.selected_remote().as_slice() {
                    self.ask_rename(entry.clone(), cx);
                }
                true
            }
            (Side::Remote, "delete") => {
                let selected = self.selected_remote();
                self.ask_remove(selected, cx);
                true
            }
            _ => false,
        };
        if handled {
            cx.stop_propagation();
        }
    }

    fn open_local(&mut self, path: PathBuf) {
        match read_local(&path) {
            Ok(entries) => {
                self.local = entries;
                self.local_path = path;
                self.local_error = None;
                self.local_selection.clear();
                self.local_bar.stale = true;
            }
            Err(error) => {
                self.local_error = Some(format!("{}: {error}", path.display()).into());
                self.local_bar.stale = true;
            }
        }
    }

    fn reload_local(&mut self, path: PathBuf) {
        if let Ok(entries) = read_local(&path) {
            self.local = entries;
        }
    }

    fn local_up(&mut self) {
        if let Some(parent) = self.local_path.parent() {
            self.open_local(parent.to_path_buf());
        }
    }

    fn remote_up(&mut self) {
        let parent = sftp::parent(&self.remote_path);
        self.send(ToSftp::List { path: parent });
    }

    fn upload(&mut self, paths: Vec<PathBuf>, cx: &mut Context<Self>) {
        if paths.is_empty() || !matches!(self.status, Status::Ready) {
            return;
        }
        let items: Vec<(PathBuf, String)> = paths
            .into_iter()
            .filter_map(|local| {
                let name = local.file_name()?.to_string_lossy().into_owned();
                Some((local, sftp::join(&self.remote_path, &name)))
            })
            .collect();
        let clashes: Vec<String> = items
            .iter()
            .filter_map(|(local, _)| {
                let name = local.file_name()?.to_string_lossy().into_owned();
                self.remote
                    .iter()
                    .any(|entry| entry.name == name)
                    .then_some(name)
            })
            .collect();
        if clashes.is_empty() {
            self.start(Pending::Upload(items), false, cx);
        } else {
            self.dialog = Some(Dialog::Confirm {
                message: t!("files.exists_server", names = list_names(&clashes)).into(),
                action: Pending::Upload(items),
            });
            cx.notify();
        }
    }

    fn download(&mut self, entries: Vec<RemoteEntry>, cx: &mut Context<Self>) {
        if entries.is_empty() {
            return;
        }
        let items: Vec<(String, PathBuf)> = entries
            .iter()
            .map(|entry| (entry.path.clone(), self.local_path.join(&entry.name)))
            .collect();
        let clashes: Vec<String> = entries
            .iter()
            .filter(|entry| self.local_path.join(&entry.name).exists())
            .map(|entry| entry.name.clone())
            .collect();
        if clashes.is_empty() {
            self.start(Pending::Download(items), false, cx);
        } else {
            self.dialog = Some(Dialog::Confirm {
                message: t!("files.exists_local", names = list_names(&clashes)).into(),
                action: Pending::Download(items),
            });
            cx.notify();
        }
    }

    fn start(&mut self, action: Pending, overwrite: bool, cx: &mut Context<Self>) {
        match action {
            Pending::Upload(items) => {
                for (local, remote) in items {
                    let id = self.next_id;
                    self.next_id += 1;
                    self.transfers.push(Transfer {
                        id,
                        name: display_name(&local),
                        direction: Direction::Upload,
                        done: 0,
                        total: 0,
                        state: TransferState::Running,
                        target_dir: self.remote_path.clone(),
                    });
                    self.send(ToSftp::Upload {
                        id,
                        local,
                        remote,
                        overwrite,
                    });
                }
            }
            Pending::Download(items) => {
                for (remote, local) in items {
                    let id = self.next_id;
                    self.next_id += 1;
                    self.transfers.push(Transfer {
                        id,
                        name: remote.rsplit('/').next().unwrap_or(&remote).to_string(),
                        direction: Direction::Download,
                        done: 0,
                        total: 0,
                        state: TransferState::Running,
                        target_dir: self.local_path.to_string_lossy().into_owned(),
                    });
                    self.send(ToSftp::Download {
                        id,
                        remote,
                        local,
                        overwrite,
                    });
                }
            }
            Pending::Remove(paths) => {
                for path in paths {
                    self.send(ToSftp::Remove { path });
                }
                self.remote_selection.clear();
            }
        }
        cx.notify();
    }

    fn cancel(&mut self, id: TransferId, cx: &mut Context<Self>) {
        self.send(ToSftp::Cancel { id });
        cx.notify();
    }

    fn clear_finished(&mut self, cx: &mut Context<Self>) {
        self.transfers.retain(|t| t.state == TransferState::Running);
        cx.notify();
    }

    fn ask_remove(&mut self, selected: Vec<RemoteEntry>, cx: &mut Context<Self>) {
        if selected.is_empty() || !matches!(self.status, Status::Ready) {
            return;
        }
        let message = if let [entry] = selected.as_slice() {
            if entry.is_dir {
                t!("files.delete_folder", name = entry.name).to_string()
            } else {
                t!("files.delete_file", name = entry.name).to_string()
            }
        } else {
            t!("files.delete_many", count = selected.len()).to_string()
        };
        self.dialog = Some(Dialog::Confirm {
            message: message.into(),
            action: Pending::Remove(selected.into_iter().map(|entry| entry.path).collect()),
        });
        cx.notify();
    }

    fn ask_rename(&mut self, entry: RemoteEntry, cx: &mut Context<Self>) {
        if !matches!(self.status, Status::Ready) {
            return;
        }
        self.dialog = Some(Dialog::Name {
            rename_from: Some(entry.path),
            initial: entry.name,
            input: None,
        });
        cx.notify();
    }

    fn ask_new_folder(&mut self, cx: &mut Context<Self>) {
        if !matches!(self.status, Status::Ready) {
            return;
        }
        self.dialog = Some(Dialog::Name {
            rename_from: None,
            initial: String::new(),
            input: None,
        });
        cx.notify();
    }

    fn pick_and_upload(&mut self, cx: &mut Context<Self>) {
        let receiver = cx.prompt_for_paths(gpui_kit::PathPromptOptions {
            files: true,
            directories: true,
            multiple: true,
            prompt: Some(t!("files.upload_to_server").into()),
        });
        cx.spawn(async move |this: gpui_kit::WeakEntity<Self>, cx| {
            if let Ok(Ok(Some(paths))) = receiver.await {
                let _ = this.update(cx, |this, cx| this.upload(paths, cx));
            }
        })
        .detach();
    }

    fn bar_mut(&mut self, side: Side) -> &mut PathBar {
        match side {
            Side::Local => &mut self.local_bar,
            Side::Remote => &mut self.remote_bar,
        }
    }

    /// Shows the path input instead of the breadcrumbs.
    fn edit_path(&mut self, side: Side, cx: &mut Context<Self>) {
        let bar = self.bar_mut(side);
        bar.editing = true;
        bar.focus = true;
        bar.stale = true;
        cx.notify();
    }

    /// Hides the path input; what was typed and not applied is dropped.
    fn stop_editing_path(&mut self, side: Side, cx: &mut Context<Self>) {
        let bar = self.bar_mut(side);
        if bar.editing {
            bar.editing = false;
            bar.stale = true;
            cx.notify();
        }
    }

    fn ensure_path_bars(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        for side in [Side::Local, Side::Remote] {
            if self.bar_mut(side).input.is_some() {
                continue;
            }
            let placeholder = match side {
                Side::Local => t!("files.path_local"),
                Side::Remote => t!("files.path_server"),
            };
            let input = cx.new(|cx| InputState::new(window, cx).placeholder(placeholder));
            let subscription = cx.subscribe(&input, move |this, input, event: &InputEvent, cx| {
                match event {
                    InputEvent::PressEnter { .. } => {
                        let path = input.read(cx).value().trim().to_string();
                        match side {
                            Side::Local => this.open_local(PathBuf::from(path)),
                            Side::Remote => this.send(ToSftp::List { path }),
                        }
                        this.stop_editing_path(side, cx);
                    }
                    InputEvent::Blur => this.stop_editing_path(side, cx),
                    _ => {}
                }
            });
            let bar = self.bar_mut(side);
            bar._subscription = Some(subscription);
            bar.input = Some(input);
            bar.stale = true;
        }
        for side in [Side::Local, Side::Remote] {
            let value = match side {
                Side::Local => self.local_path.display().to_string(),
                Side::Remote => self.remote_path.clone(),
            };
            let bar = self.bar_mut(side);
            let (stale, focus) = (std::mem::take(&mut bar.stale), std::mem::take(&mut bar.focus));
            let Some(input) = bar.input.clone() else {
                continue;
            };
            if stale {
                input.update(cx, |state, cx| state.set_value(value, window, cx));
            }
            if focus {
                window.focus(&input.focus_handle(cx), cx);
            }
        }
    }

    /// Path as clickable segments; a click on a segment opens that folder, a
    /// click on the free space switches to typing the path.
    fn path_bar(&self, side: Side, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let bar = match side {
            Side::Local => &self.local_bar,
            Side::Remote => &self.remote_bar,
        };
        if bar.editing
            && let Some(input) = &bar.input
        {
            return div()
                .on_key_down(cx.listener(move |this, event: &gpui_kit::KeyDownEvent, _window, cx| {
                    if event.keystroke.key == "escape" {
                        this.stop_editing_path(side, cx);
                        cx.stop_propagation();
                    }
                }))
                .child(Input::new(input).small())
                .into_any_element();
        }

        let segments = match side {
            Side::Local => local_segments(&self.local_path),
            Side::Remote => remote_segments(&self.remote_path),
        };
        let last = segments.len().saturating_sub(1);
        // Long paths: the first segment, "…" and the last ones.
        const SHOWN_TAIL: usize = 3;
        let skip = if segments.len() > SHOWN_TAIL + 2 {
            1..segments.len() - SHOWN_TAIL
        } else {
            0..0
        };

        let mut crumbs: Vec<AnyElement> = Vec::new();
        for (index, (label, target)) in segments.into_iter().enumerate() {
            if skip.contains(&index) {
                if index == skip.start {
                    crumbs.push(chevron(&theme));
                    crumbs.push(
                        crumb(
                            SharedString::from(format!("{side:?}-crumb-more")),
                            "…".into(),
                            false,
                            &theme,
                        )
                        .on_click(cx.listener(move |this, _, _window, cx| {
                            cx.stop_propagation();
                            this.edit_path(side, cx)
                        }))
                        .into_any_element(),
                    );
                }
                continue;
            }
            if index > 0 {
                crumbs.push(chevron(&theme));
            }
            crumbs.push(
                crumb(
                    SharedString::from(format!("{side:?}-crumb-{index}")),
                    label.into(),
                    index == last,
                    &theme,
                )
                .on_click(cx.listener(move |this, _, _window, cx| {
                    cx.stop_propagation();
                    match side {
                        Side::Local => this.open_local(PathBuf::from(&target)),
                        Side::Remote => this.send(ToSftp::List {
                            path: target.clone(),
                        }),
                    }
                    cx.notify();
                }))
                .into_any_element(),
            );
        }

        h_flex()
            .id(SharedString::from(format!("{side:?}-path")))
            .h(px(26.))
            .px_1()
            .gap_0p5()
            .items_center()
            .rounded_md()
            .border_1()
            .border_color(theme.border)
            .bg(theme.background)
            .overflow_hidden()
            .cursor_text()
            .on_click(cx.listener(move |this, _, _window, cx| this.edit_path(side, cx)))
            .children(crumbs)
            .into_any_element()
    }

    fn ensure_dialog_input(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let (needs, masked, initial) = match &self.dialog {
            Some(Dialog::Name {
                input: None,
                initial,
                ..
            }) => (true, false, initial.clone()),
            Some(Dialog::Secret { input: None, .. }) => (true, true, String::new()),
            _ => (false, false, String::new()),
        };
        if !needs {
            return;
        }
        let state = cx.new(|cx| {
            let mut state = InputState::new(window, cx).masked(masked);
            state.set_value(initial, window, cx);
            state
        });
        window.focus(&state.focus_handle(cx), cx);
        self._dialog_subscription =
            Some(cx.subscribe(&state, |this, _, event: &InputEvent, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    this.submit_dialog(cx);
                }
            }));
        match &mut self.dialog {
            Some(Dialog::Name { input, .. }) | Some(Dialog::Secret { input, .. }) => {
                *input = Some(state)
            }
            _ => {}
        }
    }

    fn submit_dialog(&mut self, cx: &mut Context<Self>) {
        let Some(dialog) = self.dialog.take() else {
            return;
        };
        self._dialog_subscription = None;
        match dialog {
            Dialog::Confirm { action, .. } => self.start(action, true, cx),
            Dialog::Name {
                rename_from,
                input: Some(input),
                ..
            } => {
                let name = input.read(cx).value().trim().to_string();
                if name.is_empty() || name.contains('/') {
                    return;
                }
                let target = sftp::join(&self.remote_path, &name);
                match rename_from {
                    Some(from) => self.send(ToSftp::Rename { from, to: target }),
                    None => self.send(ToSftp::CreateDir { path: target }),
                }
            }
            Dialog::Secret {
                input: Some(input), ..
            } => {
                let secret = input.read(cx).value().to_string();
                self.answer(Answer::Secret(Some(secret)));
            }
            Dialog::HostKey { changed, .. } => {
                let decision = if changed {
                    HostKeyDecision::Reject
                } else {
                    HostKeyDecision::Accept { remember: true }
                };
                self.answer(Answer::HostKey(decision));
            }
            _ => {}
        }
        cx.notify();
    }

    fn trust_once(&mut self, cx: &mut Context<Self>) {
        if matches!(self.dialog, Some(Dialog::HostKey { changed: false, .. })) {
            self.dialog = None;
            self.answer(Answer::HostKey(HostKeyDecision::Accept { remember: false }));
            cx.notify();
        }
    }

    fn cancel_dialog(&mut self, cx: &mut Context<Self>) {
        match self.dialog.take() {
            Some(Dialog::Secret { .. }) => self.answer(Answer::Secret(None)),
            Some(Dialog::HostKey { .. }) => self.answer(Answer::HostKey(HostKeyDecision::Reject)),
            _ => {}
        }
        self._dialog_subscription = None;
        cx.notify();
    }

    fn local_pane(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let view = cx.entity().downgrade();
        let ready = matches!(self.status, Status::Ready);
        let selected = self.selected_local();
        let count = selected.len();
        let visible: Vec<LocalEntry> = self.visible_local().into_iter().cloned().collect();

        let mut rows: Vec<AnyElement> = Vec::new();
        if self.local_path.parent().is_some() {
            rows.push(
                up_row("local-up-row", &theme)
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(|this, event: &MouseDownEvent, _window, cx| {
                            if event.click_count >= 2 {
                                this.local_up();
                                cx.notify();
                            }
                        }),
                    )
                    .into_any_element(),
            );
        }
        for (index, entry) in visible.into_iter().enumerate() {
            let is_selected = self.local_selection.contains(index);
            // What a drag or the context menu acts on: the selection when the row
            // is in it, otherwise the row alone.
            let targets: Vec<LocalEntry> = if is_selected {
                selected.clone()
            } else {
                vec![entry.clone()]
            };
            let dragged: Vec<PathBuf> = targets.iter().map(|entry| entry.path.clone()).collect();
            let preview = drag_label(dragged.len(), &entry.name);
            let path = entry.path.clone();
            let is_dir = entry.is_dir;
            let view = view.clone();
            rows.push(
                row(
                    SharedString::from(format!("local-{index}")),
                    entry.is_dir,
                    &entry.name,
                    if entry.is_dir {
                        String::new()
                    } else {
                        human_size(entry.size)
                    },
                    entry.modified.map(format_time).unwrap_or_default(),
                    is_selected,
                    &theme,
                )
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(move |this, event: &MouseDownEvent, _window, cx| {
                        if event.click_count >= 2 && is_dir {
                            this.open_local(path.clone());
                        } else {
                            this.local_selection.click(index, &event.modifiers);
                        }
                        cx.notify();
                    }),
                )
                .on_mouse_down(
                    MouseButton::Right,
                    cx.listener(move |this, _: &MouseDownEvent, _window, cx| {
                        if !this.local_selection.contains(index) {
                            this.local_selection.click(index, &Modifiers::default());
                            cx.notify();
                        }
                    }),
                )
                .on_drag(Dragged::Local(dragged), move |_, _, _, cx| {
                    let label = preview.clone();
                    cx.new(|_| DragPreview(label))
                })
                .context_menu(move |menu, _window, _cx| local_menu(menu, &view, &targets, ready))
                .into_any_element(),
            );
        }

        let mut toolbar = h_flex().gap_0p5().items_center();
        if ready && count > 0 {
            toolbar = toolbar
                .child(
                    Button::new("upload-selected")
                        .primary()
                        .xsmall()
                        .icon(Icon::empty().path("icons/upload.svg"))
                        .label(if count > 1 {
                            SharedString::from(t!("files.to_server_count", count = count))
                        } else {
                            SharedString::from(t!("files.to_server"))
                        })
                        .tooltip(t!("files.upload_selection_tip"))
                        .on_click(cx.listener(|this, _, _window, cx| {
                            let paths = this.selected_local().into_iter().map(|e| e.path).collect();
                            this.upload(paths, cx);
                        })),
                )
                .child(divider(&theme));
        }
        let toolbar = toolbar
            .child(
                tool("local-hidden", "icons/eye.svg", t!("files.show_hidden"))
                    .selected(self.local_hidden)
                    .on_click(cx.listener(|this, _, _window, cx| this.toggle_hidden(Side::Local, cx))),
            )
            .child(
                tool("local-refresh", "icons/refresh-cw.svg", t!("files.refresh"))
                    .on_click(cx.listener(|this, _, _window, cx| this.refresh_side(Side::Local, cx))),
            );

        let list = self.pane_list(Side::Local, rows, self.local.is_empty(), cx);
        pane(
            t!("files.this_computer").into(),
            "icons/monitor.svg",
            &theme,
            toolbar.into_any_element(),
            self.path_bar(Side::Local, cx),
            self.local_error.clone(),
            list,
        )
        .id("local-pane")
        .drag_over::<Dragged>(|style, dragged, _, cx| match dragged {
            Dragged::Remote(_) => style.bg(cx.theme().drop_target),
            Dragged::Local(_) => style,
        })
        .on_drop(cx.listener(|this, dragged: &Dragged, _window, cx| {
            if let Dragged::Remote(entries) = dragged {
                this.download(entries.clone(), cx);
            }
        }))
        .into_any_element()
    }

    fn remote_pane(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let view = cx.entity().downgrade();
        let ready = matches!(self.status, Status::Ready);
        let selected = self.selected_remote();
        let count = selected.len();
        let visible: Vec<RemoteEntry> = self.visible_remote().into_iter().cloned().collect();

        let mut rows: Vec<AnyElement> = Vec::new();
        if ready && !self.remote_path.is_empty() && self.remote_path != "/" {
            rows.push(
                up_row("remote-up-row", &theme)
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(|this, event: &MouseDownEvent, _window, cx| {
                            if event.click_count >= 2 {
                                this.remote_up();
                                cx.notify();
                            }
                        }),
                    )
                    .into_any_element(),
            );
        }
        for (index, entry) in visible.into_iter().enumerate() {
            let is_selected = self.remote_selection.contains(index);
            let targets: Vec<RemoteEntry> = if is_selected {
                selected.clone()
            } else {
                vec![entry.clone()]
            };
            let preview = drag_label(targets.len(), &entry.name);
            let file = entry.clone();
            let view = view.clone();
            let dragged = targets.clone();
            rows.push(
                row(
                    SharedString::from(format!("remote-{index}")),
                    entry.is_dir,
                    &entry.name,
                    if entry.is_dir {
                        String::new()
                    } else {
                        human_size(entry.size)
                    },
                    entry.modified.map(format_time).unwrap_or_default(),
                    is_selected,
                    &theme,
                )
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(move |this, event: &MouseDownEvent, _window, cx| {
                        if event.click_count >= 2 {
                            this.open_remote_entry(file.clone(), cx);
                        } else {
                            this.remote_selection.click(index, &event.modifiers);
                        }
                        cx.notify();
                    }),
                )
                .on_mouse_down(
                    MouseButton::Right,
                    cx.listener(move |this, _: &MouseDownEvent, _window, cx| {
                        if !this.remote_selection.contains(index) {
                            this.remote_selection.click(index, &Modifiers::default());
                            cx.notify();
                        }
                    }),
                )
                .on_drag(Dragged::Remote(dragged), move |_, _, _, cx| {
                    let label = preview.clone();
                    cx.new(|_| DragPreview(label))
                })
                .context_menu(move |menu, _window, _cx| remote_menu(menu, &view, &targets, ready))
                .into_any_element(),
            );
        }

        let mut toolbar = h_flex().gap_0p5().items_center();
        if ready && count > 0 {
            toolbar = toolbar
                .child(
                    Button::new("download-selected")
                        .primary()
                        .xsmall()
                        .icon(Icon::empty().path("icons/download.svg"))
                        .label(if count > 1 {
                            SharedString::from(t!("files.download_count", count = count))
                        } else {
                            SharedString::from(t!("files.download"))
                        })
                        .tooltip(t!("files.download_selection_tip"))
                        .on_click(cx.listener(|this, _, _window, cx| {
                            let entries = this.selected_remote();
                            this.download_entries(entries, cx);
                        })),
                )
                .child(divider(&theme));
        }
        let toolbar = toolbar
            .child(
                tool("pick-upload", "icons/upload.svg", t!("files.pick_upload_tip"))
                    .disabled(!ready)
                    .on_click(cx.listener(|this, _, _window, cx| this.pick_and_upload(cx))),
            )
            .child(
                tool("mkdir", "icons/folder-plus.svg", t!("files.new_folder"))
                    .disabled(!ready)
                    .on_click(cx.listener(|this, _, _window, cx| this.ask_new_folder(cx))),
            )
            .child(divider(&theme))
            .child(
                tool("remote-hidden", "icons/eye.svg", t!("files.show_hidden"))
                    .selected(self.remote_hidden)
                    .on_click(cx.listener(|this, _, _window, cx| this.toggle_hidden(Side::Remote, cx))),
            )
            .child(
                tool("remote-refresh", "icons/refresh-cw.svg", t!("files.refresh"))
                    .disabled(!ready)
                    .on_click(cx.listener(|this, _, _window, cx| this.refresh_side(Side::Remote, cx))),
            );

        let list = self.pane_list(Side::Remote, rows, ready && self.remote.is_empty(), cx);
        pane(
            t!("files.server").into(),
            "icons/server.svg",
            &theme,
            toolbar.into_any_element(),
            self.path_bar(Side::Remote, cx),
            self.remote_error.clone(),
            list,
        )
        .id("remote-pane")
        .drag_over::<Dragged>(|style, dragged, _, cx| match dragged {
            Dragged::Local(_) => style.bg(cx.theme().drop_target),
            Dragged::Remote(_) => style,
        })
        .drag_over::<ExternalPaths>(|style, _, _, cx| style.bg(cx.theme().drop_target))
        .on_drop(cx.listener(|this, dragged: &Dragged, _window, cx| {
            if let Dragged::Local(paths) = dragged {
                this.upload(paths.clone(), cx);
            }
        }))
        .on_drop(cx.listener(|this, paths: &ExternalPaths, _window, cx| {
            this.upload(paths.paths().to_vec(), cx);
        }))
        .into_any_element()
    }

    /// File list of a pane: takes focus on a click (for the keys), and has its
    /// own context menu on the free space.
    fn pane_list(
        &self,
        side: Side,
        rows: Vec<AnyElement>,
        empty: bool,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = cx.theme().clone();
        let view = cx.entity().downgrade();
        let ready = matches!(self.status, Status::Ready);
        let (focus, hidden) = match side {
            Side::Local => (self.local_focus.clone(), self.local_hidden),
            Side::Remote => (self.remote_focus.clone(), self.remote_hidden),
        };

        div()
            .id(SharedString::from(format!("{side:?}-list")))
            .track_focus(&focus)
            .flex()
            .flex_col()
            .flex_grow_1()
            .min_h(px(0.))
            .on_mouse_down(MouseButton::Left, move |_, window, cx| window.focus(&focus, cx))
            .on_key_down(cx.listener(move |this, event: &gpui_kit::KeyDownEvent, _window, cx| {
                this.on_pane_key(side, event, cx)
            }))
            .child(
                v_flex()
                    .id(SharedString::from(format!("{side:?}-rows")))
                    .flex_grow_1()
                    .min_h(px(0.))
                    .overflow_y_scrollbar()
                    .children(rows)
                    .when(empty, |this| {
                        this.child(
                            div().p_3().child(
                                Label::new(t!("files.empty"))
                                    .text_sm()
                                    .text_color(theme.muted_foreground),
                            ),
                        )
                    }),
            )
            .context_menu(move |menu, _window, _cx| pane_menu(menu, &view, side, ready, hidden))
            .into_any_element()
    }

    fn transfers_panel(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        if self.transfers.is_empty() {
            return None;
        }
        let theme = cx.theme().clone();
        let any_finished = self
            .transfers
            .iter()
            .any(|t| t.state != TransferState::Running);

        Some(
            v_flex()
                .border_t_1()
                .border_color(theme.border)
                .max_h(px(180.))
                .child(
                    h_flex()
                        .px_3()
                        .py_1()
                        .justify_between()
                        .items_center()
                        .child(
                            Label::new(t!("files.transfers"))
                                .text_sm()
                                .text_color(theme.muted_foreground),
                        )
                        .when(any_finished, |this| {
                            this.child(
                                Button::new("clear-transfers")
                                    .ghost()
                                    .xsmall()
                                    .label(t!("files.clear_completed"))
                                    .on_click(
                                        cx.listener(|this, _, _window, cx| this.clear_finished(cx)),
                                    ),
                            )
                        }),
                )
                .child(
                    v_flex()
                        .id("transfers")
                        .overflow_y_scrollbar()
                        .px_3()
                        .pb_2()
                        .gap_1()
                        .children(self.transfers.iter().rev().map(|transfer| {
                            let id = transfer.id;
                            let fraction = if transfer.total > 0 {
                                (transfer.done as f32 / transfer.total as f32).clamp(0., 1.)
                            } else if transfer.state == TransferState::Done {
                                1.
                            } else {
                                0.
                            };
                            let (status, color) = match &transfer.state {
                                TransferState::Running => (
                                    t!(
                                        "files.progress",
                                        done = human_size(transfer.done),
                                        total = human_size(transfer.total)
                                    )
                                    .to_string(),
                                    theme.muted_foreground,
                                ),
                                TransferState::Done => (t!("files.done").to_string(), theme.success),
                                TransferState::Failed(error) => (error.clone(), theme.danger),
                            };
                            let arrow = match transfer.direction {
                                Direction::Upload => "↑",
                                Direction::Download => "↓",
                            };
                            h_flex()
                                .gap_2()
                                .items_center()
                                .child(Label::new(arrow).text_sm())
                                .child(
                                    v_flex()
                                        .flex_grow_1()
                                        .min_w(px(0.))
                                        .gap_px()
                                        .child(
                                            h_flex()
                                                .justify_between()
                                                .gap_2()
                                                .child(
                                                    Label::new(SharedString::from(
                                                        transfer.name.clone(),
                                                    ))
                                                    .text_sm(),
                                                )
                                                .child(
                                                    Label::new(SharedString::from(status))
                                                        .text_xs()
                                                        .text_color(color),
                                                ),
                                        )
                                        .child(
                                            div()
                                                .h(px(4.))
                                                .w_full()
                                                .rounded_full()
                                                .bg(theme.muted)
                                                .child(
                                                    div()
                                                        .h_full()
                                                        .rounded_full()
                                                        .bg(match transfer.state {
                                                            TransferState::Failed(_) => {
                                                                theme.danger
                                                            }
                                                            _ => theme.primary,
                                                        })
                                                        .w(gpui_kit::relative(fraction)),
                                                ),
                                        ),
                                )
                                .when(transfer.state == TransferState::Running, |this| {
                                    this.child(
                                        Button::new(SharedString::from(format!("cancel-{id}")))
                                            .ghost()
                                            .xsmall()
                                            .icon(Icon::new(IconName::Close))
                                            .tooltip(t!("files.cancel"))
                                            .on_click(cx.listener(move |this, _, _window, cx| {
                                                this.cancel(id, cx)
                                            })),
                                    )
                                })
                        })),
                )
                .into_any_element(),
        )
    }

    fn dialog_panel(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let dialog = self.dialog.as_ref()?;
        let theme = cx.theme().clone();
        let mono = crate::ui::font::MonoFont::get(cx).family.clone();
        let trust_once = matches!(dialog, Dialog::HostKey { changed: false, .. });

        let (title, body, confirm_label, danger): (SharedString, AnyElement, SharedString, bool) =
            match dialog {
                Dialog::Confirm { message, .. } => (
                    t!("files.confirmation").into(),
                    Label::new(message.clone()).into_any_element(),
                    t!("files.yes").into(),
                    true,
                ),
                Dialog::Name {
                    rename_from, input, ..
                } => (
                    if rename_from.is_some() {
                        t!("files.new_name").into()
                    } else {
                        t!("files.new_folder").into()
                    },
                    match input {
                        Some(input) => Input::new(input).into_any_element(),
                        None => div().into_any_element(),
                    },
                    if rename_from.is_some() {
                        t!("files.rename").into()
                    } else {
                        t!("files.create").into()
                    },
                    false,
                ),
                Dialog::Secret { label, input } => (
                    label.clone(),
                    match input {
                        Some(input) => Input::new(input).into_any_element(),
                        None => div().into_any_element(),
                    },
                    t!("files.enter").into(),
                    false,
                ),
                Dialog::HostKey {
                    message,
                    fingerprint,
                    changed,
                } => (
                    if *changed {
                        t!("files.key_changed").into()
                    } else {
                        t!("files.new_server").into()
                    },
                    v_flex()
                        .gap_2()
                        .child(Label::new(message.clone()).text_sm())
                        .child(
                            div().px_2().py_1().rounded_md().bg(theme.muted).child(
                                Label::new(fingerprint.clone())
                                    .font_family(mono.clone())
                                    .text_sm(),
                            ),
                        )
                        .into_any_element(),
                    if *changed {
                        t!("files.reject").into()
                    } else {
                        t!("files.trust_save").into()
                    },
                    *changed,
                ),
            };

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
                .bg(gpui_kit::black().opacity(0.4))
                .child(
                    v_flex()
                        .w(px(440.))
                        .p_4()
                        .gap_3()
                        .rounded_lg()
                        .bg(theme.popover)
                        .border_1()
                        .border_color(if danger { theme.danger } else { theme.border })
                        .child(Label::new(title).text_lg())
                        .child(body)
                        .child(
                            h_flex()
                                .gap_2()
                                .justify_end()
                                .child(
                                    Button::new("dialog-cancel")
                                        .ghost()
                                        .label(t!("files.cancel"))
                                        .on_click(cx.listener(|this, _, _window, cx| {
                                            this.cancel_dialog(cx)
                                        })),
                                )
                                .when(trust_once, |this| {
                                    this.child(
                                        Button::new("dialog-once")
                                            .outline()
                                            .label(t!("files.trust_once"))
                                            .on_click(cx.listener(|this, _, _window, cx| {
                                                this.trust_once(cx)
                                            })),
                                    )
                                })
                                .child({
                                    let button = Button::new("dialog-ok")
                                        .label(confirm_label)
                                        .on_click(cx.listener(|this, _, _window, cx| {
                                            this.submit_dialog(cx)
                                        }));
                                    if danger {
                                        button.danger()
                                    } else {
                                        button.primary()
                                    }
                                }),
                        ),
                )
                .into_any_element(),
        )
    }

    fn status_bar(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let theme = cx.theme().clone();
        match &self.status {
            Status::Ready => None,
            Status::Connecting => Some(
                h_flex()
                    .px_3()
                    .py_2()
                    .bg(theme.muted)
                    .child(
                        Label::new(t!("files.connecting"))
                            .text_sm()
                            .text_color(theme.muted_foreground),
                    )
                    .into_any_element(),
            ),
            Status::Closed { message, failed } => Some(
                h_flex()
                    .px_3()
                    .py_2()
                    .gap_2()
                    .justify_between()
                    .items_center()
                    .bg(theme.muted)
                    .child(
                        Label::new(message.clone())
                            .text_sm()
                            .text_color(if *failed {
                                theme.danger
                            } else {
                                theme.muted_foreground
                            }),
                    )
                    .when(self.config.is_some(), |this| {
                        this.child(
                            Button::new("files-reconnect")
                                .primary()
                                .small()
                                .icon(Icon::empty().path("icons/refresh-cw.svg"))
                                .label(t!("files.reconnect"))
                                .on_click(cx.listener(|this, _, _window, cx| {
                                    this.connect(cx);
                                    cx.notify();
                                })),
                        )
                    })
                    .into_any_element(),
            ),
        }
    }
}

impl Render for FilesView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.ensure_dialog_input(window, cx);
        self.ensure_path_bars(window, cx);

        div()
            .relative()
            .size_full()
            .child(
                v_flex()
                    .size_full()
                    .children(self.status_bar(cx))
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .flex_grow_1()
                            .min_h(px(0.))
                            .gap_2()
                            .p_2()
                            .when(!self.compact, |this| {
                                this.child(
                                    div()
                                        .flex_1()
                                        .min_w(px(0.))
                                        .h_full()
                                        .child(self.local_pane(cx)),
                                )
                            })
                            .child(
                                div()
                                    .flex_1()
                                    .min_w(px(0.))
                                    .h_full()
                                    .child(self.remote_pane(cx)),
                            ),
                    )
                    .children(self.transfers_panel(cx)),
            )
            .children(self.dialog_panel(cx))
    }
}

fn pane(
    title: SharedString,
    icon: &'static str,
    theme: &gpui_kit::component::Theme,
    toolbar: AnyElement,
    path: AnyElement,
    error: Option<SharedString>,
    list: AnyElement,
) -> gpui_kit::Div {
    v_flex()
        .size_full()
        .rounded_lg()
        .border_1()
        .border_color(theme.border)
        .overflow_hidden()
        .child(
            v_flex()
                .px_3()
                .py_2()
                .gap_1p5()
                .bg(theme.secondary)
                .border_b_1()
                .border_color(theme.border)
                .child(
                    h_flex()
                        .h(px(24.))
                        .gap_2()
                        .justify_between()
                        .items_center()
                        .child(
                            h_flex()
                                .gap_2()
                                .items_center()
                                .min_w(px(0.))
                                .child(Icon::empty().path(icon).small())
                                .child(
                                    Label::new(title)
                                        .text_sm()
                                        .font_weight(gpui_kit::FontWeight::SEMIBOLD),
                                ),
                        )
                        .child(toolbar),
                )
                .child(path),
        )
        .children(error.map(|error| {
            div()
                .px_3()
                .py_1()
                .child(Label::new(error).text_xs().text_color(theme.danger))
        }))
        .child(list)
}

/// Icon button of a pane toolbar.
fn tool(id: &'static str, icon: &'static str, tooltip: impl Into<SharedString>) -> Button {
    Button::new(id)
        .ghost()
        .xsmall()
        .icon(Icon::empty().path(icon))
        .tooltip(tooltip.into())
}

/// Vertical line between groups of toolbar buttons.
fn divider(theme: &gpui_kit::component::Theme) -> AnyElement {
    div()
        .w(px(1.))
        .h(px(14.))
        .mx_1()
        .bg(theme.border)
        .into_any_element()
}

fn menu_item(label: impl Into<SharedString>, icon: &'static str) -> PopupMenuItem {
    PopupMenuItem::new(label).icon(Icon::empty().path(icon))
}

/// Menu of local files: `targets` — the clicked row, or the selection it is in.
fn local_menu(
    mut menu: PopupMenu,
    view: &WeakEntity<FilesView>,
    targets: &[LocalEntry],
    ready: bool,
) -> PopupMenu {
    if let [entry] = targets
        && entry.is_dir
    {
        let (view, path) = (view.clone(), entry.path.clone());
        menu = menu.item(menu_item(t!("files.open"), "icons/folder.svg").on_click(
            move |_, _, cx| {
                let _ = view.update(cx, |this, cx| {
                    this.open_local(path.clone());
                    cx.notify();
                });
            },
        ));
    }
    let (view, paths) = (
        view.clone(),
        targets.iter().map(|entry| entry.path.clone()).collect::<Vec<_>>(),
    );
    let label = if paths.len() > 1 {
        t!("files.to_server_count", count = paths.len())
    } else {
        t!("files.to_server")
    };
    menu.item(
        menu_item(label, "icons/upload.svg")
            .disabled(!ready)
            .on_click(move |_, _, cx| {
                let _ = view.update(cx, |this, cx| this.upload(paths.clone(), cx));
            }),
    )
}

/// Menu of server files: `targets` — the clicked row, or the selection it is in.
fn remote_menu(
    mut menu: PopupMenu,
    view: &WeakEntity<FilesView>,
    targets: &[RemoteEntry],
    ready: bool,
) -> PopupMenu {
    if let [entry] = targets {
        let (view, entry) = (view.clone(), entry.clone());
        let icon = if entry.is_dir {
            "icons/folder.svg"
        } else {
            "icons/file.svg"
        };
        menu = menu.item(menu_item(t!("files.open"), icon).disabled(!ready).on_click(
            move |_, _, cx| {
                let _ = view.update(cx, |this, cx| this.open_remote_entry(entry.clone(), cx));
            },
        ));
    }
    let download = {
        let (view, entries) = (view.clone(), targets.to_vec());
        let label = if entries.len() > 1 {
            t!("files.download_count", count = entries.len())
        } else {
            t!("files.download")
        };
        menu_item(label, "icons/download.svg")
            .disabled(!ready)
            .on_click(move |_, _, cx| {
                let _ = view.update(cx, |this, cx| this.download_entries(entries.clone(), cx));
            })
    };
    let rename = {
        let view = view.clone();
        let entry = targets.first().cloned();
        menu_item(t!("files.rename_key"), "icons/pencil.svg")
            .disabled(!ready || targets.len() != 1)
            .on_click(move |_, _, cx| {
                if let Some(entry) = entry.clone() {
                    let _ = view.update(cx, |this, cx| this.ask_rename(entry, cx));
                }
            })
    };
    let delete = {
        let (view, entries) = (view.clone(), targets.to_vec());
        menu_item(t!("files.delete_key"), "icons/delete.svg")
            .disabled(!ready)
            .on_click(move |_, _, cx| {
                let _ = view.update(cx, |this, cx| this.ask_remove(entries.clone(), cx));
            })
    };
    menu.item(download)
        .item(PopupMenuItem::separator())
        .item(rename)
        .item(delete)
}

/// Menu on the free space of a file list.
fn pane_menu(
    mut menu: PopupMenu,
    view: &WeakEntity<FilesView>,
    side: Side,
    ready: bool,
    hidden: bool,
) -> PopupMenu {
    if side == Side::Remote {
        let (upload, mkdir) = (view.clone(), view.clone());
        menu = menu
            .item(
                menu_item(t!("files.upload_files"), "icons/upload.svg")
                    .disabled(!ready)
                    .on_click(move |_, _, cx| {
                        let _ = upload.update(cx, |this, cx| this.pick_and_upload(cx));
                    }),
            )
            .item(
                menu_item(t!("files.new_folder"), "icons/folder-plus.svg")
                    .disabled(!ready)
                    .on_click(move |_, _, cx| {
                        let _ = mkdir.update(cx, |this, cx| this.ask_new_folder(cx));
                    }),
            )
            .item(PopupMenuItem::separator());
    }
    let (refresh, toggle) = (view.clone(), view.clone());
    menu.item(
        menu_item(t!("files.refresh"), "icons/refresh-cw.svg")
            .disabled(side == Side::Remote && !ready)
            .on_click(move |_, _, cx| {
                let _ = refresh.update(cx, |this, cx| this.refresh_side(side, cx));
            }),
    )
    .item(
        PopupMenuItem::new(t!("files.show_hidden"))
            .checked(hidden)
            .on_click(move |_, _, cx| {
                let _ = toggle.update(cx, |this, cx| this.toggle_hidden(side, cx));
            }),
    )
}

fn crumb(
    id: SharedString,
    label: SharedString,
    current: bool,
    theme: &gpui_kit::component::Theme,
) -> gpui_kit::Stateful<gpui_kit::Div> {
    let (hover, foreground) = (theme.list_hover, theme.foreground);
    div()
        .id(id)
        .px_1()
        .rounded_sm()
        .flex_shrink_0()
        .whitespace_nowrap()
        .text_sm()
        .cursor_pointer()
        .text_color(if current {
            theme.foreground
        } else {
            theme.muted_foreground
        })
        .hover(move |style| style.bg(hover).text_color(foreground))
        .child(label)
}

fn chevron(theme: &gpui_kit::component::Theme) -> AnyElement {
    Icon::empty()
        .path("icons/chevron-right.svg")
        .xsmall()
        .text_color(theme.muted_foreground)
        .into_any_element()
}

/// Breadcrumbs of a local path: (label, full path), from the root.
fn local_segments(path: &Path) -> Vec<(String, String)> {
    let mut segments: Vec<(String, String)> = path
        .ancestors()
        .filter(|ancestor| !ancestor.as_os_str().is_empty())
        .map(|ancestor| {
            let full = ancestor.display().to_string();
            let label = match ancestor.file_name() {
                Some(name) => name.to_string_lossy().into_owned(),
                // The root: "C:\" shows as "C:", "/" stays "/".
                None => {
                    let trimmed = full.trim_end_matches(['\\', '/']);
                    if trimmed.is_empty() {
                        full.clone()
                    } else {
                        trimmed.to_string()
                    }
                }
            };
            (label, full)
        })
        .collect();
    segments.reverse();
    segments
}

/// Breadcrumbs of a server path: (label, full path), from the root.
fn remote_segments(path: &str) -> Vec<(String, String)> {
    let absolute = path.starts_with('/');
    let mut segments = Vec::new();
    if absolute {
        segments.push(("/".to_string(), "/".to_string()));
    }
    let mut current = String::new();
    for part in path.split('/').filter(|part| !part.is_empty()) {
        if absolute || !current.is_empty() {
            current.push('/');
        }
        current.push_str(part);
        segments.push((part.to_string(), current.clone()));
    }
    segments
}

fn up_row(
    id: &'static str,
    theme: &gpui_kit::component::Theme,
) -> gpui_kit::Stateful<gpui_kit::Div> {
    h_flex()
        .id(id)
        .px_3()
        .py_1()
        .gap_2()
        .items_center()
        .border_l_2()
        .border_color(gpui_kit::transparent_black())
        .hover(|style| style.bg(theme.list_hover))
        .child(
            Icon::empty()
                .path("icons/arrow-up.svg")
                .small()
                .text_color(theme.muted_foreground),
        )
        .child(div().text_sm().child(".."))
}

fn row(
    id: SharedString,
    is_dir: bool,
    name: &str,
    size: String,
    modified: String,
    selected: bool,
    theme: &gpui_kit::component::Theme,
) -> gpui_kit::Stateful<gpui_kit::Div> {
    h_flex()
        .id(id)
        .px_3()
        .py_1()
        .gap_2()
        .items_center()
        .border_l_2()
        .border_color(if selected {
            theme.list_active_border
        } else {
            gpui_kit::transparent_black()
        })
        .when(selected, |this| this.bg(theme.list_active))
        .when(!selected, |this| {
            this.hover(|style| style.bg(theme.list_hover))
        })
        .child(
            Icon::empty()
                .path(if is_dir {
                    "icons/folder.svg"
                } else {
                    "icons/file.svg"
                })
                .small()
                .text_color(if is_dir {
                    theme.primary
                } else {
                    theme.muted_foreground
                }),
        )
        .child(
            div()
                .flex_grow_1()
                .min_w(px(0.))
                .overflow_hidden()
                .text_sm()
                .line_clamp(1)
                .text_ellipsis()
                .child(SharedString::from(name.to_string())),
        )
        .child(
            div()
                .w(px(72.))
                .flex_shrink_0()
                .whitespace_nowrap()
                .text_xs()
                .text_color(theme.muted_foreground)
                .text_right()
                .child(SharedString::from(size)),
        )
        .child(
            div()
                .w(px(120.))
                .flex_shrink_0()
                .whitespace_nowrap()
                .text_xs()
                .text_color(theme.muted_foreground)
                .text_right()
                .child(SharedString::from(modified)),
        )
}

fn drag_label(count: usize, name: &str) -> SharedString {
    if count > 1 {
        t!("files.items", count = count).into()
    } else {
        name.to_string().into()
    }
}

fn list_names(names: &[String]) -> String {
    let shown: Vec<String> = names
        .iter()
        .take(3)
        .map(|name| t!("files.quoted", name = name).to_string())
        .collect();
    if names.len() > 3 {
        t!("files.and_more", names = shown.join(", "), count = names.len() - 3).to_string()
    } else {
        shown.join(", ")
    }
}

fn read_local(path: &Path) -> std::io::Result<Vec<LocalEntry>> {
    let mut entries: Vec<LocalEntry> = std::fs::read_dir(path)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let metadata = entry.metadata().ok()?;
            let name = entry.file_name().to_string_lossy().into_owned();
            Some(LocalEntry {
                hidden: name.starts_with('.') || is_hidden_attribute(&metadata),
                name,
                path: entry.path(),
                is_dir: metadata.is_dir(),
                size: metadata.len(),
                modified: metadata.modified().ok(),
            })
        })
        .collect();
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(entries)
}

#[cfg(windows)]
fn is_hidden_attribute(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    metadata.file_attributes() & FILE_ATTRIBUTE_HIDDEN != 0
}

#[cfg(not(windows))]
fn is_hidden_attribute(_metadata: &std::fs::Metadata) -> bool {
    false
}

fn home_dir() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn display_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

pub fn human_size(bytes: u64) -> String {
    let units: [String; 5] = [
        t!("files.unit_b").to_string(),
        t!("files.unit_kb").to_string(),
        t!("files.unit_mb").to_string(),
        t!("files.unit_gb").to_string(),
        t!("files.unit_tb").to_string(),
    ];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024. && unit < units.len() - 1 {
        value /= 1024.;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", units[0])
    } else if value < 10. {
        format!("{value:.1} {}", units[unit])
    } else {
        format!("{value:.0} {}", units[unit])
    }
}

pub fn format_time(time: SystemTime) -> String {
    let Ok(since) = time.duration_since(SystemTime::UNIX_EPOCH) else {
        return String::new();
    };
    let seconds = since.as_secs() as i64;
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);

    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}",
        rest / 3600,
        (rest % 3600) / 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn size_is_human_readable() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(999), "999 B");
        assert_eq!(human_size(1536), "1.5 KB");
        assert_eq!(human_size(12 * 1024 * 1024), "12 MB");
    }

    #[test]
    fn date_by_calendar() {
        let epoch = SystemTime::UNIX_EPOCH;
        assert_eq!(format_time(epoch), "1970-01-01 00:00");
        assert_eq!(
            format_time(epoch + Duration::from_secs(1_790_431_380)),
            "2026-09-26 14:03"
        );
        assert_eq!(
            format_time(epoch + Duration::from_secs(951_782_400)),
            "2000-02-29 00:00"
        );
    }

    fn mods(control: bool, shift: bool) -> Modifiers {
        Modifiers {
            control,
            shift,
            ..Modifiers::default()
        }
    }

    #[test]
    fn selection_like_in_a_file_manager() {
        let mut selection = Selection::default();
        selection.click(2, &mods(false, false));
        assert_eq!(selection.rows.iter().copied().collect::<Vec<_>>(), vec![2]);

        selection.click(5, &mods(false, true));
        assert_eq!(
            selection.rows.iter().copied().collect::<Vec<_>>(),
            vec![2, 3, 4, 5]
        );

        selection.click(9, &mods(true, false));
        assert_eq!(
            selection.rows.iter().copied().collect::<Vec<_>>(),
            vec![2, 3, 4, 5, 9]
        );

        selection.click(3, &mods(true, false));
        assert!(!selection.contains(3));

        selection.click(0, &mods(false, false));
        assert_eq!(selection.rows.iter().copied().collect::<Vec<_>>(), vec![0]);
    }

    #[test]
    fn server_path_breadcrumbs() {
        let pairs = |path| {
            remote_segments(path)
                .into_iter()
                .map(|(label, full)| format!("{label}={full}"))
                .collect::<Vec<_>>()
        };
        assert_eq!(pairs("/opt/stacks"), ["/=/", "opt=/opt", "stacks=/opt/stacks"]);
        assert_eq!(pairs("/"), ["/=/"]);
        assert_eq!(pairs("home/user/"), ["home=home", "user=home/user"]);
    }

    #[test]
    fn local_path_breadcrumbs() {
        let root = if cfg!(windows) { r"C:\" } else { "/" };
        let path = Path::new(root).join("Users").join("me");
        let segments = local_segments(&path);
        let labels: Vec<&str> = segments.iter().map(|(label, _)| label.as_str()).collect();
        let root_label = if cfg!(windows) { "C:" } else { "/" };
        assert_eq!(labels, [root_label, "Users", "me"]);
        assert_eq!(segments.last().map(|(_, full)| full.clone()), Some(path.display().to_string()));
    }

    #[test]
    fn list_of_names_in_prompt() {
        let names: Vec<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
        assert_eq!(list_names(&names), "\"a\", \"b\"");
        let many: Vec<String> = (0..5).map(|i| i.to_string()).collect();
        assert_eq!(list_names(&many), "\"0\", \"1\", \"2\" and 2 more");
    }
}
