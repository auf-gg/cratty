use crate::ui::theme::MainAction;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use gpui::{
    AnyElement, Context, Entity, ExternalPaths, Focusable, IntoElement, Modifiers, MouseButton,
    MouseDownEvent, Render, SharedString, Subscription, Window, div, prelude::*, px,
};
use gpui_component::{
    ActiveTheme, Disableable, Icon, IconName, Selectable, Sizable,
    button::{Button, ButtonVariants},
    h_flex,
    input::{Input, InputEvent, InputState},
    label::Label,
    scroll::ScrollableElement,
    v_flex,
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

#[derive(Default)]
struct PathBar {
    input: Option<Entity<InputState>>,
    stale: bool,
    _subscription: Option<Subscription>,
}

pub enum FilesEvent {
    OpenFile {
        path: String,
        name: String,
        content: String,
        commands: futures::channel::mpsc::UnboundedSender<ToSftp>,
    },
}

impl gpui::EventEmitter<FilesEvent> for FilesView {}

pub struct FilesView {
    _pump: gpui::Task<()>,
    handle: Option<SftpHandle>,
    config: Option<SshConfig>,
    compact: bool,
    title: SharedString,
    status: Status,
    show_hidden: bool,
    local_path: PathBuf,
    local: Vec<LocalEntry>,
    local_error: Option<SharedString>,
    local_selection: Selection,
    local_bar: PathBar,
    remote_path: String,
    remote: Vec<RemoteEntry>,
    remote_selection: Selection,
    remote_error: Option<SharedString>,
    remote_bar: PathBar,
    transfers: Vec<Transfer>,
    next_id: TransferId,
    dialog: Option<Dialog>,
    _dialog_subscription: Option<Subscription>,
}

impl FilesView {
    pub fn new(title: impl Into<SharedString>, config: SshConfig, cx: &mut Context<Self>) -> Self {
        let mut this = Self::blank(title.into(), Some(config), false);
        this.connect(cx);
        this
    }

    pub fn attached(
        title: impl Into<SharedString>,
        handle: SftpHandle,
        cx: &mut Context<Self>,
    ) -> Self {
        let mut this = Self::blank(title.into(), None, true);
        this.attach_handle(handle, cx);
        this
    }

    fn blank(title: SharedString, config: Option<SshConfig>, compact: bool) -> Self {
        let local_path = home_dir();
        let mut this = Self {
            _pump: gpui::Task::ready(()),
            handle: None,
            config,
            compact,
            title,
            status: Status::Connecting,
            show_hidden: false,
            local_path: local_path.clone(),
            local: Vec::new(),
            local_error: None,
            local_selection: Selection::default(),
            local_bar: PathBar::default(),
            remote_path: String::new(),
            remote: Vec::new(),
            remote_selection: Selection::default(),
            remote_error: None,
            remote_bar: PathBar::default(),
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
                    message: format!("Не удалось запустить поток: {error}").into(),
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

        self._pump = cx.spawn(async move |this: gpui::WeakEntity<Self>, cx| {
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
                        message: "Соединение закрыто.".into(),
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
                format!(
                    "Файл «{}» больше {} МБ и не может быть открыт в редакторе. Скачайте его.",
                    entry.name,
                    sftp::MAX_EDIT_BYTES / 1024 / 1024
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
        cx.spawn(async move |this: gpui::WeakEntity<Self>, cx| {
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
                                format!(
                                    "Файл «{}» не является текстовым (UTF-8). Скачайте его.",
                                    entry.name
                                )
                                .into(),
                            )
                        }
                    },
                    Ok(Err(error)) => this.remote_error = Some(error.into()),
                    Err(_) => this.remote_error = Some("Соединение закрыто.".into()),
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn download_to_chosen(&mut self, cx: &mut Context<Self>) {
        let entries = self.selected_remote();
        if entries.is_empty() {
            return;
        }
        let receiver = cx.prompt_for_paths(gpui::PathPromptOptions {
            files: false,
            directories: true,
            multiple: false,
            prompt: Some("Скачать сюда".into()),
        });
        cx.spawn(async move |this: gpui::WeakEntity<Self>, cx| {
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
                        message: "Соединение закрыто.".into(),
                        failed: false,
                    },
                };
                for transfer in &mut self.transfers {
                    if transfer.state == TransferState::Running {
                        transfer.state = TransferState::Failed("Соединение прервано.".into());
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
            .filter(|entry| self.show_hidden || !entry.hidden)
            .collect()
    }

    fn visible_remote(&self) -> Vec<&RemoteEntry> {
        self.remote
            .iter()
            .filter(|entry| self.show_hidden || !entry.name.starts_with('.'))
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

    fn toggle_hidden(&mut self, cx: &mut Context<Self>) {
        self.show_hidden = !self.show_hidden;
        self.local_selection.clear();
        self.remote_selection.clear();
        cx.notify();
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

    fn refresh(&mut self, cx: &mut Context<Self>) {
        let path = self.local_path.clone();
        self.reload_local(path);
        self.send(ToSftp::List {
            path: self.remote_path.clone(),
        });
        cx.notify();
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
                message: format!(
                    "На сервере уже существует: {}. Заменить?",
                    list_names(&clashes)
                )
                .into(),
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
                message: format!(
                    "На компьютере уже существует: {}. Заменить?",
                    list_names(&clashes)
                )
                .into(),
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

    fn ask_remove(&mut self, cx: &mut Context<Self>) {
        let selected = self.selected_remote();
        if selected.is_empty() {
            return;
        }
        let message = if let [entry] = selected.as_slice() {
            let what = if entry.is_dir {
                "папку со всем содержимым"
            } else {
                "файл"
            };
            format!(
                "Удалить с сервера {what} «{}»? Действие необратимо.",
                entry.name
            )
        } else {
            format!(
                "Удалить с сервера объекты ({}), включая содержимое папок? Действие необратимо.",
                selected.len()
            )
        };
        self.dialog = Some(Dialog::Confirm {
            message: message.into(),
            action: Pending::Remove(selected.into_iter().map(|entry| entry.path).collect()),
        });
        cx.notify();
    }

    fn ask_name(&mut self, rename: bool, cx: &mut Context<Self>) {
        let (rename_from, initial) = if rename {
            let selected = self.selected_remote();
            let [entry] = selected.as_slice() else {
                return;
            };
            (Some(entry.path.clone()), entry.name.clone())
        } else {
            (None, String::new())
        };
        self.dialog = Some(Dialog::Name {
            rename_from,
            initial,
            input: None,
        });
        cx.notify();
    }

    fn pick_and_upload(&mut self, cx: &mut Context<Self>) {
        let receiver = cx.prompt_for_paths(gpui::PathPromptOptions {
            files: true,
            directories: true,
            multiple: true,
            prompt: Some("Загрузить на сервер".into()),
        });
        cx.spawn(async move |this: gpui::WeakEntity<Self>, cx| {
            if let Ok(Ok(Some(paths))) = receiver.await {
                let _ = this.update(cx, |this, cx| this.upload(paths, cx));
            }
        })
        .detach();
    }

    fn ensure_path_bars(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.local_bar.input.is_none() {
            let input = cx.new(|cx| InputState::new(window, cx).placeholder("Путь на компьютере"));
            self.local_bar._subscription =
                Some(cx.subscribe(&input, |this, input, event: &InputEvent, cx| {
                    if matches!(event, InputEvent::PressEnter { .. }) {
                        let path = PathBuf::from(input.read(cx).value().trim());
                        this.open_local(path);
                        cx.notify();
                    }
                }));
            self.local_bar.input = Some(input);
            self.local_bar.stale = true;
        }
        if self.remote_bar.input.is_none() {
            let input = cx.new(|cx| InputState::new(window, cx).placeholder("Путь на сервере"));
            self.remote_bar._subscription =
                Some(cx.subscribe(&input, |this, input, event: &InputEvent, cx| {
                    if matches!(event, InputEvent::PressEnter { .. }) {
                        let path = input.read(cx).value().trim().to_string();
                        this.send(ToSftp::List { path });
                        cx.notify();
                    }
                }));
            self.remote_bar.input = Some(input);
            self.remote_bar.stale = true;
        }
        if std::mem::take(&mut self.local_bar.stale)
            && let Some(input) = &self.local_bar.input
        {
            let value = self.local_path.display().to_string();
            input.update(cx, |state, cx| state.set_value(value, window, cx));
        }
        if std::mem::take(&mut self.remote_bar.stale)
            && let Some(input) = &self.remote_bar.input
        {
            let value = self.remote_path.clone();
            input.update(cx, |state, cx| state.set_value(value, window, cx));
        }
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
        window.focus(&state.focus_handle(cx));
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
        let selected = self.selected_local();
        let can_upload = !selected.is_empty() && matches!(self.status, Status::Ready);
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
            let dragged = if is_selected {
                selected.iter().map(|entry| entry.path.clone()).collect()
            } else {
                vec![entry.path.clone()]
            };
            let preview = drag_label(dragged.len(), &entry.name);
            let path = entry.path.clone();
            let is_dir = entry.is_dir;
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
                .on_drag(Dragged::Local(dragged), move |_, _, _, cx| {
                    let label = preview.clone();
                    cx.new(|_| DragPreview(label))
                })
                .into_any_element(),
            );
        }

        let count = selected.len();
        pane(
            "Этот компьютер",
            "icons/monitor.svg",
            self.local_bar.input.clone(),
            &theme,
            h_flex()
                .gap_1()
                .child(
                    Button::new("local-up")
                        .ghost()
                        .xsmall()
                        .icon(Icon::empty().path("icons/arrow-up.svg"))
                        .tooltip("На уровень выше")
                        .on_click(cx.listener(|this, _, _window, cx| {
                            this.local_up();
                            cx.notify();
                        })),
                )
                .child(
                    Button::new("upload-selected")
                        .xsmall()
                        .icon(Icon::empty().path("icons/upload.svg"))
                        .label(if count > 1 {
                            SharedString::from(format!("На сервер ({count})"))
                        } else {
                            SharedString::from("На сервер")
                        })
                        .tooltip("Загрузить выделенное в открытую папку сервера")
                        .main_action(can_upload)
                        .on_click(cx.listener(|this, _, _window, cx| {
                            let paths = this.selected_local().into_iter().map(|e| e.path).collect();
                            this.upload(paths, cx);
                        })),
                )
                .into_any_element(),
            self.local_error.clone(),
            rows,
            self.local.is_empty(),
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
            let dragged = if is_selected {
                selected.clone()
            } else {
                vec![entry.clone()]
            };
            let preview = drag_label(dragged.len(), &entry.name);
            let (path, is_dir) = (entry.path.clone(), entry.is_dir);
            let file = entry.clone();
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
                        if event.click_count >= 2 && is_dir {
                            this.send(ToSftp::List { path: path.clone() });
                        } else if event.click_count >= 2 {
                            this.open_remote_file(file.clone(), cx);
                        } else {
                            this.remote_selection.click(index, &event.modifiers);
                        }
                        cx.notify();
                    }),
                )
                .on_drag(Dragged::Remote(dragged), move |_, _, _, cx| {
                    let label = preview.clone();
                    cx.new(|_| DragPreview(label))
                })
                .into_any_element(),
            );
        }

        pane(
            "Сервер",
            "icons/server.svg",
            self.remote_bar.input.clone(),
            &theme,
            h_flex()
                .gap_1()
                .child(
                    Button::new("remote-up")
                        .ghost()
                        .xsmall()
                        .icon(Icon::empty().path("icons/arrow-up.svg"))
                        .tooltip("На уровень выше")
                        .disabled(!ready)
                        .on_click(cx.listener(|this, _, _window, cx| {
                            this.remote_up();
                            cx.notify();
                        })),
                )
                .child(
                    Button::new("download-selected")
                        .xsmall()
                        .icon(Icon::empty().path("icons/download.svg"))
                        .label(if count > 1 {
                            SharedString::from(format!("Скачать ({count})"))
                        } else {
                            SharedString::from("Скачать")
                        })
                        .tooltip("Скачать выделенное в открытую папку компьютера")
                        .main_action(ready && count > 0)
                        .on_click(cx.listener(|this, _, _window, cx| {
                            if this.compact {
                                this.download_to_chosen(cx);
                            } else {
                                let entries = this.selected_remote();
                                this.download(entries, cx);
                            }
                        })),
                )
                .child(
                    Button::new("pick-upload")
                        .ghost()
                        .xsmall()
                        .icon(Icon::empty().path("icons/upload.svg"))
                        .tooltip("Выбрать файлы на компьютере и загрузить сюда")
                        .disabled(!ready)
                        .on_click(cx.listener(|this, _, _window, cx| this.pick_and_upload(cx))),
                )
                .child(
                    Button::new("mkdir")
                        .ghost()
                        .xsmall()
                        .icon(Icon::empty().path("icons/folder-plus.svg"))
                        .tooltip("Новая папка")
                        .disabled(!ready)
                        .on_click(cx.listener(|this, _, _window, cx| this.ask_name(false, cx))),
                )
                .child(
                    Button::new("rename")
                        .ghost()
                        .xsmall()
                        .icon(Icon::empty().path("icons/pencil.svg"))
                        .tooltip("Переименовать")
                        .disabled(!ready || count != 1)
                        .on_click(cx.listener(|this, _, _window, cx| this.ask_name(true, cx))),
                )
                .child(
                    Button::new("remove")
                        .ghost()
                        .xsmall()
                        .icon(Icon::new(IconName::Delete))
                        .tooltip("Удалить")
                        .disabled(!ready || count == 0)
                        .on_click(cx.listener(|this, _, _window, cx| this.ask_remove(cx))),
                )
                .into_any_element(),
            self.remote_error.clone(),
            rows,
            ready && self.remote.is_empty(),
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
                            Label::new("Передачи")
                                .text_sm()
                                .text_color(theme.muted_foreground),
                        )
                        .when(any_finished, |this| {
                            this.child(
                                Button::new("clear-transfers")
                                    .ghost()
                                    .xsmall()
                                    .label("Очистить завершённые")
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
                                    format!(
                                        "{} из {}",
                                        human_size(transfer.done),
                                        human_size(transfer.total)
                                    ),
                                    theme.muted_foreground,
                                ),
                                TransferState::Done => ("Готово".to_string(), theme.success),
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
                                        .flex_grow()
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
                                                        .w(gpui::relative(fraction)),
                                                ),
                                        ),
                                )
                                .when(transfer.state == TransferState::Running, |this| {
                                    this.child(
                                        Button::new(SharedString::from(format!("cancel-{id}")))
                                            .ghost()
                                            .xsmall()
                                            .icon(Icon::new(IconName::Close))
                                            .tooltip("Отменить")
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

        let (title, body, confirm_label, danger): (SharedString, AnyElement, &'static str, bool) =
            match dialog {
                Dialog::Confirm { message, .. } => (
                    "Подтверждение".into(),
                    Label::new(message.clone()).into_any_element(),
                    "Да",
                    true,
                ),
                Dialog::Name {
                    rename_from, input, ..
                } => (
                    if rename_from.is_some() {
                        "Новое имя".into()
                    } else {
                        "Новая папка".into()
                    },
                    match input {
                        Some(input) => Input::new(input).into_any_element(),
                        None => div().into_any_element(),
                    },
                    if rename_from.is_some() {
                        "Переименовать"
                    } else {
                        "Создать"
                    },
                    false,
                ),
                Dialog::Secret { label, input } => (
                    label.clone(),
                    match input {
                        Some(input) => Input::new(input).into_any_element(),
                        None => div().into_any_element(),
                    },
                    "Войти",
                    false,
                ),
                Dialog::HostKey {
                    message,
                    fingerprint,
                    changed,
                } => (
                    if *changed {
                        "Ключ сервера изменился".into()
                    } else {
                        "Новый сервер".into()
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
                        "Отклонить"
                    } else {
                        "Доверять и сохранить"
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
                .bg(gpui::black().opacity(0.4))
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
                                        .label("Отмена")
                                        .on_click(cx.listener(|this, _, _window, cx| {
                                            this.cancel_dialog(cx)
                                        })),
                                )
                                .when(trust_once, |this| {
                                    this.child(
                                        Button::new("dialog-once")
                                            .outline()
                                            .label("Доверять однократно")
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
                        Label::new("Подключение…")
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
                                .label("Переподключиться")
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
                        h_flex().justify_end().items_center().px_3().pt_2().child(
                            h_flex()
                                .gap_1()
                                .child(
                                    Button::new("files-hidden")
                                        .ghost()
                                        .xsmall()
                                        .selected(self.show_hidden)
                                        .label("Скрытые")
                                        .tooltip("Показывать скрытые файлы")
                                        .on_click(cx.listener(|this, _, _window, cx| {
                                            this.toggle_hidden(cx)
                                        })),
                                )
                                .child(
                                    Button::new("files-refresh")
                                        .ghost()
                                        .xsmall()
                                        .icon(Icon::empty().path("icons/refresh-cw.svg"))
                                        .label("Обновить")
                                        .on_click(
                                            cx.listener(|this, _, _window, cx| this.refresh(cx)),
                                        ),
                                ),
                        ),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .flex_grow()
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

#[allow(clippy::too_many_arguments)]
fn pane(
    title: &'static str,
    icon: &'static str,
    path: Option<Entity<InputState>>,
    theme: &gpui_component::Theme,
    toolbar: AnyElement,
    error: Option<SharedString>,
    rows: Vec<AnyElement>,
    empty: bool,
) -> gpui::Div {
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
                .gap_1()
                .bg(theme.secondary)
                .border_b_1()
                .border_color(theme.border)
                .child(
                    h_flex()
                        .justify_between()
                        .items_center()
                        .child(
                            h_flex()
                                .gap_2()
                                .items_center()
                                .child(Icon::empty().path(icon).small())
                                .child(Label::new(title).text_sm()),
                        )
                        .child(toolbar),
                )
                .children(path.map(|input| Input::new(&input).small())),
        )
        .children(error.map(|error| {
            div()
                .px_3()
                .py_1()
                .child(Label::new(error).text_xs().text_color(theme.danger))
        }))
        .child(
            v_flex()
                .id(SharedString::from(format!("{title}-rows")))
                .flex_grow()
                .overflow_y_scrollbar()
                .children(rows)
                .when(empty, |this| {
                    this.child(
                        div().p_3().child(
                            Label::new("Папка пуста")
                                .text_sm()
                                .text_color(theme.muted_foreground),
                        ),
                    )
                }),
        )
}

fn up_row(id: &'static str, theme: &gpui_component::Theme) -> gpui::Stateful<gpui::Div> {
    h_flex()
        .id(id)
        .px_3()
        .py_1()
        .gap_2()
        .items_center()
        .border_l_2()
        .border_color(gpui::transparent_black())
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
    theme: &gpui_component::Theme,
) -> gpui::Stateful<gpui::Div> {
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
            gpui::transparent_black()
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
                .flex_grow()
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
        format!("Объектов: {count}").into()
    } else {
        name.to_string().into()
    }
}

fn list_names(names: &[String]) -> String {
    let shown: Vec<String> = names
        .iter()
        .take(3)
        .map(|name| format!("«{name}»"))
        .collect();
    if names.len() > 3 {
        format!("{} и ещё {}", shown.join(", "), names.len() - 3)
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
    const UNITS: [&str; 5] = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024. && unit < UNITS.len() - 1 {
        value /= 1024.;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} Б")
    } else if value < 10. {
        format!("{value:.1} {}", UNITS[unit]).replace('.', ",")
    } else {
        format!("{value:.0} {}", UNITS[unit])
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
    fn razmer_chelovecheski() {
        assert_eq!(human_size(0), "0 Б");
        assert_eq!(human_size(999), "999 Б");
        assert_eq!(human_size(1536), "1,5 КБ");
        assert_eq!(human_size(12 * 1024 * 1024), "12 МБ");
    }

    #[test]
    fn data_po_kalendaryu() {
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
    fn vydelenie_kak_v_faylovom_menedzhere() {
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
    fn spisok_imen_v_voprose() {
        let names: Vec<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
        assert_eq!(list_names(&names), "«a», «b»");
        let many: Vec<String> = (0..5).map(|i| i.to_string()).collect();
        assert_eq!(list_names(&many), "«0», «1», «2» и ещё 2");
    }
}
