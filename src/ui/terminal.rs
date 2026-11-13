use rust_i18n::t;
use gpui_kit::component::{
    ActiveTheme, Sizable,
    button::{Button, ButtonVariants},
    checkbox::Checkbox,
    input::{Input, InputEvent, InputState},
    label::Label,
};
use gpui_kit::{
    App, Bounds, ClipboardItem, Context, Entity, FocusHandle, Focusable, FontWeight, Hsla,
    IntoElement, KeyDownEvent, MouseButton, MouseDownEvent, MouseMoveEvent, MouseUpEvent, Pixels,
    Point, Render, ScrollDelta, ScrollEvent, SharedString, Subscription, Window, canvas, div,
    prelude::*, px, relative,
};

use crate::ssh::forward::ForwardState;
use crate::ssh::{
    Answer, CloseReason, FromSsh, HostKeyDecision, PtySize, SecretKind, SshSession, ToSsh,
};
use crate::term::keys::{Key, Mods};
use crate::term::mouse;
use crate::term::predict::{Policy, Predictor};
use crate::term::{Responder, Rgb, Snapshot, Style, Terminal};
use crate::ui::element::{Cell as SelectionCell, Selection, TerminalElement};
use crate::ui::font::MonoFont;

pub const FONT_SIZE: Pixels = px(14.);
pub const LINE_HEIGHT: f32 = 1.2;
const PADDING: Pixels = px(4.);

pub enum Status {
    Connecting {
        target: SharedString,
    },
    Connected {
        target: SharedString,
        fingerprint: SharedString,
    },
    Closed {
        message: SharedString,
        failed: bool,
    },
}

#[derive(Clone, Copy, Debug)]
pub struct CellMetrics {
    pub width: Pixels,
    pub height: Pixels,
}

impl CellMetrics {
    pub fn new(width: Pixels, height: Pixels) -> Self {
        Self { width, height }
    }

    fn grid_for(&self, bounds: Bounds<Pixels>) -> PtySize {
        let cols = (bounds.size.width / self.width).floor().max(1.) as u16;
        let rows = (bounds.size.height / self.height).floor().max(1.) as u16;
        PtySize {
            cols,
            rows,
            pixel_width: f32::from(bounds.size.width) as u16,
            pixel_height: f32::from(bounds.size.height) as u16,
        }
    }
}

pub struct TerminalView {
    _pump: gpui_kit::Task<()>,
    terminal: Terminal,
    session: Option<SshSession>,
    can_save_secrets: bool,
    pending_stored_rejected: bool,
    /// Secrets with the "Save" checkbox ticked: they wait for a successful login so a wrong
    /// password does not end up in the vault. Entering again replaces the previous one.
    unsaved: Vec<(proto::SecretPurpose, proto::Secret)>,
    save_unsaved: bool,
    status: Status,
    font_family: SharedString,
    /// Grid font: the main one plus the icon font as a fallback.
    font: gpui_kit::Font,
    focus: FocusHandle,
    metrics: CellMetrics,
    pending_focus: bool,
    grid_origin: Point<Pixels>,
    selection: Option<Selection>,
    selecting: bool,
    copied: bool,
    mouse_button: Option<mouse::Button>,
    mouse_cell: Option<SelectionCell>,
    predictor: Predictor,
    search: Option<SearchBar>,
    forwards: Vec<(proto::PortForward, ForwardState)>,
    broadcast: bool,
    prompt: Option<Prompt>,
    secret_input: Option<Subscription>,
    font_size: Pixels,
    cursor_color: Rgb,
    selection_color: Rgb,
    selection_foreground: Rgb,
}

pub enum TerminalEvent {
    SaveSecret {
        purpose: proto::SecretPurpose,
        secret: proto::Secret,
    },
    Typed(bytes::Bytes),
    StoredPasswordRejected,
}

impl gpui_kit::EventEmitter<TerminalEvent> for TerminalView {}

fn secret_purpose(kind: SecretKind) -> Option<proto::SecretPurpose> {
    match kind {
        SecretKind::Password => Some(proto::SecretPurpose::Password),
        SecretKind::Passphrase => None,
        SecretKind::Challenge => None,
    }
}

pub enum Prompt {
    Secret {
        label: SharedString,
        kind: SecretKind,
        input: Option<Entity<InputState>>,
        remember: bool,
        error: Option<SharedString>,
    },
    HostKey {
        message: SharedString,
        fingerprint: SharedString,
        changed: bool,
    },
}

impl TerminalView {
    pub fn new(
        target: impl Into<SharedString>,
        size: PtySize,
        session: SshSession,
        cx: &mut Context<Self>,
    ) -> Self {
        let target = target.into();
        let responder = Responder::new(session.commands.clone());
        let terminal = Terminal::new(size, responder);
        let font_family = MonoFont::get(cx).family.clone();
        let font = MonoFont::get(cx).font();
        let metrics = measure_cell(&font_family, FONT_SIZE, cx);

        let mut session = session;
        let mut events = std::mem::replace(&mut session.events, crate::ssh::closed_events());

        let pump = cx.spawn(async move |this: gpui_kit::WeakEntity<Self>, cx| {
            use futures::StreamExt;

            while let Some(event) = events.next().await {
                let mut chunks = vec![event];
                while let Ok(more) = events.try_recv() {
                    chunks.push(more);
                }

                let update = this.update(cx, |this, cx| {
                    for event in chunks {
                        this.apply(event);
                    }
                    if std::mem::take(&mut this.pending_stored_rejected) {
                        cx.emit(TerminalEvent::StoredPasswordRejected);
                    }
                    if std::mem::take(&mut this.save_unsaved) {
                        for (purpose, secret) in std::mem::take(&mut this.unsaved) {
                            cx.emit(TerminalEvent::SaveSecret { purpose, secret });
                        }
                    }
                    if let Some(text) = this.terminal.responder().take_clipboard() {
                        cx.write_to_clipboard(ClipboardItem::new_string(text));
                    }
                    cx.notify();
                });

                if update.is_err() {
                    return;
                }
            }
        });

        Self {
            _pump: pump,
            terminal,
            session: Some(session),
            can_save_secrets: false,
            pending_stored_rejected: false,
            unsaved: Vec::new(),
            save_unsaved: false,
            status: Status::Connecting { target },
            font_family,
            font,
            focus: cx.focus_handle(),
            metrics,
            pending_focus: true,
            grid_origin: gpui_kit::point(px(0.), px(0.)),
            selection: None,
            selecting: false,
            copied: false,
            mouse_button: None,
            mouse_cell: None,
            predictor: Predictor::new(Policy::Adaptive),
            search: None,
            forwards: Vec::new(),
            broadcast: false,
            prompt: None,
            secret_input: None,
            font_size: FONT_SIZE,
            cursor_color: crate::term::palette::DEFAULT.cursor,
            selection_color: Rgb::new(0x33, 0x46, 0x7c),
            selection_foreground: Rgb::new(0xff, 0xff, 0xff),
        }
    }

    pub fn type_bytes(&mut self, bytes: Vec<u8>, cx: &mut Context<Self>) {
        self.predictor.other_input();
        self.send(bytes::Bytes::from(bytes));
        self.pending_focus = true;
        cx.notify();
    }

    pub fn set_broadcast(&mut self, on: bool) {
        self.broadcast = on;
    }

    pub fn receive_broadcast(&mut self, bytes: bytes::Bytes) {
        self.predictor.other_input();
        self.send(bytes);
    }

    fn send_typed(&mut self, bytes: bytes::Bytes, cx: &mut Context<Self>) {
        if self.broadcast {
            cx.emit(TerminalEvent::Typed(bytes.clone()));
        }
        self.send(bytes);
    }

    pub fn with_forwards(mut self, rules: Vec<proto::PortForward>) -> Self {
        self.forwards = rules
            .into_iter()
            .map(|rule| (rule, ForwardState::Off))
            .collect();
        self
    }

    pub fn forwards(&self) -> &[(proto::PortForward, ForwardState)] {
        &self.forwards
    }

    pub fn status(&self) -> &Status {
        &self.status
    }

    pub fn set_forward(&self, index: usize, enabled: bool) {
        if let Some(session) = &self.session {
            let _ = session
                .commands
                .unbounded_send(ToSsh::SetForward { index, enabled });
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn set_appearance(
        &mut self,
        font_size: Pixels,
        background: Rgb,
        foreground: Rgb,
        cursor: Rgb,
        selection: Rgb,
        selection_foreground: Rgb,
        cx: &mut Context<Self>,
    ) {
        let palette = crate::ui::theme::terminal_base(cx).themed(background, foreground, cursor);
        self.terminal.set_palette(palette);
        self.cursor_color = cursor;
        self.selection_color = selection;
        self.selection_foreground = selection_foreground;

        let mono = MonoFont::get(cx);
        let font = mono.font();
        if self.font_size != font_size || self.font != font {
            self.font_size = font_size;
            self.font_family = mono.family.clone();
            self.font = font;
            self.metrics = measure_cell(&self.font_family, font_size, cx);
        }
        cx.notify();
    }

    fn apply(&mut self, event: FromSsh) {
        match event {
            FromSsh::Connected { fingerprint } => {
                let target = match &self.status {
                    Status::Connecting { target } | Status::Connected { target, .. } => {
                        target.clone()
                    }
                    Status::Closed { .. } => SharedString::default(),
                };
                self.status = Status::Connected {
                    target,
                    fingerprint: fingerprint.into(),
                };
                self.save_unsaved = true;
            }
            FromSsh::Output(data) => {
                self.terminal.advance(&data);
                self.predictor
                    .observe(&self.terminal, std::time::Instant::now());
            }
            FromSsh::NeedSecret {
                prompt,
                kind,
                error,
            } => {
                // On a repeated prompt the checkbox stays as it was left.
                let remember = secret_purpose(kind)
                    .is_some_and(|purpose| self.unsaved.iter().any(|(p, _)| *p == purpose));
                self.prompt = Some(Prompt::Secret {
                    label: prompt.into(),
                    kind,
                    input: None,
                    remember,
                    error: error.map(Into::into),
                });
            }
            FromSsh::NeedHostKey {
                fingerprint,
                message,
                changed,
                ..
            } => {
                self.pending_focus = true;
                self.prompt = Some(Prompt::HostKey {
                    message: message.into(),
                    fingerprint: fingerprint.into(),
                    changed,
                });
            }
            FromSsh::Forward { index, state } => {
                if let Some((_, slot)) = self.forwards.get_mut(index) {
                    *slot = state;
                }
            }
            FromSsh::Closed(reason) => {
                self.session = None;
                self.unsaved.clear();
                for (_, state) in &mut self.forwards {
                    if *state == ForwardState::Active {
                        *state = ForwardState::Off;
                    }
                }

                if let CloseReason::Error(text) = &reason
                    && text.contains(&crate::ssh::stored_password_rejected())
                {
                    self.pending_stored_rejected = true;
                }

                self.status = match reason {
                    CloseReason::Remote { exit_status } => Status::Closed {
                        message: match exit_status {
                            Some(code) => {
                                t!("terminal.closed_code", code = code).into()
                            }
                            None => t!("terminal.closed_remote").into(),
                        },
                        failed: false,
                    },
                    CloseReason::Local => Status::Closed {
                        message: t!("terminal.disconnected").into(),
                        failed: false,
                    },
                    CloseReason::Error(text) => Status::Closed {
                        message: text.into(),
                        failed: true,
                    },
                };
            }
        }
    }

    pub fn send(&self, bytes: bytes::Bytes) {
        if let Some(session) = &self.session {
            let _ = session.commands.unbounded_send(ToSsh::Input(bytes));
        }
    }

    pub fn resize(&mut self, size: PtySize) {
        if size == self.terminal.size() {
            return;
        }
        self.terminal.resize(size);
        if let Some(session) = &self.session {
            let _ = session.commands.unbounded_send(ToSsh::Resize(size));
        }
    }

    pub fn terminal(&self) -> &Terminal {
        &self.terminal
    }

    pub fn request_focus(&mut self, cx: &mut Context<Self>) {
        self.pending_focus = true;
        cx.notify();
    }

    /// Where tools send commands for this session; `None` once it is closed.
    pub fn ssh_commands(&self) -> Option<futures::channel::mpsc::UnboundedSender<ToSsh>> {
        self.session.as_ref().map(|session| session.commands.clone())
    }

    pub fn open_sftp(&self) -> Option<crate::ssh::sftp::SftpHandle> {
        self.session.as_ref().map(SshSession::open_sftp)
    }

    pub fn is_closed(&self) -> bool {
        matches!(self.status, Status::Closed { .. })
    }

    fn copy(&self, cx: &mut App) -> bool {
        let Some(selection) = self.selection else {
            return false;
        };
        let text = selection.text(&self.terminal.snapshot());
        if text.is_empty() {
            return false;
        }
        cx.write_to_clipboard(ClipboardItem::new_string(text));
        true
    }

    fn paste(&mut self, cx: &mut Context<Self>) {
        self.predictor.other_input();
        let Some(text) = cx.read_from_clipboard().and_then(|item| item.text()) else {
            return;
        };
        if text.is_empty() {
            return;
        }

        let bytes = if self
            .terminal
            .mode()
            .contains(alacritty_terminal::term::TermMode::BRACKETED_PASTE)
        {
            let mut wrapped = Vec::with_capacity(text.len() + 12);
            wrapped.extend_from_slice(b"\x1b[200~");
            wrapped.extend_from_slice(text.as_bytes());
            wrapped.extend_from_slice(b"\x1b[201~");
            wrapped
        } else {
            text.into_bytes()
        };
        self.send_typed(bytes::Bytes::from(bytes), cx);
    }

    fn ensure_secret_input(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(Prompt::Secret { input, .. }) = &self.prompt else {
            return;
        };
        if input.is_some() {
            return;
        }

        let state = cx.new(|cx| InputState::new(window, cx).masked(true));
        window.focus(&state.focus_handle(cx), cx);

        self.secret_input = Some(cx.subscribe(&state, |this, _, event: &InputEvent, cx| {
            if matches!(event, InputEvent::PressEnter { .. }) {
                this.submit_secret(cx);
            }
        }));

        if let Some(Prompt::Secret { input, .. }) = &mut self.prompt {
            *input = Some(state);
        }
    }

    fn submit_secret(&mut self, cx: &mut Context<Self>) {
        let Some(Prompt::Secret {
            input: Some(input),
            remember,
            kind,
            ..
        }) = &self.prompt
        else {
            return;
        };
        let secret = input.read(cx).value().to_string();
        let (purpose, remember) = (secret_purpose(*kind), *remember);

        self.prompt = None;
        self.secret_input = None;
        self.pending_focus = true;
        self.answer(Answer::Secret(Some(secret.clone())));

        if let Some(purpose) = purpose {
            self.unsaved.retain(|(p, _)| *p != purpose);
            if remember {
                self.unsaved
                    .push((purpose, proto::Secret::new(secret.into_bytes())));
            }
        }
        cx.notify();
    }

    pub fn set_can_save_secrets(&mut self, can: bool, cx: &mut Context<Self>) {
        if self.can_save_secrets != can {
            self.can_save_secrets = can;
            cx.notify();
        }
    }

    fn answer(&self, answer: Answer) {
        if let Some(session) = &self.session {
            let _ = session.answers.unbounded_send(answer);
        }
    }

    fn open_search(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(bar) = &self.search {
            window.focus(&bar.input.focus_handle(cx), cx);
            return;
        }
        let input = cx.new(|cx| InputState::new(window, cx).placeholder(t!("terminal.search_placeholder")));
        window.focus(&input.focus_handle(cx), cx);

        let subscription = cx.subscribe(&input, |this, _, event: &InputEvent, cx| {
            if let InputEvent::PressEnter { secondary, .. } = event {
                this.search_step(!secondary, cx);
            }
        });
        self.search = Some(SearchBar {
            input,
            status: None,
            _subscription: subscription,
        });
        cx.notify();
    }

    fn search_step(&mut self, older: bool, cx: &mut Context<Self>) {
        let Some(bar) = &self.search else {
            return;
        };
        let query = bar.input.read(cx).value().to_string();
        let result = self.terminal.find(&query, older);
        let status = match result {
            Ok(Some(found)) => {
                self.selection = Some(Selection {
                    anchor: SelectionCell {
                        row: found.start.0,
                        column: found.start.1,
                    },
                    head: SelectionCell {
                        row: found.end.0,
                        column: found.end.1,
                    },
                });
                self.copied = false;
                None
            }
            Ok(None) if query.is_empty() => None,
            Ok(None) => Some(SharedString::from(t!("terminal.not_found"))),
            Err(error) => Some(SharedString::from(error)),
        };
        if let Some(bar) = &mut self.search {
            bar.status = status;
        }
        cx.notify();
    }

    fn close_search(&mut self, cx: &mut Context<Self>) {
        self.search = None;
        self.terminal.end_search();
        self.terminal.scroll_to_bottom();
        self.selection = None;
        self.pending_focus = true;
        cx.notify();
    }

    fn search_panel(&self, cx: &mut Context<Self>) -> Option<gpui_kit::AnyElement> {
        let bar = self.search.as_ref()?;
        let theme = cx.theme();
        Some(
            div()
                .absolute()
                .occlude()
                .top(px(6.))
                .right(px(10.))
                .w(px(320.))
                .p_1()
                .rounded_md()
                .border_1()
                .border_color(theme.border)
                .bg(theme.popover)
                .flex()
                .items_center()
                .gap_1()
                .child(div().flex_grow_1().child(Input::new(&bar.input).small()))
                .children(bar.status.clone().map(|status| {
                    Label::new(status)
                        .text_xs()
                        .text_color(theme.muted_foreground)
                }))
                .child(
                    Button::new("search-older")
                        .ghost()
                        .xsmall()
                        .label("↑")
                        .tooltip(t!("terminal.prev_match"))
                        .on_click(cx.listener(|this, _, _window, cx| this.search_step(true, cx))),
                )
                .child(
                    Button::new("search-newer")
                        .ghost()
                        .xsmall()
                        .label("↓")
                        .tooltip(t!("terminal.next_match"))
                        .on_click(cx.listener(|this, _, _window, cx| this.search_step(false, cx))),
                )
                .child(
                    Button::new("search-close")
                        .ghost()
                        .xsmall()
                        .label("×")
                        .tooltip(t!("terminal.close"))
                        .on_click(cx.listener(|this, _, _window, cx| this.close_search(cx))),
                )
                .into_any_element(),
        )
    }

    fn on_prompt_key(&mut self, event: &KeyDownEvent, cx: &mut Context<Self>) -> bool {
        let Some(prompt) = &mut self.prompt else {
            return false;
        };
        let key = event.keystroke.key.as_str();
        let modifiers = &event.keystroke.modifiers;

        match prompt {
            Prompt::Secret { .. } => {
                if key == "escape" && !modifiers.control && !modifiers.alt {
                    self.prompt = None;
                    self.secret_input = None;
                    self.answer(Answer::Secret(None));
                    self.pending_focus = true;
                    cx.notify();
                }
                true
            }
            Prompt::HostKey { changed, .. } => {
                let changed = *changed;
                self.pending_focus = true;
                match key {
                    "y" if !changed => {
                        self.prompt = None;
                        self.answer(Answer::HostKey(HostKeyDecision::Accept { remember: true }));
                    }
                    "o" => {
                        self.prompt = None;
                        self.answer(Answer::HostKey(HostKeyDecision::Accept { remember: false }));
                    }
                    "n" | "escape" => {
                        self.prompt = None;
                        self.answer(Answer::HostKey(HostKeyDecision::Reject));
                    }
                    _ => return true,
                }
                cx.notify();
                true
            }
        }
    }

    fn decide_host_key(&mut self, decision: HostKeyDecision, cx: &mut Context<Self>) {
        if !matches!(self.prompt, Some(Prompt::HostKey { .. })) {
            return;
        }
        self.prompt = None;
        self.pending_focus = true;
        self.answer(Answer::HostKey(decision));
        cx.notify();
    }

    fn on_key(&mut self, event: &KeyDownEvent, window: &mut Window, cx: &mut Context<Self>) {
        if self.on_prompt_key(event, cx) {
            return;
        }

        let modifiers = &event.keystroke.modifiers;
        if modifiers.control
            && modifiers.shift
            && !modifiers.platform
            && event.keystroke.key.as_str() == "f"
        {
            self.open_search(window, cx);
            return;
        }

        if self.search.is_some() {
            if event.keystroke.key.as_str() == "escape" {
                self.close_search(cx);
            }
            return;
        }

        let modifiers = &event.keystroke.modifiers;
        if modifiers.control && modifiers.shift && !modifiers.platform {
            match event.keystroke.key.as_str() {
                "c" => {
                    if self.copy(cx) {
                        return;
                    }
                }
                "v" => {
                    self.paste(cx);
                    return;
                }
                _ => {}
            }
        }

        let Some((key, mods)) = translate(event) else {
            return;
        };
        let Some(bytes) = self.terminal.encode_key(key, mods) else {
            return;
        };

        if self.selection.take().is_some() {
            self.copied = false;
            cx.notify();
        }

        if self.terminal.snapshot().display_offset != 0 {
            self.terminal.scroll_to_bottom();
            cx.notify();
        }

        self.predictor
            .key(key, mods, &self.terminal, std::time::Instant::now());
        self.send_typed(bytes::Bytes::from(bytes), cx);
        if self.predictor.visible() {
            cx.notify();
        }
    }

    pub fn set_prediction(&mut self, policy: Policy, cx: &mut Context<Self>) {
        if self.predictor.policy() != policy {
            self.predictor.set_policy(policy);
            cx.notify();
        }
    }

    pub fn echo_latency(&self) -> Option<std::time::Duration> {
        self.predictor.srtt()
    }

    fn cell_at(&self, position: Point<Pixels>) -> SelectionCell {
        TerminalElement::cell_at(
            self.metrics,
            self.grid_origin,
            position,
            &self.terminal.snapshot(),
        )
    }

    fn report_mouse(
        &mut self,
        button: mouse::Button,
        action: mouse::Action,
        position: Point<Pixels>,
        modifiers: gpui_kit::Modifiers,
    ) -> bool {
        let cell = self.cell_at(position);
        let event = mouse::Event {
            button,
            action,
            column: cell.column,
            row: cell.row,
            mods: mouse::Mods {
                shift: modifiers.shift,
                alt: modifiers.alt,
                ctrl: modifiers.control,
            },
        };
        let mode = self.terminal.mode();
        if !mouse::wants(mode, &event) {
            return false;
        }
        if let Some(bytes) = mouse::encode(mode, &event) {
            self.send(bytes::Bytes::from(bytes));
        }
        self.mouse_cell = Some(cell);
        true
    }

    fn on_mouse_down(
        &mut self,
        event: &MouseDownEvent,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if event.modifiers.control || event.modifiers.platform {
            let cell = self.cell_at(event.position);
            if let Some(url) = self.terminal.link_at(cell.row, cell.column) {
                cx.open_url(&url);
                return;
            }
        }
        if self.report_mouse(
            mouse::Button::Left,
            mouse::Action::Press,
            event.position,
            event.modifiers,
        ) {
            self.mouse_button = Some(mouse::Button::Left);
            self.selection = None;
            cx.notify();
            return;
        }
        self.selection = Some(Selection::new(self.cell_at(event.position)));
        self.selecting = true;
        self.copied = false;
        cx.notify();
    }

    fn on_other_mouse_down(
        &mut self,
        event: &MouseDownEvent,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) {
        let Some(button) = protocol_button(event.button) else {
            return;
        };
        if self.report_mouse(
            button,
            mouse::Action::Press,
            event.position,
            event.modifiers,
        ) {
            self.mouse_button = Some(button);
        }
    }

    fn on_other_mouse_up(
        &mut self,
        event: &MouseUpEvent,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) {
        let Some(button) = protocol_button(event.button) else {
            return;
        };
        if self.mouse_button == Some(button) {
            self.mouse_button = None;
            self.report_mouse(
                button,
                mouse::Action::Release,
                event.position,
                event.modifiers,
            );
        }
    }

    fn on_mouse_move(
        &mut self,
        event: &MouseMoveEvent,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !self.selecting {
            let button = self.mouse_button.unwrap_or(mouse::Button::None);
            let cell = self.cell_at(event.position);
            if self.mouse_cell != Some(cell) {
                self.report_mouse(
                    button,
                    mouse::Action::Motion,
                    event.position,
                    event.modifiers,
                );
            }
            if self.mouse_button.is_some() {
                return;
            }
        }

        if !self.selecting || !event.dragging() {
            return;
        }
        let head = self.cell_at(event.position);
        if let Some(selection) = &mut self.selection
            && selection.head != head
        {
            selection.head = head;
            cx.notify();
        }
    }

    fn on_mouse_up(&mut self, event: &MouseUpEvent, _window: &mut Window, cx: &mut Context<Self>) {
        if self.mouse_button == Some(mouse::Button::Left) {
            self.mouse_button = None;
            self.report_mouse(
                mouse::Button::Left,
                mouse::Action::Release,
                event.position,
                event.modifiers,
            );
            return;
        }
        self.selecting = false;

        if self.selection.is_some_and(|selection| selection.is_empty()) {
            self.selection = None;
            self.copied = false;
            cx.notify();
            return;
        }

        self.copied = self.copy(cx);
        cx.notify();
    }

    fn on_scroll(&mut self, event: &ScrollEvent, window: &mut Window, cx: &mut Context<Self>) {
        let lines = match event.delta {
            ScrollDelta::Lines(delta) => delta.y,
            ScrollDelta::Pixels(delta) => f32::from(delta.y) / f32::from(self.metrics.height),
        };
        let lines = lines.round() as i32;
        if lines == 0 {
            return;
        }
        let _ = window;

        let up = lines > 0;
        let count = lines.unsigned_abs().min(MAX_WHEEL_REPORTS) as usize;

        let wheel = if up {
            mouse::Button::WheelUp
        } else {
            mouse::Button::WheelDown
        };
        let mut reported = false;
        for _ in 0..count {
            reported =
                self.report_mouse(wheel, mouse::Action::Press, event.position, event.modifiers);
            if !reported {
                break;
            }
        }
        if reported {
            return;
        }

        if let Some(arrows) = mouse::wheel_as_arrows(self.terminal.mode(), up, count) {
            self.send(bytes::Bytes::from(arrows));
            return;
        }

        self.terminal.scroll(lines);
        cx.notify();
    }

    fn fit(&mut self, bounds: Bounds<Pixels>) -> bool {
        let size = self.metrics.grid_for(bounds);
        if size == self.terminal.size() {
            return false;
        }
        self.resize(size);
        true
    }
}

impl Focusable for TerminalView {
    fn focus_handle(&self, _cx: &gpui_kit::App) -> FocusHandle {
        self.focus.clone()
    }
}

struct SearchBar {
    input: Entity<InputState>,
    status: Option<SharedString>,
    _subscription: Subscription,
}

const MAX_WHEEL_REPORTS: u32 = 5;

fn protocol_button(button: MouseButton) -> Option<mouse::Button> {
    match button {
        MouseButton::Left => Some(mouse::Button::Left),
        MouseButton::Right => Some(mouse::Button::Right),
        MouseButton::Middle => Some(mouse::Button::Middle),
        MouseButton::Navigate(_) => None,
    }
}

fn measure_cell(family: &SharedString, font_size: Pixels, cx: &gpui_kit::App) -> CellMetrics {
    let font = gpui_kit::font(family.clone());
    let font_id = cx.text_system().resolve_font(&font);

    let width = cx
        .text_system()
        .advance(font_id, font_size, 'M')
        .map(|advance| advance.width)
        .unwrap_or(font_size * 0.6);

    CellMetrics {
        width: if width > px(0.) {
            width
        } else {
            font_size * 0.6
        },
        height: font_size * LINE_HEIGHT,
    }
}

fn translate(event: &KeyDownEvent) -> Option<(Key, Mods)> {
    let keystroke = &event.keystroke;
    let mods = Mods {
        ctrl: keystroke.modifiers.control,
        alt: keystroke.modifiers.alt,
        shift: keystroke.modifiers.shift,
    };

    if keystroke.modifiers.platform {
        return None;
    }

    let named = match keystroke.key.as_str() {
        "enter" => Some(Key::Enter),
        "tab" => Some(Key::Tab),
        "backspace" => Some(Key::Backspace),
        "escape" => Some(Key::Escape),
        "delete" => Some(Key::Delete),
        "insert" => Some(Key::Insert),
        "up" => Some(Key::Up),
        "down" => Some(Key::Down),
        "right" => Some(Key::Right),
        "left" => Some(Key::Left),
        "home" => Some(Key::Home),
        "end" => Some(Key::End),
        "pageup" => Some(Key::PageUp),
        "pagedown" => Some(Key::PageDown),
        "space" => Some(Key::Char(' ')),
        other => other
            .strip_prefix('f')
            .and_then(|number| number.parse::<u8>().ok())
            .map(Key::Function),
    };

    if let Some(key) = named {
        return Some((key, mods));
    }

    if mods.ctrl {
        return keystroke
            .key
            .chars()
            .next()
            .map(|character| (Key::Char(character), mods));
    }

    let typed = keystroke
        .key_char
        .as_deref()
        .filter(|text| !text.is_empty())
        .unwrap_or(keystroke.key.as_str());

    let mut characters = typed.chars();
    let character = characters.next()?;
    if characters.next().is_some() {
        return None;
    }

    Some((
        Key::Char(character),
        Mods {
            shift: false,
            ..mods
        },
    ))
}

fn color(rgb: Rgb) -> Hsla {
    gpui_kit::rgb(rgb.to_hex()).into()
}

fn run_element(text: &str, style: Style, background: Rgb) -> impl IntoElement {
    let mut element = div()
        .whitespace_nowrap()
        .text_color(color(style.fg))
        .child(SharedString::from(text.to_string()));

    if style.bg != background {
        element = element.bg(color(style.bg));
    }
    if style.bold {
        element = element.font_weight(FontWeight::BOLD);
    }
    if style.italic {
        element = element.italic();
    }
    if style.underline {
        element = element.underline();
    }
    if style.strikeout {
        element = element.line_through();
    }
    element
}

pub fn grid_element(snapshot: &Snapshot, metrics: CellMetrics) -> impl IntoElement {
    let background = snapshot.background;
    div()
        .flex()
        .flex_col()
        .size_full()
        .children(snapshot.lines.iter().map(move |line| {
            div().flex().flex_row().h(metrics.height).children(
                line.runs
                    .iter()
                    .map(|run| run_element(&run.text, run.style, background)),
            )
        }))
}

impl Render for TerminalView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.ensure_secret_input(window, cx);

        let secret_open = matches!(self.prompt, Some(Prompt::Secret { .. }));
        if self.pending_focus && !secret_open {
            window.focus(&self.focus, cx);
            self.pending_focus = false;
        }

        let mut snapshot = self.terminal.snapshot();
        self.predictor.paint(&mut snapshot);
        let background = snapshot.background;
        let metrics = self.metrics;
        let focused = self.focus.is_focused(window);

        let grid = TerminalElement::new(
            snapshot.clone(),
            metrics,
            self.font.clone(),
            self.font_size,
            focused,
        )
        .colors(
            self.cursor_color,
            self.selection_color,
            self.selection_foreground,
        )
        .selection(self.selection)
        .icons(MonoFont::get(cx).icons.clone().map(gpui_kit::font));

        let view = cx.entity().downgrade();
        let measure = canvas(
            move |bounds, _window, cx| {
                view.update(cx, |this, cx| {
                    this.grid_origin = bounds.origin;
                    if this.fit(bounds) {
                        cx.notify();
                    }
                })
                .ok();
            },
            |_bounds, _prepainted, _window, _cx| {},
        )
        .absolute()
        .size_full();

        div()
            .key_context("Terminal")
            .track_focus(&self.focus)
            .on_key_down(cx.listener(Self::on_key))
            .on_mouse_down(MouseButton::Left, cx.listener(Self::on_mouse_down))
            .on_mouse_down(MouseButton::Right, cx.listener(Self::on_other_mouse_down))
            .on_mouse_down(MouseButton::Middle, cx.listener(Self::on_other_mouse_down))
            .on_mouse_move(cx.listener(Self::on_mouse_move))
            .on_mouse_up(MouseButton::Left, cx.listener(Self::on_mouse_up))
            .on_mouse_up(MouseButton::Right, cx.listener(Self::on_other_mouse_up))
            .on_mouse_up(MouseButton::Middle, cx.listener(Self::on_other_mouse_up))
            .on_scroll(cx.listener(Self::on_scroll))
            .size_full()
            .flex()
            .flex_col()
            .when(crate::ui::theme::terminal_opacity(cx) >= 1.0, |this| {
                this.bg(color(background))
            })
            .font_family(self.font_family.clone())
            .text_size(self.font_size)
            .line_height(relative(LINE_HEIGHT))
            .child(
                div()
                    .relative()
                    .flex_grow_1()
                    .overflow_hidden()
                    .p(PADDING)
                    .child(measure)
                    .child(grid)
                    .children(self.search_panel(cx))
                    .children(self.prompt.is_some().then(|| self.prompt_panel(cx))),
            )
            .children(self.status_bar(cx))
    }
}

impl TerminalView {
    /// Status line under the terminal. Hidden while the session is simply
    /// connected: it only shows connecting, closing and the "copied" notice.
    fn status_bar(&self, cx: &mut Context<Self>) -> Option<impl IntoElement> {
        let theme = cx.theme();
        let (dim, error, ok) = (theme.muted_foreground, theme.danger, theme.success);

        let (text, color) = match &self.status {
            Status::Connecting { target } => (t!("terminal.connecting", target = target).to_string(), dim),
            Status::Connected { target, .. } if self.copied => {
                (t!("terminal.copied", target = target).to_string(), ok)
            }
            Status::Connected { .. } => return None,
            Status::Closed { message, failed } => {
                (message.to_string(), if *failed { error } else { dim })
            }
        };

        Some(div()
            .flex_shrink_0()
            .px_2()
            .py_1()
            .text_size(px(12.))
            .text_color(color)
            .whitespace_nowrap()
            .overflow_hidden()
            .text_ellipsis()
            .child(SharedString::from(text)))
    }
}

impl TerminalView {
    fn prompt_panel(&self, cx: &mut Context<Self>) -> gpui_kit::AnyElement {
        let Some(prompt) = self.prompt.as_ref() else {
            return div().into_any_element();
        };
        let theme = cx.theme().clone();

        let backdrop = div()
            .absolute()
            .occlude()
            .top_0()
            .left_0()
            .size_full()
            .flex()
            .items_center()
            .justify_center()
            .bg(gpui_kit::black().opacity(0.55));

        let card = div()
            .w(px(600.))
            .max_w(gpui_kit::relative(0.94))
            .max_h(gpui_kit::relative(0.94))
            .id("prompt-card")
            .overflow_y_scroll()
            .p_5()
            .flex()
            .flex_col()
            .gap_3()
            .font_family(theme.font_family.clone())
            .rounded_lg()
            .bg(theme.popover)
            .text_color(theme.popover_foreground)
            .border_1()
            .shadow_lg();

        match prompt {
            Prompt::Secret {
                label,
                kind,
                input,
                remember,
                error,
            } => {
                let remember = *remember;
                let can_remember = self.can_save_secrets && secret_purpose(*kind).is_some();

                backdrop.child(
                    card.border_color(theme.border)
                        .child(Label::new(label.clone()))
                        .children(input.as_ref().map(Input::new))
                        .children(
                            error
                                .clone()
                                .map(|error| Label::new(error).text_sm().text_color(theme.danger)),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .when(can_remember, |this| {
                                    this.child(
                                        Checkbox::new("remember-secret")
                                            .small()
                                            .label(SharedString::from(t!("terminal.save_to_vault")))
                                            .checked(remember)
                                            .on_click(cx.listener(
                                                |this, checked: &bool, _window, cx| {
                                                    if let Some(Prompt::Secret {
                                                        remember, ..
                                                    }) = &mut this.prompt
                                                    {
                                                        *remember = *checked;
                                                    }
                                                    cx.notify();
                                                },
                                            )),
                                    )
                                })
                                .child(div().flex_grow_1())
                                .child(
                                    Button::new("submit-secret")
                                        .primary()
                                        .small()
                                        .label(t!("terminal.confirm"))
                                        .on_click(cx.listener(|this, _, _window, cx| {
                                            this.submit_secret(cx)
                                        })),
                                ),
                        ),
                )
            }
            Prompt::HostKey {
                message,
                fingerprint,
                changed,
            } => backdrop.child(
                card.border_color(if *changed { theme.danger } else { theme.border })
                    .child(
                        Label::new(if *changed {
                            t!("terminal.key_changed")
                        } else {
                            t!("terminal.unknown_host")
                        })
                        .text_xl()
                        .text_color(if *changed {
                            theme.danger
                        } else {
                            theme.popover_foreground
                        }),
                    )
                    .child(
                        Label::new(message.clone())
                            .text_sm()
                            .text_color(theme.muted_foreground),
                    )
                    .child(
                        div()
                            .px_2()
                            .py_1()
                            .rounded_md()
                            .bg(theme.muted)
                            .font_family(self.font_family.clone())
                            .child(Label::new(fingerprint.clone())),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .gap_2()
                            .justify_end()
                            .child(
                                Button::new("hostkey-reject")
                                    .ghost()
                                    .label(t!("terminal.reject"))
                                    .on_click(cx.listener(|this, _, _window, cx| {
                                        this.decide_host_key(HostKeyDecision::Reject, cx)
                                    })),
                            )
                            .child(
                                Button::new("hostkey-once")
                                    .outline()
                                    .label(t!("terminal.trust_once"))
                                    .on_click(cx.listener(|this, _, _window, cx| {
                                        this.decide_host_key(
                                            HostKeyDecision::Accept { remember: false },
                                            cx,
                                        )
                                    })),
                            )
                            .when(!*changed, |this| {
                                this.child(
                                    Button::new("hostkey-remember")
                                        .primary()
                                        .label(t!("terminal.trust_save"))
                                        .on_click(cx.listener(|this, _, _window, cx| {
                                            this.decide_host_key(
                                                HostKeyDecision::Accept { remember: true },
                                                cx,
                                            )
                                        })),
                                )
                            }),
                    )
                    .child(
                        Label::new(if *changed {
                            t!("terminal.keys_changed")
                        } else {
                            t!("terminal.keys_unknown")
                        })
                        .text_xs()
                        .text_color(theme.muted_foreground),
                    ),
            ),
        }
        .into_any_element()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui_kit::{Keystroke, Modifiers};

    fn press(key: &str, key_char: Option<&str>, modifiers: Modifiers) -> Option<(Key, Mods)> {
        translate(&KeyDownEvent {
            keystroke: Keystroke {
                modifiers,
                key: key.to_string(),
                key_char: key_char.map(str::to_string),
            },
            is_held: false,
            prefer_character_input: false,
        })
    }

    fn plain() -> Modifiers {
        Modifiers::default()
    }

    fn ctrl() -> Modifiers {
        Modifiers {
            control: true,
            ..Default::default()
        }
    }

    #[test]
    fn named_keys_map_to_their_terminal_counterparts() {
        assert_eq!(
            press("enter", None, plain()).map(|(key, _)| key),
            Some(Key::Enter)
        );
        assert_eq!(
            press("up", None, plain()).map(|(key, _)| key),
            Some(Key::Up)
        );
        assert_eq!(
            press("pageup", None, plain()).map(|(key, _)| key),
            Some(Key::PageUp)
        );
        assert_eq!(
            press("f5", None, plain()).map(|(key, _)| key),
            Some(Key::Function(5))
        );
        assert_eq!(
            press("space", None, plain()).map(|(key, _)| key),
            Some(Key::Char(' '))
        );
    }

    #[test]
    fn typing_uses_the_layout_character_not_the_ascii_equivalent() {
        assert_eq!(
            press("q", Some("é"), plain()).map(|(key, _)| key),
            Some(Key::Char('é'))
        );
    }

    #[test]
    fn ctrl_uses_the_physical_key_so_ctrl_letters_work_in_any_layout() {
        let (key, mods) = press("a", Some("à"), ctrl()).expect("key recognized");
        assert_eq!(key, Key::Char('a'));
        assert!(mods.ctrl);
    }

    #[test]
    fn shift_is_not_passed_twice_for_printable_characters() {
        let modifiers = Modifiers {
            shift: true,
            ..Default::default()
        };
        let (key, mods) = press("a", Some("A"), modifiers).expect("key recognized");
        assert_eq!(key, Key::Char('A'));
        assert!(!mods.shift);
    }

    #[test]
    fn shift_still_matters_for_named_keys() {
        let modifiers = Modifiers {
            shift: true,
            ..Default::default()
        };
        let (key, mods) = press("tab", None, modifiers).expect("key recognized");
        assert_eq!(key, Key::Tab);
        assert!(mods.shift, "Shift+Tab must remain Shift+Tab");
    }

    #[test]
    fn platform_modifier_is_left_to_the_system() {
        let modifiers = Modifiers {
            platform: true,
            ..Default::default()
        };
        assert_eq!(press("q", Some("q"), modifiers), None);
    }

    #[test]
    fn multi_character_input_is_left_to_the_ime() {
        assert_eq!(press("a", Some("ab"), plain()), None);
    }

    #[test]
    fn cell_metrics_fill_the_area_and_never_collapse_to_zero() {
        let metrics = CellMetrics {
            width: px(10.),
            height: px(20.),
        };
        let bounds = Bounds {
            origin: gpui_kit::point(px(0.), px(0.)),
            size: gpui_kit::size(px(105.), px(203.)),
        };
        let grid = metrics.grid_for(bounds);
        assert_eq!((grid.cols, grid.rows), (10, 10));

        let empty = Bounds {
            origin: gpui_kit::point(px(0.), px(0.)),
            size: gpui_kit::size(px(0.), px(0.)),
        };
        let grid = metrics.grid_for(empty);
        assert_eq!((grid.cols, grid.rows), (1, 1));
    }
}
