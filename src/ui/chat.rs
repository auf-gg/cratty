//! The AI tab of the session panel: conversations with an agent (Claude Code,
//! OpenCode) that works on the tab's server through Cratty's MCP tools (see
//! `crate::acp` and `crate::mcp`). Commands and file changes it asks for still go
//! through the approval dialog of the window.
//!
//! The top row picks the agent, remembered for every server, and the chat: the
//! server's saved chats with that agent, a new one, or none deleted.

use futures::StreamExt;
use futures::channel::mpsc;
use gpui_kit::component::{
    ActiveTheme, Disableable, Icon, Sizable, StyledExt,
    button::{Button, ButtonVariants},
    h_flex,
    input::{InputEvent, Textarea, TextareaState},
    label::Label,
    scroll::ScrollableElement,
    text::TextView,
    v_flex,
};
use gpui_kit::{
    AnyElement, Context, Entity, EventEmitter, Focusable, Hsla, IntoElement, Render, ScrollHandle,
    SharedString, Subscription, Task, WeakEntity, Window, div, prelude::*, px,
};
use rust_i18n::t;

use crate::acp::agents::Missing;
use crate::acp::{
    self, AgentCommand, AgentKind, FromAgent, LoginMethod, PermissionAsk, PlanEntry, Setup,
    ToAgent, Update,
};
use crate::ssh::LocalProgram;

/// Lines of tool output shown when a tool row is opened.
const OUTPUT_LINES: usize = 40;
/// Height of the row with the agent and chat menus; the menus open under it.
const TOP_ROW: f32 = 44.;

#[derive(Clone, Debug, PartialEq)]
enum State {
    Starting,
    /// A saved chat is coming back from the agent.
    Loading,
    Ready,
    Working,
    Closed(Option<SharedString>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Menu {
    Agents,
    Chats,
}

enum Entry {
    User(SharedString),
    Agent(String),
    Thought {
        text: String,
        open: bool,
    },
    Tool(ToolEntry),
    Plan(Vec<PlanEntry>),
    Permission {
        request: u64,
        ask: PermissionAsk,
        answer: Option<SharedString>,
    },
    Notice {
        text: SharedString,
        error: bool,
    },
}

struct ToolEntry {
    id: String,
    title: String,
    detail: Option<String>,
    status: String,
    output: Option<String>,
    open: bool,
}

pub enum ChatEvent {
    /// Run the agent's sign-in in a terminal.
    Login {
        agent: &'static str,
        program: LocalProgram,
    },
}

impl EventEmitter<ChatEvent> for ChatView {}

pub type Agents = Vec<(AgentKind, Result<AgentCommand, Missing>)>;

/// The agent picked last, if this computer has it, else the first one it has.
pub fn pick_agent(agents: &Agents) -> Option<AgentCommand> {
    let usable = |kind: AgentKind| {
        agents
            .iter()
            .find(|(each, _)| *each == kind)
            .and_then(|(_, found)| found.as_ref().ok())
            .cloned()
    };
    acp::sessions::chosen_agent().and_then(usable).or_else(|| {
        agents
            .iter()
            .find_map(|(_, found)| found.as_ref().ok().cloned())
    })
}

pub struct ChatView {
    /// The agents found on this computer, for the agent menu.
    agents: Agents,
    command: AgentCommand,
    setup: Setup,
    /// The server the chats are about: the key of its saved chats.
    server: String,
    commands: Option<mpsc::UnboundedSender<ToAgent>>,
    _pump: Option<Task<()>>,
    agent_name: SharedString,
    state: State,
    /// Loading a saved chat was asked for and has not been answered yet.
    resuming: bool,
    /// The session in use, and whether it is among the server's saved chats yet: a new
    /// chat is saved after its first answer, so an untouched one leaves no trace.
    session: Option<String>,
    saved: bool,
    /// The first message of an unsaved chat: its title once it is saved.
    first_message: Option<String>,
    entries: Vec<Entry>,
    /// Ways to sign in, when the agent asked for it.
    login: Vec<LoginMethod>,
    menu: Option<Menu>,
    /// Made with the window on first render.
    input: Option<Entity<TextareaState>>,
    focus_pending: bool,
    scroll: ScrollHandle,
    _input_events: Option<Subscription>,
}

impl ChatView {
    /// Starts `command`'s agent; with `continue_latest`, the server's latest chat with
    /// it comes back.
    pub fn new(
        agents: Agents,
        command: AgentCommand,
        setup: Setup,
        server: String,
        continue_latest: bool,
        cx: &mut Context<Self>,
    ) -> Self {
        let mut chat = Self {
            agents,
            agent_name: SharedString::from(command.kind.title()),
            command,
            setup,
            server,
            commands: None,
            _pump: None,
            state: State::Starting,
            resuming: false,
            session: None,
            saved: false,
            first_message: None,
            entries: Vec::new(),
            login: Vec::new(),
            menu: None,
            input: None,
            focus_pending: true,
            scroll: ScrollHandle::new(),
            _input_events: None,
        };
        chat.setup.resume = if continue_latest {
            chat.latest_chat()
        } else {
            None
        };
        chat.start(cx);
        chat
    }

    fn latest_chat(&self) -> Option<String> {
        acp::sessions::chats(&self.server, self.command.kind)
            .into_iter()
            .next()
            .map(|chat| chat.session)
    }

    fn ensure_input(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Entity<TextareaState> {
        if let Some(input) = &self.input {
            return input.clone();
        }
        let input = cx.new(|cx| {
            TextareaState::new(window, cx)
                .submit_on_enter(true)
                .placeholder(t!("chat.placeholder"))
        });
        self._input_events =
            Some(
                cx.subscribe_in(&input, window, |this, _, event: &InputEvent, window, cx| {
                    if let InputEvent::PressEnter { shift: false, .. } = event {
                        this.send(window, cx);
                    }
                }),
            );
        self.input = Some(input.clone());
        input
    }

    /// Starts the agent process with `setup.resume`.
    fn start(&mut self, cx: &mut Context<Self>) {
        self.commands = None;
        self._pump = None;
        self.entries.clear();
        self.session = None;
        self.saved = false;
        self.first_message = None;
        self.login.clear();
        self.resuming = self.setup.resume.is_some();
        self.state = if self.resuming {
            State::Loading
        } else {
            State::Starting
        };
        match acp::spawn(self.command.clone(), self.setup.clone()) {
            Ok(handle) => {
                let acp::AgentHandle { commands, events } = handle;
                self.commands = Some(commands);
                self._pump = Some(cx.spawn(async move |this: WeakEntity<Self>, cx| {
                    let mut events = events;
                    while let Some(event) = events.next().await {
                        let mut batch = vec![event];
                        while let Ok(more) = events.try_recv() {
                            batch.push(more);
                        }
                        let applied = this.update(cx, |this, cx| {
                            let follow = this.at_bottom();
                            for event in batch {
                                this.apply(event);
                            }
                            if follow {
                                this.scroll.scroll_to_bottom();
                            }
                            cx.notify();
                        });
                        if applied.is_err() {
                            return;
                        }
                    }
                }));
            }
            Err(error) => {
                self.state = State::Closed(Some(error.to_string().into()));
            }
        }
        cx.notify();
    }

    /// Starts the agent again after it stopped, with the chat that was open.
    fn restart(&mut self, cx: &mut Context<Self>) {
        self.setup.resume = self
            .session
            .clone()
            .filter(|_| self.saved)
            .or_else(|| self.setup.resume.clone());
        self.start(cx);
    }

    /// Switches the running agent to a saved chat, or to a new one with `None`. A
    /// stopped agent is started again instead.
    fn open_chat(&mut self, target: Option<String>, cx: &mut Context<Self>) {
        if target.is_some() && target == self.session {
            return;
        }
        if target.is_none() && self.session.is_some() && !self.saved && self.entries.is_empty() {
            // Already a new, untouched chat.
            return;
        }
        let sent = self.state == State::Ready
            && self.commands.as_ref().is_some_and(|commands| {
                commands
                    .unbounded_send(ToAgent::Switch(target.clone()))
                    .is_ok()
            });
        if sent {
            self.entries.clear();
            self.session = None;
            self.saved = false;
            self.first_message = None;
            self.resuming = target.is_some();
            self.state = if self.resuming {
                State::Loading
            } else {
                State::Starting
            };
        } else {
            self.setup.resume = target;
            self.start(cx);
        }
        self.focus_pending = true;
        cx.notify();
    }

    /// Deletes a saved chat at once; the menu stays open.
    fn delete_chat(&mut self, session: String, cx: &mut Context<Self>) {
        acp::sessions::forget(&self.server, &session);
        if let Some(commands) = &self.commands {
            let _ = commands.unbounded_send(ToAgent::Delete(session.clone()));
        }
        // An agent that cannot delete over ACP leaves the files behind.
        acp::agents::delete_saved_session(self.command.kind, &session);
        if self.setup.resume.as_deref() == Some(session.as_str()) {
            self.setup.resume = None;
        }
        if self.session.as_deref() == Some(session.as_str()) {
            self.open_chat(None, cx);
        }
        cx.notify();
    }

    /// Picks another agent for every server and opens its latest chat here.
    fn choose_agent(&mut self, kind: AgentKind, cx: &mut Context<Self>) {
        self.menu = None;
        if kind == self.command.kind {
            cx.notify();
            return;
        }
        let Some(command) = self
            .agents
            .iter()
            .find(|(each, _)| *each == kind)
            .and_then(|(_, found)| found.as_ref().ok())
            .cloned()
        else {
            return;
        };
        acp::sessions::choose_agent(kind);
        self.agent_name = SharedString::from(kind.title());
        self.setup.login = kind.login_command().into();
        self.command = command;
        self.setup.resume = self.latest_chat();
        self.focus_pending = true;
        self.start(cx);
    }

    fn toggle_menu(&mut self, menu: Menu, cx: &mut Context<Self>) {
        self.menu = if self.menu == Some(menu) {
            None
        } else {
            Some(menu)
        };
        cx.notify();
    }

    /// Switching is for a quiet moment: not while the agent starts, loads or answers.
    fn can_switch(&self) -> bool {
        matches!(self.state, State::Ready | State::Closed(_))
    }

    fn at_bottom(&self) -> bool {
        let offset = self.scroll.offset().y;
        let max = self.scroll.max_offset().y;
        // The offset goes negative as the view scrolls down.
        max - (-offset) < px(24.)
    }

    fn apply(&mut self, event: FromAgent) {
        match event {
            FromAgent::Ready {
                agent,
                session,
                resumed,
            } => {
                if !agent.is_empty() {
                    self.agent_name = agent.into();
                }
                if self.resuming && !resumed {
                    self.entries.push(Entry::Notice {
                        text: t!("chat.not_resumed").into(),
                        error: false,
                    });
                }
                self.resuming = false;
                self.state = State::Ready;
                self.saved = resumed;
                self.session = Some(session);
            }
            FromAgent::LoginRequired(methods) => self.login = methods,
            FromAgent::Update(update) => self.apply_update(update),
            FromAgent::Permission { request, ask } => self.entries.push(Entry::Permission {
                request,
                ask,
                answer: None,
            }),
            FromAgent::TurnEnded { stop_reason } => {
                self.state = State::Ready;
                if let Some(session) = &self.session {
                    let first = self.first_message.take().unwrap_or_default();
                    acp::sessions::touch(&self.server, self.command.kind, session, &first);
                    self.saved = true;
                }
                let note = match stop_reason.as_str() {
                    "end_turn" | "cancelled" => None,
                    "max_tokens" => Some(t!("chat.stop_max_tokens")),
                    "max_turn_requests" => Some(t!("chat.stop_max_requests")),
                    "refusal" => Some(t!("chat.stop_refusal")),
                    _ => None,
                };
                if stop_reason == "cancelled" {
                    self.cancel_open_tools();
                }
                if let Some(note) = note {
                    self.entries.push(Entry::Notice {
                        text: note.into(),
                        error: false,
                    });
                }
            }
            FromAgent::TurnFailed(error) => {
                self.state = State::Ready;
                self.entries.push(Entry::Notice {
                    text: error.into(),
                    error: true,
                });
            }
            FromAgent::Closed { error } => {
                self.commands = None;
                self.cancel_open_tools();
                self.state = State::Closed(error.map(SharedString::from));
            }
        }
    }

    fn apply_update(&mut self, update: Update) {
        match update {
            Update::AgentText(chunk) => match self.entries.last_mut() {
                Some(Entry::Agent(text)) => text.push_str(&chunk),
                _ => self.entries.push(Entry::Agent(chunk)),
            },
            Update::Thought(chunk) => match self.entries.last_mut() {
                Some(Entry::Thought { text, .. }) => text.push_str(&chunk),
                _ => self.entries.push(Entry::Thought {
                    text: chunk,
                    open: false,
                }),
            },
            // A replayed conversation brings the user's messages back; live, the window
            // shows them itself when they are sent.
            Update::UserText(chunk) if self.state == State::Loading => {
                match self.entries.last_mut() {
                    Some(Entry::User(text)) => *text = format!("{text}{chunk}").into(),
                    _ => self.entries.push(Entry::User(chunk.into())),
                }
            }
            Update::UserText(_) => {}
            Update::ToolCall(call) => self.entries.push(Entry::Tool(ToolEntry {
                id: call.id,
                title: tool_title(&call.title),
                detail: call.input.as_ref().and_then(input_detail),
                status: call.status,
                output: call.output,
                open: false,
            })),
            Update::ToolCallUpdate(update) => {
                let Some(tool) = self.entries.iter_mut().rev().find_map(|entry| match entry {
                    Entry::Tool(tool) if tool.id == update.id => Some(tool),
                    _ => None,
                }) else {
                    return;
                };
                if let Some(title) = update.title {
                    tool.title = tool_title(&title);
                }
                if let Some(detail) = update.input.as_ref().and_then(input_detail) {
                    tool.detail = Some(detail);
                }
                if let Some(status) = update.status {
                    tool.status = status;
                }
                if update.output.is_some() {
                    tool.output = update.output;
                }
            }
            Update::Plan(entries) => {
                match self.entries.iter_mut().rev().find_map(|entry| match entry {
                    Entry::Plan(plan) => Some(plan),
                    _ => None,
                }) {
                    // One plan per conversation, updated in place.
                    Some(plan) => *plan = entries,
                    None => self.entries.push(Entry::Plan(entries)),
                }
            }
        }
    }

    fn cancel_open_tools(&mut self) {
        for entry in &mut self.entries {
            match entry {
                Entry::Tool(tool) if matches!(tool.status.as_str(), "pending" | "in_progress") => {
                    tool.status = "cancelled".into();
                }
                Entry::Permission {
                    answer: answer @ None,
                    ..
                } => {
                    *answer = Some(t!("chat.cancelled").into());
                }
                _ => {}
            }
        }
    }

    fn send(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.state != State::Ready {
            return;
        }
        let Some(input) = self.input.clone() else {
            return;
        };
        let text = input.read(cx).value().trim().to_owned();
        if text.is_empty() {
            return;
        }
        let Some(commands) = &self.commands else {
            return;
        };
        if commands
            .unbounded_send(ToAgent::Prompt(text.clone()))
            .is_err()
        {
            return;
        }
        if !self.saved && self.first_message.is_none() {
            self.first_message = Some(text.clone());
        }
        self.entries.push(Entry::User(text.into()));
        self.state = State::Working;
        self.menu = None;
        input.update(cx, |input, cx| input.set_value("", window, cx));
        self.scroll.scroll_to_bottom();
        cx.notify();
    }

    /// A note in the conversation from the window, such as how to sign in by hand.
    pub fn add_notice(&mut self, text: SharedString, cx: &mut Context<Self>) {
        self.entries.push(Entry::Notice { text, error: false });
        cx.notify();
    }

    fn stop(&mut self, cx: &mut Context<Self>) {
        if let Some(commands) = &self.commands {
            let _ = commands.unbounded_send(ToAgent::Cancel);
        }
        self.cancel_open_tools();
        cx.notify();
    }

    fn answer(
        &mut self,
        index: usize,
        option: Option<(String, SharedString)>,
        cx: &mut Context<Self>,
    ) {
        let Some(Entry::Permission {
            request, answer, ..
        }) = self.entries.get_mut(index)
        else {
            return;
        };
        if answer.is_some() {
            return;
        }
        let (id, name) = match option {
            Some((id, name)) => (Some(id), name),
            None => (None, t!("chat.denied").into()),
        };
        if let Some(commands) = &self.commands {
            let _ = commands.unbounded_send(ToAgent::Permission {
                request: *request,
                option: id,
            });
        }
        *answer = Some(name);
        cx.notify();
    }

    fn toggle(&mut self, index: usize, cx: &mut Context<Self>) {
        match self.entries.get_mut(index) {
            Some(Entry::Tool(tool)) => tool.open = !tool.open,
            Some(Entry::Thought { open, .. }) => *open = !*open,
            _ => return,
        }
        cx.notify();
    }

    fn render_entry(&self, index: usize, entry: &Entry, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        match entry {
            Entry::User(text) => div()
                .px_3()
                .py_2()
                .rounded_lg()
                .bg(theme.secondary)
                .text_sm()
                .child(text.clone())
                .into_any_element(),
            Entry::Agent(text) => {
                TextView::markdown(("chat-text", index), SharedString::from(text.clone()))
                    .selectable(true)
                    .text_sm()
                    .into_any_element()
            }
            Entry::Thought { text, open } => {
                let shown = if *open {
                    text.trim().to_owned()
                } else {
                    t!("chat.thinking").to_string()
                };
                div()
                    .id(("chat-thought", index))
                    .cursor_pointer()
                    .text_xs()
                    .italic()
                    .text_color(theme.muted_foreground)
                    .child(shown)
                    .on_click(cx.listener(move |this, _, _window, cx| this.toggle(index, cx)))
                    .into_any_element()
            }
            Entry::Tool(tool) => self.render_tool(index, tool, cx),
            Entry::Plan(plan) => v_flex()
                .gap_1()
                .p_2()
                .rounded_md()
                .border_1()
                .border_color(theme.border)
                .child(
                    Label::new(t!("chat.plan"))
                        .text_xs()
                        .font_medium()
                        .text_color(theme.muted_foreground),
                )
                .children(plan.iter().map(|entry| {
                    let (mark, color) = match entry.status.as_str() {
                        "completed" => ("✓", theme.success),
                        "in_progress" => ("›", theme.warning),
                        _ => ("·", theme.muted_foreground),
                    };
                    h_flex()
                        .gap_2()
                        .items_start()
                        .text_xs()
                        .child(
                            div()
                                .w(px(10.))
                                .flex_shrink_0()
                                .text_color(color)
                                .child(mark),
                        )
                        .child(div().flex_1().child(entry.content.clone()))
                }))
                .into_any_element(),
            Entry::Permission { ask, answer, .. } => {
                let mut card = v_flex()
                    .gap_2()
                    .p_2()
                    .rounded_md()
                    .border_1()
                    .border_color(theme.warning)
                    .child(
                        Label::new(SharedString::from(
                            t!("chat.permission", tool = ask.title).to_string(),
                        ))
                        .text_sm(),
                    )
                    .children(ask.detail.clone().map(|detail| {
                        div()
                            .p_1()
                            .rounded_sm()
                            .bg(theme.muted)
                            .font_family(crate::ui::app::mono_family(cx))
                            .text_xs()
                            .child(detail)
                    }));
                card = match answer {
                    Some(answer) => card.child(
                        Label::new(answer.clone())
                            .text_xs()
                            .text_color(theme.muted_foreground),
                    ),
                    None => card.child(h_flex().gap_1().flex_wrap().children(
                        ask.options.iter().enumerate().map(|(number, option)| {
                            let choice =
                                (option.id.clone(), SharedString::from(option.name.clone()));
                            let button = Button::new(("chat-permission", index * 16 + number))
                                .xsmall()
                                .label(option.name.clone())
                                .on_click(cx.listener(move |this, _, _window, cx| {
                                    this.answer(index, Some(choice.clone()), cx)
                                }));
                            if option.allows() {
                                button.outline().into_any_element()
                            } else {
                                button.ghost().into_any_element()
                            }
                        }),
                    )),
                };
                card.into_any_element()
            }
            Entry::Notice { text, error } => Label::new(text.clone())
                .text_xs()
                .text_color(if *error {
                    theme.danger
                } else {
                    theme.muted_foreground
                })
                .into_any_element(),
        }
    }

    fn render_tool(&self, index: usize, tool: &ToolEntry, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let color: Hsla = match tool.status.as_str() {
            "completed" => theme.success,
            "failed" => theme.danger,
            "in_progress" => theme.warning,
            _ => theme.muted_foreground,
        };
        let mono = crate::ui::app::mono_family(cx);
        let output = tool
            .open
            .then(|| tool.output.clone())
            .flatten()
            .map(|output| {
                let lines: Vec<&str> = output.lines().collect();
                let mut shown = lines[..lines.len().min(OUTPUT_LINES)].join("\n");
                if lines.len() > OUTPUT_LINES {
                    shown.push_str(&format!("\n… ({})", lines.len() - OUTPUT_LINES));
                }
                div()
                    .id(("chat-tool-output", index))
                    .max_h(px(240.))
                    .overflow_y_scrollbar()
                    .p_2()
                    .rounded_sm()
                    .bg(theme.muted)
                    .font_family(mono.clone())
                    .text_xs()
                    .children(
                        shown
                            .lines()
                            .map(|line| div().child(SharedString::from(line.to_owned())))
                            .collect::<Vec<_>>(),
                    )
            });
        v_flex()
            .gap_1()
            .child(
                h_flex()
                    .id(("chat-tool", index))
                    .gap_2()
                    .items_center()
                    .cursor_pointer()
                    .child(div().size(px(7.)).flex_shrink_0().rounded_full().bg(color))
                    .child(
                        Label::new(SharedString::from(tool.title.clone()))
                            .text_xs()
                            .font_medium()
                            .flex_shrink_0(),
                    )
                    .children(tool.detail.clone().map(|detail| {
                        div()
                            .flex_1()
                            .min_w(px(0.))
                            .truncate()
                            .font_family(mono.clone())
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child(detail)
                    }))
                    .on_click(cx.listener(move |this, _, _window, cx| this.toggle(index, cx))),
            )
            .children(output)
            .into_any_element()
    }
}

/// `mcp__cratty__run_command` and `cratty_run_command` read better as `run_command`.
fn tool_title(title: &str) -> String {
    let prefixes = [
        format!("mcp__{}__", crate::mcp::SERVER_NAME),
        format!("{}_", crate::mcp::SERVER_NAME),
    ];
    for prefix in &prefixes {
        if let Some(rest) = title.strip_prefix(prefix.as_str()) {
            return rest.to_owned();
        }
    }
    title.to_owned()
}

/// The command or path of a tool call; nothing for empty arguments.
fn input_detail(input: &serde_json::Value) -> Option<String> {
    if input.as_object().is_some_and(|object| object.is_empty()) {
        return None;
    }
    let detail = acp::protocol::input_summary(input);
    Some(detail.lines().next().unwrap_or_default().to_owned())
}

impl ChatView {
    fn state_look(&self, cx: &Context<Self>) -> (SharedString, Hsla) {
        let theme = cx.theme();
        let (text, color) = match &self.state {
            State::Starting => (t!("chat.starting"), theme.warning),
            State::Loading => (t!("chat.loading"), theme.warning),
            State::Ready => (t!("chat.ready"), theme.success),
            State::Working => (t!("chat.working"), theme.warning),
            State::Closed(Some(_)) => (t!("chat.failed"), theme.danger),
            State::Closed(None) => (t!("chat.closed"), theme.muted_foreground),
        };
        (text.into(), color)
    }

    /// The title of the open chat: saved, about to be saved, or new.
    fn chat_title(&self) -> SharedString {
        let saved = self
            .session
            .as_ref()
            .filter(|_| self.saved)
            .and_then(|session| {
                acp::sessions::chats(&self.server, self.command.kind)
                    .into_iter()
                    .find(|chat| &chat.session == session)
            })
            .map(|chat| chat.title)
            .filter(|title| !title.is_empty());
        match saved.or_else(|| self.first_message.clone()) {
            Some(title) => title.into(),
            None => t!("chat.new_chat").into(),
        }
    }

    /// A button of the top row that opens a menu.
    fn menu_button(
        &self,
        id: &'static str,
        menu: Menu,
        content: impl IntoElement,
        cx: &mut Context<Self>,
    ) -> gpui_kit::Stateful<gpui_kit::Div> {
        let theme = cx.theme().clone();
        let enabled = self.can_switch();
        div()
            .id(id)
            .h(px(28.))
            .px_2()
            .gap_2()
            .flex()
            .items_center()
            .rounded_md()
            .when(self.menu == Some(menu), |this| this.bg(theme.secondary))
            .when(enabled, |this| {
                this.cursor_pointer()
                    .hover(|style| style.bg(theme.secondary_hover))
                    .on_click(cx.listener(move |this, _, _window, cx| this.toggle_menu(menu, cx)))
            })
            .when(!enabled, |this| this.opacity(0.6))
            .child(content)
            .child(
                Icon::empty()
                    .path("icons/chevron-down.svg")
                    .xsmall()
                    .text_color(theme.muted_foreground),
            )
    }

    fn top_row(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let (_, color) = self.state_look(cx);
        let agent = h_flex()
            .gap_2()
            .items_center()
            .child(div().size(px(7.)).flex_shrink_0().rounded_full().bg(color))
            .child(
                Label::new(self.command.kind.title())
                    .text_sm()
                    .font_medium(),
            );
        let chat = div()
            .min_w(px(0.))
            .truncate()
            .text_sm()
            .child(self.chat_title());
        h_flex()
            .h(px(TOP_ROW))
            .flex_shrink_0()
            .px_2()
            .gap_1()
            .items_center()
            .border_b_1()
            .border_color(theme.border)
            .child(
                self.menu_button("chat-agent", Menu::Agents, agent, cx)
                    .flex_shrink_0(),
            )
            .child(
                self.menu_button("chat-chats", Menu::Chats, chat, cx)
                    .flex_1()
                    .min_w(px(0.))
                    .justify_between(),
            )
            .into_any_element()
    }

    fn menu_row(
        id: impl Into<gpui_kit::ElementId>,
        cx: &Context<Self>,
    ) -> gpui_kit::Stateful<gpui_kit::Div> {
        let theme = cx.theme();
        div()
            .id(id)
            .min_h(px(30.))
            .px_2()
            .gap_2()
            .flex()
            .items_center()
            .rounded_md()
            .hover(|style| style.bg(theme.secondary_hover))
            .cursor_pointer()
    }

    fn agents_menu(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let rows: Vec<AnyElement> =
            self.agents
                .iter()
                .map(|(kind, found)| {
                    let kind = *kind;
                    let current = kind == self.command.kind;
                    match found {
                        Ok(_) => Self::menu_row(
                            SharedString::from(format!("chat-agent-{}", kind.id())),
                            cx,
                        )
                        .child(
                            div()
                                .w(px(12.))
                                .flex_shrink_0()
                                .text_color(theme.primary)
                                .child(if current { "✓" } else { "" }),
                        )
                        .child(Label::new(kind.title()).text_sm())
                        .on_click(
                            cx.listener(move |this, _, _window, cx| this.choose_agent(kind, cx)),
                        )
                        .into_any_element(),
                        Err(missing) => v_flex()
                            .px_2()
                            .py_1()
                            .pl(px(28.))
                            .child(
                                Label::new(kind.title())
                                    .text_sm()
                                    .text_color(theme.muted_foreground),
                            )
                            .child(
                                Label::new(SharedString::from(
                                    t!("chat.install", program = missing.install).to_string(),
                                ))
                                .text_xs()
                                .text_color(theme.muted_foreground),
                            )
                            .into_any_element(),
                    }
                })
                .collect();
        v_flex().children(rows).into_any_element()
    }

    fn chats_menu(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let chats = acp::sessions::chats(&self.server, self.command.kind);
        let current = self.session.clone().filter(|_| self.saved);
        let create = Self::menu_row("chat-create", cx)
            .child(
                div().w(px(12.)).flex_shrink_0().child(
                    Icon::empty()
                        .path("icons/plus.svg")
                        .xsmall()
                        .text_color(theme.primary),
                ),
            )
            .child(Label::new(t!("chat.create")).text_sm())
            .on_click(cx.listener(|this, _, _window, cx| {
                this.menu = None;
                this.open_chat(None, cx);
            }));
        let rows: Vec<AnyElement> = chats
            .into_iter()
            .enumerate()
            .map(|(number, chat)| {
                let open = chat.session.clone();
                let delete = chat.session.clone();
                let selected = current.as_deref() == Some(chat.session.as_str());
                let title = if chat.title.is_empty() {
                    t!("chat.untitled").to_string()
                } else {
                    chat.title
                };
                Self::menu_row(("chat-row", number), cx)
                    .child(
                        div()
                            .w(px(12.))
                            .flex_shrink_0()
                            .text_color(theme.primary)
                            .child(if selected { "✓" } else { "" }),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.))
                            .truncate()
                            .text_sm()
                            .child(title),
                    )
                    .child(
                        Button::new(("chat-delete", number))
                            .ghost()
                            .xsmall()
                            .icon(Icon::empty().path("icons/delete.svg"))
                            .tooltip(t!("chat.delete"))
                            .on_click(cx.listener(move |this, _, _window, cx| {
                                // Deleting is not choosing: the menu stays open.
                                cx.stop_propagation();
                                this.delete_chat(delete.clone(), cx);
                            })),
                    )
                    .on_click(cx.listener(move |this, _, _window, cx| {
                        this.menu = None;
                        this.open_chat(Some(open.clone()), cx);
                    }))
                    .into_any_element()
            })
            .collect();
        let empty = rows.is_empty();
        v_flex()
            .child(create)
            .child(div().my_1().h(px(1.)).bg(theme.border))
            .when(empty, |this| {
                this.child(
                    div().px_2().py_1().child(
                        Label::new(t!("chat.no_chats"))
                            .text_xs()
                            .text_color(theme.muted_foreground),
                    ),
                )
            })
            .children(rows)
            .into_any_element()
    }

    /// The open menu over the chat, and a cover that closes it on a click elsewhere.
    fn open_menu(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let menu = self.menu?;
        let theme = cx.theme().clone();
        let body = match menu {
            Menu::Agents => self.agents_menu(cx),
            Menu::Chats => self.chats_menu(cx),
        };
        Some(
            div()
                .absolute()
                .top_0()
                .left_0()
                .size_full()
                .child(
                    div()
                        .id("chat-menu-cover")
                        .absolute()
                        .top_0()
                        .left_0()
                        .size_full()
                        .occlude()
                        .on_click(cx.listener(|this, _, _window, cx| {
                            this.menu = None;
                            cx.notify();
                        })),
                )
                .child(
                    div()
                        .id("chat-menu")
                        .absolute()
                        .occlude()
                        .top(px(TOP_ROW + 2.))
                        .left(px(8.))
                        .right(px(8.))
                        .max_h(px(360.))
                        // Plain scrolling: the scrollbar wrapper would stretch the box to
                        // its full height.
                        .overflow_y_scroll()
                        .p_1()
                        .rounded_lg()
                        .border_1()
                        .border_color(theme.border)
                        .bg(theme.popover)
                        .shadow_lg()
                        .child(body),
                )
                .into_any_element(),
        )
    }
}

impl Render for ChatView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let input = self.ensure_input(window, cx);
        if std::mem::take(&mut self.focus_pending) {
            window.focus(&input.focus_handle(cx), cx);
        }
        let theme = cx.theme().clone();
        let working = self.state == State::Working;
        let closed = matches!(self.state, State::Closed(_));
        let (status, _) = self.state_look(cx);

        let entries: Vec<AnyElement> = self
            .entries
            .iter()
            .enumerate()
            .map(|(index, entry)| self.render_entry(index, entry, cx))
            .collect();
        let empty = entries.is_empty();

        // Shown whenever the agent asked for a sign-in: at start, or at the first prompt.
        let login = (!self.login.is_empty()).then(|| {
            v_flex()
                .gap_2()
                .p_2()
                .rounded_md()
                .border_1()
                .border_color(theme.warning)
                .child(
                    Label::new(SharedString::from(
                        t!("chat.login_title", agent = self.command.kind.title()).to_string(),
                    ))
                    .text_sm(),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .child(SharedString::from(t!("chat.login_hint").to_string())),
                )
                .children(self.login.iter().enumerate().map(|(number, method)| {
                    let program = self.command.program_with(&method.args);
                    let agent = self.command.kind.title();
                    v_flex()
                        .gap_1()
                        .child(
                            h_flex().child(
                                Button::new(("chat-login", number))
                                    .outline()
                                    .xsmall()
                                    .label(method.name.clone())
                                    .on_click(cx.listener(move |_, _, _window, cx| {
                                        cx.emit(ChatEvent::Login {
                                            agent,
                                            program: program.clone(),
                                        })
                                    })),
                            ),
                        )
                        .children(method.description.clone().map(|description| {
                            Label::new(description)
                                .text_xs()
                                .text_color(theme.muted_foreground)
                        }))
                }))
                .child(
                    h_flex().child(
                        Button::new("chat-login-done")
                            .primary()
                            .xsmall()
                            .label(t!("chat.login_done"))
                            .on_click(cx.listener(|this, _, _window, cx| this.restart(cx))),
                    ),
                )
        });
        let failure = match &self.state {
            State::Closed(Some(_)) if login.is_some() => None,
            State::Closed(Some(error)) => Some(
                v_flex()
                    .gap_2()
                    .p_2()
                    .rounded_md()
                    .border_1()
                    .border_color(theme.danger)
                    .child(
                        div()
                            .max_h(px(200.))
                            .overflow_hidden()
                            .text_xs()
                            .text_color(theme.danger)
                            .child(error.clone()),
                    )
                    .child(
                        h_flex().child(
                            Button::new("chat-start-again")
                                .outline()
                                .xsmall()
                                .label(t!("chat.start_again"))
                                .on_click(cx.listener(|this, _, _window, cx| this.restart(cx))),
                        ),
                    ),
            ),
            _ => None,
        };
        let placeholder = match self.state {
            State::Starting | State::Loading if empty => Some(status),
            State::Ready if empty => Some(t!("chat.intro").into()),
            _ => None,
        };

        let body = div()
            .id("chat-body")
            .flex_1()
            .min_h(px(0.))
            .overflow_y_scroll()
            .track_scroll(&self.scroll)
            .child(
                v_flex()
                    .px_4()
                    .py_3()
                    .gap_3()
                    .children(placeholder.map(|text| {
                        Label::new(text)
                            .text_xs()
                            .text_color(theme.muted_foreground)
                    }))
                    .children(entries)
                    .children(login)
                    .children(failure),
            );

        let action = if working {
            Button::new("chat-stop")
                .outline()
                .small()
                .label(t!("chat.stop"))
                .on_click(cx.listener(|this, _, _window, cx| this.stop(cx)))
        } else {
            Button::new("chat-send")
                .primary()
                .small()
                .label(t!("chat.send"))
                .disabled(self.state != State::Ready)
                .on_click(cx.listener(|this, _, window, cx| this.send(window, cx)))
        };

        let composer = v_flex()
            .flex_shrink_0()
            .p_3()
            .gap_2()
            .border_t_1()
            .border_color(theme.border)
            .child(Textarea::new(&input).h(px(72.)).disabled(closed))
            .child(
                h_flex()
                    .gap_2()
                    .items_center()
                    // The hint wraps in a narrow panel; the button keeps its size.
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.))
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child(SharedString::from(t!("chat.hint").to_string())),
                    )
                    .child(div().flex_shrink_0().child(action)),
            );

        let top = self.top_row(cx);
        let menu = self.open_menu(cx);
        v_flex()
            .relative()
            .size_full()
            .child(top)
            .child(body)
            .child(composer)
            .children(menu)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cratty_tools_lose_their_prefix() {
        assert_eq!(tool_title("mcp__cratty__run_command"), "run_command");
        assert_eq!(tool_title("cratty_read_file"), "read_file");
        assert_eq!(tool_title("Bash"), "Bash");
    }

    #[test]
    fn detail_is_the_first_line_of_the_command() {
        assert_eq!(
            input_detail(&serde_json::json!({"command": "df -h\necho done"})),
            Some("df -h".into())
        );
        assert_eq!(input_detail(&serde_json::json!({})), None);
    }
}
