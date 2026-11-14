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
    ActiveTheme, Disableable, Icon, IconName, Sizable, StyledExt,
    button::{Button, ButtonVariants},
    clipboard::Clipboard,
    h_flex,
    input::{Input, InputEvent, InputState, Textarea, TextareaState},
    label::Label,
    spinner::Spinner,
    switch::Switch,
    text::{TextView, TextViewStyle},
    v_flex,
};
use gpui_kit::{
    AnyElement, App, Context, ElementId, Entity, EventEmitter, Focusable, Hsla, IntoElement,
    Render, ScrollHandle, SharedString, StyleRefinement, Subscription, Task, WeakEntity, Window,
    div, prelude::*, px, relative,
};
use rust_i18n::t;

use crate::acp::agents::Missing;
use crate::acp::{
    self, AgentCommand, AgentKind, ConfigChoice, ConfigOption, FromAgent, LoginMethod,
    PermissionAsk, PlanEntry, Setup, ToAgent, Update,
};
use crate::ssh::LocalProgram;

/// A setting with more values than this gets a search box in its menu.
const SEARCH_FROM: usize = 8;
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
    /// The values of the session setting at this index.
    Setting(usize),
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
    /// The tool's arguments, as the agent last reported them.
    input: Option<serde_json::Value>,
    status: String,
    output: Option<String>,
    open: bool,
}

pub enum ChatEvent {
    /// The user asked to run commands and change files on this tab without approval, or
    /// to be asked again.
    Trust(bool),
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
    /// The session's settings the agent offers: model, reasoning level, mode…
    config: Vec<ConfigOption>,
    /// Made with the window on first render.
    input: Option<Entity<TextareaState>>,
    /// The search box of a long setting menu, made with the window when first needed.
    filter: Option<Entity<InputState>>,
    _filter_events: Option<Subscription>,
    /// The sign-ins are being copied from the user's OpenCode.
    syncing: bool,
    _sync: Option<Task<()>>,
    /// A new chat has not had the default model applied yet.
    apply_default: bool,
    /// Commands and file changes on this tab run without approval.
    trusted: bool,
    /// The id of the user message a replay is bringing back.
    user_message: Option<String>,
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
            config: Vec::new(),
            input: None,
            filter: None,
            _filter_events: None,
            syncing: false,
            _sync: None,
            apply_default: false,
            trusted: false,
            user_message: None,
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
        self.user_message = None;
        self.session = None;
        self.saved = false;
        self.first_message = None;
        self.login.clear();
        self.config.clear();
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
            self.user_message = None;
            self.session = None;
            self.saved = false;
            self.first_message = None;
            self.config.clear();
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

    /// Asks the agent for another value of a setting; the answer brings the new state.
    fn set_setting(&mut self, index: usize, value: String, cx: &mut Context<Self>) {
        self.menu = None;
        let Some(option) = self.config.get_mut(index) else {
            return;
        };
        if option.current == value {
            cx.notify();
            return;
        }
        if let Some(commands) = &self.commands {
            let _ = commands.unbounded_send(ToAgent::SetConfig {
                id: option.id.clone(),
                value: value.clone(),
            });
            // Shown at once; the agent's answer corrects it if it refused.
            if option.category.as_deref() == Some("model") {
                acp::sessions::set_default_model(self.command.kind, &value);
            }
            option.current = value;
        }
        cx.notify();
    }

    /// Starts a new chat with the model the user picked last. Chats already open keep
    /// theirs: nothing is sent to them.
    fn apply_default_model(&mut self) {
        if !std::mem::take(&mut self.apply_default) {
            return;
        }
        let Some(wanted) = acp::sessions::default_model(self.command.kind) else {
            return;
        };
        let Some(option) = self
            .config
            .iter_mut()
            .find(|option| option.category.as_deref() == Some("model"))
        else {
            return;
        };
        if option.current == wanted || !option.choices.iter().any(|choice| choice.value == wanted) {
            return;
        }
        if let Some(commands) = &self.commands {
            let _ = commands.unbounded_send(ToAgent::SetConfig {
                id: option.id.clone(),
                value: wanted.clone(),
            });
            option.current = wanted;
        }
    }

    /// Settings can change while the agent answers, but not while a chat loads.
    fn can_configure(&self) -> bool {
        matches!(self.state, State::Ready | State::Working)
    }

    fn toggle_menu(&mut self, menu: Menu, window: &mut Window, cx: &mut Context<Self>) {
        self.menu = if self.menu == Some(menu) {
            None
        } else {
            Some(menu)
        };
        // A long list opens with an empty search box that has the keyboard.
        if let (Some(Menu::Setting(index)), Some(filter)) =
            (self.menu, self.ensure_filter(window, cx))
            && self
                .config
                .get(index)
                .is_some_and(|option| option.choices.len() > SEARCH_FROM)
        {
            filter.update(cx, |filter, cx| filter.set_value("", window, cx));
            window.focus(&filter.focus_handle(cx), cx);
        }
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
                // Only a new chat takes the default model; a saved one keeps its own.
                self.apply_default = !resumed;
            }
            FromAgent::LoginRequired(methods) => self.login = methods,
            FromAgent::Config(options) => {
                self.config = options;
                self.apply_default_model();
            }
            FromAgent::Notice(text) => self.entries.push(Entry::Notice {
                text: text.into(),
                error: true,
            }),
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
            Update::UserText {
                text: chunk,
                message,
            } if self.state == State::Loading => {
                // Pieces of one message come in a row; another id starts the next one, even
                // right after it, as when an answer failed in between.
                let same = message.is_none() || message == self.user_message;
                match self.entries.last_mut() {
                    Some(Entry::User(text)) if same => *text = format!("{text}{chunk}").into(),
                    _ => self.entries.push(Entry::User(chunk.into())),
                }
                self.user_message = message;
            }
            Update::UserText { .. } => {}
            Update::Config(options) => self.config = options,
            Update::ToolCall(call) => self.entries.push(Entry::Tool(ToolEntry {
                id: call.id,
                title: tool_title(&call.title),
                input: call.input.filter(has_arguments),
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
                if let Some(input) = update.input.filter(has_arguments) {
                    tool.input = Some(input);
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

    /// Follows the tab's approval setting, which the approval dialog changes too.
    pub fn set_trusted(&mut self, trusted: bool, cx: &mut Context<Self>) {
        if self.trusted != trusted {
            self.trusted = trusted;
            cx.notify();
        }
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
            Entry::User(text) => h_flex()
                .justify_end()
                .child(
                    div()
                        .max_w(relative(0.88))
                        .px_3()
                        .py_2()
                        .rounded_lg()
                        .bg(theme.secondary)
                        .text_sm()
                        .child(text.clone()),
                )
                .into_any_element(),
            Entry::Agent(text) => {
                // The copy button of the whole answer shows under it on hover.
                let group = SharedString::from(format!("chat-answer-{index}"));
                v_flex()
                    .group(group.clone())
                    .gap_1()
                    .child(markdown_view(("chat-text", index), text))
                    .child(
                        h_flex()
                            .opacity(0.)
                            .group_hover(group, |style| style.opacity(1.))
                            .child(copy_button(("chat-copy-text", index), text.clone())),
                    )
                    .into_any_element()
            }
            Entry::Thought { text, open } => {
                let live = self.state == State::Working && index + 1 == self.entries.len();
                let label = if live {
                    t!("chat.thinking_now")
                } else {
                    t!("chat.thoughts")
                };
                let foreground = theme.foreground;
                v_flex()
                    .gap_1()
                    .child(
                        h_flex()
                            .id(("chat-thought", index))
                            .gap_1()
                            .items_center()
                            .cursor_pointer()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .hover(move |style| style.text_color(foreground))
                            .child(chevron(*open))
                            .child(SharedString::from(label.to_string()))
                            .when(live, |this| {
                                this.child(Spinner::new().xsmall().color(theme.muted_foreground))
                            })
                            .on_click(
                                cx.listener(move |this, _, _window, cx| this.toggle(index, cx)),
                            ),
                    )
                    .when(*open, |this| {
                        this.child(
                            div()
                                .ml(px(6.))
                                .pl_3()
                                .border_l_2()
                                .border_color(theme.border)
                                .text_xs()
                                .text_color(theme.muted_foreground)
                                .child(
                                    TextView::markdown(
                                        ("chat-thought-text", index),
                                        SharedString::from(text.trim().to_owned()),
                                    )
                                    .selectable(true),
                                ),
                        )
                    })
                    .into_any_element()
            }
            Entry::Tool(tool) => self.render_tool(index, tool, cx),
            Entry::Plan(plan) => {
                let done = plan
                    .iter()
                    .filter(|entry| entry.status == "completed")
                    .count();
                v_flex()
                    .gap_1()
                    .p_2()
                    .rounded_md()
                    .border_1()
                    .border_color(theme.border)
                    .child(
                        h_flex()
                            .justify_between()
                            .items_center()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child(Label::new(t!("chat.plan")).text_xs().font_medium())
                            .child(SharedString::from(format!("{done}/{}", plan.len()))),
                    )
                    .children(plan.iter().map(|entry| {
                        let completed = entry.status == "completed";
                        let mark: AnyElement = match entry.status.as_str() {
                            "completed" => Icon::new(IconName::CircleCheck)
                                .xsmall()
                                .text_color(theme.success)
                                .into_any_element(),
                            "in_progress" => Spinner::new()
                                .xsmall()
                                .color(theme.warning)
                                .into_any_element(),
                            _ => div()
                                .size(px(9.))
                                .rounded_full()
                                .border_1()
                                .border_color(theme.muted_foreground)
                                .into_any_element(),
                        };
                        h_flex()
                            .gap_2()
                            .items_start()
                            .text_xs()
                            .child(
                                div()
                                    .w(px(14.))
                                    .h(px(16.))
                                    .flex_shrink_0()
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .child(mark),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .min_w(px(0.))
                                    .when(completed, |this| {
                                        this.line_through().text_color(theme.muted_foreground)
                                    })
                                    .child(entry.content.clone()),
                            )
                    }))
                    .into_any_element()
            }
            Entry::Permission { ask, answer, .. } => {
                let mut card = v_flex()
                    .gap_2()
                    .p_2()
                    .rounded_md()
                    .border_1()
                    .border_color(theme.warning)
                    .child(
                        h_flex()
                            .gap_2()
                            .items_center()
                            .child(
                                Icon::new(IconName::TriangleAlert)
                                    .xsmall()
                                    .text_color(theme.warning),
                            )
                            .child(
                                Label::new(SharedString::from(
                                    t!("chat.permission", tool = ask.title).to_string(),
                                ))
                                .text_sm(),
                            ),
                    )
                    .children(ask.detail.as_deref().map(|detail| {
                        code_section(
                            ("chat-permission", index),
                            t!("chat.arguments"),
                            "",
                            detail,
                            cx,
                        )
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
            Entry::Notice { text, error } => h_flex()
                .gap_2()
                .items_start()
                .text_xs()
                .text_color(if *error {
                    theme.danger
                } else {
                    theme.muted_foreground
                })
                .child(
                    div().pt(px(1.)).flex_shrink_0().child(
                        Icon::new(if *error {
                            IconName::TriangleAlert
                        } else {
                            IconName::Info
                        })
                        .xsmall(),
                    ),
                )
                .child(div().flex_1().min_w(px(0.)).child(text.clone()))
                .into_any_element(),
        }
    }

    /// A tool call as a card: a row with what it does and how it went, and, opened by a
    /// click, its command or file, and what it returned.
    fn render_tool(&self, index: usize, tool: &ToolEntry, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let mono = crate::ui::app::mono_family(cx);
        let kind = ToolKind::of(&tool.title);
        let parsed = match kind {
            ToolKind::Run => tool.output.as_deref().and_then(CommandOutput::parse),
            _ => None,
        };
        let status: AnyElement = match tool.status.as_str() {
            "pending" | "in_progress" => Spinner::new()
                .xsmall()
                .color(theme.muted_foreground)
                .into_any_element(),
            "completed" => Icon::new(IconName::CircleCheck)
                .xsmall()
                .text_color(theme.success)
                .into_any_element(),
            "failed" => Icon::new(IconName::CircleX)
                .xsmall()
                .text_color(theme.danger)
                .into_any_element(),
            _ => Icon::new(IconName::Ban)
                .xsmall()
                .text_color(theme.muted_foreground)
                .into_any_element(),
        };
        let badge = parsed
            .as_ref()
            .and_then(|output| output.badge.clone())
            .map(|(text, ok)| {
                let color = match ok {
                    Some(true) => theme.success,
                    Some(false) => theme.danger,
                    None => theme.muted_foreground,
                };
                div()
                    .flex_shrink_0()
                    .px_1()
                    .rounded_sm()
                    .bg(color.opacity(0.12))
                    .text_color(color)
                    .font_family(mono.clone())
                    .text_xs()
                    .child(text)
            });
        let summary = tool.input.as_ref().and_then(input_detail);
        let hover = theme.secondary_hover;
        let header = h_flex()
            .id(("chat-tool", index))
            .px_2()
            .py(px(6.))
            .gap_2()
            .items_center()
            .cursor_pointer()
            .hover(move |style| style.bg(hover))
            .child(
                kind.icon()
                    .xsmall()
                    .flex_shrink_0()
                    .text_color(theme.muted_foreground),
            )
            .child(
                Label::new(kind.label(&tool.title))
                    .text_xs()
                    .font_medium()
                    .flex_shrink_0(),
            )
            .child(
                div()
                    .flex_1()
                    .min_w(px(0.))
                    .truncate()
                    .font_family(mono)
                    .text_xs()
                    .text_color(theme.muted_foreground)
                    .children(summary),
            )
            .children(badge)
            .child(div().flex_shrink_0().child(status))
            .child(
                div()
                    .flex_shrink_0()
                    .text_color(theme.muted_foreground)
                    .child(chevron(tool.open)),
            )
            .on_click(cx.listener(move |this, _, _window, cx| this.toggle(index, cx)));
        let body = tool
            .open
            .then(|| self.tool_body(index, kind, tool, parsed, cx));
        v_flex()
            .rounded_md()
            .border_1()
            .border_color(theme.border)
            .overflow_hidden()
            .child(header)
            .children(body)
            .into_any_element()
    }

    fn tool_body(
        &self,
        index: usize,
        kind: ToolKind,
        tool: &ToolEntry,
        parsed: Option<CommandOutput>,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = cx.theme().clone();
        let argument = |key: &str| {
            tool.input
                .as_ref()
                .and_then(|input| input.get(key))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        };
        let path = argument("path").unwrap_or_default();
        let file_name = path.rsplit('/').next().unwrap_or_default();
        let language = crate::ui::editor::language_of(file_name);
        let note = |text: SharedString, cx: &Context<Self>| {
            div()
                .text_xs()
                .text_color(cx.theme().muted_foreground)
                .child(text)
                .into_any_element()
        };

        let mut sections: Vec<AnyElement> = Vec::new();
        match kind {
            ToolKind::Run => {
                if let Some(command) = argument("command") {
                    sections.push(code_section(
                        ("chat-tool-command", index),
                        t!("chat.command"),
                        "bash",
                        &command,
                        cx,
                    ));
                }
                if let Some(cwd) = argument("cwd") {
                    sections.push(note(t!("ai.in_folder", path = cwd).into(), cx));
                }
            }
            ToolKind::Write => {
                if let Some(content) = argument("content") {
                    sections.push(code_section(
                        ("chat-tool-content", index),
                        t!("chat.content"),
                        &language,
                        &content,
                        cx,
                    ));
                }
            }
            ToolKind::Edit => {
                if let (Some(old), Some(new)) = (argument("old_text"), argument("new_text")) {
                    sections.push(diff_section(
                        ("chat-tool-diff", index),
                        t!("chat.changes"),
                        &old,
                        &new,
                        cx,
                    ));
                }
            }
            ToolKind::Other => {
                if let Some(input) = tool
                    .input
                    .as_ref()
                    .and_then(|input| serde_json::to_string_pretty(input).ok())
                {
                    sections.push(code_section(
                        ("chat-tool-input", index),
                        t!("chat.arguments"),
                        "json",
                        &input,
                        cx,
                    ));
                }
            }
            ToolKind::Read | ToolKind::List | ToolKind::Screen => {}
        }

        match (parsed, tool.output.as_deref()) {
            (Some(parsed), _) => {
                if let Some(stdout) = &parsed.stdout {
                    sections.push(code_section(
                        ("chat-tool-stdout", index),
                        t!("chat.output"),
                        "",
                        stdout,
                        cx,
                    ));
                }
                if let Some(stderr) = &parsed.stderr {
                    sections.push(code_section(
                        ("chat-tool-stderr", index),
                        "stderr",
                        "",
                        stderr,
                        cx,
                    ));
                }
                if parsed.stdout.is_none() && parsed.stderr.is_none() {
                    sections.push(note(t!("chat.no_output").into(), cx));
                }
            }
            // A write or an edit answers with one line: no block for it.
            (None, Some(output)) if matches!(kind, ToolKind::Write | ToolKind::Edit) => {
                let color = if tool.status == "failed" {
                    theme.danger
                } else {
                    theme.muted_foreground
                };
                sections.push(
                    div()
                        .text_xs()
                        .text_color(color)
                        .child(SharedString::from(output.to_owned()))
                        .into_any_element(),
                );
            }
            (None, Some(output)) => {
                let (title, language) = match kind {
                    ToolKind::Read => (t!("chat.content"), language.as_str()),
                    ToolKind::List => (t!("chat.content"), ""),
                    ToolKind::Screen => (t!("chat.screen"), ""),
                    _ => (t!("chat.result"), ""),
                };
                sections.push(code_section(
                    ("chat-tool-output", index),
                    title,
                    language,
                    output,
                    cx,
                ));
            }
            (None, None) => {}
        }

        v_flex()
            .p_2()
            .gap_2()
            .border_t_1()
            .border_color(theme.border)
            .children(sections)
            .into_any_element()
    }
}

/// What a tool call does, for its icon and its name in the chat.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ToolKind {
    Run,
    Read,
    List,
    Write,
    Edit,
    Screen,
    /// A tool of the agent's own, or one Cratty does not know.
    Other,
}

impl ToolKind {
    fn of(title: &str) -> Self {
        match title {
            "run_command" => Self::Run,
            "read_file" => Self::Read,
            "list_directory" => Self::List,
            "write_file" => Self::Write,
            "edit_file" => Self::Edit,
            "read_terminal" => Self::Screen,
            _ => Self::Other,
        }
    }

    fn icon(self) -> Icon {
        match self {
            Self::Run => Icon::new(IconName::SquareTerminal),
            Self::Read => Icon::new(IconName::FileText),
            Self::List => Icon::new(IconName::Folder),
            Self::Write => Icon::new(IconName::File),
            Self::Edit => Icon::empty().path("icons/pencil.svg"),
            Self::Screen => Icon::empty().path("icons/monitor.svg"),
            Self::Other => Icon::new(IconName::Bot),
        }
    }

    fn label(self, title: &str) -> SharedString {
        match self {
            Self::Run => t!("chat.tool_run").into(),
            Self::Read => t!("chat.tool_read").into(),
            Self::List => t!("chat.tool_list").into(),
            Self::Write => t!("chat.tool_write").into(),
            Self::Edit => t!("chat.tool_edit").into(),
            Self::Screen => t!("chat.tool_screen").into(),
            Self::Other => SharedString::from(title.to_owned()),
        }
    }
}

/// What `run_command` answers (see `crate::mcp::tools`), split for the chat.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CommandOutput {
    /// How the command ended, and whether that is a success; `None` when unknown.
    badge: Option<(String, Option<bool>)>,
    stdout: Option<String>,
    stderr: Option<String>,
}

impl CommandOutput {
    /// `None` for any other text, such as the error of a denied command.
    fn parse(text: &str) -> Option<Self> {
        let (first, rest) = text.split_once('\n').unwrap_or((text, ""));
        let badge = if let Some(code) = first.strip_prefix("exit code: ") {
            Some((format!("exit {}", code.trim()), Some(code.trim() == "0")))
        } else if first.starts_with("timed out") {
            Some(("timeout".to_owned(), Some(false)))
        } else if let Some(signal) = first.strip_prefix("killed by signal ") {
            let name = signal.split(':').next().unwrap_or(signal).trim();
            Some((format!("signal {name}"), Some(false)))
        } else if first.starts_with("the server did not report") {
            None
        } else {
            return None;
        };
        let (stdout, stderr) = match rest.strip_prefix("--- stdout ---\n") {
            Some(after) => match after.split_once("\n--- stderr ---\n") {
                Some((out, err)) => (Some(out), Some(err)),
                None => (Some(after), None),
            },
            None => (None, rest.strip_prefix("--- stderr ---\n")),
        };
        Some(Self {
            badge,
            stdout: stdout.map(str::to_owned),
            stderr: stderr.map(str::to_owned),
        })
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

fn has_arguments(input: &serde_json::Value) -> bool {
    !input.is_null() && !input.as_object().is_some_and(|object| object.is_empty())
}

fn chevron(open: bool) -> Icon {
    Icon::new(if open {
        IconName::ChevronDown
    } else {
        IconName::ChevronRight
    })
    .xsmall()
}

fn copy_button(id: impl Into<ElementId>, text: impl Into<SharedString>) -> Clipboard {
    Clipboard::new(id).value(text).tooltip(t!("chat.copy"))
}

/// An answer of the agent: Markdown, with code highlighted and a copy button on each
/// code block, next to its language.
fn markdown_view(id: impl Into<ElementId>, text: &str) -> TextView {
    TextView::markdown(id, SharedString::from(text.to_owned()))
        .selectable(true)
        .text_sm()
        .style(
            TextViewStyle::default().code_block(
                // The top keeps the first line clear of the language and the button.
                StyleRefinement::default()
                    .pt(px(30.))
                    .pb(px(10.))
                    .px(px(12.))
                    .text_size(px(12.)),
            ),
        )
        .code_block_actions(|block, _window, cx| {
            let muted = cx.theme().muted_foreground;
            h_flex()
                .gap_1()
                .items_center()
                .children(
                    block
                        .lang()
                        .filter(|lang| !lang.is_empty())
                        .map(|lang| div().px_1().text_xs().text_color(muted).child(lang)),
                )
                .child(copy_button("copy", block.code()))
        })
}

/// Text in a highlighted block, under a title with a copy button. A long text shows its
/// beginning; the button still copies all of it.
fn code_section(
    id: (&'static str, usize),
    title: impl Into<SharedString>,
    language: &str,
    text: &str,
    cx: &App,
) -> AnyElement {
    let theme = cx.theme();
    let (name, number) = id;
    let (shown, hidden) = clip(text);
    let code = TextView::markdown(
        SharedString::from(format!("{name}-{number}")),
        SharedString::from(fenced(language, &shown)),
    )
    .selectable(true)
    .style(
        TextViewStyle::default().code_block(
            StyleRefinement::default()
                .px(px(10.))
                .py(px(8.))
                .text_size(px(12.)),
        ),
    )
    // Something in the corner takes the language label's place: the title copies.
    .code_block_actions(|_, _, _| div());
    v_flex()
        .gap_1()
        .child(
            h_flex()
                .h(px(20.))
                .items_center()
                .justify_between()
                .child(
                    Label::new(title.into())
                        .text_xs()
                        .text_color(theme.muted_foreground),
                )
                .child(copy_button(
                    SharedString::from(format!("{name}-{number}-copy")),
                    text.to_owned(),
                )),
        )
        .child(
            div()
                .id(SharedString::from(format!("{name}-{number}-scroll")))
                .max_h(px(320.))
                .overflow_y_scroll()
                .child(code),
        )
        .when(hidden > 0, |this| {
            this.child(
                Label::new(SharedString::from(
                    t!("ai.more_lines", count = hidden).to_string(),
                ))
                .text_xs()
                .text_color(theme.muted_foreground),
            )
        })
        .into_any_element()
}

/// An edit: the old lines on red, the new ones on green, under a title with a button
/// that copies it as a diff.
fn diff_section(
    id: (&'static str, usize),
    title: impl Into<SharedString>,
    old: &str,
    new: &str,
    cx: &App,
) -> AnyElement {
    let theme = cx.theme();
    let mono = crate::ui::app::mono_family(cx);
    let (name, number) = id;
    let (old_shown, old_hidden) = clip(old);
    let (new_shown, new_hidden) = clip(new);
    let line = |sign: &'static str, text: &str, color: Hsla| {
        h_flex()
            .items_start()
            .px_2()
            .bg(color.opacity(0.12))
            .child(
                div()
                    .w(px(14.))
                    .flex_shrink_0()
                    .text_color(color)
                    .child(sign),
            )
            .child(
                div()
                    .flex_1()
                    .min_w(px(0.))
                    .child(SharedString::from(text.to_owned())),
            )
    };
    let lines: Vec<_> = old_shown
        .lines()
        .map(|text| line("-", text, theme.danger))
        .chain(new_shown.lines().map(|text| line("+", text, theme.success)))
        .collect();
    v_flex()
        .gap_1()
        .child(
            h_flex()
                .h(px(20.))
                .items_center()
                .justify_between()
                .child(
                    Label::new(title.into())
                        .text_xs()
                        .text_color(theme.muted_foreground),
                )
                .child(copy_button(
                    SharedString::from(format!("{name}-{number}-copy")),
                    diff_text(old, new),
                )),
        )
        .child(
            v_flex()
                .id(SharedString::from(format!("{name}-{number}-scroll")))
                .max_h(px(320.))
                .overflow_y_scroll()
                .py_1()
                .rounded_md()
                .border_1()
                .border_color(theme.border)
                .bg(theme.muted)
                .font_family(mono)
                .text_size(px(12.))
                .line_height(relative(1.5))
                .children(lines),
        )
        .when(old_hidden + new_hidden > 0, |this| {
            this.child(
                Label::new(SharedString::from(
                    t!("ai.more_lines", count = old_hidden + new_hidden).to_string(),
                ))
                .text_xs()
                .text_color(theme.muted_foreground),
            )
        })
        .into_any_element()
}

/// A fenced block that holds any text: its fence is longer than any run of backticks in it.
fn fenced(language: &str, text: &str) -> String {
    let longest = text
        .split(|c: char| c != '`')
        .map(str::len)
        .max()
        .unwrap_or(0);
    let fence = "`".repeat(longest.max(2) + 1);
    format!(
        "{fence}{language}\n{}\n{fence}",
        text.trim_end_matches('\n')
    )
}

/// The beginning of a long text and how many lines were left out.
fn clip(text: &str) -> (String, usize) {
    const LINES: usize = 400;
    const CHARS: usize = 40_000;
    let total = text.lines().count();
    let mut shown = String::new();
    let mut lines = 0;
    for line in text.lines() {
        if lines == LINES || shown.len() + line.len() > CHARS {
            break;
        }
        shown.push_str(line);
        shown.push('\n');
        lines += 1;
    }
    if lines == 0 && !text.is_empty() {
        // One huge line: its beginning.
        let mut cut = CHARS.min(text.len());
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        return (format!("{}…", &text[..cut]), total.saturating_sub(1));
    }
    (shown.trim_end_matches('\n').to_owned(), total - lines)
}

/// An edit as a diff: the old lines taken out, the new ones put in.
fn diff_text(old: &str, new: &str) -> String {
    old.lines()
        .map(|line| format!("-{line}"))
        .chain(new.lines().map(|line| format!("+{line}")))
        .collect::<Vec<_>>()
        .join("\n")
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
                    .on_click(
                        cx.listener(move |this, _, window, cx| this.toggle_menu(menu, window, cx)),
                    )
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

    /// The row of settings under the top row: a button per setting with its value.
    fn settings_row(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        if self.config.is_empty() {
            return None;
        }
        let theme = cx.theme().clone();
        let enabled = self.can_configure();
        let buttons: Vec<AnyElement> = self
            .config
            .iter()
            .enumerate()
            .map(|(index, option)| {
                let value = option
                    .choices
                    .iter()
                    .find(|choice| choice.value == option.current)
                    .map(|choice| choice.name.clone())
                    .unwrap_or_else(|| option.current.clone());
                let menu = Menu::Setting(index);
                div()
                    .id(("chat-setting", index))
                    .h(px(24.))
                    .px_2()
                    .gap_1()
                    .flex()
                    .items_center()
                    .rounded_md()
                    .border_1()
                    .border_color(theme.border)
                    .text_xs()
                    .when(self.menu == Some(menu), |this| this.bg(theme.secondary))
                    .when(enabled, |this| {
                        this.cursor_pointer()
                            .hover(|style| style.bg(theme.secondary_hover))
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.toggle_menu(menu, window, cx)
                            }))
                    })
                    .when(!enabled, |this| this.opacity(0.6))
                    .child(
                        div()
                            .text_color(theme.muted_foreground)
                            .child(SharedString::from(option.name.clone())),
                    )
                    .child(div().child(SharedString::from(value)))
                    .into_any_element()
            })
            .collect();
        Some(
            h_flex()
                .flex_shrink_0()
                .flex_wrap()
                .px_2()
                .py_1()
                .gap_1()
                .border_b_1()
                .border_color(theme.border)
                .children(buttons)
                .into_any_element(),
        )
    }

    fn ensure_filter(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Option<Entity<InputState>> {
        if self.filter.is_none() {
            let filter = cx.new(|cx| InputState::new(window, cx).placeholder(t!("chat.search")));
            self._filter_events = Some(cx.subscribe(&filter, |_, _, event: &InputEvent, cx| {
                if matches!(event, InputEvent::Change) {
                    cx.notify();
                }
            }));
            self.filter = Some(filter);
        }
        self.filter.clone()
    }

    /// Values of a setting that match the search words, in any case, in the name,
    /// the description or the value itself.
    fn matching(option: &ConfigOption, query: &str) -> Vec<(usize, ConfigChoice)> {
        let words: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
        option
            .choices
            .iter()
            .enumerate()
            .filter(|(_, choice)| {
                let text = format!(
                    "{} {} {}",
                    choice.name,
                    choice.description.as_deref().unwrap_or_default(),
                    choice.value
                )
                .to_lowercase();
                words.iter().all(|word| text.contains(word))
            })
            .map(|(number, choice)| (number, choice.clone()))
            .collect()
    }

    fn setting_menu(&self, index: usize, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let Some(option) = self.config.get(index) else {
            return div().into_any_element();
        };
        let query = self
            .filter
            .as_ref()
            .filter(|_| option.choices.len() > SEARCH_FROM)
            .map(|filter| filter.read(cx).value().to_string())
            .unwrap_or_default();
        let shown = Self::matching(option, &query);
        let nothing = shown.is_empty();
        let rows: Vec<AnyElement> = shown
            .iter()
            .map(|(number, choice)| {
                let number = *number;
                let selected = choice.value == option.current;
                let value = choice.value.clone();
                Self::menu_row(("chat-choice", number), cx)
                    .child(
                        div()
                            .w(px(12.))
                            .flex_shrink_0()
                            .text_color(theme.primary)
                            .child(if selected { "✓" } else { "" }),
                    )
                    .child(
                        v_flex()
                            .flex_1()
                            .min_w(px(0.))
                            .child(
                                div()
                                    .text_sm()
                                    .child(SharedString::from(choice.name.clone())),
                            )
                            .children(choice.description.clone().map(|text| {
                                div()
                                    .text_xs()
                                    .text_color(theme.muted_foreground)
                                    .child(SharedString::from(text))
                            })),
                    )
                    .on_click(cx.listener(move |this, _, _window, cx| {
                        this.set_setting(index, value.clone(), cx)
                    }))
                    .into_any_element()
            })
            .collect();
        v_flex()
            .children(rows)
            .when(nothing, |this| {
                this.child(
                    div().px_2().py_1().child(
                        Label::new(t!("chat.nothing_found"))
                            .text_xs()
                            .text_color(theme.muted_foreground),
                    ),
                )
            })
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

    /// Copies the sign-ins again from the user's OpenCode; the running OpenCode chat
    /// starts over with them, since an agent reads them only when it starts.
    fn sync_sign_ins(&mut self, cx: &mut Context<Self>) {
        if self.syncing {
            return;
        }
        let Some(command) = self
            .agents
            .iter()
            .find(|(kind, _)| *kind == AgentKind::OpenCode)
            .and_then(|(_, found)| found.as_ref().ok())
            .cloned()
        else {
            return;
        };
        self.syncing = true;
        let work = cx
            .background_executor()
            .spawn(async move { acp::sync_credentials(&command) });
        self._sync = Some(cx.spawn(async move |this: WeakEntity<Self>, cx| {
            let done = work.await;
            let _ = this.update(cx, |this, cx| {
                this.syncing = false;
                this.menu = None;
                if this.command.kind == AgentKind::OpenCode {
                    this.restart(cx);
                }
                this.entries.push(Entry::Notice {
                    text: if done {
                        t!("chat.synced").into()
                    } else {
                        t!("chat.sync_failed").into()
                    },
                    error: !done,
                });
                cx.notify();
            });
        }));
        cx.notify();
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
        let opencode = self
            .agents
            .iter()
            .any(|(kind, found)| *kind == AgentKind::OpenCode && found.is_ok());
        let sync = opencode.then(|| {
            Self::menu_row("chat-sync", cx)
                .child(
                    div().w(px(12.)).flex_shrink_0().child(
                        Icon::empty()
                            .path("icons/refresh-cw.svg")
                            .xsmall()
                            .text_color(theme.primary),
                    ),
                )
                .child(
                    v_flex()
                        .child(
                            Label::new(if self.syncing {
                                t!("chat.syncing")
                            } else {
                                t!("chat.sync")
                            })
                            .text_sm(),
                        )
                        .child(
                            Label::new(t!("chat.sync_hint"))
                                .text_xs()
                                .text_color(theme.muted_foreground),
                        ),
                )
                .when(self.syncing, |this| this.opacity(0.6))
                .on_click(cx.listener(|this, _, _window, cx| this.sync_sign_ins(cx)))
        });
        v_flex()
            .children(rows)
            .when(sync.is_some(), |this| {
                this.child(div().my_1().h(px(1.)).bg(theme.border))
            })
            .children(sync)
            .into_any_element()
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
        let search = match (menu, &self.filter) {
            (Menu::Setting(index), Some(filter))
                if self
                    .config
                    .get(index)
                    .is_some_and(|option| option.choices.len() > SEARCH_FROM) =>
            {
                Some(div().p_1().child(Input::new(filter).small()))
            }
            _ => None,
        };
        let body = match menu {
            Menu::Agents => self.agents_menu(cx),
            Menu::Chats => self.chats_menu(cx),
            Menu::Setting(index) => self.setting_menu(index, cx),
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
                        .flex()
                        .flex_col()
                        .p_1()
                        .rounded_lg()
                        .border_1()
                        .border_color(theme.border)
                        .bg(theme.popover)
                        .shadow_lg()
                        .children(search)
                        .child(
                            // Plain scrolling: the scrollbar wrapper would stretch the box
                            // to its full height.
                            div()
                                .id("chat-menu-list")
                                .flex_1()
                                .min_h(px(0.))
                                .overflow_y_scroll()
                                .child(body),
                        ),
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
        // Something is happening even when the agent shows nothing yet.
        let thinking = matches!(self.entries.last(), Some(Entry::Thought { .. }));
        let busy = (working && !thinking).then(|| {
            h_flex()
                .gap_2()
                .items_center()
                .text_xs()
                .text_color(theme.muted_foreground)
                .child(Spinner::new().xsmall().color(theme.muted_foreground))
                .child(SharedString::from(t!("chat.working").to_string()))
        });
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
                    .children(busy)
                    .children(login)
                    .children(failure),
            );

        let action = if working {
            Button::new("chat-stop")
                .outline()
                .small()
                .icon(Icon::new(IconName::Square))
                .tooltip(t!("chat.stop"))
                .on_click(cx.listener(|this, _, _window, cx| this.stop(cx)))
        } else {
            Button::new("chat-send")
                .primary()
                .small()
                .icon(Icon::new(IconName::ArrowUp))
                .tooltip(t!("chat.send"))
                .disabled(self.state != State::Ready)
                .on_click(cx.listener(|this, _, window, cx| this.send(window, cx)))
        };
        let trust = Switch::new("chat-no-ask")
            .small()
            .checked(self.trusted)
            .when(self.trusted, |this| this.color(theme.warning))
            .label(SharedString::from(t!("chat.no_ask").to_string()))
            .tooltip(t!("chat.no_ask_hint"))
            .on_change(cx.listener(|this, checked: &bool, _window, cx| {
                this.trusted = *checked;
                cx.emit(ChatEvent::Trust(*checked));
                cx.notify();
            }));

        let composer = div().flex_shrink_0().p_3().child(
            v_flex()
                .rounded_lg()
                .border_1()
                .border_color(if self.trusted {
                    theme.warning
                } else {
                    theme.border
                })
                .child(
                    div().px_1().pt_1().child(
                        Textarea::new(&input)
                            .appearance(false)
                            .h(px(64.))
                            .disabled(closed),
                    ),
                )
                .child(
                    h_flex()
                        .px_2()
                        .pb_2()
                        .gap_2()
                        .items_center()
                        .child(div().flex_1().min_w(px(0.)).child(trust))
                        .child(div().flex_shrink_0().child(action)),
                ),
        );

        let top = self.top_row(cx);
        let settings = self.settings_row(cx);
        let menu = self.open_menu(cx);
        v_flex()
            .relative()
            .size_full()
            .child(top)
            .children(settings)
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
    fn search_matches_all_words_in_name_description_or_value() {
        let choice = |value: &str, name: &str, description: Option<&str>| ConfigChoice {
            value: value.into(),
            name: name.into(),
            description: description.map(str::to_owned),
        };
        let option = ConfigOption {
            id: "model".into(),
            name: "Model".into(),
            description: None,
            category: Some("model".into()),
            current: "a".into(),
            choices: vec![
                choice("google/gemini-2.5-flash", "google/Gemini 2.5 Flash", None),
                choice("anthropic/sonnet", "Claude Sonnet", Some("Balanced")),
                choice("google/gemini-2.5-pro", "google/Gemini 2.5 Pro", None),
            ],
        };
        let found = |query: &str| -> Vec<usize> {
            ChatView::matching(&option, query)
                .into_iter()
                .map(|(n, _)| n)
                .collect()
        };
        assert_eq!(found(""), [0, 1, 2]);
        assert_eq!(found("GEMINI flash"), [0]);
        assert_eq!(found("2.5"), [0, 2]);
        assert_eq!(found("balanced"), [1]);
        assert_eq!(found("anthropic"), [1]);
        assert!(found("gpt").is_empty());
    }

    #[test]
    fn command_output_splits_into_its_streams() {
        let both =
            CommandOutput::parse("exit code: 2\n--- stdout ---\nhi\nthere\n--- stderr ---\noops")
                .unwrap();
        assert_eq!(both.badge, Some(("exit 2".into(), Some(false))));
        assert_eq!(both.stdout.as_deref(), Some("hi\nthere"));
        assert_eq!(both.stderr.as_deref(), Some("oops"));

        let quiet = CommandOutput::parse("exit code: 0\n(no output)").unwrap();
        assert_eq!(quiet.badge, Some(("exit 0".into(), Some(true))));
        assert_eq!((quiet.stdout, quiet.stderr), (None, None));

        let errors = CommandOutput::parse("exit code: 1\n--- stderr ---\nno such file").unwrap();
        assert_eq!(
            (errors.stdout, errors.stderr.as_deref()),
            (None, Some("no such file"))
        );

        let late =
            CommandOutput::parse("timed out after 5 s and was stopped; pass a larger timeout")
                .unwrap();
        assert_eq!(late.badge, Some(("timeout".into(), Some(false))));
        let killed = CommandOutput::parse("killed by signal KILL: out of memory").unwrap();
        assert_eq!(killed.badge, Some(("signal KILL".into(), Some(false))));

        assert_eq!(CommandOutput::parse("the user denied this in Cratty"), None);
    }

    #[test]
    fn fence_outgrows_backticks_inside() {
        assert_eq!(fenced("bash", "ls\n"), "```bash\nls\n```");
        assert_eq!(fenced("", "a ```` b"), "`````\na ```` b\n`````");
    }

    #[test]
    fn long_text_keeps_its_beginning() {
        assert_eq!(clip("a\nb"), ("a\nb".into(), 0));
        let many: String = (0..1000).map(|n| format!("{n}\n")).collect();
        let (shown, hidden) = clip(&many);
        assert_eq!(shown.lines().count(), 400);
        assert_eq!(hidden, 600);
        let (shown, hidden) = clip(&"я".repeat(50_000));
        assert!(shown.ends_with('…') && shown.len() <= 40_003);
        assert_eq!(hidden, 0);
    }

    #[test]
    fn edit_reads_as_a_diff() {
        assert_eq!(
            diff_text("port = 80\nhost = a", "port = 8080"),
            "-port = 80\n-host = a\n+port = 8080"
        );
    }

    #[test]
    fn tools_are_known_by_name() {
        assert_eq!(ToolKind::of("run_command"), ToolKind::Run);
        assert_eq!(ToolKind::of("edit_file"), ToolKind::Edit);
        assert_eq!(ToolKind::of("TodoWrite"), ToolKind::Other);
        assert!(!has_arguments(&serde_json::json!({})));
        assert!(!has_arguments(&serde_json::Value::Null));
        assert!(has_arguments(&serde_json::json!({"path": "/etc"})));
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
