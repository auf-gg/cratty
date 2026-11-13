//! The AI tab of the session panel: a conversation with an agent (Claude Code,
//! OpenCode) that works on the tab's server through Cratty's MCP tools (see
//! `crate::acp` and `crate::mcp`). Commands and file changes it asks for still go
//! through the approval dialog of the window.

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
    AnyElement, Context, Entity, Focusable, Hsla, IntoElement, Render, ScrollHandle, SharedString,
    Subscription, Task, WeakEntity, Window, div, prelude::*, px,
};
use rust_i18n::t;

use crate::acp::{self, AgentCommand, FromAgent, PermissionAsk, PlanEntry, Setup, ToAgent, Update};

/// Lines of tool output shown when a tool row is opened.
const OUTPUT_LINES: usize = 40;

#[derive(Clone, Debug, PartialEq)]
enum State {
    Starting,
    Ready,
    Working,
    Closed(Option<SharedString>),
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

pub struct ChatView {
    command: AgentCommand,
    setup: Setup,
    commands: Option<mpsc::UnboundedSender<ToAgent>>,
    _pump: Option<Task<()>>,
    agent_name: SharedString,
    state: State,
    entries: Vec<Entry>,
    input: Entity<TextareaState>,
    scroll: ScrollHandle,
    _input_events: Subscription,
}

impl ChatView {
    pub fn new(
        command: AgentCommand,
        setup: Setup,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let input = cx.new(|cx| {
            TextareaState::new(window, cx)
                .submit_on_enter(true)
                .placeholder(t!("chat.placeholder"))
        });
        let input_events =
            cx.subscribe_in(&input, window, |this, _, event: &InputEvent, window, cx| {
                if let InputEvent::PressEnter { shift: false, .. } = event {
                    this.send(window, cx);
                }
            });
        let agent_name = SharedString::from(command.kind.title());
        let mut chat = Self {
            command,
            setup,
            commands: None,
            _pump: None,
            agent_name,
            state: State::Starting,
            entries: Vec::new(),
            input,
            scroll: ScrollHandle::new(),
            _input_events: input_events,
        };
        chat.start(cx);
        chat
    }

    pub fn focus_input(&self, window: &mut Window, cx: &mut Context<Self>) {
        window.focus(&self.input.focus_handle(cx), cx);
    }

    fn start(&mut self, cx: &mut Context<Self>) {
        self.state = State::Starting;
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

    /// Starts over: a new agent process and an empty conversation.
    fn restart(&mut self, cx: &mut Context<Self>) {
        self.commands = None;
        self._pump = None;
        self.entries.clear();
        self.start(cx);
    }

    fn at_bottom(&self) -> bool {
        let offset = self.scroll.offset().y;
        let max = self.scroll.max_offset().y;
        // The offset goes negative as the view scrolls down.
        max - (-offset) < px(24.)
    }

    fn apply(&mut self, event: FromAgent) {
        match event {
            FromAgent::Ready { agent } => {
                if !agent.is_empty() {
                    self.agent_name = agent.into();
                }
                self.state = State::Ready;
            }
            FromAgent::Update(update) => self.apply_update(update),
            FromAgent::Permission { request, ask } => self.entries.push(Entry::Permission {
                request,
                ask,
                answer: None,
            }),
            FromAgent::TurnEnded { stop_reason } => {
                self.state = State::Ready;
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
            // The window shows the user's own message when it is sent.
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
        let text = self.input.read(cx).value().trim().to_owned();
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
        self.entries.push(Entry::User(text.into()));
        self.state = State::Working;
        self.input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.scroll.scroll_to_bottom();
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

impl Render for ChatView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        let (status, color) = match &self.state {
            State::Starting => (t!("chat.starting"), theme.warning),
            State::Ready => (t!("chat.ready"), theme.success),
            State::Working => (t!("chat.working"), theme.warning),
            State::Closed(Some(_)) => (t!("chat.failed"), theme.danger),
            State::Closed(None) => (t!("chat.closed"), theme.muted_foreground),
        };
        let working = self.state == State::Working;
        let closed = matches!(self.state, State::Closed(_));

        let header = h_flex()
            .flex_shrink_0()
            .px_4()
            .py_2()
            .gap_2()
            .items_center()
            .border_b_1()
            .border_color(theme.border)
            .child(div().size(px(7.)).flex_shrink_0().rounded_full().bg(color))
            .child(
                v_flex()
                    .flex_1()
                    .min_w(px(0.))
                    .child(
                        Label::new(self.agent_name.clone())
                            .text_sm()
                            .font_medium()
                            .truncate(),
                    )
                    .child(
                        Label::new(status)
                            .text_xs()
                            .text_color(theme.muted_foreground),
                    ),
            )
            .child(
                Button::new("chat-restart")
                    .ghost()
                    .xsmall()
                    .icon(Icon::empty().path("icons/refresh-cw.svg"))
                    .tooltip(t!("chat.new"))
                    .on_click(cx.listener(|this, _, _window, cx| this.restart(cx))),
            );

        let entries: Vec<AnyElement> = self
            .entries
            .iter()
            .enumerate()
            .map(|(index, entry)| self.render_entry(index, entry, cx))
            .collect();
        let empty = entries.is_empty();

        let failure = match &self.state {
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
                    .when(empty && failure.is_none(), |this| {
                        this.child(
                            Label::new(t!("chat.intro"))
                                .text_xs()
                                .text_color(theme.muted_foreground),
                        )
                    })
                    .children(entries)
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
            .child(Textarea::new(&self.input).h(px(72.)).disabled(closed))
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

        v_flex()
            .size_full()
            .child(header)
            .child(body)
            .child(composer)
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
