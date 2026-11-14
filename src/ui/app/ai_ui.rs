//! The AI tab's chat on a tab, and the agent access behind it: the token that lets
//! Cratty's own agents reach the tab's server through MCP, and approval of every
//! command and file change they ask for (see `crate::mcp`). Access is never handed out
//! to other programs.

use super::*;
use crate::mcp::{self, Action, Ask, CallAsk, Grant, SessionInfo};
use crate::ssh::remote::Remote;

// Read by the model, so in English.
const REVOKED: &str = "agent access to this tab was revoked or the tab was closed in Cratty";
const DENIED: &str = "the user denied this in Cratty";
const DISCONNECTED: &str =
    "the tab's SSH session is disconnected; ask the user to reconnect it in Cratty";
const NO_TERMINAL: &str = "this tab has no terminal session";

/// Lines of a command or file shown in the approval dialog.
const PREVIEW_LINES: usize = 24;
const PREVIEW_CHARS: usize = 4000;

pub(super) struct AgentAccess {
    pub(super) token: String,
    /// The user let agents run commands and change files here without asking.
    pub(super) trusted: bool,
}

pub(super) struct PendingCall {
    ask: Box<CallAsk>,
}

pub(super) struct ChatPanel {
    view: Entity<crate::ui::chat::ChatView>,
    _events: Subscription,
}

impl AppView {
    /// Starts the MCP server if it is not running yet.
    fn ensure_mcp(&mut self, cx: &mut Context<Self>) -> bool {
        if self.mcp.is_some() {
            return true;
        }
        let started = crate::agent::mcp_address().and_then(mcp::spawn);
        match started {
            Ok((running, asks)) => {
                self.mcp = Some(running);
                self.mcp_error = None;
                self.mcp_task =
                    Some(cx.spawn(async move |this: gpui_kit::WeakEntity<Self>, cx| {
                        let mut asks = asks;
                        while let Some(ask) = asks.next().await {
                            if this
                                .update(cx, |this, cx| this.on_mcp_ask(ask, cx))
                                .is_err()
                            {
                                return;
                            }
                        }
                    }));
                true
            }
            Err(error) => {
                self.mcp_error = Some(t!("ai.server_failed", error = format!("{error:#}")).into());
                false
            }
        }
    }

    /// The tab's access token, made with the MCP server on first use.
    fn agent_token(&mut self, index: usize, cx: &mut Context<Self>) -> Option<String> {
        if let Some(access) = self.tabs.get(index)?.agents.as_ref() {
            return Some(access.token.clone());
        }
        if !self.ensure_mcp(cx) {
            return None;
        }
        let token = match mcp::new_token() {
            Ok(token) => token,
            Err(error) => {
                self.mcp_error = Some(t!("ai.server_failed", error = format!("{error:#}")).into());
                return None;
            }
        };
        self.tabs.get_mut(index)?.agents = Some(AgentAccess {
            token: token.clone(),
            trusted: false,
        });
        Some(token)
    }

    /// Commands and file changes on the tab run without approval, or ask again. The
    /// chat's switch and the approval dialog both come here, and the switch follows.
    fn set_agents_trusted(&mut self, index: usize, trusted: bool, cx: &mut Context<Self>) {
        let Some(tab) = self.tabs.get_mut(index) else {
            return;
        };
        if let Some(access) = tab.agents.as_mut() {
            access.trusted = trusted;
        }
        if let Some(chat) = &tab.chat {
            chat.view
                .update(cx, |view, cx| view.set_trusted(trusted, cx));
        }
        cx.notify();
    }

    /// Looks for agents once, in the background: it may start the login shell.
    pub(super) fn scan_agents(&mut self, cx: &mut Context<Self>) {
        if self.agent_kinds.is_some() || self.agent_scan.is_some() {
            return;
        }
        let scan = cx.background_executor().spawn(async move {
            crate::acp::AgentKind::ALL
                .into_iter()
                .map(|kind| (kind, crate::acp::agents::find(kind)))
                .collect::<Vec<_>>()
        });
        self.agent_scan = Some(cx.spawn(async move |this: gpui_kit::WeakEntity<Self>, cx| {
            let found = scan.await;
            let _ = this.update(cx, |this, cx| {
                this.agent_kinds = Some(found);
                this.agent_scan = None;
                cx.notify();
            });
        }));
    }

    /// Starts the AI tab's chat with the agent picked last. It continues the server's
    /// latest chat, unless another tab of the server has it open.
    fn start_chat(&mut self, index: usize, cx: &mut Context<Self>) {
        let Some(agents) = self.agent_kinds.clone() else {
            return;
        };
        let Some(command) = crate::ui::chat::pick_agent(&agents) else {
            return;
        };
        let Some(token) = self.agent_token(index, cx) else {
            cx.notify();
            return;
        };
        let Some(tab) = self.tabs.get(index) else {
            return;
        };
        let server = session_panel::address(&tab.request);
        let open_elsewhere = self
            .tabs
            .iter()
            .any(|other| other.chat.is_some() && session_panel::address(&other.request) == server);
        let Some(address) = self.mcp.as_ref().map(|running| running.address().as_text()) else {
            return;
        };
        let prepared = crate::acp::agents::prepare_workdir()
            .and_then(|dir| Ok((dir, mcp::bridge_executable()?)));
        let (workdir, bridge) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                self.mcp_error = Some(t!("ai.server_failed", error = format!("{error:#}")).into());
                cx.notify();
                return;
            }
        };
        let setup = crate::acp::Setup {
            cwd: workdir.to_string_lossy().into_owned(),
            mcp: crate::acp::McpServer {
                name: mcp::SERVER_NAME.into(),
                command: bridge,
                args: vec![mcp::bridge::FLAG.into()],
                env: vec![
                    (mcp::bridge::TOKEN_VAR.into(), token),
                    (mcp::bridge::ADDRESS_VAR.into(), address),
                ],
            },
            login: command.kind.login_command().into(),
            resume: None,
        };
        let view = cx.new(|cx| {
            crate::ui::chat::ChatView::new(agents, command, setup, server, !open_elsewhere, cx)
        });
        let trusted = self
            .tabs
            .get(index)
            .and_then(|tab| tab.agents.as_ref())
            .is_some_and(|access| access.trusted);
        view.update(cx, |view, cx| view.set_trusted(trusted, cx));
        let events = cx.subscribe(
            &view,
            |this, view, event: &crate::ui::chat::ChatEvent, cx| {
                this.on_chat_event(&view, event, cx)
            },
        );
        if let Some(tab) = self.tabs.get_mut(index) {
            tab.chat = Some(ChatPanel {
                view,
                _events: events,
            });
        }
        cx.notify();
    }

    fn on_chat_event(
        &mut self,
        view: &Entity<crate::ui::chat::ChatView>,
        event: &crate::ui::chat::ChatEvent,
        cx: &mut Context<Self>,
    ) {
        let (agent, program) = match event {
            crate::ui::chat::ChatEvent::Trust(trusted) => {
                if let Some(index) = self
                    .tabs
                    .iter()
                    .position(|tab| tab.chat.as_ref().is_some_and(|chat| &chat.view == view))
                {
                    self.set_agents_trusted(index, *trusted, cx);
                }
                return;
            }
            crate::ui::chat::ChatEvent::Login { agent, program } => (agent, program),
        };
        let title = t!("chat.login_tab", agent = agent).to_string();
        if let Err(error) = self.open_program_tab(program, title, cx) {
            // The terminal could not start (an old Windows without ConPTY, say): the
            // user runs the command by hand.
            let line = command_line(program);
            cx.write_to_clipboard(gpui_kit::ClipboardItem::new_string(line.clone()));
            let text = t!(
                "chat.login_manual",
                error = error.to_string(),
                command = line
            );
            view.update(cx, |view, cx| view.add_notice(text.into(), cx));
        }
    }

    /// A local terminal tab running a program, such as an agent's sign-in.
    fn open_program_tab(
        &mut self,
        program: &crate::ssh::LocalProgram,
        title: String,
        cx: &mut Context<Self>,
    ) -> std::io::Result<()> {
        let session = crate::ssh::spawn_local_program(DEFAULT_PTY, "xterm-256color", program)?;
        let view = cx.new(|cx| TerminalView::new(title.clone(), DEFAULT_PTY, session, cx));
        let events = self.subscribe_terminal(&view, None, title.clone(), cx);
        self.tabs.push(SessionTab {
            title: title.into(),
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
            shell: None,
            agents: None,
            chat: None,
        });
        self.active = Some(self.tabs.len() - 1);
        self.showing_page = false;
        self.apply_appearance(cx);
        self.focus_active(cx);
        Ok(())
    }

    /// The AI tab of the session panel: the chat, started on first sight.
    pub(super) fn chat_panel(
        &self,
        index: usize,
        tab: &SessionTab,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = cx.theme().clone();
        if let Some(chat) = &tab.chat {
            return div()
                .size_full()
                .child(chat.view.clone())
                .into_any_element();
        }

        let note = |text: SharedString| {
            v_flex().px_4().py_3().gap_2().child(
                Label::new(text)
                    .text_xs()
                    .text_color(theme.muted_foreground),
            )
        };
        if tab.local {
            return note(t!("chat.ssh_only").into()).into_any_element();
        }
        let Some(kinds) = &self.agent_kinds else {
            let this = cx.entity().downgrade();
            cx.defer(move |cx| {
                let _ = this.update(cx, |this, cx| this.scan_agents(cx));
            });
            return note(t!("chat.looking").into()).into_any_element();
        };
        if kinds.iter().all(|(_, found)| found.is_err()) {
            return note(t!("chat.no_agents").into())
                .children(kinds.iter().filter_map(|(kind, found)| {
                    let missing = found.as_ref().err()?;
                    Some(
                        Label::new(SharedString::from(
                            t!(
                                "chat.missing",
                                agent = kind.title(),
                                program = missing.install
                            )
                            .to_string(),
                        ))
                        .text_xs()
                        .text_color(theme.muted_foreground),
                    )
                }))
                .into_any_element();
        }

        if let Some(error) = self.mcp_error.clone() {
            // Starting again on every frame would not help: the error says why.
            return note(error).into_any_element();
        }
        // Started after this frame: the chat needs the app, not just a look at it.
        let this = cx.entity().downgrade();
        cx.defer(move |cx| {
            let _ = this.update(cx, |this, cx| {
                if this.tabs.get(index).is_some_and(|tab| tab.chat.is_none()) {
                    this.start_chat(index, cx);
                }
            });
        });
        note(t!("chat.starting").into()).into_any_element()
    }

    fn agent_tab(&self, token: &str) -> Option<usize> {
        self.tabs.iter().position(|tab| {
            tab.agents
                .as_ref()
                .is_some_and(|access| access.token == token)
        })
    }

    fn grant_for(&self, index: usize, action: &Action, cx: &App) -> Result<Grant, String> {
        let Some(TabKind::Terminal { view, .. }) = self.tabs.get(index).map(|tab| &tab.kind) else {
            return Err(NO_TERMINAL.into());
        };
        let view = view.read(cx);
        match action {
            Action::Screen { rows } => Ok(Grant::Screen(view.terminal().recent_text(*rows))),
            _ => view
                .ssh_commands()
                .map(|commands| Grant::Remote(Remote::new(commands)))
                .ok_or_else(|| DISCONNECTED.into()),
        }
    }

    fn on_mcp_ask(&mut self, ask: Ask, cx: &mut Context<Self>) {
        match ask {
            Ask::Hello { token, reply } => {
                let info = self.agent_tab(&token).map(|index| {
                    let tab = &self.tabs[index];
                    SessionInfo {
                        title: tab.title.to_string(),
                        target: session_panel::address(&tab.request),
                    }
                });
                let _ = reply.send(info);
            }
            Ask::Call(ask) => {
                let Some(index) = self.agent_tab(&ask.token) else {
                    let _ = ask.reply.send(Err(REVOKED.into()));
                    return;
                };
                let trusted = self.tabs[index]
                    .agents
                    .as_ref()
                    .is_some_and(|access| access.trusted);
                if ask.action.changes_server() && !trusted {
                    self.agent_queue.push_back(PendingCall { ask });
                    cx.notify();
                    return;
                }
                let grant = self.grant_for(index, &ask.action, cx);
                let _ = ask.reply.send(grant);
            }
            Ask::Withdraw { id } => {
                let before = self.agent_queue.len();
                self.agent_queue.retain(|pending| pending.ask.id != id);
                if self.agent_queue.len() != before {
                    cx.notify();
                }
            }
        }
    }

    fn answer_agent(&mut self, allow: bool, cx: &mut Context<Self>) {
        let Some(pending) = self.agent_queue.pop_front() else {
            return;
        };
        let reply = if allow {
            match self.agent_tab(&pending.ask.token) {
                Some(index) => self.grant_for(index, &pending.ask.action, cx),
                None => Err(REVOKED.into()),
            }
        } else {
            Err(DENIED.into())
        };
        let _ = pending.ask.reply.send(reply);
        self.touch_all();
        cx.notify();
    }

    /// Allows this call and everything else agents ask on the same tab.
    fn trust_agent(&mut self, cx: &mut Context<Self>) {
        let Some(token) = self
            .agent_queue
            .front()
            .map(|pending| pending.ask.token.clone())
        else {
            return;
        };
        if let Some(index) = self.agent_tab(&token) {
            self.set_agents_trusted(index, true, cx);
        }
        let (same, other): (Vec<_>, Vec<_>) = std::mem::take(&mut self.agent_queue)
            .into_iter()
            .partition(|pending| pending.ask.token == token);
        self.agent_queue = other.into();
        for pending in same {
            let reply = match self.agent_tab(&token) {
                Some(index) => self.grant_for(index, &pending.ask.action, cx),
                None => Err(REVOKED.into()),
            };
            let _ = pending.ask.reply.send(reply);
        }
        self.touch_all();
        cx.notify();
    }

    /// Refuses the calls of a tab that is gone or no longer open to agents.
    pub(super) fn drop_agent_calls(&mut self, token: &str) {
        let (gone, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut self.agent_queue)
            .into_iter()
            .partition(|pending| pending.ask.token == token);
        self.agent_queue = kept.into();
        for pending in gone {
            let _ = pending.ask.reply.send(Err(REVOKED.into()));
        }
    }

    pub(super) fn agent_dialog(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let pending = self.agent_queue.front()?;
        let theme = cx.theme().clone();
        let waiting = self.agent_queue.len().saturating_sub(1);
        let place = self
            .agent_tab(&pending.ask.token)
            .map(|index| {
                let tab = &self.tabs[index];
                let target = session_panel::address(&tab.request);
                // A quick-connect tab is named after its address: do not say it twice.
                if tab.title.as_ref() == target {
                    target
                } else {
                    t!("ai.on_server", title = tab.title, target = target).to_string()
                }
            })
            .unwrap_or_default();

        let block = |id: &'static str, text: &str| {
            let (preview, more) = preview(text);
            v_flex()
                .gap_1()
                .child(
                    div()
                        .id(id)
                        .max_h(px(260.))
                        .overflow_y_scrollbar()
                        .p_2()
                        .rounded_md()
                        .bg(theme.muted)
                        .font_family(mono_family(cx))
                        .text_xs()
                        .children(preview.lines().map(|line| {
                            div().child(SharedString::from(if line.is_empty() {
                                " ".to_owned()
                            } else {
                                line.to_owned()
                            }))
                        })),
                )
                .when(more > 0, |this| {
                    this.child(
                        Label::new(SharedString::from(
                            t!("ai.more_lines", count = more).to_string(),
                        ))
                        .text_xs()
                        .text_color(theme.muted_foreground),
                    )
                })
        };

        let is_command = matches!(pending.ask.action, Action::Run { .. });
        let (title, body): (SharedString, AnyElement) = match &pending.ask.action {
            Action::Run { command, cwd } => (
                t!("ai.ask_run").into(),
                v_flex()
                    .gap_2()
                    .child(block("ai-command", command))
                    .children(cwd.as_ref().map(|cwd| {
                        Label::new(SharedString::from(
                            t!("ai.in_folder", path = cwd).to_string(),
                        ))
                        .text_xs()
                        .text_color(theme.muted_foreground)
                    }))
                    .into_any_element(),
            ),
            Action::Write { path, content } => (
                t!("ai.ask_write", path = path).into(),
                block("ai-content", content).into_any_element(),
            ),
            Action::Edit {
                path,
                old_text,
                new_text,
            } => (
                t!("ai.ask_edit", path = path).into(),
                v_flex()
                    .gap_1()
                    .child(
                        Label::new(t!("ai.replace"))
                            .text_xs()
                            .text_color(theme.muted_foreground),
                    )
                    .child(block("ai-old", old_text))
                    .child(
                        Label::new(t!("ai.with"))
                            .text_xs()
                            .text_color(theme.muted_foreground),
                    )
                    .child(block("ai-new", new_text))
                    .into_any_element(),
            ),
            // Reading needs no approval and never waits here.
            Action::Read { path } | Action::List { path } => {
                (SharedString::from(path.clone()), div().into_any_element())
            }
            Action::Screen { .. } => (SharedString::default(), div().into_any_element()),
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
                .bg(gpui_kit::hsla(0., 0., 0., 0.5))
                .on_mouse_down(MouseButton::Left, |_, _, _| {})
                .child(
                    v_flex()
                        .w(px(560.))
                        .p_4()
                        .gap_3()
                        .rounded_lg()
                        .bg(theme.background)
                        .border_1()
                        .border_color(theme.border)
                        .child(
                            v_flex()
                                .gap_1()
                                .child(Label::new(title).font_semibold())
                                .child(
                                    Label::new(SharedString::from(place))
                                        .text_xs()
                                        .text_color(theme.muted_foreground),
                                ),
                        )
                        .child(body)
                        .when(is_command, |this| {
                            this.child(
                                Label::new(t!("ai.request_note"))
                                    .text_xs()
                                    .text_color(theme.muted_foreground),
                            )
                        })
                        .when(waiting > 0, |this| {
                            this.child(
                                Label::new(SharedString::from(
                                    t!("ai.pending", count = waiting).to_string(),
                                ))
                                .text_xs()
                                .text_color(theme.warning),
                            )
                        })
                        .child(
                            h_flex()
                                .gap_2()
                                .child(
                                    Button::new("ai-approve")
                                        .primary()
                                        .label(t!("ai.approve"))
                                        .on_click(cx.listener(|this, _, _window, cx| {
                                            this.answer_agent(true, cx)
                                        })),
                                )
                                .child(
                                    Button::new("ai-deny")
                                        .outline()
                                        .label(t!("ai.deny"))
                                        .on_click(cx.listener(|this, _, _window, cx| {
                                            this.answer_agent(false, cx)
                                        })),
                                )
                                .child(div().flex_grow_1())
                                .child(
                                    Button::new("ai-trust")
                                        .ghost()
                                        .label(t!("ai.approve_all"))
                                        .tooltip(t!("ai.approve_all_hint"))
                                        .on_click(
                                            cx.listener(|this, _, _window, cx| {
                                                this.trust_agent(cx)
                                            }),
                                        ),
                                ),
                        ),
                )
                .into_any_element(),
        )
    }
}

/// A program as one line for the user's shell, for running it by hand.
fn command_line(program: &crate::ssh::LocalProgram) -> String {
    if cfg!(windows) {
        powershell_line(program)
    } else {
        posix_line(program)
    }
}

fn posix_line(program: &crate::ssh::LocalProgram) -> String {
    use crate::ssh::remote::quote;

    let mut words: Vec<String> = program
        .env
        .iter()
        .filter(|(name, _)| name != "PATH")
        .map(|(name, value)| format!("{name}={}", quote(&value.to_string_lossy())))
        .collect();
    words.push(quote(&program.program.to_string_lossy()));
    words.extend(program.args.iter().map(|arg| quote(arg)));
    words.join(" ")
}

/// PowerShell is the terminal's shell on Windows. Every word is quoted: to it a bare
/// `@package` means something else.
fn powershell_line(program: &crate::ssh::LocalProgram) -> String {
    let quote = |word: &str| format!("'{}'", word.replace('\'', "''"));
    let mut line: String = program
        .env
        .iter()
        .filter(|(name, _)| !name.eq_ignore_ascii_case("PATH"))
        .map(|(name, value)| format!("$env:{name} = {}; ", quote(&value.to_string_lossy())))
        .collect();
    line.push_str("& ");
    line.push_str(&quote(&program.program.to_string_lossy()));
    for arg in &program.args {
        line.push(' ');
        line.push_str(&quote(arg));
    }
    line
}

/// The first lines of a text for the dialog, and how many lines were left out.
fn preview(text: &str) -> (String, usize) {
    let total = text.lines().count();
    let mut shown = String::new();
    let mut lines = 0;
    for line in text.lines() {
        if lines == PREVIEW_LINES || shown.len() + line.len() > PREVIEW_CHARS {
            break;
        }
        shown.push_str(line);
        shown.push('\n');
        lines += 1;
    }
    if lines == 0 && !text.is_empty() {
        // One huge line: show its beginning.
        let mut cut = PREVIEW_CHARS.min(text.len());
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        shown = format!("{}…", &text[..cut]);
        lines = 1;
    }
    (
        shown.trim_end_matches('\n').to_owned(),
        total.saturating_sub(lines),
    )
}

#[cfg(test)]
mod tests {
    use super::{posix_line, powershell_line, preview};

    #[test]
    fn sign_in_reads_as_a_line_for_the_shell() {
        let program = crate::ssh::LocalProgram {
            program: r"C:\Program Files\nodejs\npx.cmd".into(),
            args: vec![
                "-y".into(),
                "@agentclientprotocol/claude-agent-acp".into(),
                "--cli".into(),
            ],
            env: vec![
                (
                    "CLAUDE_CONFIG_DIR".into(),
                    r"C:\Users\O'Neil\cratty\claude".into(),
                ),
                ("Path".into(), r"C:\bin".into()),
            ],
            cwd: None,
        };
        assert_eq!(
            powershell_line(&program),
            r"$env:CLAUDE_CONFIG_DIR = 'C:\Users\O''Neil\cratty\claude'; & 'C:\Program Files\nodejs\npx.cmd' '-y' '@agentclientprotocol/claude-agent-acp' '--cli'"
        );
        assert_eq!(
            posix_line(&program),
            r#"CLAUDE_CONFIG_DIR='C:\Users\O'\''Neil\cratty\claude' Path='C:\bin' 'C:\Program Files\nodejs\npx.cmd' '-y' '@agentclientprotocol/claude-agent-acp' '--cli'"#
        );
    }

    #[test]
    fn preview_shows_the_beginning_and_counts_the_rest() {
        assert_eq!(preview("ls -la"), ("ls -la".into(), 0));
        let long: String = (1..=30).map(|n| format!("line {n}\n")).collect();
        let (shown, more) = preview(&long);
        assert_eq!(shown.lines().count(), 24);
        assert_eq!(more, 6);
        let (shown, more) = preview(&"x".repeat(10_000));
        assert!(shown.ends_with('…') && shown.len() < 4100);
        assert_eq!(more, 0);
    }
}
