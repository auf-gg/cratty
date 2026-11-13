//! Cratty as an ACP client: the AI tab runs an agent (Claude Code, OpenCode) as a child
//! process and shows its conversation. The agent gets one MCP server, Cratty's own
//! (see `crate::mcp`), so it works on the tab's server, and its own tools are off.
//! No provider or API key is involved: the agent signs in on its own.

pub mod agents;
pub mod protocol;
pub mod sessions;

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

pub use agents::{AgentCommand, AgentKind};
pub use protocol::{
    LoginMethod, PermissionAsk, PermissionOption, PlanEntry, ToolCall, ToolCallUpdate, Update,
};

/// Starting may download the agent first (npx), so it gets a long time.
const START_TIMEOUT: Duration = Duration::from_secs(300);
const STOP_GRACE: Duration = Duration::from_secs(2);
/// The longest line read from the agent.
const MAX_LINE: u64 = 32 * 1024 * 1024;
/// How much of the agent's stderr is kept to explain a failure.
const STDERR_TAIL: usize = 4 * 1024;

/// An MCP server given to the agent, started over stdio.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpServer {
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

#[derive(Clone, Debug)]
pub struct Setup {
    /// Absolute path of the folder the session runs in.
    pub cwd: String,
    pub mcp: McpServer,
    /// What the user runs to sign in, for the error that asks for it.
    pub login: String,
    /// A saved session to continue: the agent replays its conversation first.
    pub resume: Option<String>,
}

#[derive(Debug)]
pub enum ToAgent {
    Prompt(String),
    Cancel,
    /// The answer to a permission request: an option, or `None` to refuse.
    Permission {
        request: u64,
        option: Option<String>,
    },
    /// Leave the current conversation for a new one; the agent deletes the old one if
    /// it can.
    NewSession,
}

#[derive(Clone, Debug, PartialEq)]
pub enum FromAgent {
    /// A session is ready for prompts. `resumed` when it is the saved one, whose
    /// conversation has just been replayed as updates.
    Ready {
        agent: String,
        session: String,
        resumed: bool,
    },
    Update(Update),
    Permission {
        request: u64,
        ask: PermissionAsk,
    },
    TurnEnded {
        stop_reason: String,
    },
    /// A prompt failed; the session goes on.
    TurnFailed(String),
    /// The agent wants the user to sign in, in one of these ways.
    LoginRequired(Vec<LoginMethod>),
    /// The agent has stopped, or could not start.
    Closed {
        error: Option<String>,
    },
}

/// Dropping both halves ends the session: the thread closes the agent's input, waits a
/// little and kills it. Nobody waits for that, so closing a tab stays quick.
pub struct AgentHandle {
    pub commands: mpsc::UnboundedSender<ToAgent>,
    pub events: mpsc::Receiver<FromAgent>,
}

/// Starts the agent in its own thread.
pub fn spawn(command: AgentCommand, setup: Setup) -> std::io::Result<AgentHandle> {
    let (commands_tx, commands_rx) = mpsc::unbounded();
    let (events_tx, events_rx) = mpsc::channel(256);
    std::thread::Builder::new()
        .name(format!("acp:{}", command.kind.title()))
        .spawn(move || {
            let mut events = events_tx;
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = events.try_send(FromAgent::Closed {
                        error: Some(error.to_string()),
                    });
                    return;
                }
            };
            runtime.block_on(run_process(command, setup, commands_rx, events));
            runtime.shutdown_background();
        })?;
    Ok(AgentHandle {
        commands: commands_tx,
        events: events_rx,
    })
}

async fn run_process(
    command: AgentCommand,
    setup: Setup,
    commands: mpsc::UnboundedReceiver<ToAgent>,
    mut events: mpsc::Sender<FromAgent>,
) {
    let mut process = tokio::process::Command::new(&command.program);
    for name in agents::foreign_config(command.kind) {
        process.env_remove(name);
    }
    process
        .args(&command.args)
        .env("PATH", &command.path)
        .envs(command.env.iter().map(|(name, value)| (name, value)))
        .current_dir(&setup.cwd)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    // A console program started from a GUI app would open a console window.
    #[cfg(windows)]
    process.creation_flags(0x0800_0000);

    let mut child = match process.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = events
                .send(FromAgent::Closed {
                    error: Some(format!("{}: {error}", command.program.display())),
                })
                .await;
            return;
        }
    };
    let (Some(stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        return;
    };

    let tail = Arc::new(Mutex::new(VecDeque::<u8>::new()));
    let keeper = tail.clone();
    let reading_stderr = tokio::spawn(async move {
        let mut stderr = stderr;
        let mut buffer = [0u8; 4096];
        while let Ok(read @ 1..) = stderr.read(&mut buffer).await {
            if let Ok(mut tail) = keeper.lock() {
                tail.extend(&buffer[..read]);
                let over = tail.len().saturating_sub(STDERR_TAIL);
                tail.drain(..over);
            }
        }
    });

    let result = run(stdout, stdin, &setup, commands, events.clone()).await;

    // The input is closed by now: agents exit on their own; stragglers are killed.
    if tokio::time::timeout(STOP_GRACE, child.wait())
        .await
        .is_err()
    {
        let _ = child.kill().await;
    }
    // What the agent printed last explains why it stopped: read it to the end.
    let _ = tokio::time::timeout(Duration::from_millis(500), reading_stderr).await;
    let error = result.err().map(|error| {
        let tail = tail
            .lock()
            .map(|mut tail| {
                String::from_utf8_lossy(tail.make_contiguous())
                    .trim()
                    .to_owned()
            })
            .unwrap_or_default();
        if tail.is_empty() {
            format!("{error:#}")
        } else {
            format!("{error:#}\n\n{tail}")
        }
    });
    let _ = events.send(FromAgent::Closed { error }).await;
}

enum Incoming {
    Response {
        id: u64,
        result: Result<Value, RpcError>,
    },
    Request {
        id: Value,
        method: String,
        params: Value,
    },
    Notification {
        method: String,
        params: Value,
    },
}

struct RpcError {
    code: i64,
    message: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pending {
    Initialize,
    NewSession,
    Load,
    Prompt,
    Delete,
}

/// Talks ACP over the agent's standard streams until the window closes the session
/// (`Ok`) or the agent fails or exits (`Err`).
pub async fn run<R, W>(
    reader: R,
    writer: W,
    setup: &Setup,
    mut commands: mpsc::UnboundedReceiver<ToAgent>,
    mut events: mpsc::Sender<FromAgent>,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (out, mut outgoing) = mpsc::unbounded::<Value>();
    let writing = tokio::spawn(async move {
        let mut writer = writer;
        while let Some(message) = outgoing.next().await {
            let mut line = serde_json::to_vec(&message).unwrap_or_default();
            line.push(b'\n');
            if writer.write_all(&line).await.is_err() || writer.flush().await.is_err() {
                break;
            }
        }
        // Dropping the writer closes the agent's input.
    });
    let (incoming_tx, mut incoming) = mpsc::unbounded::<Incoming>();
    tokio::spawn(read_messages(reader, incoming_tx));

    let mut next_id = 0u64;
    let mut pending: HashMap<u64, Pending> = HashMap::new();
    let mut call =
        |method: &str, params: Value, kind: Pending, pending: &mut HashMap<u64, Pending>| {
            let id = next_id;
            next_id += 1;
            pending.insert(id, kind);
            let _ = out.unbounded_send(
                json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }),
            );
        };
    let reply = |id: Value, result: Result<Value, (i64, &str)>| {
        let message = match result {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err((code, message)) => {
                json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
            }
        };
        let _ = out.unbounded_send(message);
    };

    call(
        "initialize",
        protocol::initialize(),
        Pending::Initialize,
        &mut pending,
    );
    // Set while a session is ready; `None` while one is being made or loaded.
    let mut session: Option<String> = None;
    let mut started = false;
    let mut agent_name = String::new();
    let mut caps = protocol::AgentCaps::default();
    let mut logins: Vec<LoginMethod> = Vec::new();
    let mut permissions: HashMap<u64, Value> = HashMap::new();
    let mut next_permission = 0u64;
    let starting = tokio::time::sleep(START_TIMEOUT);
    tokio::pin!(starting);

    let outcome = loop {
        tokio::select! {
            _ = &mut starting, if !started => {
                break Err(anyhow!("the agent did not start in {} s", START_TIMEOUT.as_secs()));
            }
            command = commands.next() => match command {
                None => break Ok(()),
                Some(ToAgent::Prompt(text)) => match &session {
                    Some(id) if !pending.values().any(|kind| *kind == Pending::Prompt) => {
                        call("session/prompt", protocol::prompt(id, &text), Pending::Prompt, &mut pending);
                    }
                    _ => {
                        events.send(FromAgent::TurnFailed("the agent is busy".into())).await?;
                    }
                },
                Some(ToAgent::Cancel) => {
                    if let Some(id) = &session {
                        let _ = out.unbounded_send(json!({
                            "jsonrpc": "2.0", "method": "session/cancel", "params": protocol::cancel(id),
                        }));
                    }
                    // A cancelled turn answers every open permission request.
                    for (_, id) in permissions.drain() {
                        reply(id, Ok(protocol::permission_outcome(None)));
                    }
                }
                Some(ToAgent::Permission { request, option }) => {
                    if let Some(id) = permissions.remove(&request) {
                        reply(id, Ok(protocol::permission_outcome(option.as_deref())));
                    }
                }
                Some(ToAgent::NewSession) => {
                    if let Some(old) = session.take()
                        && caps.delete
                    {
                        call("session/delete", protocol::delete_session(&old), Pending::Delete, &mut pending);
                    }
                    call("session/new", protocol::new_session(&setup.cwd, &setup.mcp), Pending::NewSession, &mut pending);
                }
            },
            message = incoming.next() => match message {
                None => break Err(anyhow!("the agent exited")),
                Some(Incoming::Response { id, result }) => match pending.remove(&id) {
                    Some(Pending::Initialize) => {
                        let result = result.map_err(|error| rpc_error(error, setup, &logins))?;
                        let version = result.get("protocolVersion").and_then(Value::as_u64);
                        if version != Some(protocol::PROTOCOL_VERSION) {
                            break Err(anyhow!("the agent speaks ACP version {version:?}, Cratty speaks {}", protocol::PROTOCOL_VERSION));
                        }
                        agent_name = agent_title(&result);
                        caps = protocol::agent_caps(&result);
                        logins = protocol::login_methods(&result);
                        match setup.resume.as_deref().filter(|_| caps.load) {
                            Some(saved) => call("session/load", protocol::load_session(saved, &setup.cwd, &setup.mcp), Pending::Load, &mut pending),
                            None => call("session/new", protocol::new_session(&setup.cwd, &setup.mcp), Pending::NewSession, &mut pending),
                        }
                    }
                    Some(Pending::Load) => match result {
                        Ok(_) => {
                            let id = setup.resume.clone().unwrap_or_default();
                            session = Some(id.clone());
                            started = true;
                            events.send(FromAgent::Ready { agent: agent_name.clone(), session: id, resumed: true }).await?;
                        }
                        Err(error) if error.code == protocol::AUTH_REQUIRED => {
                            events.send(FromAgent::LoginRequired(logins.clone())).await?;
                            break Err(rpc_error(error, setup, &logins));
                        }
                        // The saved session is gone: start a new one.
                        Err(_) => call("session/new", protocol::new_session(&setup.cwd, &setup.mcp), Pending::NewSession, &mut pending),
                    },
                    Some(Pending::NewSession) => match result {
                        Ok(result) => {
                            let id = result
                                .get("sessionId")
                                .and_then(Value::as_str)
                                .context("the agent gave no session id")?
                                .to_owned();
                            session = Some(id.clone());
                            started = true;
                            events.send(FromAgent::Ready { agent: agent_name.clone(), session: id, resumed: false }).await?;
                        }
                        Err(error) => {
                            if error.code == protocol::AUTH_REQUIRED {
                                events.send(FromAgent::LoginRequired(logins.clone())).await?;
                            }
                            break Err(rpc_error(error, setup, &logins));
                        }
                    },
                    Some(Pending::Prompt) => {
                        let event = match result {
                            Ok(result) => FromAgent::TurnEnded {
                                stop_reason: result
                                    .get("stopReason")
                                    .and_then(Value::as_str)
                                    .unwrap_or("end_turn")
                                    .to_owned(),
                            },
                            Err(error) => {
                                if error.code == protocol::AUTH_REQUIRED {
                                    events.send(FromAgent::LoginRequired(logins.clone())).await?;
                                }
                                FromAgent::TurnFailed(format!("{:#}", rpc_error(error, setup, &logins)))
                            }
                        };
                        events.send(event).await?;
                    }
                    // Deleting the old conversation is a courtesy: its outcome changes nothing.
                    Some(Pending::Delete) | None => {}
                },
                Some(Incoming::Request { id, method, params }) => {
                    if method == "session/request_permission" {
                        let request = next_permission;
                        next_permission += 1;
                        permissions.insert(request, id);
                        let ask = protocol::permission_ask(&params);
                        events.send(FromAgent::Permission { request, ask }).await?;
                    } else {
                        // No file system, no terminal, no forms: Cratty offered none of them.
                        reply(id, Err((protocol::METHOD_NOT_FOUND, "not supported by Cratty")));
                    }
                }
                Some(Incoming::Notification { method, params }) => {
                    if method == "session/update"
                        && let Some(update) = protocol::update(&params)
                    {
                        events.send(FromAgent::Update(update)).await?;
                    }
                }
            },
        }
    };

    drop(out);
    let _ = writing.await;
    outcome
}

async fn read_messages<R: AsyncRead + Unpin>(reader: R, incoming: mpsc::UnboundedSender<Incoming>) {
    let mut reader = BufReader::new(reader);
    let mut line = Vec::new();
    loop {
        line.clear();
        match (&mut reader)
            .take(MAX_LINE)
            .read_until(b'\n', &mut line)
            .await
        {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        // Agents may print other things; only JSON-RPC objects count.
        let Ok(message) = serde_json::from_slice::<Value>(&line) else {
            continue;
        };
        let method = message
            .get("method")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        let item = match (method, message.get("id").cloned()) {
            (Some(method), Some(id)) if !id.is_null() => Incoming::Request { id, method, params },
            (Some(method), _) => Incoming::Notification { method, params },
            (None, Some(id)) => {
                let Some(id) = id.as_u64() else { continue };
                let result = match message.get("error") {
                    Some(error) => Err(RpcError {
                        code: error.get("code").and_then(Value::as_i64).unwrap_or(0),
                        message: error
                            .get("message")
                            .and_then(Value::as_str)
                            .unwrap_or("error")
                            .to_owned(),
                    }),
                    None => Ok(message.get("result").cloned().unwrap_or(Value::Null)),
                };
                Incoming::Response { id, result }
            }
            (None, None) => continue,
        };
        if incoming.unbounded_send(item).is_err() {
            return;
        }
    }
}

fn rpc_error(error: RpcError, setup: &Setup, logins: &[LoginMethod]) -> anyhow::Error {
    match error.code {
        // The window offers the agent's own ways to sign in.
        protocol::AUTH_REQUIRED if !logins.is_empty() => anyhow!("{}", error.message),
        protocol::AUTH_REQUIRED => anyhow!(
            "{}: sign in by running `{}` in a terminal, then start the chat again",
            error.message,
            setup.login
        ),
        _ => anyhow!("{} ({})", error.message, error.code),
    }
}

fn agent_title(initialize: &Value) -> String {
    let info = initialize.get("agentInfo");
    let name = info
        .and_then(|info| info.get("title").or_else(|| info.get("name")))
        .and_then(Value::as_str)
        .unwrap_or_default();
    match info
        .and_then(|info| info.get("version"))
        .and_then(Value::as_str)
    {
        Some(version) if !name.is_empty() => format!("{name} {version}"),
        _ => name.to_owned(),
    }
}
