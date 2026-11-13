//! Cratty as an MCP server: AI agents (Claude Code, OpenCode, Codex…) work on the
//! servers of open tabs through it, over the connections those tabs already have.
//!
//! The server listens on a local socket next to the instance one. An agent starts
//! `cratty --mcp-bridge` as an ordinary stdio MCP server; the bridge connects to the
//! socket, presents the access token of one tab and then passes MCP messages through.
//! A token is made when the user allows agent access on a tab and lives only in memory:
//! closing the tab, revoking access or restarting the app ends it.
//!
//! The window checks every tool call: the token must still belong to an open tab, and
//! commands and file changes wait for the user's approval. The agent's own permission
//! settings play no part in it.

pub mod bridge;
mod protocol;
pub mod tools;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures::StreamExt;
use futures::channel::{mpsc, oneshot};
use rust_i18n::t;
use serde_json::{Value, json};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};

use crate::agent::{Address, Listener};
use crate::ssh::remote::Remote;
use protocol::Incoming;
pub use tools::Action;

/// The name agents know the server by: its tools become `mcp__cratty__run_command`.
pub const SERVER_NAME: &str = "cratty";

const MAX_HELLO: u64 = 4 * 1024;
/// The longest message: a file written whole, escaped as JSON.
const MAX_MESSAGE: u64 = 16 * 1024 * 1024;
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

const UNKNOWN_TOKEN: &str = "Cratty has no agent access with this token: it was revoked, the tab \
     was closed or Cratty was restarted. Allow agent access on the tab again and use the new MCP \
     configuration.";
const WINDOW_GONE: &str = "Cratty is closing and no longer takes requests";

/// A bridge has connected, or a tool call wants to run.
pub enum Ask {
    /// Which tab does this token open? `None` when no tab has it.
    Hello {
        token: String,
        reply: oneshot::Sender<Option<SessionInfo>>,
    },
    Call(Box<CallAsk>),
    /// A call waiting for approval is no longer wanted: the agent cancelled it or left.
    Withdraw {
        id: u64,
    },
}

pub struct CallAsk {
    pub id: u64,
    pub token: String,
    pub action: Action,
    pub reply: oneshot::Sender<Result<Grant, String>>,
}

/// What a call may use once allowed.
pub enum Grant {
    Remote(Remote),
    /// The text of the tab's terminal.
    Screen(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionInfo {
    pub title: String,
    pub target: String,
}

pub struct Running {
    address: Address,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Running {
    pub fn address(&self) -> &Address {
        &self.address
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub fn spawn(address: Address) -> Result<(Running, mpsc::UnboundedReceiver<Ask>)> {
    let (asks_tx, asks_rx) = mpsc::unbounded();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
    let ids = Arc::new(AtomicU64::new(1));

    let bound = address.clone();
    let thread = std::thread::Builder::new()
        .name("mcp".to_owned())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ =
                        ready_tx.send(Err(t!("agent.runtime_failed", error = error).into_owned()));
                    return;
                }
            };

            runtime.block_on(async move {
                #[allow(unused_mut)]
                let mut listener = match Listener::bind(&bound).await {
                    Ok(listener) => {
                        let _ = ready_tx.send(Ok(()));
                        listener
                    }
                    Err(error) => {
                        let _ = ready_tx.send(Err(format!("{error:#}")));
                        return;
                    }
                };

                loop {
                    tokio::select! {
                        biased;
                        _ = &mut stop_rx => return,
                        accepted = listener.accept() => {
                            let Ok(stream) = accepted else { return };
                            let asks = asks_tx.clone();
                            let ids = ids.clone();
                            tokio::spawn(async move {
                                let _ = serve_connection(stream, asks, ids).await;
                            });
                        }
                    }
                }
            });
            // Calls still running belong to agents that are going away with the app.
            runtime.shutdown_background();
        })
        .context(t!("ai.server_thread_failed"))?;

    match ready_rx.recv() {
        Ok(Ok(())) => Ok((
            Running {
                address,
                stop: Some(stop_tx),
                thread: Some(thread),
            },
            asks_rx,
        )),
        Ok(Err(error)) => {
            let _ = thread.join();
            bail!("{error}")
        }
        Err(_) => {
            let _ = thread.join();
            bail!(t!("ai.server_thread_failed"))
        }
    }
}

/// A fresh access token for one tab.
pub fn new_token() -> Result<String> {
    let mut bytes = [0u8; 24];
    getrandom::fill(&mut bytes).map_err(|error| anyhow!("{error}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// The path agents start for the bridge: this executable.
pub fn bridge_executable() -> Result<String> {
    let path = std::env::current_exe()?;
    Ok(path.to_string_lossy().into_owned())
}

/// The `mcpServers` configuration that Claude Code, Cursor, Gemini CLI and others read.
pub fn client_config(token: &str, address: &Address) -> Result<Value> {
    Ok(json!({
        "mcpServers": {
            SERVER_NAME: {
                "type": "stdio",
                "command": bridge_executable()?,
                "args": [bridge::FLAG],
                "env": {
                    bridge::TOKEN_VAR: token,
                    bridge::ADDRESS_VAR: address.as_text(),
                },
            }
        }
    }))
}

/// Starts Claude Code with only this server: none of the user's other MCP servers and
/// none of the built-in tools, which would act on this computer rather than the server.
/// Cratty asks the user about every change itself, so Claude Code need not ask again.
pub fn claude_command(config: &Value) -> String {
    format!(
        "claude --strict-mcp-config --mcp-config {} --tools '' --allowedTools mcp__{SERVER_NAME}",
        crate::ssh::remote::quote(&config.to_string())
    )
}

/// What a tool call goes through: the window decides, the call does the work.
#[derive(Clone)]
pub struct Gate {
    token: String,
    asks: mpsc::UnboundedSender<Ask>,
    ids: Arc<AtomicU64>,
}

impl Gate {
    async fn ask(&self, action: Action) -> Result<Grant, String> {
        let id = self.ids.fetch_add(1, Ordering::Relaxed);
        let (reply, answer) = oneshot::channel();
        self.asks
            .unbounded_send(Ask::Call(Box::new(CallAsk {
                id,
                token: self.token.clone(),
                action,
                reply,
            })))
            .map_err(|_| WINDOW_GONE.to_owned())?;
        let mut withdraw = Withdraw {
            id,
            asks: Some(self.asks.clone()),
        };
        let answer = answer.await;
        withdraw.asks = None;
        answer.map_err(|_| WINDOW_GONE.to_owned())?
    }

    pub async fn remote(&self, action: Action) -> Result<Remote, String> {
        match self.ask(action).await? {
            Grant::Remote(remote) => Ok(remote),
            Grant::Screen(_) => Err("unexpected answer from Cratty".into()),
        }
    }

    pub async fn screen(&self, rows: usize) -> Result<String, String> {
        match self.ask(Action::Screen { rows }).await? {
            Grant::Screen(text) => Ok(text),
            Grant::Remote(_) => Err("unexpected answer from Cratty".into()),
        }
    }
}

/// Takes a call back from the window when it is dropped before the answer came.
struct Withdraw {
    id: u64,
    asks: Option<mpsc::UnboundedSender<Ask>>,
}

impl Drop for Withdraw {
    fn drop(&mut self) {
        if let Some(asks) = self.asks.take() {
            let _ = asks.unbounded_send(Ask::Withdraw { id: self.id });
        }
    }
}

/// One bridge: a hello line with the token, then MCP messages, one JSON object per line.
pub async fn serve_connection<S>(
    stream: S,
    asks: mpsc::UnboundedSender<Ask>,
    ids: Arc<AtomicU64>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (read, mut write) = tokio::io::split(stream);
    let mut reader = BufReader::new(read);
    let mut line = Vec::new();

    tokio::time::timeout(HELLO_TIMEOUT, read_line(&mut reader, &mut line, MAX_HELLO))
        .await
        .context("the bridge sent no hello")??;
    let token = serde_json::from_slice::<Value>(&line)
        .ok()
        .and_then(|hello| hello.get("token")?.as_str().map(str::to_owned))
        .unwrap_or_default();
    let (reply, answer) = oneshot::channel();
    asks.unbounded_send(Ask::Hello {
        token: token.clone(),
        reply,
    })
    .map_err(|_| anyhow!(WINDOW_GONE))?;
    let Some(info) = answer.await.ok().flatten() else {
        write_message(&mut write, &json!({ "error": UNKNOWN_TOKEN })).await?;
        return Ok(());
    };
    write_message(&mut write, &json!({ "ok": true })).await?;

    let (out, mut outgoing) = mpsc::unbounded::<Value>();
    let writer = tokio::spawn(async move {
        while let Some(message) = outgoing.next().await {
            if write_message(&mut write, &message).await.is_err() {
                break;
            }
        }
    });
    let send = |message: Value| {
        let _ = out.unbounded_send(message);
    };

    let gate = Gate { token, asks, ids };
    let mut calls: HashMap<String, tokio::task::AbortHandle> = HashMap::new();
    let mut running = tokio::task::JoinSet::new();

    loop {
        line.clear();
        if read_line(&mut reader, &mut line, MAX_MESSAGE).await? == 0 {
            break;
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        match protocol::parse(&line) {
            Incoming::Request { id, method, params } => match method.as_str() {
                "initialize" => send(protocol::result_reply(
                    id,
                    protocol::initialize(&params, &info),
                )),
                "ping" => send(protocol::result_reply(id, json!({}))),
                "tools/list" => send(protocol::result_reply(
                    id,
                    json!({ "tools": tools::definitions() }),
                )),
                "tools/call" => {
                    let key = id.to_string();
                    let gate = gate.clone();
                    let out = out.clone();
                    let handle = running.spawn(async move {
                        let reply = call(id, params, &gate).await;
                        let _ = out.unbounded_send(reply);
                    });
                    while running.try_join_next().is_some() {}
                    calls.retain(|_, call| !call.is_finished());
                    calls.insert(key, handle);
                }
                _ => send(protocol::error_reply(
                    id,
                    protocol::METHOD_NOT_FOUND,
                    &format!("unknown method: {method}"),
                )),
            },
            Incoming::Notification { method, params } => {
                if method == "notifications/cancelled"
                    && let Some(call) = params
                        .get("requestId")
                        .and_then(|id| calls.remove(&id.to_string()))
                {
                    call.abort();
                }
            }
            Incoming::Response => {}
            Incoming::Invalid(reply) => send(reply),
        }
    }

    // The agent has gone: calls still waiting for approval are withdrawn.
    drop(running);
    drop(out);
    let _ = writer.await;
    Ok(())
}

async fn call(id: Value, params: Value, gate: &Gate) -> Value {
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return protocol::error_reply(id, protocol::INVALID_PARAMS, "tools/call needs a tool name");
    };
    let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
    let outcome = match tools::parse(name, arguments) {
        Ok(call) => tools::run(call, gate).await,
        Err(error) => Err(error),
    };
    protocol::result_reply(id, protocol::tool_result(outcome))
}

async fn read_line<R>(reader: &mut R, line: &mut Vec<u8>, max: u64) -> Result<usize>
where
    R: AsyncBufRead + Unpin,
{
    let read = (&mut *reader).take(max).read_until(b'\n', line).await?;
    if read as u64 == max && !line.ends_with(b"\n") {
        bail!("message longer than {max} bytes");
    }
    Ok(read)
}

async fn write_message<W: AsyncWrite + Unpin>(write: &mut W, message: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec(message)?;
    bytes.push(b'\n');
    write.write_all(&bytes).await?;
    write.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_long_and_different() {
        let first = new_token().expect("token");
        assert_eq!(first.len(), 48);
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(first, new_token().expect("token"));
    }

    #[test]
    fn config_starts_the_bridge_with_the_token() {
        let address = Address::Socket("/run/user/1000/cratty/mcp.sock".into());
        let config = client_config("abc", &address).expect("config");
        let server = &config["mcpServers"]["cratty"];
        assert_eq!(server["args"], json!(["--mcp-bridge"]));
        assert_eq!(server["env"]["CRATTY_MCP_TOKEN"], "abc");
        assert_eq!(server["env"]["CRATTY_MCP_ADDRESS"], address.as_text());

        let command = claude_command(&config);
        assert!(command.starts_with("claude --strict-mcp-config --mcp-config '{"));
        assert!(command.ends_with("--tools '' --allowedTools mcp__cratty"));
    }
}
