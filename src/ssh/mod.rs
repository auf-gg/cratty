pub mod auth;
pub mod forward;
pub mod known_hosts;
pub mod route;
mod session;
pub mod sftp;

use std::thread::JoinHandle;

use bytes::Bytes;
use futures::channel::mpsc;

pub use known_hosts::{HostKeyPolicy, HostKeyVerdict};
pub use route::{Hop, JumpHost, Socks5Hop};
pub use session::STORED_PASSWORD_REJECTED;

const OUTPUT_CAPACITY: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PtySize {
    pub cols: u16,
    pub rows: u16,
    pub pixel_width: u16,
    pub pixel_height: u16,
}

impl PtySize {
    pub fn new(cols: u16, rows: u16) -> Self {
        Self {
            cols: cols.max(1),
            rows: rows.max(1),
            pixel_width: 0,
            pixel_height: 0,
        }
    }
}

impl Default for PtySize {
    fn default() -> Self {
        Self::new(80, 24)
    }
}

#[derive(Clone)]
pub enum AuthMethod {
    Password(String),
    Plan(auth::AuthPlan),
}

impl std::fmt::Debug for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password(_) => f.write_str("Password(<скрыт>)"),
            Self::Plan(plan) => write!(f, "Plan({:?})", plan.order),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretKind {
    Password,
    Passphrase,
    Challenge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostKeyDecision {
    Accept { remember: bool },
    Reject,
}

#[derive(Clone)]
pub enum Answer {
    Secret(Option<String>),
    HostKey(HostKeyDecision),
}

impl std::fmt::Debug for Answer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Secret(Some(_)) => f.write_str("Secret(<скрыт>)"),
            Self::Secret(None) => f.write_str("Secret(отказ)"),
            Self::HostKey(decision) => write!(f, "HostKey({decision:?})"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: AuthMethod,
    pub stored_password: Option<proto::Secret>,
    pub host_key_policy: HostKeyPolicy,
    pub agent: Option<crate::agent::Address>,
    pub term: String,
    pub pty: PtySize,
    pub via: Result<Vec<Hop>, String>,
    pub forward_agent: bool,
    pub forwards: Vec<proto::PortForward>,
}

impl SshConfig {
    pub fn new(
        host: impl Into<String>,
        port: u16,
        user: impl Into<String>,
        auth: AuthMethod,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            user: user.into(),
            auth,
            stored_password: None,
            host_key_policy: HostKeyPolicy::KnownHosts,
            agent: None,
            term: "xterm-256color".into(),
            pty: PtySize::default(),
            via: Ok(Vec::new()),
            forward_agent: false,
            forwards: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub enum ToSsh {
    OpenSftp(sftp::SftpAttach),
    Input(Bytes),
    Resize(PtySize),
    SetForward { index: usize, enabled: bool },
    Disconnect,
}

#[derive(Clone, Debug)]
pub enum FromSsh {
    Connected {
        fingerprint: String,
    },
    Output(Bytes),
    NeedSecret {
        prompt: String,
        kind: SecretKind,
    },
    NeedHostKey {
        host: String,
        port: u16,
        fingerprint: String,
        message: String,
        changed: bool,
    },
    Forward {
        index: usize,
        state: forward::ForwardState,
    },
    Closed(CloseReason),
}

#[derive(Clone, Debug)]
pub enum CloseReason {
    Remote { exit_status: Option<u32> },
    Local,
    Error(String),
}

pub struct SshSession {
    pub commands: mpsc::UnboundedSender<ToSsh>,
    pub answers: mpsc::UnboundedSender<Answer>,
    pub events: mpsc::Receiver<FromSsh>,
    thread: Option<JoinHandle<()>>,
}

pub fn closed_events() -> mpsc::Receiver<FromSsh> {
    mpsc::channel(0).1
}

impl SshSession {
    pub fn open_sftp(&self) -> sftp::SftpHandle {
        let (handle, attach) = sftp::attach();
        let _ = self.commands.unbounded_send(ToSsh::OpenSftp(attach));
        handle
    }

    pub fn join(mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for SshSession {
    fn drop(&mut self) {
        self.events.close();
        self.commands.close_channel();
        self.answers.close_channel();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub fn spawn_ssh(config: SshConfig) -> std::io::Result<SshSession> {
    let (command_tx, command_rx) = mpsc::unbounded();
    let (answer_tx, answer_rx) = mpsc::unbounded();
    let (event_tx, event_rx) = mpsc::channel(OUTPUT_CAPACITY);

    let thread = std::thread::Builder::new()
        .name(format!("ssh:{}", config.host))
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
            {
                Ok(runtime) => runtime,
                Err(err) => {
                    let mut event_tx = event_tx;
                    let _ = event_tx.try_send(FromSsh::Closed(CloseReason::Error(format!(
                        "не удалось создать tokio-рантайм: {err}"
                    ))));
                    return;
                }
            };
            runtime.block_on(session::run(config, command_rx, answer_rx, event_tx));
        })?;

    Ok(SshSession {
        commands: command_tx,
        answers: answer_tx,
        events: event_rx,
        thread: Some(thread),
    })
}
