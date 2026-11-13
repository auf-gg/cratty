#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use russh::keys::{Algorithm, PrivateKey, ssh_key::HashAlg};
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId, Pty};
use tokio::net::TcpListener;

const USER: &str = "tester";
const PASSWORD: &str = "s3cret";
const PROMPT: &[u8] = b"fake$ ";
pub const OTP: &str = "424242";

#[derive(Default)]
struct Observed {
    interactive_answers: Vec<String>,
    pty: Option<PtyRequest>,
    resizes: Vec<(u32, u32)>,
    auth_attempts: usize,
    public_key: Option<String>,
    connections: usize,
    tunnels: Vec<(String, u32)>,
    agent_requested: bool,
    handle: Option<server::Handle>,
    execs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PtyRequest {
    pub term: String,
    pub cols: u32,
    pub rows: u32,
    pub modes: HashMap<u8, u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AuthMode {
    #[default]
    PasswordOnly,
    SinglePrompt,
    TwoPrompts,
    PublicKeyOnly,
}

pub struct FakeSshd {
    addr: SocketAddr,
    fingerprint: String,
    observed: Arc<Mutex<Observed>>,
    shutdown: server::RunningServerHandle,
}

impl FakeSshd {
    pub async fn start() -> Self {
        Self::start_with_auth(AuthMode::PasswordOnly).await
    }

    pub async fn start_with_auth(mode: AuthMode) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("could not bind a port for the test sshd");
        let addr = listener.local_addr().expect("listener has no address");

        let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
            .expect("could not generate a host key");
        let fingerprint = host_key
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string();

        let config = Arc::new(server::Config {
            auth_rejection_time: std::time::Duration::from_millis(1),
            auth_rejection_time_initial: Some(std::time::Duration::from_millis(0)),
            keys: vec![host_key],
            nodelay: true,
            ..Default::default()
        });

        let observed = Arc::new(Mutex::new(Observed::default()));

        let (handle_tx, handle_rx) = tokio::sync::oneshot::channel();
        let observed_for_server = observed.clone();
        tokio::spawn(async move {
            let listener = listener;
            let mut factory = Factory {
                observed: observed_for_server,
                mode,
            };
            let running = factory.run_on_socket(config, &listener);
            let _ = handle_tx.send(running.handle());
            let _ = running.await;
        });
        let shutdown = handle_rx.await.expect("server did not hand over its shutdown handle");

        Self {
            addr,
            fingerprint,
            observed,
            shutdown,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn fingerprint(&self) -> String {
        self.fingerprint.clone()
    }

    pub fn pty_request(&self) -> Option<PtyRequest> {
        self.lock().pty.clone()
    }

    pub fn resizes(&self) -> Vec<(u32, u32)> {
        self.lock().resizes.clone()
    }

    pub fn public_key(&self) -> Option<String> {
        self.lock().public_key.clone()
    }

    pub fn saw_auth_attempt(&self) -> bool {
        self.lock().auth_attempts > 0
    }

    pub fn interactive_answers(&self) -> Vec<String> {
        self.lock().interactive_answers.clone()
    }

    pub fn connections(&self) -> usize {
        self.lock().connections
    }

    pub fn tunnels(&self) -> Vec<(String, u32)> {
        self.lock().tunnels.clone()
    }

    /// Commands of exec requests, in the order they came.
    pub fn execs(&self) -> Vec<String> {
        self.lock().execs.clone()
    }

    pub fn agent_requested(&self) -> bool {
        self.lock().agent_requested
    }

    pub async fn probe_agent(&self) -> Result<u32, String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let handle = self.lock().handle.clone().ok_or("session not opened yet")?;
        let channel = handle
            .channel_open_agent()
            .await
            .map_err(|error| format!("channel to the agent did not open: {error}"))?;
        let mut stream = channel.into_stream();

        stream
            .write_all(&[0, 0, 0, 1, 11])
            .await
            .map_err(|error| error.to_string())?;
        let mut head = [0u8; 9];
        stream
            .read_exact(&mut head)
            .await
            .map_err(|error| error.to_string())?;
        if head[4] != 12 {
            return Err(format!("agent replied with code {}", head[4]));
        }
        Ok(u32::from_be_bytes([head[5], head[6], head[7], head[8]]))
    }

    pub fn user(&self) -> &'static str {
        USER
    }

    pub fn password(&self) -> &'static str {
        PASSWORD
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Observed> {
        self.observed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Drop for FakeSshd {
    fn drop(&mut self) {
        self.shutdown.shutdown("test finished".into());
    }
}

struct Factory {
    observed: Arc<Mutex<Observed>>,
    mode: AuthMode,
}

impl server::Server for Factory {
    type Handler = Shell;

    fn new_client(&mut self, _peer: Option<SocketAddr>) -> Shell {
        if let Ok(mut observed) = self.observed.lock() {
            observed.connections += 1;
        }
        Shell {
            observed: self.observed.clone(),
            line: Vec::new(),
            mode: self.mode,
            asked_prompts: 0,
            tunnels: std::collections::HashSet::new(),
            execs: HashMap::new(),
        }
    }
}

struct Shell {
    observed: Arc<Mutex<Observed>>,
    line: Vec<u8>,
    mode: AuthMode,
    asked_prompts: usize,
    tunnels: std::collections::HashSet<ChannelId>,
    /// Exec channels: input for the command's standard input; dropped on EOF.
    execs: HashMap<ChannelId, tokio::sync::mpsc::UnboundedSender<Vec<u8>>>,
}

impl Shell {
    fn observe<R>(&self, f: impl FnOnce(&mut Observed) -> R) -> R {
        let mut guard = self
            .observed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f(&mut guard)
    }

    fn run_line(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<bool, russh::Error> {
        let line = String::from_utf8_lossy(&self.line).trim().to_string();
        self.line.clear();

        if line == "exit" {
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            session.close(channel)?;
            return Ok(true);
        }

        if let Some(rest) = line.strip_prefix("echo ") {
            session.data(channel, format!("{rest}\r\n").into_bytes())?;
        } else if !line.is_empty() {
            session.data(
                channel,
                format!("fake: unknown command: {line}\r\n").into_bytes(),
            )?;
        }

        session.data(channel, PROMPT.to_vec())?;
        Ok(false)
    }
}

impl server::Handler for Shell {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.observe(|observed| observed.auth_attempts += 1);

        if self.mode != AuthMode::PasswordOnly {
            return Ok(Auth::reject());
        }

        if user == USER && password == PASSWORD {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.observe(|observed| observed.auth_attempts += 1);

        if self.mode != AuthMode::PublicKeyOnly || user != USER {
            return Ok(Auth::reject());
        }

        let fingerprint = key
            .fingerprint(russh::keys::ssh_key::HashAlg::Sha256)
            .to_string();
        self.observe(|observed| observed.public_key = Some(fingerprint.clone()));
        Ok(Auth::Accept)
    }

    async fn auth_keyboard_interactive(
        &mut self,
        user: &str,
        _submethods: &str,
        response: Option<russh::server::Response<'_>>,
    ) -> Result<Auth, Self::Error> {
        use std::borrow::Cow;

        if self.mode == AuthMode::PasswordOnly {
            return Ok(Auth::reject());
        }

        let Some(mut response) = response else {
            self.observe(|observed| observed.auth_attempts += 1);
            self.asked_prompts = match self.mode {
                AuthMode::TwoPrompts => 2,
                _ => 1,
            };
            let prompts: Vec<(Cow<'static, str>, bool)> = match self.mode {
                AuthMode::TwoPrompts => vec![
                    (Cow::Borrowed("Password: "), false),
                    (Cow::Borrowed("Verification code: "), false),
                ],
                _ => vec![(Cow::Borrowed("Password: "), false)],
            };
            return Ok(Auth::Partial {
                name: Cow::Borrowed(""),
                instructions: Cow::Borrowed(""),
                prompts: Cow::Owned(prompts),
            });
        };

        let answers: Vec<String> = std::iter::from_fn(|| {
            response
                .next()
                .map(|bytes| String::from_utf8_lossy(bytes.as_ref()).into_owned())
        })
        .collect();

        self.observe(|observed| observed.interactive_answers = answers.clone());

        let ok = user == USER
            && answers.len() == self.asked_prompts
            && answers.first().map(String::as_str) == Some(PASSWORD)
            && match self.mode {
                AuthMode::TwoPrompts => answers.get(1).map(String::as_str) == Some(OTP),
                _ => true,
            };

        if ok {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.observe(|observed| {
            observed
                .tunnels
                .push((host_to_connect.to_string(), port_to_connect))
        });
        let Ok(port) = u16::try_from(port_to_connect) else {
            return Ok(());
        };
        let Ok(mut tcp) = tokio::net::TcpStream::connect((host_to_connect, port)).await else {
            return Ok(());
        };
        self.tunnels.insert(channel.id());
        reply.accept().await;
        tokio::spawn(async move {
            let mut stream = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
        });
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.observe(|observed| {
            observed.pty = Some(PtyRequest {
                term: term.to_string(),
                cols: col_width,
                rows: row_height,
                modes: modes
                    .iter()
                    .map(|(pty, value)| (*pty as u8, *value))
                    .collect(),
            });
        });
        session.channel_success(channel)?;
        Ok(())
    }

    async fn agent_request(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.observe(|observed| observed.agent_requested = true);
        Ok(true)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let handle = session.handle();
        self.observe(|observed| observed.handle = Some(handle));
        session.channel_success(channel)?;
        session.data(channel, PROMPT.to_vec())?;
        Ok(())
    }

    /// Runs the command with the local `sh`, like a real server with a POSIX login shell.
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        use std::process::Stdio;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let command = String::from_utf8_lossy(data).into_owned();
        self.observe(|observed| observed.execs.push(command.clone()));
        let spawned = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(&command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn();
        let Ok(mut child) = spawned else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        session.channel_success(channel)?;

        let (input, mut inputs) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        self.execs.insert(channel, input);
        let mut stdin = child.stdin.take().expect("piped stdin");
        tokio::spawn(async move {
            while let Some(chunk) = inputs.recv().await {
                if stdin.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        });

        let handle = session.handle();
        let mut stdout = child.stdout.take().expect("piped stdout");
        let mut stderr = child.stderr.take().expect("piped stderr");
        tokio::spawn(async move {
            let out = async {
                let mut buffer = vec![0u8; 8192];
                while let Ok(read @ 1..) = stdout.read(&mut buffer).await {
                    if handle.data(channel, buffer[..read].to_vec()).await.is_err() {
                        break;
                    }
                }
            };
            let err = async {
                let mut buffer = vec![0u8; 8192];
                while let Ok(read @ 1..) = stderr.read(&mut buffer).await {
                    if handle
                        .extended_data(channel, 1, buffer[..read].to_vec())
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            };
            tokio::join!(out, err);
            let code = child
                .wait()
                .await
                .ok()
                .and_then(|status| status.code())
                .unwrap_or(255);
            let _ = handle.exit_status_request(channel, code as u32).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        });
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.execs.remove(&channel);
        Ok(())
    }

    /// No SFTP here: clients fall back to commands.
    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        _channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.observe(|observed| observed.resizes.push((col_width, row_height)));
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.tunnels.contains(&channel) {
            return Ok(());
        }
        if let Some(input) = self.execs.get(&channel) {
            let _ = input.send(data.to_vec());
            return Ok(());
        }
        let mut echo = Vec::with_capacity(data.len());
        for byte in data {
            match byte {
                b'\r' | b'\n' => echo.extend_from_slice(b"\r\n"),
                other => echo.push(*other),
            }
        }
        session.data(channel, echo)?;

        for byte in data {
            match byte {
                b'\r' | b'\n' => {
                    if self.run_line(channel, session)? {
                        return Ok(());
                    }
                }
                other => self.line.push(*other),
            }
        }
        Ok(())
    }
}
