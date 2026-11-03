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
            .expect("не удалось занять порт под тестовый sshd");
        let addr = listener.local_addr().expect("у слушателя нет адреса");

        let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
            .expect("не удалось сгенерировать ключ хоста");
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
        let shutdown = handle_rx.await.expect("сервер не отдал ручку остановки");

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

    pub fn agent_requested(&self) -> bool {
        self.lock().agent_requested
    }

    pub async fn probe_agent(&self) -> Result<u32, String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let handle = self.lock().handle.clone().ok_or("сессия ещё не открыта")?;
        let channel = handle
            .channel_open_agent()
            .await
            .map_err(|error| format!("канал к агенту не открылся: {error}"))?;
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
            return Err(format!("агент ответил кодом {}", head[4]));
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
        self.shutdown.shutdown("тест закончился".into());
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
        }
    }
}

struct Shell {
    observed: Arc<Mutex<Observed>>,
    line: Vec<u8>,
    mode: AuthMode,
    asked_prompts: usize,
    tunnels: std::collections::HashSet<ChannelId>,
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
                format!("fake: неизвестная команда: {line}\r\n").into_bytes(),
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
