use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};
use russh::keys::PublicKeyOrCertificate;
use russh::keys::agent::AgentIdentity;
use russh::keys::agent::client::{AgentClient, AgentStream};
use russh::{Channel, ChannelMsg, ChannelWriteHalf, Disconnect, Pty, client};

use super::auth::{self, Credential};
use super::known_hosts::{self, HostKeyPolicy};
use super::route::{self, Hop, JumpHost, Transport};
use super::{
    Answer, AuthMethod, CloseReason, FromSsh, HostKeyDecision, HostKeyVerdict, PtySize, SecretKind,
    SshConfig, ToSsh,
};

const PTY_MODES: &[(Pty, u32)] = &[
    (Pty::ECHO, 1),
    (Pty::TTY_OP_ISPEED, 14_400),
    (Pty::TTY_OP_OSPEED, 14_400),
];

const KEEPALIVE: Duration = Duration::from_secs(30);

pub(super) async fn run(
    config: SshConfig,
    commands: mpsc::UnboundedReceiver<ToSsh>,
    answers: mpsc::UnboundedReceiver<Answer>,
    mut events: mpsc::Sender<FromSsh>,
) {
    let host = config.host.clone();
    let port = config.port;

    let prompter = Prompter::new(events.clone(), answers);

    let reason = match serve(config, commands, prompter, &mut events).await {
        Ok(reason) => reason,
        Err(err) => CloseReason::Error(format!("{host}:{port}: {err:#}")),
    };

    let _ = events.send(FromSsh::Closed(reason)).await;
    events.close_channel();
}

pub(super) struct Connected {
    pub session: Arc<client::Handle<Verifier>>,
    pub remote_forwards: super::forward::RemoteMap,
    pub jumps: Vec<client::Handle<Verifier>>,
    pub fingerprint: String,
}

impl Connected {
    pub async fn disconnect(self) {
        let _ = self
            .session
            .disconnect(Disconnect::ByApplication, "", "")
            .await;
        for jump in self.jumps.into_iter().rev() {
            let _ = jump.disconnect(Disconnect::ByApplication, "", "").await;
        }
    }
}

pub(super) async fn connect(config: &SshConfig, prompter: &Prompter) -> Result<Connected> {
    let fingerprint = Arc::new(Mutex::new(None));
    let remote_forwards = super::forward::RemoteMap::default();
    let verifier = Verifier {
        policy: config.host_key_policy.clone(),
        host: config.host.clone(),
        port: config.port,
        fingerprint: fingerprint.clone(),
        prompter: prompter.clone(),
        forward_agent: config.forward_agent,
        agent: config.agent.clone(),
        remote_forwards: remote_forwards.clone(),
    };

    let client_config = Arc::new(client::Config {
        nodelay: true,
        keepalive_interval: Some(KEEPALIVE),
        ..Default::default()
    });

    let hops = config.via.clone().map_err(|reason| anyhow!("{reason}"))?;

    let (transport, jumps) = open_route(config, &hops, &client_config, prompter).await?;

    let mut session = client::connect_stream(client_config, transport, verifier)
        .await
        .with_context(|| format!("подключение к {}", route::join(&config.host, config.port)))?;

    authenticate(&mut session, &Login::target(config), prompter).await?;

    let fingerprint = fingerprint
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .unwrap_or_else(|| "<неизвестен>".to_string());

    Ok(Connected {
        session: Arc::new(session),
        remote_forwards,
        jumps,
        fingerprint,
    })
}

async fn serve(
    config: SshConfig,
    mut commands: mpsc::UnboundedReceiver<ToSsh>,
    prompter: Prompter,
    events: &mut mpsc::Sender<FromSsh>,
) -> Result<CloseReason> {
    let connected = connect(&config, &prompter).await?;
    let session = &connected.session;

    let mut channel = session
        .channel_open_session()
        .await
        .context("сервер не открыл сессионный канал")?;

    let mut early = Vec::new();

    channel
        .request_pty(
            true,
            &config.term,
            config.pty.cols as u32,
            config.pty.rows as u32,
            config.pty.pixel_width as u32,
            config.pty.pixel_height as u32,
            PTY_MODES,
        )
        .await
        .context("запрос PTY")?;
    await_reply(&mut channel, "выделение PTY", &mut early).await?;

    if config.forward_agent {
        channel
            .agent_forward(false)
            .await
            .context("запрос проброса агента")?;
    }

    channel.request_shell(true).await.context("запрос shell")?;
    await_reply(&mut channel, "запуск shell", &mut early).await?;

    events
        .send(FromSsh::Connected {
            fingerprint: connected.fingerprint.clone(),
        })
        .await?;

    for data in early.drain(..) {
        events.send(FromSsh::Output(data)).await?;
    }

    let mut forwards = super::forward::Forwards::new(
        connected.session.clone(),
        connected.remote_forwards.clone(),
        config.forwards.clone(),
        events.clone(),
    );
    forwards.start_enabled().await;

    let (mut reader, writer) = channel.split();
    let mut exit_status = None;

    let reason = loop {
        tokio::select! {
            message = reader.wait() => match message {
                Some(ChannelMsg::Data { data }) => events.send(FromSsh::Output(data)).await?,
                Some(ChannelMsg::ExtendedData { data, .. }) => {
                    events.send(FromSsh::Output(data)).await?
                }
                Some(ChannelMsg::ExitStatus { exit_status: status }) => exit_status = Some(status),
                Some(ChannelMsg::ExitSignal { signal_name, error_message, .. }) => {
                    let text = if error_message.is_empty() {
                        format!("\r\nshell убит сигналом {signal_name:?}\r\n")
                    } else {
                        format!("\r\nshell убит сигналом {signal_name:?}: {error_message}\r\n")
                    };
                    events.send(FromSsh::Output(Bytes::from(text))).await?;
                }
                Some(ChannelMsg::Eof) => {}
                Some(ChannelMsg::Close) | None => {
                    break CloseReason::Remote { exit_status };
                }
                Some(_) => {}
            },
            command = commands.next() => match command {
                Some(ToSsh::Input(data)) => writer
                    .data_bytes(data)
                    .await
                    .context("отправка ввода в PTY")?,
                Some(ToSsh::Resize(size)) => resize(&writer, size).await?,
                Some(ToSsh::SetForward { index, enabled }) => forwards.set(index, enabled).await,
                Some(ToSsh::OpenSftp(attach)) => match session.channel_open_session().await {
                    Ok(channel) => {
                        tokio::spawn(attach.run(channel));
                    }
                    Err(error) => {
                        attach.fail(format!("сервер не открыл канал для файлов: {error}")).await;
                    }
                },
                Some(ToSsh::Disconnect) | None => {
                    let _ = writer.eof().await;
                    break CloseReason::Local;
                }
            },
        }
    };

    drop(forwards);
    connected.disconnect().await;

    Ok(reason)
}

async fn open_route(
    config: &SshConfig,
    hops: &[Hop],
    client_config: &Arc<client::Config>,
    prompter: &Prompter,
) -> Result<(Transport, Vec<client::Handle<Verifier>>)> {
    let next = |index: usize| -> (String, u16) {
        match hops.get(index + 1) {
            Some(hop) => {
                let (host, port) = hop.address();
                (host.to_owned(), port)
            }
            None => (config.host.clone(), config.port),
        }
    };

    let (first_host, first_port) = match hops.first() {
        Some(hop) => hop.address(),
        None => (config.host.as_str(), config.port),
    };
    let mut stream =
        route::tcp(first_host, first_port)
            .await
            .with_context(|| match hops.first() {
                Some(hop) => format!("подключение к {}", hop.describe()),
                None => format!("подключение к {}", route::join(&config.host, config.port)),
            })?;

    let mut jumps = Vec::new();
    for (index, hop) in hops.iter().enumerate() {
        let (host, port) = next(index);
        stream = match hop {
            Hop::Socks5(socks) => route::socks5(stream, socks, &host, port)
                .await
                .with_context(|| {
                    format!(
                        "{} не соединил с {}",
                        hop.describe(),
                        route::join(&host, port)
                    )
                })?,
            Hop::Jump(jump) => {
                let (session, channel) =
                    open_jump(stream, jump, config, client_config, prompter, &host, port)
                        .await
                        .with_context(|| hop.describe())?;
                jumps.push(session);
                channel
            }
        };
    }

    Ok((stream, jumps))
}

async fn open_jump(
    stream: Transport,
    jump: &JumpHost,
    config: &SshConfig,
    client_config: &Arc<client::Config>,
    prompter: &Prompter,
    host: &str,
    port: u16,
) -> Result<(client::Handle<Verifier>, Transport)> {
    let verifier = Verifier {
        policy: jump.host_key_policy.clone(),
        host: jump.host.clone(),
        port: jump.port,
        fingerprint: Arc::new(Mutex::new(None)),
        prompter: prompter.clone(),
        forward_agent: false,
        agent: None,
        remote_forwards: Default::default(),
    };

    let mut session = client::connect_stream(client_config.clone(), stream, verifier)
        .await
        .context("SSH-рукопожатие")?;

    let login = Login {
        user: &jump.user,
        auth: &jump.auth,
        stored_password: jump.stored_password.as_ref(),
        agent: config.agent.as_ref(),
        whom: format!("{}@{}", jump.user, route::join(&jump.host, jump.port)),
    };
    authenticate(&mut session, &login, prompter).await?;

    let channel = session
        .channel_open_direct_tcpip(host, u32::from(port), "127.0.0.1", 0)
        .await
        .with_context(|| format!("хост не открыл туннель до {}", route::join(host, port)))?;

    Ok((session, Box::new(channel.into_stream())))
}

async fn resize(writer: &ChannelWriteHalf<client::Msg>, size: PtySize) -> Result<()> {
    writer
        .window_change(
            size.cols as u32,
            size.rows as u32,
            size.pixel_width as u32,
            size.pixel_height as u32,
        )
        .await
        .context("изменение размера PTY")
}

async fn await_reply(
    channel: &mut Channel<client::Msg>,
    what: &str,
    early: &mut Vec<Bytes>,
) -> Result<()> {
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => return Ok(()),
            Some(ChannelMsg::Failure) => bail!("сервер отказал: {what}"),
            Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                early.push(data)
            }
            Some(ChannelMsg::Eof | ChannelMsg::Close) | None => {
                bail!("канал закрыт, не ответив на запрос: {what}")
            }
            Some(_) => {}
        }
    }
}

struct Login<'a> {
    user: &'a str,
    auth: &'a AuthMethod,
    stored_password: Option<&'a proto::Secret>,
    agent: Option<&'a crate::agent::Address>,
    whom: String,
}

impl<'a> Login<'a> {
    fn target(config: &'a SshConfig) -> Self {
        Self {
            user: &config.user,
            auth: &config.auth,
            stored_password: config.stored_password.as_ref(),
            agent: config.agent.as_ref(),
            whom: config.user.clone(),
        }
    }
}

async fn authenticate(
    session: &mut client::Handle<Verifier>,
    login: &Login<'_>,
    prompter: &Prompter,
) -> Result<()> {
    let plan = match login.auth {
        AuthMethod::Password(password) => {
            let result = session
                .authenticate_password(login.user, password.clone())
                .await
                .context("аутентификация по паролю")?;
            return match auth_failure_message(&login.whom, &result) {
                Some(message) => bail!("{message}"),
                None => Ok(()),
            };
        }
        AuthMethod::Plan(plan) => plan.clone(),
    };

    let best_rsa_hash = session.best_supported_rsa_hash().await.ok().flatten();

    let mut attempts: Vec<String> = Vec::new();

    for credential in &plan.order {
        let outcome = match credential {
            Credential::Agent => try_agent(session, login.user, login.agent).await,
            Credential::Key(path) => {
                try_key(session, login.user, path, best_rsa_hash, prompter).await
            }
            Credential::Password => try_password(session, login.user, &login.whom, prompter).await,
            Credential::Stored => match login.stored_password {
                Some(secret) => try_stored_password(session, login.user, secret, prompter).await,
                None => Ok(Attempt::Rejected("сохранённого пароля нет".into())),
            },
        };

        match outcome {
            Ok(Attempt::Succeeded) => return Ok(()),
            Ok(Attempt::Rejected(why)) => attempts.push(why),
            Ok(Attempt::Cancelled) => bail!("вход отменён"),
            Ok(Attempt::StoredRejected) => bail!(
                "{STORED_PASSWORD_REJECTED}: сервер не принял сохранённый пароль \
                 для {}. Обновите его в записи и попробуйте снова.",
                login.whom
            ),
            Err(err) => attempts.push(format!("{err:#}")),
        }
    }

    bail!(
        "не удалось войти как {}. Что пробовали:\n  {}",
        login.whom,
        attempts.join("\n  ")
    )
}

pub const STORED_PASSWORD_REJECTED: &str = "сохранённый пароль отвергнут";

enum Attempt {
    Succeeded,
    Rejected(String),
    Cancelled,
    StoredRejected,
}

async fn try_agent(
    session: &mut client::Handle<Verifier>,
    user: &str,
    own: Option<&crate::agent::Address>,
) -> Result<Attempt> {
    let Some(mut agent) = connect_agent(own).await else {
        return Ok(Attempt::Rejected("ssh-agent недоступен".into()));
    };

    let identities = agent
        .request_identities()
        .await
        .context("ssh-agent не отдал список ключей")?;

    if identities.is_empty() {
        return Ok(Attempt::Rejected("в ssh-agent нет ключей".into()));
    }

    let total = identities.len();
    for identity in identities {
        let key = match identity {
            AgentIdentity::PublicKey { key, .. } => key,
            AgentIdentity::Certificate { .. } => continue,
        };

        let result = session
            .authenticate_publickey_with(user, key, None, &mut agent)
            .await
            .context("подпись ключом из ssh-agent")?;
        if result.success() {
            return Ok(Attempt::Succeeded);
        }
    }

    Ok(Attempt::Rejected(format!(
        "ни один из {total} ключей ssh-agent не подошёл"
    )))
}

#[allow(clippy::collapsible_match)]
async fn connect_agent(
    own: Option<&crate::agent::Address>,
) -> Option<AgentClient<Box<dyn AgentStream + Send + Unpin>>> {
    if let Some(address) = own {
        match address {
            #[cfg(unix)]
            crate::agent::Address::Socket(path) => {
                if let Ok(agent) = AgentClient::connect_uds(path).await {
                    return Some(agent.dynamic());
                }
            }
            #[cfg(windows)]
            crate::agent::Address::Pipe(name) => {
                if let Ok(agent) = AgentClient::connect_named_pipe(name).await {
                    return Some(agent.dynamic());
                }
            }
            #[allow(unreachable_patterns)]
            _ => {}
        }
    }

    #[cfg(unix)]
    {
        if let Ok(agent) = AgentClient::connect_env().await {
            return Some(agent.dynamic());
        }
    }
    #[cfg(windows)]
    {
        if let Ok(agent) = AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await {
            return Some(agent.dynamic());
        }
        if let Ok(agent) = AgentClient::connect_pageant().await {
            return Some(agent.dynamic());
        }
    }
    None
}

#[allow(clippy::collapsible_match)]
async fn agent_stream(own: Option<&crate::agent::Address>) -> Option<Transport> {
    if let Some(address) = own {
        match address {
            #[cfg(unix)]
            crate::agent::Address::Socket(path) => {
                if let Ok(stream) = tokio::net::UnixStream::connect(path).await {
                    return Some(Box::new(stream));
                }
            }
            #[cfg(windows)]
            crate::agent::Address::Pipe(name) => {
                if let Ok(pipe) = tokio::net::windows::named_pipe::ClientOptions::new().open(name) {
                    return Some(Box::new(pipe));
                }
            }
            #[allow(unreachable_patterns)]
            _ => {}
        }
    }

    #[cfg(unix)]
    {
        if let Some(path) = std::env::var_os("SSH_AUTH_SOCK") {
            if let Ok(stream) = tokio::net::UnixStream::connect(path).await {
                return Some(Box::new(stream));
            }
        }
    }
    #[cfg(windows)]
    {
        if let Ok(pipe) = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(r"\\.\pipe\openssh-ssh-agent")
        {
            return Some(Box::new(pipe));
        }
    }
    None
}

async fn try_key(
    session: &mut client::Handle<Verifier>,
    user: &str,
    path: &std::path::Path,
    best_rsa_hash: Option<Option<russh::keys::HashAlg>>,
    prompter: &Prompter,
) -> Result<Attempt> {
    let label = path.display().to_string();

    let key = match auth::load_key(path, None)? {
        auth::KeyLoad::Loaded(key) => key,
        auth::KeyLoad::NeedsPassphrase => {
            let Some(passphrase) = prompter
                .ask_secret(
                    format!("Passphrase к ключу {label}"),
                    SecretKind::Passphrase,
                    None,
                )
                .await?
            else {
                return Ok(Attempt::Cancelled);
            };
            match auth::load_key(path, Some(&passphrase))? {
                auth::KeyLoad::Loaded(key) => key,
                auth::KeyLoad::NeedsPassphrase => {
                    return Ok(Attempt::Rejected(format!("неверный passphrase к {label}")));
                }
            }
        }
    };

    let signing_key = auth::with_hash_alg(key, best_rsa_hash)?;

    let result = session
        .authenticate_publickey(user, signing_key)
        .await
        .with_context(|| format!("вход по ключу {label}"))?;

    if result.success() {
        Ok(Attempt::Succeeded)
    } else {
        Ok(Attempt::Rejected(format!("сервер не принял ключ {label}")))
    }
}

const MAX_INTERACTIVE_ROUNDS: usize = 8;

async fn try_stored_password(
    session: &mut client::Handle<Verifier>,
    user: &str,
    secret: &proto::Secret,
    prompter: &Prompter,
) -> Result<Attempt> {
    let Ok(text) = std::str::from_utf8(secret.expose()) else {
        return Ok(Attempt::Rejected(
            "сохранённый пароль не UTF-8 — сервер такой не примет".into(),
        ));
    };

    let result = session
        .authenticate_password(user, text.to_owned())
        .await
        .context("аутентификация сохранённым паролем")?;
    if result.success() {
        return Ok(Attempt::Succeeded);
    }

    match try_keyboard_interactive(session, user, Some(text), prompter).await? {
        Attempt::Rejected(_) => Ok(Attempt::StoredRejected),
        other => Ok(other),
    }
}

async fn try_keyboard_interactive(
    session: &mut client::Handle<Verifier>,
    user: &str,
    stored: Option<&str>,
    prompter: &Prompter,
) -> Result<Attempt> {
    use russh::client::KeyboardInteractiveAuthResponse as Response;

    let mut response = session
        .authenticate_keyboard_interactive_start(user, None)
        .await
        .context("keyboard-interactive")?;

    let mut first_round = true;

    for _ in 0..MAX_INTERACTIVE_ROUNDS {
        let prompts = match response {
            Response::Success => return Ok(Attempt::Succeeded),
            Response::Failure { .. } => {
                return Ok(Attempt::Rejected(
                    "сервер не принял keyboard-interactive".into(),
                ));
            }
            Response::InfoRequest { prompts, .. } => prompts,
        };

        let mut answers: Vec<String> = Vec::with_capacity(prompts.len());

        let substitute = first_round && prompts.len() == 1 && !prompts[0].echo && stored.is_some();

        if let (true, Some(stored)) = (substitute, stored) {
            answers.push(stored.to_owned());
        } else {
            for prompt in &prompts {
                let kind = if prompt.echo {
                    SecretKind::Challenge
                } else if first_round && prompts.len() == 1 {
                    SecretKind::Password
                } else {
                    SecretKind::Challenge
                };

                let Some(answer) = prompter
                    .ask_secret(prompt.prompt.clone(), kind, None)
                    .await?
                else {
                    return Ok(Attempt::Cancelled);
                };
                answers.push(answer);
            }
        }

        first_round = false;
        response = session
            .authenticate_keyboard_interactive_respond(answers)
            .await
            .context("keyboard-interactive")?;
    }

    Ok(Attempt::Rejected(
        "сервер не закончил keyboard-interactive за разумное число шагов".into(),
    ))
}

/// Столько раз даём ввести пароль заново. Больше не стоит: каждая попытка
/// тратит до двух из MaxAuthTries сервера (по умолчанию 6) — пароль и
/// keyboard-interactive с тем же паролем.
const PASSWORD_ATTEMPTS: usize = 3;

async fn try_password(
    session: &mut client::Handle<Verifier>,
    user: &str,
    whom: &str,
    prompter: &Prompter,
) -> Result<Attempt> {
    let mut error = None;
    let mut last = Attempt::Rejected("пароль не подошёл".into());

    for _ in 0..PASSWORD_ATTEMPTS {
        let Some(password) = prompter
            .ask_secret(format!("Пароль для {whom}"), SecretKind::Password, error)
            .await?
        else {
            return Ok(Attempt::Cancelled);
        };

        let result = session
            .authenticate_password(user, password.clone())
            .await
            .context("аутентификация по паролю")?;

        if result.success() {
            return Ok(Attempt::Succeeded);
        }

        last = try_keyboard_interactive(session, user, Some(&password), prompter).await?;
        if !matches!(last, Attempt::Rejected(_)) {
            return Ok(last);
        }
        error = Some("Неверный пароль. Попробуйте ещё раз.".to_string());
    }

    Ok(last)
}

fn auth_failure_message(user: &str, result: &russh::client::AuthResult) -> Option<String> {
    let russh::client::AuthResult::Failure {
        remaining_methods,
        partial_success,
    } = result
    else {
        return None;
    };

    let methods = remaining_methods
        .iter()
        .map(|method| format!("{method:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    let methods = if methods.is_empty() {
        "сервер не предложил других способов".to_string()
    } else {
        format!("сервер предлагает: {methods}")
    };

    Some(if *partial_success {
        format!("для {user} нужен ещё один фактор ({methods})")
    } else {
        format!("не удалось войти как {user} ({methods})")
    })
}

#[derive(Clone)]
pub(super) struct Prompter {
    events: mpsc::Sender<FromSsh>,
    answers: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<Answer>>>,
}

impl Prompter {
    pub(super) fn new(
        events: mpsc::Sender<FromSsh>,
        answers: mpsc::UnboundedReceiver<Answer>,
    ) -> Self {
        Self {
            events,
            answers: Arc::new(tokio::sync::Mutex::new(answers)),
        }
    }

    async fn ask_secret(
        &self,
        prompt: String,
        kind: SecretKind,
        error: Option<String>,
    ) -> Result<Option<String>> {
        match self
            .ask(FromSsh::NeedSecret {
                prompt,
                kind,
                error,
            })
            .await?
        {
            Some(Answer::Secret(secret)) => Ok(secret),
            Some(_) | None => Ok(None),
        }
    }

    async fn ask_host_key(&self, request: FromSsh) -> Result<HostKeyDecision> {
        match self.ask(request).await? {
            Some(Answer::HostKey(decision)) => Ok(decision),
            Some(_) | None => Ok(HostKeyDecision::Reject),
        }
    }

    async fn ask(&self, request: FromSsh) -> Result<Option<Answer>> {
        let mut events = self.events.clone();
        if events.send(request).await.is_err() {
            return Ok(None);
        }
        let mut answers = self.answers.lock().await;
        Ok(answers.next().await)
    }
}

pub(super) struct Verifier {
    policy: HostKeyPolicy,
    host: String,
    port: u16,
    fingerprint: Arc<Mutex<Option<String>>>,
    prompter: Prompter,
    forward_agent: bool,
    agent: Option<crate::agent::Address>,
    remote_forwards: super::forward::RemoteMap,
}

impl client::Handler for Verifier {
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<client::Msg>,
        _connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<()> {
        let Some((host, port)) =
            super::forward::remote_target(&self.remote_forwards, connected_port)
        else {
            return Ok(());
        };
        let Ok(mut local) = tokio::net::TcpStream::connect((host.as_str(), port)).await else {
            return Ok(());
        };
        reply.accept().await;
        tokio::spawn(async move {
            let mut remote = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut remote, &mut local).await;
        });
        Ok(())
    }

    type Error = anyhow::Error;

    async fn server_channel_open_agent_forward(
        &mut self,
        channel: Channel<client::Msg>,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<()> {
        if !self.forward_agent {
            return Ok(());
        }
        let Some(mut agent) = agent_stream(self.agent.as_ref()).await else {
            return Ok(());
        };
        reply.accept().await;
        tokio::spawn(async move {
            let mut remote = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut remote, &mut agent).await;
        });
        Ok(())
    }

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool> {
        let key = match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
            PublicKeyOrCertificate::Certificate(_) => bail!(
                "сервер предъявил OpenSSH-сертификат; их проверка пока не поддерживается, \
                 сейчас доверять ему нельзя"
            ),
        };

        if let Ok(mut slot) = self.fingerprint.lock() {
            *slot = Some(known_hosts::fingerprint(&key));
        }

        let verdict = known_hosts::verify(&self.policy, &self.host, self.port, &key);
        if verdict.is_trusted() {
            return Ok(true);
        }

        let askable = matches!(
            self.policy,
            HostKeyPolicy::KnownHosts | HostKeyPolicy::KnownHostsFile(_)
        ) && matches!(
            verdict,
            HostKeyVerdict::Unknown { .. } | HostKeyVerdict::Changed { .. }
        );

        if !askable {
            return Err(anyhow!(
                "{} Отпечаток предъявленного ключа: {}",
                verdict.message(&self.host, self.port),
                known_hosts::fingerprint(&key)
            ));
        }

        let fingerprint = known_hosts::fingerprint(&key);
        let changed = matches!(verdict, HostKeyVerdict::Changed { .. });
        let decision = self
            .prompter
            .ask_host_key(FromSsh::NeedHostKey {
                host: self.host.clone(),
                port: self.port,
                fingerprint,
                message: verdict.message(&self.host, self.port),
                changed,
            })
            .await?;

        match decision {
            HostKeyDecision::Accept { remember } => {
                if remember {
                    if changed {
                        return Err(anyhow!(
                            "старый ключ {}:{} остаётся в known_hosts. Уберите его строку вручную, \
                             иначе проверка будет спотыкаться о неё и дальше",
                            self.host,
                            self.port
                        ));
                    }
                    if let Err(err) = known_hosts::learn(&self.policy, &self.host, self.port, &key)
                    {
                        log_learn_failure(&err);
                    }
                }
                Ok(true)
            }
            HostKeyDecision::Reject => {
                Err(anyhow!("ключ хоста {}:{} отклонён", self.host, self.port))
            }
        }
    }
}

fn log_learn_failure(error: &anyhow::Error) {
    eprintln!("не удалось записать ключ в known_hosts: {error:#}");
}
