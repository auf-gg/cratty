pub mod auth;
pub mod forward;
pub mod keygen;
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
    /// Выполнить эту команду вместо интерактивной оболочки.
    pub command: Option<String>,
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
            command: None,
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
        /// Почему спрашиваем снова, например «неверный пароль».
        error: Option<String>,
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
            // Не ждать фоновых потоков рантайма: там может висеть DNS-запрос
            // без сети, а этот поток при закрытии вкладки ждёт интерфейс.
            runtime.shutdown_background();
        })?;

    Ok(SshSession {
        commands: command_tx,
        answers: answer_tx,
        events: event_rx,
        thread: Some(thread),
    })
}

/// Локальный терминал: тот же протокол событий, что и у SSH-сеанса, только
/// вместо сети — PTY на этой машине. Хранилище не нужно: локальная вкладка
/// не хранит секретов, поэтому доступна и на экране блокировки.
#[cfg(unix)]
pub fn spawn_local(size: PtySize, term: &str) -> std::io::Result<SshSession> {
    use std::os::fd::FromRawFd;

    let master = open_pty()?;
    set_winsize(master, &size);

    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
    let child = unsafe { spawn_pty_child(master, &shell, term)? };

    // Неблокирующий режим нужен реактору tokio (AsyncFd).
    unsafe {
        let flags = libc::fcntl(master, libc::F_GETFL);
        libc::fcntl(master, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let (command_tx, command_rx) = mpsc::unbounded();
    let (answer_tx, _answer_rx) = mpsc::unbounded();
    let (event_tx, event_rx) = mpsc::channel(OUTPUT_CAPACITY);

    let thread = std::thread::Builder::new()
        .name("local-pty".into())
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
            // File владеет дескриптором: закроется вместе с задачей.
            let file = unsafe { std::fs::File::from_raw_fd(master) };
            runtime.block_on(local_pty_loop(file, child, command_rx, event_tx));
        })?;

    Ok(SshSession {
        commands: command_tx,
        answers: answer_tx,
        events: event_rx,
        thread: Some(thread),
    })
}

#[cfg(unix)]
async fn local_pty_loop(
    file: std::fs::File,
    child: libc::pid_t,
    command_rx: mpsc::UnboundedReceiver<ToSsh>,
    event_tx: mpsc::Sender<FromSsh>,
) {
    use futures::{SinkExt, StreamExt};
    use std::io::{ErrorKind, Read};
    use std::os::fd::AsRawFd;
    use tokio::io::unix::AsyncFd;

    // SAFETY: File живёт внутри AsyncFd и остаётся в неблокирующем режиме.
    let fd = match unsafe { AsyncFd::register(file) } {
        Ok(fd) => fd,
        Err(err) => {
            let mut event_tx = event_tx;
            let _ = event_tx
                .send(FromSsh::Closed(CloseReason::Error(format!(
                    "не удалось следить за PTY: {err}"
                ))))
                .await;
            return;
        }
    };

    let mut event_tx = event_tx;
    let _ = event_tx
        .send(FromSsh::Connected {
            fingerprint: String::new(),
        })
        .await;

    async fn closed(event_tx: &mut mpsc::Sender<FromSsh>, child: libc::pid_t) {
        // Собрать зомби: EOF на master означает, что дочерний процесс вышел.
        unsafe { libc::waitpid(child, std::ptr::null_mut(), 0) };
        let _ = event_tx
            .send(FromSsh::Closed(CloseReason::Remote { exit_status: None }))
            .await;
    }

    let mut command_rx = command_rx;
    let mut buf = [0u8; 8192];
    loop {
        tokio::select! {
            command = command_rx.next() => {
                match command {
                    Some(ToSsh::Input(bytes)) => {
                        if let Err(err) = pty_write(&fd, &bytes).await {
                            let _ = event_tx
                                .send(FromSsh::Closed(CloseReason::Error(format!(
                                    "запись в PTY: {err}"
                                ))))
                                .await;
                            return;
                        }
                    }
                    Some(ToSsh::Resize(size)) => {
                        set_winsize(fd.get_ref().as_raw_fd(), &size);
                    }
                    // SFTP и форварды у локальной вкладки не бывают — игнорируем.
                    Some(ToSsh::OpenSftp(_)) | Some(ToSsh::SetForward { .. }) => {}
                    Some(ToSsh::Disconnect) => {
                        // Приказ убить — не «выйти сейчас»: сначала дочитываем
                        // остаток вывода, EOF придёт от самого PTY.
                        unsafe { libc::kill(child, libc::SIGKILL) };
                    }
                    None => {
                        // Вкладка закрыта: события уже некому читать, но
                        // дочерний процесс и зомби нельзя оставлять.
                        unsafe {
                            libc::kill(child, libc::SIGHUP);
                            libc::waitpid(child, std::ptr::null_mut(), 0);
                        }
                        return;
                    }
                }
            }
            readable = fd.readable() => {
                let mut guard = match readable {
                    Ok(guard) => guard,
                    Err(err) => {
                        let _ = event_tx
                            .send(FromSsh::Closed(CloseReason::Error(format!(
                                "чтение PTY: {err}"
                            ))))
                            .await;
                        return;
                    }
                };
                loop {
                    match guard.get_inner().read(&mut buf) {
                        Ok(0) => {
                            closed(&mut event_tx, child).await;
                            return;
                        }
                        Ok(read) => {
                            if event_tx
                                .send(FromSsh::Output(Bytes::copy_from_slice(
                                    &buf[..read],
                                )))
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                        Err(err) if err.kind() == ErrorKind::WouldBlock => {
                            guard.clear_ready();
                            break;
                        }
                        Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                        // EIO: на Linux это «другой конец PTY закрыт».
                        Err(_) => {
                            closed(&mut event_tx, child).await;
                            return;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(unix)]
async fn pty_write(
    fd: &tokio::io::unix::AsyncFd<std::fs::File>,
    mut bytes: &[u8],
) -> std::io::Result<()> {
    use std::io::Write;

    while !bytes.is_empty() {
        let mut guard = fd.writable().await?;
        match guard.get_inner().write(bytes) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::WriteZero)),
            Ok(written) => bytes = &bytes[written..],
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                guard.clear_ready();
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn open_pty() -> std::io::Result<libc::c_int> {
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        if master < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::grantpt(master) != 0 || libc::unlockpt(master) != 0 {
            let err = std::io::Error::last_os_error();
            libc::close(master);
            return Err(err);
        }
        Ok(master)
    }
}

#[cfg(unix)]
fn set_winsize(fd: libc::c_int, size: &PtySize) {
    let size = libc::winsize {
        ws_col: size.cols,
        ws_row: size.rows,
        ws_xpixel: size.pixel_width,
        ws_ypixel: size.pixel_height,
    };
    unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &size) };
}

/// Форкает дочерний процесс с `slave` в качестве управляющего терминала и
/// запускает в нём интерактивную оболочку. Вызывается один раз, до любых
/// асинхронных задач, поэтому гонок на fd нет.
#[cfg(unix)]
unsafe fn spawn_pty_child(
    master: libc::c_int,
    shell: &str,
    term: &str,
) -> std::io::Result<libc::pid_t> {
    use std::ffi::CString;

    let slave = unsafe { open_pty_slave(master)? };
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(slave) };
        return Err(err);
    }
    if pid == 0 {
        unsafe {
            libc::setsid();
            libc::ioctl(slave, libc::TIOCSCTTY, 0u64);
            libc::dup2(slave, 0);
            libc::dup2(slave, 1);
            libc::dup2(slave, 2);
            if slave > 2 {
                libc::close(slave);
            }
            libc::close(master);
            // Rust выставляет SIGPIPE в SIG_IGN — оболочке нужен стандартный.
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
            std::env::set_var("TERM", term);
        }
        let shell = CString::new(shell).unwrap_or_else(|_| CString::new("/bin/sh").unwrap());
        let argv = [shell.as_ptr(), std::ptr::null()];
        unsafe { libc::execv(shell.as_ptr(), argv.as_ptr()) };
        unsafe { libc::_exit(127) };
    }
    unsafe { libc::close(slave) };
    Ok(pid)
}

/// Открывает slave-конец PTY: после fork родитель сразу закрывает его, и
/// дочерний процесс остаётся единственным владельцем.
#[cfg(unix)]
unsafe fn open_pty_slave(master: libc::c_int) -> std::io::Result<libc::c_int> {
    unsafe {
        let mut name = [0u8; 64];
        if libc::ptsname_r(master, name.as_mut_ptr() as *mut libc::c_char, name.len()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // O_NOCTTY: иначе, если cratty — лидер сессии без терминала (так его
        // запускают лаунчеры), PTY стал бы управляющим терминалом самого cratty,
        // и оболочка не смогла бы забрать его себе: fish выходит, bash остаётся
        // без управления заданиями.
        let slave = libc::open(
            name.as_ptr() as *const libc::c_char,
            libc::O_RDWR | libc::O_NOCTTY,
        );
        if slave < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(slave)
    }
}

/// На остальных платформах локального терминала нет: ConPTY — отдельная
/// большая работа. Кнопка в интерфейсе на них выключена.
#[cfg(not(unix))]
pub fn spawn_local(_size: PtySize, _term: &str) -> std::io::Result<SshSession> {
    Err(std::io::Error::other(
        "локальный терминал поддерживается только на Unix",
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// Живой PTY: оболочка отвечает на ввод и корректно закрывается
    /// по Disconnect. Ждём маркер в выводе, потом убиваем — без гонки
    /// «kill раньше echo».
    #[test]
    fn lokalnyi_pty_otvechaet_i_zakryvaetsya() {
        let mut session = spawn_local(PtySize::new(40, 10), "dumb").expect("открыть PTY");

        let mut connected = false;
        let mut marker = false;
        for _ in 0..200 {
            while let Ok(event) = session.events.try_recv() {
                match event {
                    FromSsh::Connected { .. } => connected = true,
                    FromSsh::Output(data)
                        if !marker && String::from_utf8_lossy(&data).contains("cratty-marker") =>
                    {
                        marker = true
                    }
                    _ => {}
                }
            }
            if !marker && connected {
                session
                    .commands
                    .unbounded_send(ToSsh::Input(Bytes::from("echo cratty-marker\r\n")))
                    .expect("отправить ввод");
            }
            if marker {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(connected, "PTY не доложил о подключении");
        assert!(marker, "оболочка не вернула echo");

        session
            .commands
            .unbounded_send(ToSsh::Disconnect)
            .expect("отправить Disconnect");

        let mut closed = false;
        for _ in 0..100 {
            while let Ok(event) = session.events.try_recv() {
                if matches!(event, FromSsh::Closed { .. }) {
                    closed = true;
                }
            }
            if closed {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(closed, "сессия не закрылась после Disconnect");
        session.join();
    }
}
