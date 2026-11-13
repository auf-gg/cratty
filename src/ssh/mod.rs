pub mod auth;
pub mod forward;
pub mod keygen;
pub mod known_hosts;
pub mod remote;
pub mod route;
mod session;
pub mod sftp;

use rust_i18n::t;
use std::thread::JoinHandle;

use bytes::Bytes;
use futures::channel::mpsc;

pub use known_hosts::{HostKeyPolicy, HostKeyVerdict};
pub use route::{Hop, JumpHost, Socks5Hop};
pub use session::stored_password_rejected;

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
            Self::Password(_) => f.write_str("Password(<hidden>)"),
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
            Self::Secret(Some(_)) => f.write_str("Secret(<hidden>)"),
            Self::Secret(None) => f.write_str("Secret(declined)"),
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
    /// Run this command instead of an interactive shell.
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
    /// A command in its own channel, apart from the terminal (see `remote`).
    Exec(remote::ExecRequest),
    /// A file operation for a tool (see `remote`).
    Files(remote::FileRequest),
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
        /// Why we are asking again, e.g. "wrong password".
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
                    let _ = event_tx.try_send(FromSsh::Closed(CloseReason::Error(
                        t!("ssh.runtime_failed", error = err).into_owned()
                    )));
                    return;
                }
            };
            runtime.block_on(session::run(config, command_rx, answer_rx, event_tx));
            // Do not wait for the runtime's background threads: a DNS request may hang there
            // without a network, and the UI waits on this thread when a tab is closed.
            runtime.shutdown_background();
        })?;

    Ok(SshSession {
        commands: command_tx,
        answers: answer_tx,
        events: event_rx,
        thread: Some(thread),
    })
}

/// Local terminal: the same event protocol as an SSH session, only
/// with a PTY on this machine instead of the network. No vault is needed: a local tab
/// holds no secrets, so it is available on the lock screen too.
#[cfg(unix)]
pub fn spawn_local(size: PtySize, term: &str) -> std::io::Result<SshSession> {
    use std::os::fd::FromRawFd;

    let master = open_pty()?;
    set_winsize(master, &size);

    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
    let child = unsafe { spawn_pty_child(master, &shell, term)? };

    // Non-blocking mode is required by the tokio reactor (AsyncFd).
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
                    let _ = event_tx.try_send(FromSsh::Closed(CloseReason::Error(
                        t!("ssh.runtime_failed", error = err).into_owned()
                    )));
                    return;
                }
            };
            // File owns the descriptor: it is closed together with the task.
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

    // SAFETY: File lives inside AsyncFd and stays in non-blocking mode.
    let fd = match unsafe { AsyncFd::register(file) } {
        Ok(fd) => fd,
        Err(err) => {
            let mut event_tx = event_tx;
            let _ = event_tx
                .send(FromSsh::Closed(CloseReason::Error(
                    t!("ssh.pty_watch_failed", error = err).into_owned()
                )))
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
        // Reap zombies: EOF on the master means the child process has exited.
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
                                .send(FromSsh::Closed(CloseReason::Error(
                                    t!("ssh.pty_write_failed", error = err).into_owned()
                                )))
                                .await;
                            return;
                        }
                    }
                    Some(ToSsh::Resize(size)) => {
                        set_winsize(fd.get_ref().as_raw_fd(), &size);
                    }
                    // A local tab has no SFTP or forwards — ignore them.
                    Some(ToSsh::OpenSftp(_)) | Some(ToSsh::SetForward { .. }) => {}
                    // Tools get the server, not this computer: a local tab has none.
                    Some(ToSsh::Exec(request)) => {
                        let _ = request.reply.send(Err(remote::LOCAL_TAB.to_owned()));
                    }
                    Some(ToSsh::Files(request)) => {
                        let _ = request.reply.send(Err(remote::LOCAL_TAB.to_owned()));
                    }
                    Some(ToSsh::Disconnect) => {
                        // A kill order is not "exit now": first read
                        // the rest of the output; EOF will come from the PTY itself.
                        unsafe { libc::kill(child, libc::SIGKILL) };
                    }
                    None => {
                        // The tab is closed: nobody reads the events any more, but
                        // the child process and zombie must not be left behind.
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
                            .send(FromSsh::Closed(CloseReason::Error(
                                t!("ssh.pty_read_failed", error = err).into_owned()
                            )))
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
                        // EIO: on Linux this means "the other end of the PTY is closed".
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

/// Forks a child process with `slave` as the controlling terminal and
/// runs an interactive shell in it. Called once, before any
/// async tasks, so there are no races on the fd.
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
            // Rust sets SIGPIPE to SIG_IGN — the shell needs the default.
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

/// Opens the slave end of the PTY: after fork the parent closes it right away, and
/// the child remains the sole owner.
#[cfg(unix)]
unsafe fn open_pty_slave(master: libc::c_int) -> std::io::Result<libc::c_int> {
    unsafe {
        let mut name = [0u8; 64];
        if libc::ptsname_r(master, name.as_mut_ptr() as *mut libc::c_char, name.len()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // O_NOCTTY: otherwise, if cratty is a session leader without a terminal (as
        // launchers start it), the PTY would become cratty's own controlling terminal,
        // and the shell could not take it over: fish exits, bash is left
        // without job control.
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

/// There is no local terminal on other platforms: ConPTY is a separate
/// big piece of work. The button in the UI is disabled there.
#[cfg(not(unix))]
pub fn spawn_local(_size: PtySize, _term: &str) -> std::io::Result<SshSession> {
    Err(std::io::Error::other(t!("ssh.local_unix_only").into_owned()))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// A live PTY: the shell responds to input and closes cleanly
    /// on Disconnect. We wait for the marker in the output, then kill — without the
    /// "kill before echo" race.
    #[test]
    fn local_pty_responds_and_closes() {
        let mut session = spawn_local(PtySize::new(40, 10), "dumb").expect("open PTY");

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
                    .expect("send input");
            }
            if marker {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(connected, "the PTY did not report a connection");
        assert!(marker, "the shell did not echo back");

        session
            .commands
            .unbounded_send(ToSsh::Disconnect)
            .expect("send Disconnect");

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
        assert!(closed, "the session did not close after Disconnect");
        session.join();
    }
}
