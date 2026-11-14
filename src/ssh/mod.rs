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
/// The program a local terminal runs: a shell (see `crate::shells`) or another program,
/// such as an AI agent's sign-in, with variables added to this process's environment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalProgram {
    /// Absolute path: it is not looked up on PATH.
    pub program: std::path::PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, std::ffi::OsString)>,
    /// Folder to start in; `None` keeps this process's own.
    pub cwd: Option<std::path::PathBuf>,
}

#[cfg(windows)]
mod conpty;

#[cfg(windows)]
pub fn spawn_local_program(
    size: PtySize,
    term: &str,
    program: &LocalProgram,
) -> std::io::Result<SshSession> {
    conpty::spawn(size, term, program)
}

#[cfg(unix)]
pub fn spawn_local_program(
    size: PtySize,
    term: &str,
    program: &LocalProgram,
) -> std::io::Result<SshSession> {
    use std::os::fd::FromRawFd;

    let (argv, envp) = exec_strings(program, term)?;
    let cwd = program
        .cwd
        .as_ref()
        .filter(|dir| dir.is_dir())
        .and_then(|dir| {
            use std::os::unix::ffi::OsStrExt;
            std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()
        });
    let master = open_pty()?;
    set_winsize(master, &size);

    let child = match unsafe { spawn_pty_child(master, &argv, &envp, cwd.as_deref()) } {
        Ok(child) => child,
        Err(error) => {
            unsafe { libc::close(master) };
            return Err(error);
        }
    };

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

/// The program's arguments and its whole environment as C strings, made before
/// `fork`: the child must not allocate.
#[cfg(unix)]
fn exec_strings(
    program: &LocalProgram,
    term: &str,
) -> std::io::Result<(Vec<std::ffi::CString>, Vec<std::ffi::CString>)> {
    use std::ffi::{CString, OsStr};
    use std::os::unix::ffi::OsStrExt;

    let invalid = || std::io::Error::from(std::io::ErrorKind::InvalidInput);
    let mut argv = vec![CString::new(program.program.as_os_str().as_bytes()).map_err(|_| invalid())?];
    for arg in &program.args {
        argv.push(CString::new(arg.as_bytes()).map_err(|_| invalid())?);
    }

    let mut set: Vec<(&OsStr, &OsStr)> = vec![(OsStr::new("TERM"), OsStr::new(term))];
    for (name, value) in &program.env {
        set.push((OsStr::new(name), value.as_os_str()));
    }
    let inherited = std::env::vars_os().collect::<Vec<_>>();
    let mut envp = Vec::new();
    for (name, value) in inherited
        .iter()
        .map(|(name, value)| (name.as_os_str(), value.as_os_str()))
        .filter(|(name, _)| !set.iter().any(|(own, _)| own == name))
        .chain(set.iter().copied())
    {
        let mut entry = name.as_bytes().to_vec();
        entry.push(b'=');
        entry.extend_from_slice(value.as_bytes());
        // A variable with a NUL byte cannot be passed on; leave it out.
        if let Ok(entry) = CString::new(entry) {
            envp.push(entry);
        }
    }
    Ok((argv, envp))
}

/// Forks a child process with `slave` as the controlling terminal and
/// runs the program in it. Called once, before any async tasks, so there
/// are no races on the fd.
#[cfg(unix)]
unsafe fn spawn_pty_child(
    master: libc::c_int,
    argv: &[std::ffi::CString],
    envp: &[std::ffi::CString],
    cwd: Option<&std::ffi::CStr>,
) -> std::io::Result<libc::pid_t> {
    let argv_ptrs: Vec<*const libc::c_char> = argv
        .iter()
        .map(|arg| arg.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let envp_ptrs: Vec<*const libc::c_char> = envp
        .iter()
        .map(|var| var.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

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
            if let Some(cwd) = cwd {
                libc::chdir(cwd.as_ptr());
            }
            // Rust sets SIGPIPE to SIG_IGN — the program needs the default.
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
            libc::execve(argv_ptrs[0], argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
            libc::_exit(127);
        }
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// A live PTY: the shell responds to input and closes cleanly
    /// on Disconnect. We wait for the marker in the output, then kill — without the
    /// "kill before echo" race.
    #[test]
    fn local_pty_responds_and_closes() {
        let shell = LocalProgram {
            program: "/bin/sh".into(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
        };
        let mut session =
            spawn_local_program(PtySize::new(40, 10), "dumb", &shell).expect("open PTY");

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

    /// A program with added variables, instead of the shell: it prints and exits.
    #[test]
    fn local_program_gets_its_arguments_and_variables() {
        let program = LocalProgram {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), "echo \"$CRATTY_PROBE:$1:$TERM:$(pwd)\"".into(), "sh".into(), "arg".into()],
            env: vec![("CRATTY_PROBE".into(), "value".into())],
            cwd: Some("/".into()),
        };
        let mut session =
            spawn_local_program(PtySize::new(60, 10), "dumb", &program).expect("open PTY");

        let mut output = String::new();
        let mut closed = false;
        for _ in 0..100 {
            while let Ok(event) = session.events.try_recv() {
                match event {
                    FromSsh::Output(data) => output.push_str(&String::from_utf8_lossy(&data)),
                    FromSsh::Closed(_) => closed = true,
                    _ => {}
                }
            }
            if closed {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(output.contains("value:arg:dumb:/"), "{output:?}");
        assert!(closed, "the program's exit must close the session");
        session.join();
    }
}
