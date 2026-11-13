//! Commands and files on the server for tools that act on the user's behalf, such as an
//! AI agent: one request in, one answer out, over the connection a tab already has.
//!
//! Nothing here touches the user's terminal. A command gets its own exec channel without
//! a PTY, so its output is separate from stderr, comes with an exit code and has no
//! escape sequences. Files go through a separate SFTP channel or, when the server has no
//! SFTP, through `cat` and `ls` in exec channels.
//!
//! Error texts here are read by a language model, not shown in the interface, so they
//! are in English and are not translated.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures::StreamExt;
use futures::channel::{mpsc, oneshot};
use russh::{ChannelMsg, Sig, client};
use russh_sftp::client::SftpSession;
use tokio::io::AsyncReadExt;

use super::ToSsh;
use super::session::Verifier;
use super::sftp::{self, RemoteEntry};

type Handle = Arc<client::Handle<Verifier>>;

/// The largest file read whole. Bigger files are read in parts with a command.
pub const MAX_READ: u64 = 2 * 1024 * 1024;
/// The longest a command may run.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(600);
const SFTP_START: Duration = Duration::from_secs(10);

const LOST: &str = "the SSH connection of this tab is closed";
/// The answer of a local terminal tab: there is no server behind it.
pub const LOCAL_TAB: &str = "this tab is a local terminal, not an SSH session";

#[derive(Clone, Debug)]
pub struct Exec {
    /// Passed to the server as is: the server runs it with the user's login shell.
    pub command: String,
    /// Sent to the command's standard input, followed by end of file.
    pub stdin: Vec<u8>,
    pub timeout: Duration,
    /// Bytes kept of each output stream: the beginning and the end, half each.
    pub limit: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Exit {
    Code(u32),
    Signal(String),
    TimedOut,
    /// The server closed the channel without an exit status.
    Unknown,
}

#[derive(Clone, Debug)]
pub struct ExecOutput {
    pub stdout: Clipped,
    pub stderr: Clipped,
    pub exit: Exit,
}

/// Output with its middle cut out when it was longer than the limit.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Clipped {
    pub head: Vec<u8>,
    pub tail: Vec<u8>,
    pub dropped: u64,
}

impl Clipped {
    pub fn is_empty(&self) -> bool {
        self.head.is_empty() && self.tail.is_empty()
    }

    /// The whole output, when nothing was cut.
    pub fn whole(self) -> Option<Vec<u8>> {
        (self.dropped == 0).then(|| {
            let mut all = self.head;
            all.extend_from_slice(&self.tail);
            all
        })
    }

    pub fn text(&self) -> String {
        let mut text = String::from_utf8_lossy(&self.head).into_owned();
        if self.dropped > 0 {
            text.push_str(&format!("\n[… {} bytes skipped …]\n", self.dropped));
        }
        text.push_str(&String::from_utf8_lossy(&self.tail));
        text
    }
}

/// Keeps the first and the last `limit / 2` bytes of a stream.
struct Clip {
    head: Vec<u8>,
    tail: VecDeque<u8>,
    half: usize,
    dropped: u64,
}

impl Clip {
    fn new(limit: usize) -> Self {
        let half = (limit / 2).max(1);
        Self {
            head: Vec::new(),
            tail: VecDeque::new(),
            half,
            dropped: 0,
        }
    }

    fn push(&mut self, mut data: &[u8]) {
        let room = self.half.saturating_sub(self.head.len());
        let (first, rest) = data.split_at(room.min(data.len()));
        self.head.extend_from_slice(first);
        data = rest;
        if data.len() > self.half {
            let skip = data.len() - self.half;
            self.dropped += (self.tail.len() + skip) as u64;
            self.tail.clear();
            data = &data[skip..];
        }
        self.tail.extend(data);
        let over = self.tail.len().saturating_sub(self.half);
        if over > 0 {
            self.tail.drain(..over);
            self.dropped += over as u64;
        }
    }

    fn finish(self) -> Clipped {
        Clipped {
            head: self.head,
            tail: self.tail.into(),
            dropped: self.dropped,
        }
    }
}

pub struct ExecRequest {
    pub exec: Exec,
    pub reply: oneshot::Sender<Result<ExecOutput, String>>,
}

impl std::fmt::Debug for ExecRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecRequest")
            .field("exec", &self.exec)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileOp {
    Read { path: String },
    Write { path: String, data: Vec<u8> },
    List { path: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Listing {
    /// From SFTP: the folder's full path and its entries, folders first.
    Entries {
        path: String,
        entries: Vec<RemoteEntry>,
    },
    /// From `ls -la` when the server has no SFTP.
    Text(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileReply {
    Data(Vec<u8>),
    Written,
    Listing(Listing),
}

pub struct FileRequest {
    pub op: FileOp,
    pub reply: oneshot::Sender<Result<FileReply, String>>,
}

impl std::fmt::Debug for FileRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let op = match &self.op {
            FileOp::Read { path } => format!("Read({path})"),
            FileOp::Write { path, data } => format!("Write({path}, {} bytes)", data.len()),
            FileOp::List { path } => format!("List({path})"),
        };
        f.debug_struct("FileRequest").field("op", &op).finish()
    }
}

/// What a tool holds to work on a tab's server. Cheap to clone and works from any
/// executor: it only sends requests to the session thread and waits for answers.
#[derive(Clone, Debug)]
pub struct Remote {
    ssh: mpsc::UnboundedSender<ToSsh>,
}

impl Remote {
    pub fn new(ssh: mpsc::UnboundedSender<ToSsh>) -> Self {
        Self { ssh }
    }

    pub async fn exec(&self, exec: Exec) -> Result<ExecOutput, String> {
        let (reply, answer) = oneshot::channel();
        self.ssh
            .unbounded_send(ToSsh::Exec(ExecRequest { exec, reply }))
            .map_err(|_| LOST.to_owned())?;
        answer.await.map_err(|_| LOST.to_owned())?
    }

    pub async fn read(&self, path: &str) -> Result<Vec<u8>, String> {
        match self.file(FileOp::Read { path: path.into() }).await? {
            FileReply::Data(data) => Ok(data),
            other => Err(format!("unexpected answer: {other:?}")),
        }
    }

    pub async fn write(&self, path: &str, data: Vec<u8>) -> Result<(), String> {
        match self
            .file(FileOp::Write {
                path: path.into(),
                data,
            })
            .await?
        {
            FileReply::Written => Ok(()),
            other => Err(format!("unexpected answer: {other:?}")),
        }
    }

    pub async fn list(&self, path: &str) -> Result<Listing, String> {
        match self.file(FileOp::List { path: path.into() }).await? {
            FileReply::Listing(listing) => Ok(listing),
            other => Err(format!("unexpected answer: {other:?}")),
        }
    }

    async fn file(&self, op: FileOp) -> Result<FileReply, String> {
        let (reply, answer) = oneshot::channel();
        self.ssh
            .unbounded_send(ToSsh::Files(FileRequest { op, reply }))
            .map_err(|_| LOST.to_owned())?;
        answer.await.map_err(|_| LOST.to_owned())?
    }
}

/// Quotes a word for a POSIX shell.
pub fn quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', r"'\''"))
}

/// A script run with `/bin/sh` whatever the user's login shell is, so a tool always
/// writes for the same shell. Pagers and colors are off: nobody reads interactively.
pub fn sh_command(script: &str, cwd: Option<&str>) -> String {
    let mut body = String::from(
        "export PAGER=cat GIT_PAGER=cat SYSTEMD_PAGER= SYSTEMD_COLORS=0 TERM=dumb NO_COLOR=1\n",
    );
    if let Some(cwd) = cwd.filter(|cwd| !cwd.is_empty()) {
        body.push_str(&format!("cd -- {} || exit 1\n", quote(&home_relative(cwd))));
    }
    body.push_str(script);
    format!("sh -c {}", quote(&body))
}

/// `~/x` means `x` in the home folder: SFTP and commands both start there.
fn home_relative(path: &str) -> String {
    match path {
        "~" | "~/" => ".".into(),
        _ => match path.strip_prefix("~/") {
            Some(rest) => rest.into(),
            None => path.into(),
        },
    }
}

/// Runs in the session thread: one exec channel per command.
pub(super) fn spawn_exec(session: Handle, request: ExecRequest) {
    tokio::spawn(async move {
        let ExecRequest { exec, mut reply } = request;
        let result = run_exec(&session, exec, &mut reply)
            .await
            .map_err(|error| format!("{error:#}"));
        let _ = reply.send(result);
    });
}

async fn run_exec(
    session: &Handle,
    exec: Exec,
    reply: &mut oneshot::Sender<Result<ExecOutput, String>>,
) -> Result<ExecOutput> {
    let channel = session
        .channel_open_session()
        .await
        .context("could not open an SSH channel for the command")?;
    channel
        .exec(true, exec.command.as_bytes())
        .await
        .context("could not send the command")?;
    let (mut reader, writer) = channel.split();

    let mut stdout = Clip::new(exec.limit);
    let mut stderr = Clip::new(exec.limit);
    let mut exit = Exit::Unknown;

    // Input goes in while output is read: a command may print before it reads it all.
    let stdin = exec.stdin;
    let feed = async {
        if !stdin.is_empty() {
            writer.data(&stdin[..]).await?;
        }
        writer.eof().await
    };
    let mut feed = std::pin::pin!(feed);
    let mut fed = false;
    let deadline = tokio::time::sleep(exec.timeout.min(MAX_TIMEOUT));
    let mut deadline = std::pin::pin!(deadline);

    loop {
        tokio::select! {
            // The command may exit without reading its input: that is not an error.
            _ = &mut feed, if !fed => fed = true,
            message = reader.wait() => match message {
                Some(ChannelMsg::Failure) => bail!("the server refused to run the command"),
                Some(ChannelMsg::Data { data }) => stdout.push(&data),
                Some(ChannelMsg::ExtendedData { data, .. }) => stderr.push(&data),
                Some(ChannelMsg::ExitStatus { exit_status }) => exit = Exit::Code(exit_status),
                Some(ChannelMsg::ExitSignal { signal_name, error_message, .. }) => {
                    let name = format!("{signal_name:?}");
                    exit = Exit::Signal(if error_message.is_empty() {
                        name
                    } else {
                        format!("{name}: {error_message}")
                    });
                }
                Some(ChannelMsg::Close) | None => break,
                Some(_) => {}
            },
            _ = &mut deadline => {
                exit = Exit::TimedOut;
                let _ = writer.signal(Sig::KILL).await;
                let _ = writer.close().await;
                break;
            }
            // Nobody waits for the answer any more: stop the command.
            _ = reply.cancellation() => {
                let _ = writer.signal(Sig::KILL).await;
                let _ = writer.close().await;
                bail!("cancelled");
            }
        }
    }

    Ok(ExecOutput {
        stdout: stdout.finish(),
        stderr: stderr.finish(),
        exit,
    })
}

#[derive(Clone)]
enum Backend {
    Sftp(Arc<SftpSession>),
    /// The server has no SFTP: `cat`, `ls` and `head` in exec channels.
    Shell,
}

/// Runs in the session thread. The SFTP channel opens with the first request and serves
/// the following ones; requests run side by side.
pub(super) fn spawn_files(session: Handle) -> mpsc::UnboundedSender<FileRequest> {
    let (requests_tx, mut requests) = mpsc::unbounded::<FileRequest>();
    tokio::spawn(async move {
        let mut backend: Option<Backend> = None;
        while let Some(request) = requests.next().await {
            let chosen = match &backend {
                Some(backend) => backend.clone(),
                None => {
                    let opened = open_backend(&session).await;
                    backend = Some(opened.clone());
                    opened
                }
            };
            let session = session.clone();
            tokio::spawn(async move {
                let result = match chosen {
                    Backend::Sftp(sftp) => by_sftp(&sftp, request.op).await,
                    Backend::Shell => by_shell(&session, request.op).await,
                };
                let _ = request
                    .reply
                    .send(result.map_err(|error| format!("{error:#}")));
            });
        }
    });
    requests_tx
}

async fn open_backend(session: &Handle) -> Backend {
    let opening = async {
        let channel = session.channel_open_session().await.ok()?;
        sftp::start(channel).await.ok()
    };
    // A server that neither starts the subsystem nor refuses it must not hold tools up.
    match tokio::time::timeout(SFTP_START, opening).await {
        Ok(Some(sftp)) => Backend::Sftp(Arc::new(sftp)),
        _ => Backend::Shell,
    }
}

fn too_large() -> anyhow::Error {
    anyhow::anyhow!(
        "the file is larger than {MAX_READ} bytes, too large to read at once; \
         read parts of it with a command (head, tail, grep, sed -n)"
    )
}

async fn by_sftp(sftp: &SftpSession, op: FileOp) -> Result<FileReply> {
    match op {
        FileOp::Read { path } => {
            let path = home_relative(&path);
            let metadata = sftp
                .metadata(path.clone())
                .await
                .map_err(|error| anyhow::anyhow!("{path}: {error}"))?;
            if metadata.is_dir() {
                bail!("{path} is a folder");
            }
            if metadata.len() > MAX_READ {
                return Err(too_large());
            }
            let file = sftp
                .open(path.clone())
                .await
                .map_err(|error| anyhow::anyhow!("{path}: {error}"))?;
            let mut data = Vec::with_capacity(metadata.len() as usize);
            file.take(MAX_READ + 1)
                .read_to_end(&mut data)
                .await
                .with_context(|| format!("{path}: reading"))?;
            if data.len() as u64 > MAX_READ {
                return Err(too_large());
            }
            Ok(FileReply::Data(data))
        }
        FileOp::Write { path, data } => {
            let path = home_relative(&path);
            sftp::write_file(sftp, &path, &data)
                .await
                .with_context(|| path.clone())?;
            Ok(FileReply::Written)
        }
        FileOp::List { path } => {
            let (path, entries) = sftp::list(sftp, &home_relative(&path)).await?;
            Ok(FileReply::Listing(Listing::Entries { path, entries }))
        }
    }
}

async fn by_shell(session: &Handle, op: FileOp) -> Result<FileReply> {
    let (script, stdin, limit) = match &op {
        FileOp::Read { path } => (
            format!(
                "f={}\n\
                 if [ -d \"$f\" ]; then echo \"$f is a folder\" >&2; exit 1; fi\n\
                 head -c {} -- \"$f\"",
                quote(&home_relative(path)),
                MAX_READ + 1
            ),
            Vec::new(),
            // Both halves of the clip together hold one byte more than may be read.
            2 * (MAX_READ as usize + 1),
        ),
        FileOp::Write { path, data } => (
            format!("cat > {}", quote(&home_relative(path))),
            data.clone(),
            16 * 1024,
        ),
        FileOp::List { path } => (
            format!("LC_ALL=C ls -la -- {}", quote(&home_relative(path))),
            Vec::new(),
            256 * 1024,
        ),
    };
    let exec = Exec {
        command: sh_command(&script, None),
        stdin,
        timeout: Duration::from_secs(120),
        limit,
    };
    let (mut reply, _answer) = oneshot::channel();
    let output = run_exec(session, exec, &mut reply).await?;
    match output.exit {
        Exit::Code(0) => {}
        Exit::TimedOut => bail!("timed out"),
        _ => {
            let message = output.stderr.text();
            bail!("{}", message.trim());
        }
    }
    match op {
        FileOp::Read { .. } => {
            let data = output.stdout.whole().ok_or_else(too_large)?;
            if data.len() as u64 > MAX_READ {
                return Err(too_large());
            }
            Ok(FileReply::Data(data))
        }
        FileOp::Write { .. } => Ok(FileReply::Written),
        FileOp::List { .. } => Ok(FileReply::Listing(Listing::Text(output.stdout.text()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_output_is_kept_whole() {
        let mut clip = Clip::new(10);
        clip.push(b"abc");
        clip.push(b"de");
        let clipped = clip.finish();
        assert_eq!(clipped.text(), "abcde");
        assert_eq!(clipped.whole(), Some(b"abcde".to_vec()));
    }

    #[test]
    fn long_output_keeps_its_beginning_and_end() {
        let mut clip = Clip::new(8);
        for chunk in [&b"0123"[..], b"4567", b"89", b"abcdef"] {
            clip.push(chunk);
        }
        let clipped = clip.finish();
        assert_eq!(clipped.head, b"0123");
        assert_eq!(clipped.tail, b"cdef");
        assert_eq!(clipped.dropped, 8);
        assert_eq!(clipped.text(), "0123\n[… 8 bytes skipped …]\ncdef");
        assert_eq!(clipped.whole(), None);
    }

    #[test]
    fn one_huge_chunk_is_clipped_too() {
        let mut clip = Clip::new(4);
        clip.push(b"abcdefghij");
        let clipped = clip.finish();
        assert_eq!(
            (clipped.head.as_slice(), clipped.tail.as_slice()),
            (&b"ab"[..], &b"ij"[..])
        );
        assert_eq!(clipped.dropped, 6);
    }

    #[test]
    fn words_are_quoted_for_sh() {
        assert_eq!(quote("plain"), "'plain'");
        assert_eq!(quote("it's"), r"'it'\''s'");
    }

    #[test]
    fn command_runs_in_sh_from_the_folder() {
        let command = sh_command("echo $HOME", Some("~/app"));
        assert!(command.starts_with("sh -c '"));
        assert!(command.contains(r"cd -- '\''app'\'' || exit 1"));
        assert!(command.ends_with("echo $HOME'"));
        assert!(!sh_command("ls", None).contains("cd --"));
    }

    #[test]
    fn home_paths_become_relative() {
        assert_eq!(home_relative("~"), ".");
        assert_eq!(home_relative("~/notes.txt"), "notes.txt");
        assert_eq!(home_relative("/etc/hosts"), "/etc/hosts");
        assert_eq!(home_relative("~other/x"), "~other/x");
    }
}
