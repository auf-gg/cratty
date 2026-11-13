use rust_i18n::t;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, anyhow, bail};
use futures::channel::{mpsc, oneshot};
use futures::{SinkExt, StreamExt};
use russh::{Channel, ChannelMsg, client};
use russh_sftp::client::SftpSession;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::session::{self, Prompter};
use super::{Answer, CloseReason, FromSsh, SshConfig};

const CHUNK: usize = 256 * 1024;
const PROGRESS_EVERY: Duration = Duration::from_millis(100);

pub type TransferId = u64;

pub const MAX_EDIT_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug)]
pub enum ToSftp {
    ReadFile {
        path: String,
        reply: oneshot::Sender<Result<Vec<u8>, String>>,
    },
    WriteFile {
        path: String,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<(), String>>,
    },
    List {
        path: String,
    },
    Download {
        id: TransferId,
        remote: String,
        local: PathBuf,
        overwrite: bool,
    },
    Upload {
        id: TransferId,
        local: PathBuf,
        remote: String,
        overwrite: bool,
    },
    CreateDir {
        path: String,
    },
    Remove {
        path: String,
    },
    Rename {
        from: String,
        to: String,
    },
    Cancel {
        id: TransferId,
    },
    Disconnect,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub modified: Option<SystemTime>,
}

#[derive(Debug)]
pub enum FromSftp {
    Ssh(FromSsh),
    Ready {
        home: String,
    },
    Listing {
        path: String,
        entries: Vec<RemoteEntry>,
    },
    Progress {
        id: TransferId,
        done: u64,
        total: u64,
    },
    Finished {
        id: TransferId,
        result: Result<(), String>,
    },
    Changed {
        path: String,
    },
    Failed(String),
}

pub struct SftpHandle {
    pub commands: mpsc::UnboundedSender<ToSftp>,
    pub answers: mpsc::UnboundedSender<Answer>,
    pub events: mpsc::Receiver<FromSftp>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for SftpHandle {
    fn drop(&mut self) {
        self.events.close();
        self.commands.close_channel();
        self.answers.close_channel();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub fn spawn_sftp(config: SshConfig) -> std::io::Result<SftpHandle> {
    let (command_tx, command_rx) = mpsc::unbounded();
    let (answer_tx, answer_rx) = mpsc::unbounded();
    let (event_tx, event_rx) = mpsc::channel(256);

    let thread = std::thread::Builder::new()
        .name(format!("sftp:{}", config.host))
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
            {
                Ok(runtime) => runtime,
                Err(err) => {
                    let mut event_tx = event_tx;
                    let _ = event_tx.try_send(FromSftp::Ssh(FromSsh::Closed(CloseReason::Error(
                        t!("ssh.runtime_failed", error = err).into_owned(),
                    ))));
                    return;
                }
            };
            runtime.block_on(run(config, command_rx, answer_rx, event_tx));
            // Do not wait for the runtime's background threads: a DNS request may hang there
            // without a network, and the UI waits on this thread when a tab is closed.
            runtime.shutdown_background();
        })?;

    Ok(SftpHandle {
        commands: command_tx,
        answers: answer_tx,
        events: event_rx,
        thread: Some(thread),
    })
}

async fn run(
    config: SshConfig,
    commands: mpsc::UnboundedReceiver<ToSftp>,
    answers: mpsc::UnboundedReceiver<Answer>,
    mut events: mpsc::Sender<FromSftp>,
) {
    let host = config.host.clone();
    let port = config.port;

    let (ssh_tx, mut ssh_rx) = mpsc::channel::<FromSsh>(16);
    let prompter = Prompter::new(ssh_tx, answers);
    let mut forward = events.clone();
    let forwarder = tokio::spawn(async move {
        while let Some(event) = ssh_rx.next().await {
            if forward.send(FromSftp::Ssh(event)).await.is_err() {
                break;
            }
        }
    });

    let reason = match serve(&config, commands, &prompter, &mut events).await {
        Ok(()) => CloseReason::Local,
        Err(err) => CloseReason::Error(format!("{host}:{port}: {err:#}")),
    };
    drop(prompter);
    let _ = forwarder.await;

    let _ = events.send(FromSftp::Ssh(FromSsh::Closed(reason))).await;
    events.close_channel();
}

async fn serve(
    config: &SshConfig,
    mut commands: mpsc::UnboundedReceiver<ToSftp>,
    prompter: &Prompter,
    events: &mut mpsc::Sender<FromSftp>,
) -> Result<()> {
    let mut queued = Vec::new();
    let Some(connected) = session::unless_closed(
        session::connect(config, prompter),
        &mut commands,
        &mut queued,
    )
    .await?
    else {
        return Ok(());
    };
    let commands = futures::stream::iter(queued).chain(commands);
    events
        .send(FromSftp::Ssh(FromSsh::Connected {
            fingerprint: connected.fingerprint.clone(),
        }))
        .await?;

    let channel = connected
        .session
        .channel_open_session()
        .await
        .context(t!("ssh.sftp_ctx_channel"))?;
    let result = serve_channel(channel, commands, events).await;
    connected.disconnect().await;
    result
}

/// Starts the SFTP subsystem on a freshly opened session channel.
pub(super) async fn start(mut channel: Channel<client::Msg>) -> Result<SftpSession> {
    channel
        .request_subsystem(true, "sftp")
        .await
        .context(t!("ssh.sftp_ctx_subsystem"))?;
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => break,
            Some(ChannelMsg::Failure) => bail!(t!("ssh.sftp_unsupported")),
            Some(ChannelMsg::Eof | ChannelMsg::Close) | None => {
                bail!(t!("ssh.sftp_channel_closed"))
            }
            Some(_) => {}
        }
    }

    SftpSession::new(channel.into_stream())
        .await
        .map_err(|error| anyhow!(t!("ssh.sftp_start_failed", error = error)))
}

async fn serve_channel(
    channel: Channel<client::Msg>,
    mut commands: impl futures::Stream<Item = ToSftp> + Unpin,
    events: &mut mpsc::Sender<FromSftp>,
) -> Result<()> {
    let sftp = Arc::new(start(channel).await?);
    let home = sftp
        .canonicalize(".")
        .await
        .map_err(|error| anyhow!(t!("ssh.sftp_home_dir", error = error)))?;
    events.send(FromSftp::Ready { home }).await?;

    let mut cancels: HashMap<TransferId, Arc<AtomicBool>> = HashMap::new();

    while let Some(command) = commands.next().await {
        match command {
            ToSftp::List { path } => {
                let event = match list(&sftp, &path).await {
                    Ok((path, entries)) => FromSftp::Listing { path, entries },
                    Err(error) => FromSftp::Failed(format!("{error:#}")),
                };
                events.send(event).await?;
            }
            ToSftp::Download {
                id,
                remote,
                local,
                overwrite,
            } => {
                let cancel = Arc::new(AtomicBool::new(false));
                cancels.insert(id, cancel.clone());
                let sftp = sftp.clone();
                let mut events = events.clone();
                tokio::spawn(async move {
                    let mut progress = Progress::new(id, events.clone());
                    let result =
                        download(&sftp, &remote, &local, overwrite, &cancel, &mut progress)
                            .await
                            .map_err(|error| format!("{error:#}"));
                    let _ = events.send(FromSftp::Finished { id, result }).await;
                });
            }
            ToSftp::Upload {
                id,
                local,
                remote,
                overwrite,
            } => {
                let cancel = Arc::new(AtomicBool::new(false));
                cancels.insert(id, cancel.clone());
                let sftp = sftp.clone();
                let mut events = events.clone();
                tokio::spawn(async move {
                    let mut progress = Progress::new(id, events.clone());
                    let result = upload(&sftp, &local, &remote, overwrite, &cancel, &mut progress)
                        .await
                        .map_err(|error| format!("{error:#}"));
                    let _ = events.send(FromSftp::Finished { id, result }).await;
                });
            }
            ToSftp::ReadFile { path, reply } => {
                let result = read_file(&sftp, &path)
                    .await
                    .map_err(|error| format!("{path}: {error:#}"));
                let _ = reply.send(result);
            }
            ToSftp::WriteFile { path, data, reply } => {
                let result = write_file(&sftp, &path, &data)
                    .await
                    .map_err(|error| format!("{path}: {error:#}"));
                let _ = reply.send(result);
            }
            ToSftp::CreateDir { path } => {
                let result = sftp.create_dir(path.clone()).await;
                events
                    .send(outcome(result.map_err(anyhow::Error::from), &path))
                    .await?;
            }
            ToSftp::Remove { path } => {
                let result = remove(&sftp, &path).await;
                events.send(outcome(result, &path)).await?;
            }
            ToSftp::Rename { from, to } => {
                let result = sftp.rename(from.clone(), to).await;
                events
                    .send(outcome(result.map_err(anyhow::Error::from), &from))
                    .await?;
            }
            ToSftp::Cancel { id } => {
                if let Some(flag) = cancels.remove(&id) {
                    flag.store(true, Ordering::Relaxed);
                }
            }
            ToSftp::Disconnect => break,
        }
    }

    for flag in cancels.values() {
        flag.store(true, Ordering::Relaxed);
    }
    let _ = sftp.close().await;
    Ok(())
}

pub struct SftpAttach {
    commands: mpsc::UnboundedReceiver<ToSftp>,
    events: mpsc::Sender<FromSftp>,
}

impl std::fmt::Debug for SftpAttach {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SftpAttach")
    }
}

pub(super) fn attach() -> (SftpHandle, SftpAttach) {
    let (command_tx, command_rx) = mpsc::unbounded();
    let (answer_tx, _) = mpsc::unbounded();
    let (event_tx, event_rx) = mpsc::channel(256);
    (
        SftpHandle {
            commands: command_tx,
            answers: answer_tx,
            events: event_rx,
            thread: None,
        },
        SftpAttach {
            commands: command_rx,
            events: event_tx,
        },
    )
}

impl SftpAttach {
    pub(super) async fn run(self, channel: Channel<client::Msg>) {
        let mut events = self.events;
        let reason = match serve_channel(channel, self.commands, &mut events).await {
            Ok(()) => CloseReason::Local,
            Err(error) => CloseReason::Error(format!("{error:#}")),
        };
        let _ = events.send(FromSftp::Ssh(FromSsh::Closed(reason))).await;
    }

    pub(super) async fn fail(self, message: String) {
        let mut events = self.events;
        let _ = events
            .send(FromSftp::Ssh(FromSsh::Closed(CloseReason::Error(message))))
            .await;
    }
}

async fn read_file(sftp: &SftpSession, path: &str) -> Result<Vec<u8>> {
    let metadata = sftp
        .metadata(path.to_string())
        .await
        .map_err(|error| anyhow!("{error}"))?;
    if metadata.is_dir() {
        bail!(t!("ssh.sftp_is_folder"));
    }
    if metadata.len() > MAX_EDIT_BYTES {
        bail!(t!(
            "ssh.sftp_too_large",
            mb = MAX_EDIT_BYTES / 1024 / 1024
        ));
    }
    let mut file = sftp
        .open(path.to_string())
        .await
        .map_err(|error| anyhow!("{error}"))?;
    let mut data = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut data).await.context(t!("ssh.sftp_ctx_reading"))?;
    Ok(data)
}

pub(super) async fn write_file(sftp: &SftpSession, path: &str, data: &[u8]) -> Result<()> {
    let mut file = sftp
        .create(path.to_string())
        .await
        .map_err(|error| anyhow!("{error}"))?;
    file.write_all(data).await.context(t!("ssh.sftp_ctx_writing"))?;
    file.shutdown().await.context(t!("ssh.sftp_ctx_closing"))?;
    Ok(())
}

fn outcome(result: Result<()>, path: &str) -> FromSftp {
    match result {
        Ok(()) => FromSftp::Changed { path: parent(path) },
        Err(error) => FromSftp::Failed(format!("{path}: {error:#}")),
    }
}

pub fn parent(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(0) => "/".into(),
        Some(index) => trimmed[..index].into(),
        None => ".".into(),
    }
}

pub fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

pub(super) async fn list(sftp: &SftpSession, path: &str) -> Result<(String, Vec<RemoteEntry>)> {
    let path = if path.is_empty() { "." } else { path };
    let path = sftp
        .canonicalize(path)
        .await
        .map_err(|error| anyhow!("{path}: {error}"))?;
    let mut entries: Vec<RemoteEntry> = sftp
        .read_dir(path.clone())
        .await
        .map_err(|error| anyhow!("{path}: {error}"))?
        .map(|entry| {
            let metadata = entry.metadata();
            let name = entry.file_name();
            RemoteEntry {
                path: join(&path, &name),
                name,
                is_dir: metadata.is_dir(),
                is_symlink: metadata.is_symlink(),
                size: metadata.len(),
                modified: metadata.modified().ok(),
            }
        })
        .collect();
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok((path, entries))
}

struct Progress {
    id: TransferId,
    events: mpsc::Sender<FromSftp>,
    done: u64,
    total: u64,
    reported: Instant,
}

impl Progress {
    fn new(id: TransferId, events: mpsc::Sender<FromSftp>) -> Self {
        Self {
            id,
            events,
            done: 0,
            total: 0,
            reported: Instant::now() - PROGRESS_EVERY,
        }
    }

    async fn advance(&mut self, bytes: u64) {
        self.done += bytes;
        if self.reported.elapsed() >= PROGRESS_EVERY || self.done == self.total {
            self.reported = Instant::now();
            let _ = self
                .events
                .send(FromSftp::Progress {
                    id: self.id,
                    done: self.done,
                    total: self.total,
                })
                .await;
        }
    }
}

fn check_cancel(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        bail!(t!("ssh.sftp_cancelled"));
    }
    Ok(())
}

async fn plan_download(
    sftp: &SftpSession,
    remote: &str,
    local: &Path,
    dirs: &mut Vec<PathBuf>,
    files: &mut Vec<(String, PathBuf, u64)>,
) -> Result<()> {
    let metadata = sftp
        .metadata(remote.to_string())
        .await
        .map_err(|error| anyhow!("{remote}: {error}"))?;
    if metadata.is_dir() {
        dirs.push(local.to_path_buf());
        for entry in sftp
            .read_dir(remote.to_string())
            .await
            .map_err(|error| anyhow!("{remote}: {error}"))?
        {
            let name = entry.file_name();
            let child = join(remote, &name);
            if entry.metadata().is_symlink() {
                continue;
            }
            Box::pin(plan_download(sftp, &child, &local.join(&name), dirs, files)).await?;
        }
    } else {
        files.push((remote.to_string(), local.to_path_buf(), metadata.len()));
    }
    Ok(())
}

async fn download(
    sftp: &SftpSession,
    remote: &str,
    local: &Path,
    overwrite: bool,
    cancel: &AtomicBool,
    progress: &mut Progress,
) -> Result<()> {
    if !overwrite && tokio::fs::try_exists(local).await.unwrap_or(false) {
        bail!(t!("ssh.sftp_local_exists", path = local.display()));
    }

    let mut dirs = Vec::new();
    let mut files = Vec::new();
    plan_download(sftp, remote, local, &mut dirs, &mut files).await?;
    progress.total = files.iter().map(|(_, _, size)| size).sum();

    for dir in &dirs {
        tokio::fs::create_dir_all(dir)
            .await
            .with_context(|| t!("ssh.sftp_create_failed", path = dir.display()))?;
    }

    let mut buffer = vec![0u8; CHUNK];
    for (remote, local, _) in files {
        check_cancel(cancel)?;
        let partial = partial_path(&local);
        let result = async {
            let mut source = sftp
                .open(remote.clone())
                .await
                .map_err(|error| anyhow!("{remote}: {error}"))?;
            let mut target = tokio::fs::File::create(&partial)
                .await
                .with_context(|| t!("ssh.sftp_create_failed", path = partial.display()))?;
            loop {
                check_cancel(cancel)?;
                let read = source
                    .read(&mut buffer)
                    .await
                    .with_context(|| t!("ssh.sftp_reading_path", path = remote))?;
                if read == 0 {
                    break;
                }
                target
                    .write_all(&buffer[..read])
                    .await
                    .with_context(|| t!("ssh.sftp_writing_path", path = partial.display()))?;
                progress.advance(read as u64).await;
            }
            target.flush().await?;
            drop(target);
            tokio::fs::rename(&partial, &local)
                .await
                .with_context(|| t!("ssh.sftp_rename_failed", path = local.display()))?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if let Err(error) = result {
            let _ = tokio::fs::remove_file(&partial).await;
            return Err(error);
        }
    }
    Ok(())
}

fn partial_path(local: &Path) -> PathBuf {
    let mut name = local
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".part");
    local.with_file_name(name)
}

fn plan_upload(
    local: &Path,
    remote: &str,
    dirs: &mut Vec<String>,
    files: &mut Vec<(PathBuf, String, u64)>,
) -> Result<()> {
    let metadata =
        std::fs::symlink_metadata(local).with_context(|| format!("{}", local.display()))?;
    if metadata.is_symlink() {
        return Ok(());
    }
    if metadata.is_dir() {
        dirs.push(remote.to_string());
        let mut children: Vec<_> = std::fs::read_dir(local)
            .with_context(|| format!("{}", local.display()))?
            .filter_map(|entry| entry.ok())
            .collect();
        children.sort_by_key(|entry| entry.file_name());
        for entry in children {
            let name = entry.file_name().to_string_lossy().into_owned();
            plan_upload(&entry.path(), &join(remote, &name), dirs, files)?;
        }
    } else {
        files.push((local.to_path_buf(), remote.to_string(), metadata.len()));
    }
    Ok(())
}

async fn upload(
    sftp: &SftpSession,
    local: &Path,
    remote: &str,
    overwrite: bool,
    cancel: &AtomicBool,
    progress: &mut Progress,
) -> Result<()> {
    if !overwrite && sftp.try_exists(remote.to_string()).await.unwrap_or(false) {
        bail!(t!("ssh.sftp_remote_exists", path = remote));
    }

    let mut dirs = Vec::new();
    let mut files = Vec::new();
    plan_upload(local, remote, &mut dirs, &mut files)?;
    progress.total = files.iter().map(|(_, _, size)| size).sum();

    for dir in &dirs {
        if !sftp.try_exists(dir.clone()).await.unwrap_or(false) {
            sftp.create_dir(dir.clone())
                .await
                .map_err(|error| anyhow!(t!("ssh.sftp_create_dir_failed", dir = dir, error = error)))?;
        }
    }

    let mut buffer = vec![0u8; CHUNK];
    for (local, remote, _) in files {
        check_cancel(cancel)?;
        let result = async {
            let mut source = tokio::fs::File::open(&local)
                .await
                .with_context(|| format!("{}", local.display()))?;
            let mut target = sftp
                .create(remote.clone())
                .await
                .map_err(|error| anyhow!("{remote}: {error}"))?;
            loop {
                check_cancel(cancel)?;
                let read = source
                    .read(&mut buffer)
                    .await
                    .with_context(|| t!("ssh.sftp_reading_path", path = local.display()))?;
                if read == 0 {
                    break;
                }
                target
                    .write_all(&buffer[..read])
                    .await
                    .with_context(|| t!("ssh.sftp_writing_path", path = remote))?;
                progress.advance(read as u64).await;
            }
            target
                .shutdown()
                .await
                .with_context(|| t!("ssh.sftp_closing_path", path = remote))?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if let Err(error) = result {
            let _ = sftp.remove_file(remote.clone()).await;
            return Err(error);
        }
    }
    Ok(())
}

async fn remove(sftp: &SftpSession, path: &str) -> Result<()> {
    let metadata = sftp
        .symlink_metadata(path.to_string())
        .await
        .map_err(|error| anyhow!("{error}"))?;
    if metadata.is_dir() {
        for entry in sftp
            .read_dir(path.to_string())
            .await
            .map_err(|error| anyhow!("{error}"))?
        {
            Box::pin(remove(sftp, &join(path, &entry.file_name()))).await?;
        }
        sftp.remove_dir(path.to_string())
            .await
            .map_err(|error| anyhow!("{error}"))?;
    } else {
        sftp.remove_file(path.to_string())
            .await
            .map_err(|error| anyhow!("{error}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_and_path_joining() {
        assert_eq!(parent("/var/www/html"), "/var/www");
        assert_eq!(parent("/var"), "/");
        assert_eq!(parent("/var/www/"), "/var");
        assert_eq!(join("/var", "www"), "/var/www");
        assert_eq!(join("/", "etc"), "/etc");
    }

    #[test]
    fn incomplete_download_is_written_to_part_file() {
        assert_eq!(
            partial_path(Path::new("/tmp/archive.tar.gz")),
            PathBuf::from("/tmp/archive.tar.gz.part")
        );
    }
}
