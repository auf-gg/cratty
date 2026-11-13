//! One running copy of the app.
//!
//! Copies would not see each other's changes and would overwrite each other's vault
//! records and settings. So the first copy listens on a local socket (a named pipe on
//! Windows), and a later copy hands its command line to it and exits; the first one
//! brings its window forward and opens the address, if any. If the first copy does
//! not answer, the later one starts as usual. Copies are counted per user account,
//! not per vault directory.

use std::io::{BufRead, BufReader, Read, Write};
use std::time::Duration;

use anyhow::Result;
use futures::channel::{mpsc, oneshot};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::agent::{Address, Listener, instance_address};

/// Command line (without the program name) of a copy started while this one runs.
pub type Request = Vec<String>;

/// The longest command line accepted from another copy.
const MAX_REQUEST: u64 = 64 * 1024;
const REPLY: &[u8] = b"ok\n";
const TIMEOUT: Duration = Duration::from_secs(3);

/// This copy owns the address. Dropping it stops listening and frees the address.
pub struct Primary {
    stop: Option<oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Primary {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Starts waiting for later copies. Fails when another copy already listens.
pub fn listen() -> Result<(Primary, mpsc::UnboundedReceiver<Request>)> {
    let address = instance_address()?;
    let (requests_tx, requests_rx) = mpsc::unbounded();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();

    let thread = std::thread::Builder::new()
        .name("instance".to_owned())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = ready_tx.send(Err(error.to_string()));
                    return;
                }
            };

            runtime.block_on(async move {
                #[allow(unused_mut)]
                let mut listener = match Listener::bind(&address).await {
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
                            let requests = requests_tx.clone();
                            tokio::spawn(async move {
                                let _ = tokio::time::timeout(TIMEOUT, serve(stream, requests)).await;
                            });
                        }
                    }
                }
            });
        })?;

    match ready_rx.recv() {
        Ok(Ok(())) => Ok((
            Primary {
                stop: Some(stop_tx),
                thread: Some(thread),
            },
            requests_rx,
        )),
        Ok(Err(error)) => {
            let _ = thread.join();
            anyhow::bail!("{error}")
        }
        Err(_) => {
            let _ = thread.join();
            anyhow::bail!("instance thread exited")
        }
    }
}

async fn serve<S>(mut stream: S, requests: mpsc::UnboundedSender<Request>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut line = Vec::new();
    tokio::io::BufReader::new(&mut stream)
        .take(MAX_REQUEST)
        .read_until(b'\n', &mut line)
        .await?;
    let request: Request = serde_json::from_slice(&line)?;
    requests.unbounded_send(request)?;

    stream.write_all(REPLY).await?;
    stream.flush().await?;
    // Wait until the other copy has read the reply and hung up: on Windows, closing
    // the pipe first could discard the reply before it is read.
    let _ = stream.read(&mut [0u8; 1]).await;
    Ok(())
}

/// Hands the command line to the copy that is already running. `false` when there
/// is none or it did not answer: then this copy starts as usual.
pub fn hand_over(args: &[String]) -> bool {
    try_hand_over(args).unwrap_or(false)
}

fn try_hand_over(args: &[String]) -> std::io::Result<bool> {
    let Ok(address) = instance_address() else {
        return Ok(false);
    };
    let mut stream = connect(&address)?;
    allow_foreground();

    let mut line = serde_json::to_vec(args)?;
    line.push(b'\n');
    stream.write_all(&line)?;
    stream.flush()?;

    let mut reply = Vec::new();
    BufReader::new(&mut stream)
        .take(REPLY.len() as u64)
        .read_until(b'\n', &mut reply)?;
    Ok(reply == REPLY)
}

#[cfg(unix)]
fn connect(address: &Address) -> std::io::Result<std::os::unix::net::UnixStream> {
    let Address::Socket(path) = address else {
        return Err(std::io::ErrorKind::InvalidInput.into());
    };
    let stream = std::os::unix::net::UnixStream::connect(path)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    Ok(stream)
}

#[cfg(windows)]
fn connect(address: &Address) -> std::io::Result<std::fs::File> {
    use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;

    let Address::Pipe(name) = address else {
        return Err(std::io::ErrorKind::InvalidInput.into());
    };
    // The server keeps the next pipe instance ready; "busy" only lasts a moment.
    for _ in 0..20 {
        match std::fs::OpenOptions::new().read(true).write(true).open(name) {
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                std::thread::sleep(Duration::from_millis(50));
            }
            result => return result,
        }
    }
    Err(std::io::ErrorKind::TimedOut.into())
}

/// Windows lets the running copy bring its window forward only with permission from
/// the process the user has just started — this one.
#[cfg(windows)]
fn allow_foreground() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{ASFW_ANY, AllowSetForegroundWindow};
    unsafe {
        AllowSetForegroundWindow(ASFW_ANY);
    }
}

#[cfg(not(windows))]
fn allow_foreground() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn request_reaches_the_running_copy_and_is_acknowledged() {
        let (client, server) = tokio::io::duplex(1024);
        let (tx, mut rx) = mpsc::unbounded();
        let serving = tokio::spawn(serve(server, tx));

        let (read, mut write) = tokio::io::split(client);
        write.write_all(b"[\"user@host:2222\"]\n").await.expect("write");
        let mut reply = Vec::new();
        tokio::io::BufReader::new(read)
            .read_until(b'\n', &mut reply)
            .await
            .expect("read");
        drop(write);

        assert_eq!(reply, REPLY);
        assert_eq!(rx.try_recv().expect("request"), vec!["user@host:2222".to_owned()]);
        serving.await.expect("join").expect("serve");
    }

    #[tokio::test]
    async fn garbage_is_not_acknowledged() {
        let (mut client, server) = tokio::io::duplex(1024);
        let (tx, mut rx) = mpsc::unbounded();
        let serving = tokio::spawn(serve(server, tx));

        client.write_all(b"not json\n").await.expect("write");
        assert!(serving.await.expect("join").is_err());
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.expect("read");
        assert!(reply.is_empty());
        assert!(
            matches!(rx.try_recv(), Err(mpsc::TryRecvError::Closed)),
            "nothing must reach the window"
        );
    }
}
