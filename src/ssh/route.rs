use rust_i18n::t;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_socks::tcp::Socks5Stream;

use super::{AuthMethod, HostKeyPolicy};

pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

pub type Transport = Box<dyn Duplex>;

#[derive(Clone, Debug)]
pub enum Hop {
    Socks5(Socks5Hop),
    Jump(JumpHost),
}

#[derive(Clone, Debug)]
pub struct Socks5Hop {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: Option<proto::Secret>,
}

#[derive(Clone, Debug)]
pub struct JumpHost {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: AuthMethod,
    pub host_key_policy: HostKeyPolicy,
    pub stored_password: Option<proto::Secret>,
}

impl Hop {
    pub fn address(&self) -> (&str, u16) {
        match self {
            Self::Socks5(hop) => (&hop.host, hop.port),
            Self::Jump(hop) => (&hop.host, hop.port),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Socks5(hop) => t!("ssh.hop_socks5", address = join(&hop.host, hop.port)).into_owned(),
            Self::Jump(hop) => t!(
                "ssh.hop_jump",
                user = hop.user,
                address = join(&hop.host, hop.port)
            )
            .into_owned(),
        }
    }
}

pub fn join(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// How long we wait for each network step of a connection: TCP, proxy, tunnel, the first
/// SSH server reply. Without a limit an unreachable host would hold a tab for minutes.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// `work`, but no longer than [`CONNECT_TIMEOUT`].
pub async fn deadline<T>(what: &str, work: impl Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(CONNECT_TIMEOUT, work)
        .await
        .unwrap_or_else(|_| {
            Err(anyhow!(t!(
                "ssh.route_no_response",
                what = what,
                secs = CONNECT_TIMEOUT.as_secs()
            )))
        })
}

pub async fn tcp(host: &str, port: u16) -> Result<Transport> {
    let address = join(host, port);
    let stream = deadline(&t!("ssh.route_tcp_label", address = address), async {
        tokio::net::TcpStream::connect((host, port))
            .await
            .with_context(|| t!("ssh.route_tcp_label", address = address))
    })
    .await?;
    stream
        .set_nodelay(true)
        .with_context(|| t!("ssh.route_nodelay_failed"))?;
    Ok(Box::new(stream))
}

/// A stream that waits for the first bytes from the server for no longer than [`CONNECT_TIMEOUT`].
/// Needed for the SSH handshake: a port may accept the connection and stay silent. After that
/// there is no limit — while the user decides about the host key or enters a password,
/// the server is legitimately silent, and keepalive catches a dead connection later.
pub fn answering(stream: Transport) -> Transport {
    Box::new(FirstByte {
        inner: stream,
        deadline: Some(Box::pin(tokio::time::sleep(CONNECT_TIMEOUT))),
    })
}

struct FirstByte {
    inner: Transport,
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl AsyncRead for FirstByte {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let filled = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if result.is_ready() {
            if buf.filled().len() > filled {
                self.deadline = None;
            }
            return result;
        }
        if let Some(deadline) = &mut self.deadline
            && deadline.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                t!(
                    "ssh.route_ssh_no_answer",
                    secs = CONNECT_TIMEOUT.as_secs()
                )
                .into_owned(),
            )));
        }
        Poll::Pending
    }
}

impl AsyncWrite for FirstByte {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub async fn socks5(
    stream: Transport,
    hop: &Socks5Hop,
    host: &str,
    port: u16,
) -> Result<Transport> {
    deadline(&t!("ssh.route_socks5_label"), socks5_handshake(stream, hop, host, port)).await
}

async fn socks5_handshake(
    stream: Transport,
    hop: &Socks5Hop,
    host: &str,
    port: u16,
) -> Result<Transport> {
    let target = (host, port);
    let connected = if hop.user.is_empty() {
        Socks5Stream::connect_with_socket(stream, target)
            .await
            .map_err(|error| anyhow!("{error}"))?
    } else {
        let password = match &hop.password {
            Some(secret) => std::str::from_utf8(secret.expose())
                .map_err(|_| anyhow!(t!("ssh.route_proxy_password_not_utf8")))?,
            None => {
                return Err(anyhow!(t!("ssh.route_proxy_no_password", user = hop.user)));
            }
        };
        Socks5Stream::connect_with_password_and_socket(stream, target, &hop.user, password)
            .await
            .map_err(|error| anyhow!("{error}"))?
    };
    Ok(Box::new(connected.into_inner()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_in_description_is_bracketed() {
        assert_eq!(join("::1", 22), "[::1]:22");
        assert_eq!(join("example.com", 2222), "example.com:2222");
    }

    #[test]
    fn hops_have_human_readable_names() {
        let socks = Hop::Socks5(Socks5Hop {
            host: "proxy.local".into(),
            port: 1080,
            user: String::new(),
            password: None,
        });
        assert_eq!(socks.describe(), "SOCKS5 proxy proxy.local:1080");
        assert_eq!(socks.address(), ("proxy.local", 1080));
    }
}

#[cfg(test)]
mod timeout_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test(start_paused = true)]
    async fn silent_server_drops_off_on_timeout() {
        let (ours, _theirs) = tokio::io::duplex(64);
        let mut stream = answering(Box::new(ours));
        let mut buf = [0u8; 8];
        let error = stream.read(&mut buf).await.expect_err("expected a timeout");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn no_timeout_after_first_response() {
        let (ours, mut theirs) = tokio::io::duplex(64);
        let mut stream = answering(Box::new(ours));
        theirs.write_all(b"SSH-2.0").await.unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(stream.read(&mut buf).await.unwrap(), 7);

        // After that the server may stay silent as long as it likes: it is waiting for a password from a human.
        let wait = tokio::time::timeout(CONNECT_TIMEOUT * 4, stream.read(&mut buf)).await;
        assert!(wait.is_err(), "the stream was cut off although the first reply had already arrived");
    }
}
