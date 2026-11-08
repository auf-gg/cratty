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
            Self::Socks5(hop) => format!("прокси SOCKS5 {}", join(&hop.host, hop.port)),
            Self::Jump(hop) => format!(
                "промежуточный хост {}@{}",
                hop.user,
                join(&hop.host, hop.port)
            ),
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

/// Сколько ждём каждый сетевой шаг подключения: TCP, прокси, туннель, первый
/// ответ SSH-сервера. Без предела недоступный хост держал бы вкладку минутами.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// `work`, но не дольше [`CONNECT_TIMEOUT`].
pub async fn deadline<T>(what: &str, work: impl Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(CONNECT_TIMEOUT, work)
        .await
        .unwrap_or_else(|_| {
            Err(anyhow!(
                "{what}: нет ответа за {} с",
                CONNECT_TIMEOUT.as_secs()
            ))
        })
}

pub async fn tcp(host: &str, port: u16) -> Result<Transport> {
    let address = join(host, port);
    let stream = deadline(&format!("TCP до {address}"), async {
        tokio::net::TcpStream::connect((host, port))
            .await
            .with_context(|| format!("TCP до {address}"))
    })
    .await?;
    stream
        .set_nodelay(true)
        .context("не включить TCP_NODELAY")?;
    Ok(Box::new(stream))
}

/// Поток, который ждёт первых байт от сервера не дольше [`CONNECT_TIMEOUT`].
/// Нужен для SSH-рукопожатия: порт может принять соединение и молчать. Дальше
/// предела нет — пока пользователь решает про ключ хоста или вводит пароль,
/// сервер законно молчит, а мёртвое соединение потом ловит keepalive.
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
                format!(
                    "сервер не ответил по SSH за {} с",
                    CONNECT_TIMEOUT.as_secs()
                ),
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
    deadline("прокси SOCKS5", socks5_handshake(stream, hop, host, port)).await
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
                .map_err(|_| anyhow!("пароль прокси не UTF-8 — SOCKS5 такой не передаст"))?,
            None => {
                return Err(anyhow!(
                    "у прокси задан логин {}, но нет пароля — SOCKS5 без пароля \
                     с логином не входит",
                    hop.user
                ));
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
    fn ipv6_v_opisanii_beretsya_v_skobki() {
        assert_eq!(join("::1", 22), "[::1]:22");
        assert_eq!(join("example.com", 2222), "example.com:2222");
    }

    #[test]
    fn zvenya_nazyvayutsya_chelovecheski() {
        let socks = Hop::Socks5(Socks5Hop {
            host: "proxy.local".into(),
            port: 1080,
            user: String::new(),
            password: None,
        });
        assert_eq!(socks.describe(), "прокси SOCKS5 proxy.local:1080");
        assert_eq!(socks.address(), ("proxy.local", 1080));
    }
}

#[cfg(test)]
mod timeout_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test(start_paused = true)]
    async fn molchashchiy_server_otvalivaetsya_po_taimautu() {
        let (ours, _theirs) = tokio::io::duplex(64);
        let mut stream = answering(Box::new(ours));
        let mut buf = [0u8; 8];
        let error = stream.read(&mut buf).await.expect_err("ждали таймаут");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn posle_pervogo_otveta_taimauta_net() {
        let (ours, mut theirs) = tokio::io::duplex(64);
        let mut stream = answering(Box::new(ours));
        theirs.write_all(b"SSH-2.0").await.unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(stream.read(&mut buf).await.unwrap(), 7);

        // Дальше сервер может молчать сколько угодно: ждёт пароль от человека.
        let wait = tokio::time::timeout(CONNECT_TIMEOUT * 4, stream.read(&mut buf)).await;
        assert!(wait.is_err(), "поток оборвался, хотя первый ответ уже был");
    }
}
