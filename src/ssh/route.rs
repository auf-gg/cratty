use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncRead, AsyncWrite};
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

pub async fn tcp(host: &str, port: u16) -> Result<Transport> {
    let stream = tokio::net::TcpStream::connect((host, port))
        .await
        .with_context(|| format!("TCP до {}", join(host, port)))?;
    stream
        .set_nodelay(true)
        .context("не включить TCP_NODELAY")?;
    Ok(Box::new(stream))
}

pub async fn socks5(
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
