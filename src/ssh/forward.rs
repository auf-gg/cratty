use rust_i18n::t;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow, bail};
use futures::SinkExt;
use futures::channel::mpsc;
use proto::{ForwardKind, PortForward};
use russh::client;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::FromSsh;
use super::session::Verifier;

const LISTEN_HOST: &str = "127.0.0.1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForwardState {
    Off,
    Active,
    Failed(String),
}

pub(super) type RemoteMap = Arc<Mutex<HashMap<u32, (String, u16)>>>;

pub(super) struct Forwards {
    session: Arc<client::Handle<Verifier>>,
    remote: RemoteMap,
    rules: Vec<PortForward>,
    running: HashMap<usize, Running>,
    events: mpsc::Sender<FromSsh>,
}

enum Running {
    Listener(tokio::task::AbortHandle),
    Remote(u32),
}

impl Forwards {
    pub(super) fn new(
        session: Arc<client::Handle<Verifier>>,
        remote: RemoteMap,
        rules: Vec<PortForward>,
        events: mpsc::Sender<FromSsh>,
    ) -> Self {
        Self {
            session,
            remote,
            rules,
            running: HashMap::new(),
            events,
        }
    }

    pub(super) async fn start_enabled(&mut self) {
        for index in 0..self.rules.len() {
            if self.rules[index].enabled {
                self.set(index, true).await;
            }
        }
    }

    pub(super) async fn set(&mut self, index: usize, enabled: bool) {
        let Some(rule) = self.rules.get(index).cloned() else {
            return;
        };
        let state = if enabled {
            if self.running.contains_key(&index) {
                return;
            }
            match self.start(&rule).await {
                Ok(running) => {
                    self.running.insert(index, running);
                    ForwardState::Active
                }
                Err(error) => ForwardState::Failed(format!("{error:#}")),
            }
        } else {
            match self.running.remove(&index) {
                Some(running) => self.stop(running).await,
                None => return,
            }
            ForwardState::Off
        };
        let _ = self.events.send(FromSsh::Forward { index, state }).await;
    }

    async fn start(&self, rule: &PortForward) -> Result<Running> {
        if !rule.is_usable() {
            bail!(t!("ssh.forward_rule_incomplete"));
        }
        match rule.kind {
            ForwardKind::Local | ForwardKind::Dynamic => {
                let listener = TcpListener::bind((LISTEN_HOST, rule.listen_port))
                    .await
                    .with_context(|| {
                        t!("ssh.forward_port_in_use", port = rule.listen_port).into_owned()
                    })?;
                let session = self.session.clone();
                let target = (rule.kind == ForwardKind::Local)
                    .then(|| (rule.target_host.clone(), rule.target_port));
                let task = tokio::spawn(accept_loop(listener, session, target));
                Ok(Running::Listener(task.abort_handle()))
            }
            ForwardKind::Remote => {
                let port = self
                    .session
                    .tcpip_forward("localhost", u32::from(rule.listen_port))
                    .await
                    .map_err(|error| {
                        anyhow!(t!("ssh.forward_server_refused", port = rule.listen_port, error = error))
                    })?;
                let port = if port == 0 {
                    u32::from(rule.listen_port)
                } else {
                    port
                };
                if let Ok(mut map) = self.remote.lock() {
                    map.insert(port, (rule.target_host.clone(), rule.target_port));
                }
                Ok(Running::Remote(port))
            }
            ForwardKind::Unsupported => bail!(t!("ssh.forward_rule_unknown_kind")),
        }
    }

    async fn stop(&self, running: Running) {
        match running {
            Running::Listener(task) => task.abort(),
            Running::Remote(port) => {
                if let Ok(mut map) = self.remote.lock() {
                    map.remove(&port);
                }
                let _ = self.session.cancel_tcpip_forward("localhost", port).await;
            }
        }
    }
}

impl Drop for Forwards {
    fn drop(&mut self) {
        for running in self.running.values() {
            if let Running::Listener(task) = running {
                task.abort();
            }
        }
    }
}

async fn accept_loop(
    listener: TcpListener,
    session: Arc<client::Handle<Verifier>>,
    target: Option<(String, u16)>,
) {
    while let Ok((stream, peer)) = listener.accept().await {
        let _ = stream.set_nodelay(true);
        let session = session.clone();
        let target = target.clone();
        tokio::spawn(async move {
            let _ = match target {
                Some((host, port)) => pipe(stream, &session, &host, port, peer).await,
                None => socks5(stream, &session, peer).await,
            };
        });
    }
}

async fn pipe(
    mut stream: TcpStream,
    session: &client::Handle<Verifier>,
    host: &str,
    port: u16,
    peer: std::net::SocketAddr,
) -> Result<()> {
    let channel = session
        .channel_open_direct_tcpip(
            host,
            u32::from(port),
            peer.ip().to_string(),
            u32::from(peer.port()),
        )
        .await?;
    let mut remote = channel.into_stream();
    tokio::io::copy_bidirectional(&mut stream, &mut remote).await?;
    Ok(())
}

async fn socks5(
    mut stream: TcpStream,
    session: &client::Handle<Verifier>,
    peer: std::net::SocketAddr,
) -> Result<()> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != 5 {
        bail!("not SOCKS5");
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        stream.write_all(&[5, 0xFF]).await?;
        bail!("the client requires authentication");
    }
    stream.write_all(&[5, 0]).await?;

    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;
    let host = match request[3] {
        1 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        3 => {
            let len = stream.read_u8().await?;
            let mut name = vec![0u8; usize::from(len)];
            stream.read_exact(&mut name).await?;
            String::from_utf8(name).map_err(|_| anyhow!("name is not UTF-8"))?
        }
        4 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        _ => {
            reply(&mut stream, 8).await?;
            bail!("unknown address type");
        }
    };
    let port = stream.read_u16().await?;
    if request[1] != 1 {
        reply(&mut stream, 7).await?;
        bail!("SOCKS command is not supported");
    }

    let channel = match session
        .channel_open_direct_tcpip(
            host,
            u32::from(port),
            peer.ip().to_string(),
            u32::from(peer.port()),
        )
        .await
    {
        Ok(channel) => channel,
        Err(error) => {
            reply(&mut stream, 4).await?;
            return Err(error.into());
        }
    };
    reply(&mut stream, 0).await?;
    let mut remote = channel.into_stream();
    tokio::io::copy_bidirectional(&mut stream, &mut remote).await?;
    Ok(())
}

async fn reply(stream: &mut TcpStream, code: u8) -> Result<()> {
    stream.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    Ok(())
}

pub(super) fn remote_target(map: &RemoteMap, port: u32) -> Option<(String, u16)> {
    map.lock().ok()?.get(&port).cloned()
}
