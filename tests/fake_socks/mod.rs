#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Default)]
struct Observed {
    targets: Vec<(String, u16)>,
    users: Vec<String>,
}

pub struct FakeSocks {
    addr: SocketAddr,
    observed: Arc<Mutex<Observed>>,
    task: tokio::task::JoinHandle<()>,
}

impl FakeSocks {
    pub async fn open() -> Self {
        Self::start(None).await
    }

    pub async fn with_password(user: &str, password: &str) -> Self {
        Self::start(Some((user.to_string(), password.to_string()))).await
    }

    async fn start(credentials: Option<(String, String)>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("не занять порт под тестовый SOCKS5");
        let addr = listener.local_addr().expect("у слушателя нет адреса");
        let observed = Arc::new(Mutex::new(Observed::default()));

        let shared = observed.clone();
        let task = tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let observed = shared.clone();
                let credentials = credentials.clone();
                tokio::spawn(async move {
                    let _ = serve(client, credentials, observed).await;
                });
            }
        });

        Self {
            addr,
            observed,
            task,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn targets(&self) -> Vec<(String, u16)> {
        self.lock().targets.clone()
    }

    pub fn users(&self) -> Vec<String> {
        self.lock().users.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Observed> {
        self.observed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Drop for FakeSocks {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(
    mut client: TcpStream,
    credentials: Option<(String, String)>,
    observed: Arc<Mutex<Observed>>,
) -> std::io::Result<()> {
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    let mut methods = vec![0u8; usize::from(head[1])];
    client.read_exact(&mut methods).await?;

    let wanted = if credentials.is_some() { 0x02 } else { 0x00 };
    if head[0] != 5 || !methods.contains(&wanted) {
        client.write_all(&[5, 0xFF]).await?;
        return Ok(());
    }
    client.write_all(&[5, wanted]).await?;

    if let Some((user, password)) = credentials {
        let mut version = [0u8; 1];
        client.read_exact(&mut version).await?;
        let got_user = read_short(&mut client).await?;
        let got_password = read_short(&mut client).await?;
        let got_user = String::from_utf8_lossy(&got_user).into_owned();
        if let Ok(mut observed) = observed.lock() {
            observed.users.push(got_user.clone());
        }
        if got_user != user || got_password != password.as_bytes() {
            client.write_all(&[1, 1]).await?;
            return Ok(());
        }
        client.write_all(&[1, 0]).await?;
    }

    let mut request = [0u8; 4];
    client.read_exact(&mut request).await?;
    let host = match request[3] {
        1 => {
            let mut ip = [0u8; 4];
            client.read_exact(&mut ip).await?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        3 => String::from_utf8_lossy(&read_short(&mut client).await?).into_owned(),
        4 => {
            let mut ip = [0u8; 16];
            client.read_exact(&mut ip).await?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        _ => return Ok(()),
    };
    let mut port = [0u8; 2];
    client.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);

    if let Ok(mut observed) = observed.lock() {
        observed.targets.push((host.clone(), port));
    }

    let Ok(mut upstream) = TcpStream::connect((host.as_str(), port)).await else {
        client.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        return Ok(());
    };
    client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

async fn read_short(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 1];
    stream.read_exact(&mut len).await?;
    let mut bytes = vec![0u8; usize::from(len[0])];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}
