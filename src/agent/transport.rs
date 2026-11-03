use std::path::PathBuf;

use anyhow::{Context, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address {
    Socket(PathBuf),
    Pipe(String),
}

impl Address {
    pub fn as_text(&self) -> String {
        match self {
            Self::Socket(path) => path.display().to_string(),
            Self::Pipe(name) => name.clone(),
        }
    }
}

#[cfg(windows)]
pub fn default_address() -> Result<Address> {
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "user".to_owned());
    let user: String = user
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    Ok(Address::Pipe(format!(r"\\.\pipe\cratty-agent-{user}")))
}

#[cfg(unix)]
pub fn default_address() -> Result<Address> {
    let dir = match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(runtime) => PathBuf::from(runtime).join("cratty"),
        None => crate::store::VaultStore::default_root()
            .context("не определить каталог для сокета агента")?,
    };
    Ok(Address::Socket(dir.join("agent.sock")))
}

#[cfg(unix)]
pub struct Listener {
    inner: tokio::net::UnixListener,
    path: PathBuf,
}

#[cfg(unix)]
impl Listener {
    pub async fn bind(address: &Address) -> Result<Self> {
        let Address::Socket(path) = address else {
            anyhow::bail!("на unix адрес агента — это путь к сокету");
        };

        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("не создать каталог {}", dir.display()))?;
            restrict(dir, 0o700)?;
        }

        if path.exists() {
            match tokio::net::UnixStream::connect(path).await {
                Ok(_) => anyhow::bail!(
                    "агент уже слушает {} — похоже, приложение запущено дважды",
                    path.display()
                ),
                Err(_) => {
                    std::fs::remove_file(path)
                        .with_context(|| format!("не убрать мёртвый сокет {}", path.display()))?;
                }
            }
        }

        let inner = tokio::net::UnixListener::bind(path)
            .with_context(|| format!("не занять сокет {}", path.display()))?;
        restrict(path, 0o600)?;

        Ok(Self {
            inner,
            path: path.clone(),
        })
    }

    pub async fn accept(&self) -> Result<tokio::net::UnixStream> {
        let (stream, _) = self.inner.accept().await.context("приём соединения")?;
        Ok(stream)
    }
}

#[cfg(unix)]
impl Drop for Listener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
fn restrict(path: &std::path::Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("не выставить права на {}", path.display()))
}

#[cfg(windows)]
pub struct Listener {
    name: String,
    next: Option<tokio::net::windows::named_pipe::NamedPipeServer>,
}

#[cfg(windows)]
impl Listener {
    pub async fn bind(address: &Address) -> Result<Self> {
        let Address::Pipe(name) = address else {
            anyhow::bail!("на Windows адрес агента — это имя канала");
        };

        let server = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .create(name)
            .with_context(|| format!("не занять канал {name}"))?;

        Ok(Self {
            name: name.clone(),
            next: Some(server),
        })
    }

    pub async fn accept(&mut self) -> Result<tokio::net::windows::named_pipe::NamedPipeServer> {
        let server = match self.next.take() {
            Some(server) => server,
            None => tokio::net::windows::named_pipe::ServerOptions::new()
                .reject_remote_clients(true)
                .create(&self.name)
                .with_context(|| format!("не создать экземпляр канала {}", self.name))?,
        };

        server.connect().await.context("приём соединения")?;

        self.next = Some(
            tokio::net::windows::named_pipe::ServerOptions::new()
                .reject_remote_clients(true)
                .create(&self.name)
                .with_context(|| format!("не создать экземпляр канала {}", self.name))?,
        );

        Ok(server)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adres_po_umolchaniyu_est_i_pokazyvaetsya() {
        let address = default_address().expect("адрес");
        let text = address.as_text();
        assert!(!text.is_empty());

        match address {
            Address::Socket(path) => assert!(path.ends_with("agent.sock")),
            Address::Pipe(name) => assert!(name.starts_with(r"\\.\pipe\")),
        }
    }
}
