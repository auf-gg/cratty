use rust_i18n::t;
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
fn pipe_user() -> String {
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "user".to_owned());
    user.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}

#[cfg(windows)]
pub fn default_address() -> Result<Address> {
    Ok(Address::Pipe(format!(r"\\.\pipe\cratty-agent-{}", pipe_user())))
}

#[cfg(unix)]
pub fn default_address() -> Result<Address> {
    let dir = match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(runtime) => PathBuf::from(runtime).join("cratty"),
        None => crate::store::VaultStore::default_root()
            .context(t!("agent.no_socket_dir"))?,
    };
    Ok(Address::Socket(dir.join("agent.sock")))
}

/// Where the first running copy of the app waits for the next ones (see `crate::instance`).
#[cfg(windows)]
pub fn instance_address() -> Result<Address> {
    Ok(Address::Pipe(format!(r"\\.\pipe\cratty-instance-{}", pipe_user())))
}

#[cfg(unix)]
pub fn instance_address() -> Result<Address> {
    Ok(Address::Socket(runtime_dir()?.join("instance.sock")))
}

/// Where AI agents reach the running app through `cratty --mcp-bridge` (see `crate::mcp`).
#[cfg(windows)]
pub fn mcp_address() -> Result<Address> {
    Ok(Address::Pipe(format!(r"\\.\pipe\cratty-mcp-{}", pipe_user())))
}

#[cfg(unix)]
pub fn mcp_address() -> Result<Address> {
    Ok(Address::Socket(runtime_dir()?.join("mcp.sock")))
}

#[cfg(unix)]
fn runtime_dir() -> Result<PathBuf> {
    Ok(match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(runtime) => PathBuf::from(runtime).join("cratty"),
        None => crate::store::VaultStore::default_base().context(t!("agent.no_socket_dir"))?,
    })
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
            anyhow::bail!(t!("agent.unix_address_path"));
        };

        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| t!("agent.create_dir_failed", path = dir.display()))?;
            restrict(dir, 0o700)?;
        }

        if path.exists() {
            match tokio::net::UnixStream::connect(path).await {
                Ok(_) => anyhow::bail!(t!("agent.already_listening", path = path.display())),
                Err(_) => {
                    std::fs::remove_file(path)
                        .with_context(|| t!("agent.remove_socket_failed", path = path.display()))?;
                }
            }
        }

        let inner = tokio::net::UnixListener::bind(path)
            .with_context(|| t!("agent.bind_socket_failed", path = path.display()))?;
        restrict(path, 0o600)?;

        Ok(Self {
            inner,
            path: path.clone(),
        })
    }

    pub async fn accept(&self) -> Result<tokio::net::UnixStream> {
        let (stream, _) = self.inner.accept().await.context(t!("agent.ctx_accept"))?;
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
        .with_context(|| t!("agent.set_permissions_failed", path = path.display()))
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
            anyhow::bail!(t!("agent.windows_address_pipe"));
        };

        let server = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .create(name)
            .with_context(|| t!("agent.claim_pipe_failed", name = name))?;

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
                .with_context(|| t!("agent.pipe_instance_failed", name = self.name))?,
        };

        server.connect().await.context(t!("agent.ctx_accept"))?;

        self.next = Some(
            tokio::net::windows::named_pipe::ServerOptions::new()
                .reject_remote_clients(true)
                .create(&self.name)
                .with_context(|| t!("agent.pipe_instance_failed", name = self.name))?,
        );

        Ok(server)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_address_exists_and_is_displayed() {
        let address = default_address().expect("address");
        let text = address.as_text();
        assert!(!text.is_empty());

        match address {
            Address::Socket(path) => assert!(path.ends_with("agent.sock")),
            Address::Pipe(name) => assert!(name.starts_with(r"\\.\pipe\")),
        }
    }
}
