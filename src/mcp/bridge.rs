//! `cratty --mcp-bridge`: what an agent starts as a stdio MCP server. It connects to the
//! running app, presents the tab's token and then passes messages both ways unchanged.
//! The bridge holds no state and never opens a window.

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::agent::Address;

pub const FLAG: &str = "--mcp-bridge";
pub const TOKEN_VAR: &str = "CRATTY_MCP_TOKEN";
pub const ADDRESS_VAR: &str = "CRATTY_MCP_ADDRESS";

/// Runs the bridge until either side closes; returns the process exit code.
pub fn run() -> i32 {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("cratty: {error}");
            return 1;
        }
    };
    let result = runtime.block_on(bridge());
    // Standard input is read on a blocking thread that does not end by itself.
    runtime.shutdown_background();
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("cratty: {error:#}");
            1
        }
    }
}

async fn bridge() -> Result<()> {
    let token = std::env::var(TOKEN_VAR).with_context(|| {
        format!("{TOKEN_VAR} is not set: copy the MCP configuration from the tab in Cratty")
    })?;
    let address = match std::env::var_os(ADDRESS_VAR) {
        Some(text) => from_text(&text.to_string_lossy()),
        None => crate::agent::mcp_address()?,
    };
    let stream = connect(&address).await.with_context(|| {
        format!(
            "could not reach Cratty at {}: is it running with agent access allowed on a tab?",
            address.as_text()
        )
    })?;
    let (read, mut write) = tokio::io::split(stream);
    let mut read = BufReader::new(read);

    let mut hello = serde_json::to_vec(&json!({ "token": token }))?;
    hello.push(b'\n');
    write.write_all(&hello).await?;
    write.flush().await?;

    let mut line = Vec::new();
    (&mut read)
        .take(64 * 1024)
        .read_until(b'\n', &mut line)
        .await?;
    let answer: Value = serde_json::from_slice(&line).context("Cratty closed the connection")?;
    if let Some(error) = answer.get("error").and_then(Value::as_str) {
        bail!("{error}");
    }

    tokio::select! {
        _ = pump(tokio::io::stdin(), &mut write) => {}
        _ = pump(read, tokio::io::stdout()) => {}
    }
    Ok(())
}

/// Copies until end of input, flushing after every chunk: a message must not wait in a
/// buffer for the next one.
async fn pump<R, W>(mut from: R, mut to: W) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = from.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        to.write_all(&buffer[..read]).await?;
        to.flush().await?;
    }
}

#[cfg(unix)]
fn from_text(text: &str) -> Address {
    Address::Socket(text.into())
}

#[cfg(windows)]
fn from_text(text: &str) -> Address {
    Address::Pipe(text.to_owned())
}

#[cfg(unix)]
async fn connect(address: &Address) -> std::io::Result<tokio::net::UnixStream> {
    let Address::Socket(path) = address else {
        return Err(std::io::ErrorKind::InvalidInput.into());
    };
    tokio::net::UnixStream::connect(path).await
}

#[cfg(windows)]
async fn connect(
    address: &Address,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;

    let Address::Pipe(name) = address else {
        return Err(std::io::ErrorKind::InvalidInput.into());
    };
    // The server keeps the next pipe instance ready; "busy" only lasts a moment.
    for _ in 0..20 {
        match tokio::net::windows::named_pipe::ClientOptions::new().open(name) {
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            result => return result,
        }
    }
    Err(std::io::ErrorKind::TimedOut.into())
}
