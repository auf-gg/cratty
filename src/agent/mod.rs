pub mod keys;
mod transport;

use rust_i18n::t;
use anyhow::{Context, Result};
use futures::SinkExt;
use futures::channel::{mpsc, oneshot};
use russh::keys::ssh_key::HashAlg;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub use transport::{Address, Listener, default_address, instance_address};

pub struct Running {
    address: Address,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Running {
    pub fn address(&self) -> &Address {
        &self.address
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub fn spawn(address: Address) -> Result<(Running, mpsc::UnboundedReceiver<Ask>)> {
    let (asks_tx, asks_rx) = mpsc::unbounded();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();

    let bound = address.clone();
    let thread = std::thread::Builder::new()
        .name("ssh-agent".to_owned())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = ready_tx.send(Err(t!("agent.runtime_failed", error = error).into_owned()));
                    return;
                }
            };

            runtime.block_on(async move {
                #[allow(unused_mut)]
                let mut listener = match Listener::bind(&bound).await {
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
                            let asks = asks_tx.clone();
                            tokio::spawn(async move {
                                let _ = serve_connection(stream, asks).await;
                            });
                        }
                    }
                }
            });
        })
        .context(t!("agent.thread_start_failed"))?;

    match ready_rx.recv() {
        Ok(Ok(())) => Ok((
            Running {
                address,
                stop: Some(stop_tx),
                thread: Some(thread),
            },
            asks_rx,
        )),
        Ok(Err(error)) => {
            let _ = thread.join();
            anyhow::bail!("{error}")
        }
        Err(_) => {
            let _ = thread.join();
            anyhow::bail!(t!("agent.thread_exited"))
        }
    }
}

pub enum Ask {
    Identities {
        reply: oneshot::Sender<Vec<::agent::Identity>>,
    },
    Sign(Box<SignAsk>),
}

pub struct SignAsk {
    pub public: Vec<u8>,
    pub data: Vec<u8>,
    pub hash: Option<HashAlg>,
    pub bound: Option<Bound>,
    pub reply: oneshot::Sender<Option<Vec<u8>>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bound {
    pub host_key: Vec<u8>,
    pub fingerprint: String,
    pub is_forwarding: bool,
}

pub async fn serve_connection<S>(mut stream: S, asks: mpsc::UnboundedSender<Ask>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut bound: Option<Bound> = None;
    let mut header = [0u8; 4];
    let mut frame = Vec::new();

    loop {
        match stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error).context(t!("agent.ctx_frame_header")),
        }

        let len = match ::agent::frame_len(header) {
            Ok(len) => len,
            Err(error) => return Err(anyhow::anyhow!("{error}")),
        };

        frame.clear();
        frame.resize(len, 0);
        stream
            .read_exact(&mut frame)
            .await
            .context(t!("agent.ctx_frame"))?;

        let response = respond(&frame, &mut bound, &asks).await;
        stream.write_all(&response).await.context(t!("agent.ctx_reply"))?;
        stream.flush().await.context(t!("agent.ctx_flush"))?;
    }
}

async fn respond(
    frame: &[u8],
    bound: &mut Option<Bound>,
    asks: &mpsc::UnboundedSender<Ask>,
) -> Vec<u8> {
    let request = match ::agent::Request::parse(frame) {
        Ok(request) => request,
        Err(_) => return ::agent::failure(),
    };

    match request {
        ::agent::Request::Identities => match ask_identities(asks).await {
            Some(identities) => ::agent::identities_answer(&identities),
            None => ::agent::failure(),
        },

        ::agent::Request::Sign {
            key_blob,
            data,
            flags,
        } => {
            if flags.unknown() != 0 {
                return ::agent::failure();
            }

            let hash = match flags.rsa_hash() {
                Some(::agent::RsaHash::Sha256) => Some(HashAlg::Sha256),
                Some(::agent::RsaHash::Sha512) => Some(HashAlg::Sha512),
                None => None,
            };

            let (reply, answer) = oneshot::channel();
            let ask = Ask::Sign(Box::new(SignAsk {
                public: key_blob.to_vec(),
                data: data.to_vec(),
                hash,
                bound: bound.clone(),
                reply,
            }));

            match send(asks, ask, answer).await {
                Some(Some(signature)) => ::agent::sign_response(&signature),
                _ => ::agent::failure(),
            }
        }

        ::agent::Request::Extension { name, body } if name == ::agent::SESSION_BIND => {
            match session_bind(body) {
                Some(new_bound) => {
                    *bound = Some(new_bound);
                    ::agent::success()
                }
                None => ::agent::failure(),
            }
        }

        ::agent::Request::Extension { .. } => ::agent::extension_failure(),

        ::agent::Request::Unsupported { .. } => ::agent::failure(),
    }
}

fn session_bind(body: &[u8]) -> Option<Bound> {
    let bind = ::agent::parse_session_bind(body).ok()?;
    let key = keys::verify_session_bind(bind.host_key, bind.session_id, bind.signature).ok()?;
    Some(Bound {
        host_key: bind.host_key.to_vec(),
        fingerprint: keys::fingerprint(&key),
        is_forwarding: bind.is_forwarding,
    })
}

async fn ask_identities(asks: &mpsc::UnboundedSender<Ask>) -> Option<Vec<::agent::Identity>> {
    let (reply, answer) = oneshot::channel();
    send(asks, Ask::Identities { reply }, answer).await
}

async fn send<T>(
    asks: &mpsc::UnboundedSender<Ask>,
    ask: Ask,
    answer: oneshot::Receiver<T>,
) -> Option<T> {
    let mut sender = asks.clone();
    sender.send(ask).await.ok()?;
    answer.await.ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    async fn one(frame: &[u8], answer: impl FnOnce(Ask)) -> Vec<u8> {
        let (asks, mut rx) = mpsc::unbounded();
        let mut bound = None;
        let served = respond(frame, &mut bound, &asks);
        let answering = async {
            if let Some(ask) = rx.next().await {
                answer(ask);
            }
        };
        let (response, ()) = futures::join!(served, answering);
        response
    }

    #[tokio::test]
    async fn key_list_comes_from_the_app() {
        let response = one(&[11], |ask| {
            let Ask::Identities { reply } = ask else {
                panic!("expected a list request");
            };
            let _ = reply.send(vec![::agent::Identity::new(b"blob".to_vec(), "key")]);
        })
        .await;

        assert_eq!(response[4], 12, "IDENTITIES_ANSWER");
        assert!(response.windows(4).any(|window| window == b"blob"));
    }

    #[tokio::test]
    async fn human_refusal_gives_failure() {
        let mut frame = vec![13];
        for field in [b"key".as_slice(), b"data".as_slice()] {
            frame.extend_from_slice(&(field.len() as u32).to_be_bytes());
            frame.extend_from_slice(field);
        }
        frame.extend_from_slice(&0u32.to_be_bytes());

        let response = one(&frame, |ask| {
            let Ask::Sign(ask) = ask else {
                panic!("expected a sign request");
            };
            assert_eq!(ask.public, b"key");
            assert_eq!(ask.data, b"data");
            assert!(ask.bound.is_none());
            let _ = ask.reply.send(None);
        })
        .await;

        assert_eq!(response, ::agent::failure());
    }

    #[tokio::test]
    async fn unknown_flag_does_not_reach_the_key() {
        let mut frame = vec![13];
        for field in [b"key".as_slice(), b"data".as_slice()] {
            frame.extend_from_slice(&(field.len() as u32).to_be_bytes());
            frame.extend_from_slice(field);
        }
        frame.extend_from_slice(&0x100u32.to_be_bytes());

        let (asks, mut rx) = mpsc::unbounded();
        let mut bound = None;
        let response = respond(&frame, &mut bound, &asks).await;

        assert_eq!(response, ::agent::failure());
        assert!(
            rx.try_recv().is_err(),
            "the app should not have been bothered"
        );
    }

    #[tokio::test]
    async fn adding_a_key_is_rejected() {
        let (asks, mut rx) = mpsc::unbounded();
        let mut bound = None;
        let response = respond(&[17, 1, 2, 3], &mut bound, &asks).await;
        assert_eq!(response, ::agent::failure());
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn unknown_extension_differs_from_failure() {
        let mut frame = vec![27];
        let name = "missing".as_bytes();
        frame.extend_from_slice(&(name.len() as u32).to_be_bytes());
        frame.extend_from_slice(name);

        let (asks, mut rx) = mpsc::unbounded();
        let mut bound = None;
        let response = respond(&frame, &mut bound, &asks).await;
        assert_eq!(response, ::agent::extension_failure());
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn bogus_binding_is_not_remembered() {
        let mut body = Vec::new();
        for field in [
            b"hostkey".as_slice(),
            b"session".as_slice(),
            b"sig".as_slice(),
        ] {
            body.extend_from_slice(&(field.len() as u32).to_be_bytes());
            body.extend_from_slice(field);
        }
        body.push(0);

        let mut frame = vec![27];
        frame.extend_from_slice(&(::agent::SESSION_BIND.len() as u32).to_be_bytes());
        frame.extend_from_slice(::agent::SESSION_BIND.as_bytes());
        frame.extend_from_slice(&body);

        let (asks, _rx) = mpsc::unbounded();
        let mut bound = None;
        let response = respond(&frame, &mut bound, &asks).await;

        assert_eq!(response, ::agent::failure());
        assert!(
            bound.is_none(),
            "an unverified binding must not be remembered"
        );
    }

    #[tokio::test]
    async fn genuine_binding_reaches_the_prompt() {
        let host = russh::keys::PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            russh::keys::ssh_key::Algorithm::Ed25519,
        )
        .expect("server key");
        let session_id = b"session-id".as_slice();
        let signature = keys::sign(&host, session_id, None).expect("signature");
        let host_blob = keys::public_blob(host.public_key()).expect("blob");

        let mut body = Vec::new();
        for field in [host_blob.as_slice(), session_id, signature.as_slice()] {
            body.extend_from_slice(&(field.len() as u32).to_be_bytes());
            body.extend_from_slice(field);
        }
        body.push(0);

        let mut frame = vec![27];
        frame.extend_from_slice(&(::agent::SESSION_BIND.len() as u32).to_be_bytes());
        frame.extend_from_slice(::agent::SESSION_BIND.as_bytes());
        frame.extend_from_slice(&body);

        let (asks, _rx) = mpsc::unbounded();
        let mut bound = None;
        let response = respond(&frame, &mut bound, &asks).await;

        assert_eq!(response, ::agent::success());
        let bound = bound.expect("the binding should have been remembered");
        assert_eq!(bound.host_key, host_blob);
        assert!(bound.fingerprint.starts_with("SHA256:"));
        assert!(!bound.is_forwarding);
    }

    #[tokio::test]
    async fn garbage_gets_a_failure() {
        let (asks, _rx) = mpsc::unbounded();
        let mut bound = None;
        for frame in [vec![], vec![255], vec![13, 0, 0, 0, 200]] {
            let response = respond(&frame, &mut bound, &asks).await;
            assert_eq!(response, ::agent::failure());
        }
    }
}
