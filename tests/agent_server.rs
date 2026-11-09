use std::sync::Arc;

use agent::Identity;
use cratty::agent::{self as srv, Ask, keys};
use futures::StreamExt;
use futures::channel::mpsc;
use russh::keys::agent::client::AgentClient;
use russh::keys::signature::Verifier;
use russh::keys::ssh_key::{self, Algorithm, PrivateKey, Signature};

fn address(name: &str) -> srv::Address {
    let unique = format!("{}-{name}", std::process::id());
    #[cfg(windows)]
    {
        srv::Address::Pipe(format!(r"\\.\pipe\cratty-agent-test-{unique}"))
    }
    #[cfg(unix)]
    {
        srv::Address::Socket(std::env::temp_dir().join(format!("cratty-agent-{unique}.sock")))
    }
}

async fn answer_asks(mut asks: mpsc::UnboundedReceiver<Ask>, key: Arc<PrivateKey>, allow: bool) {
    let blob = keys::public_blob(key.public_key()).expect("blob");
    while let Some(ask) = asks.next().await {
        match ask {
            Ask::Identities { reply } => {
                let _ = reply.send(vec![Identity::new(blob.clone(), "key from the vault")]);
            }
            Ask::Sign(ask) => {
                let answer = if allow && ask.public == blob {
                    keys::sign(&key, &ask.data, ask.hash).ok()
                } else {
                    None
                };
                let _ = ask.reply.send(answer);
            }
        }
    }
}

async fn start(
    name: &str,
    allow: bool,
) -> (
    Arc<PrivateKey>,
    AgentClient<Box<dyn russh::keys::agent::client::AgentStream + Send + Unpin>>,
) {
    let key = Arc::new(
        PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).expect("key"),
    );
    let address = address(name);

    let (asks_tx, asks_rx) = mpsc::unbounded();
    tokio::spawn(answer_asks(asks_rx, key.clone(), allow));

    #[allow(unused_mut)]
    let mut listener = srv::Listener::bind(&address).await.expect("address in use");
    tokio::spawn(async move {
        loop {
            let Ok(stream) = listener.accept().await else {
                return;
            };
            let asks = asks_tx.clone();
            tokio::spawn(async move {
                let _ = srv::serve_connection(stream, asks).await;
            });
        }
    });

    let client = match &address {
        #[cfg(windows)]
        srv::Address::Pipe(name) => AgentClient::connect_named_pipe(name)
            .await
            .expect("connecting to the channel")
            .dynamic(),
        #[cfg(unix)]
        srv::Address::Socket(path) => AgentClient::connect_uds(path)
            .await
            .expect("connecting to the socket")
            .dynamic(),
        #[allow(unreachable_patterns)]
        other => panic!("address {other:?} is not for this platform"),
    };

    (key, client)
}

#[tokio::test]
async fn client_sees_key_and_gets_signature() {
    let (key, mut client) = start("sign", true).await;

    let identities = client.request_identities().await.expect("key list");
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].comment(), "key from the vault");
    assert_eq!(
        identities[0].public_key().key_data(),
        key.public_key().key_data()
    );

    let data = "what we are signing".as_bytes();
    let signature: Signature = client
        .sign_request_signature(&key.public_key().clone(), None, data)
        .await
        .expect("signature");

    Verifier::verify(key.public_key().key_data(), data, &signature).expect("signature did not verify");
}

#[tokio::test]
async fn human_refusal_is_seen_by_client_as_failure() {
    let (key, mut client) = start("refuse", false).await;

    assert_eq!(client.request_identities().await.expect("list").len(), 1);

    let result = client
        .sign_request_signature(&key.public_key().clone(), None, "data".as_bytes())
        .await;
    assert!(result.is_err(), "signing should have failed");

    assert_eq!(client.request_identities().await.expect("list").len(), 1);
}

#[tokio::test]
async fn adding_key_through_agent_is_rejected() {
    let (_key, mut client) = start("add", true).await;

    let alien =
        PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).expect("key");
    let result = client.add_identity(&alien, &[]).await;
    assert!(result.is_err(), "agent must not accept keys from outside");

    assert_eq!(client.request_identities().await.expect("list").len(), 1);
}

#[tokio::test]
async fn several_requests_in_one_connection() {
    let (key, mut client) = start("many", true).await;

    for index in 0..5u8 {
        let data = vec![index; 64 * (index as usize + 1)];
        let signature = client
            .sign_request_signature(&key.public_key().clone(), None, &data)
            .await
            .expect("signature");
        Verifier::verify(key.public_key().key_data(), &data, &signature)
            .expect("signature did not verify");
        assert_eq!(client.request_identities().await.expect("list").len(), 1);
    }
}

#[tokio::test]
async fn rsa_is_signed_with_requested_hash() {
    let key = Arc::new(
        PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            Algorithm::Rsa { hash: None },
        )
        .expect("RSA key"),
    );

    let address = address("rsa");
    let (asks_tx, asks_rx) = mpsc::unbounded();
    tokio::spawn(answer_asks(asks_rx, key.clone(), true));

    #[allow(unused_mut)]
    let mut listener = srv::Listener::bind(&address).await.expect("address in use");
    tokio::spawn(async move {
        while let Ok(stream) = listener.accept().await {
            let asks = asks_tx.clone();
            tokio::spawn(async move {
                let _ = srv::serve_connection(stream, asks).await;
            });
        }
    });

    let mut client = match &address {
        #[cfg(windows)]
        srv::Address::Pipe(name) => AgentClient::connect_named_pipe(name)
            .await
            .expect("connection")
            .dynamic(),
        #[cfg(unix)]
        srv::Address::Socket(path) => AgentClient::connect_uds(path)
            .await
            .expect("connection")
            .dynamic(),
        #[allow(unreachable_patterns)]
        other => panic!("address {other:?} is not for this platform"),
    };

    for hash in [ssh_key::HashAlg::Sha256, ssh_key::HashAlg::Sha512] {
        let signature = client
            .sign_request_signature(&key.public_key().clone(), Some(hash), b"data")
            .await
            .expect("signature");
        assert_eq!(
            signature.algorithm(),
            Algorithm::Rsa { hash: Some(hash) },
            "agent signed with a different hash than requested"
        );
        Verifier::verify(key.public_key().key_data(), b"data", &signature)
            .expect("signature did not verify");
    }
}

#[tokio::test]
async fn agent_starts_as_thread_and_releases_address() {
    let key = Arc::new(
        PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).expect("key"),
    );
    let address = address("spawn");

    let (running, asks) = srv::spawn(address.clone()).expect("agent failed to start");
    assert_eq!(running.address(), &address);

    tokio::spawn(answer_asks(asks, key.clone(), true));

    {
        let mut client = match &address {
            #[cfg(windows)]
            srv::Address::Pipe(name) => AgentClient::connect_named_pipe(name)
                .await
                .expect("connection")
                .dynamic(),
            #[cfg(unix)]
            srv::Address::Socket(path) => AgentClient::connect_uds(path)
                .await
                .expect("connection")
                .dynamic(),
            #[allow(unreachable_patterns)]
            other => panic!("address {other:?} is not for this platform"),
        };
        assert_eq!(client.request_identities().await.expect("list").len(), 1);
    }

    drop(running);

    let again = srv::spawn(address).expect("address was not released");
    drop(again);
}
