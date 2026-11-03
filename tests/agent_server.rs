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
    let blob = keys::public_blob(key.public_key()).expect("блоб");
    while let Some(ask) = asks.next().await {
        match ask {
            Ask::Identities { reply } => {
                let _ = reply.send(vec![Identity::new(blob.clone(), "ключ из хранилища")]);
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
        PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).expect("ключ"),
    );
    let address = address(name);

    let (asks_tx, asks_rx) = mpsc::unbounded();
    tokio::spawn(answer_asks(asks_rx, key.clone(), allow));

    #[allow(unused_mut)]
    let mut listener = srv::Listener::bind(&address).await.expect("адрес занят");
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
            .expect("подключение к каналу")
            .dynamic(),
        #[cfg(unix)]
        srv::Address::Socket(path) => AgentClient::connect_uds(path)
            .await
            .expect("подключение к сокету")
            .dynamic(),
        #[allow(unreachable_patterns)]
        other => panic!("адрес {other:?} не для этой платформы"),
    };

    (key, client)
}

#[tokio::test]
async fn klient_vidit_klyuch_i_poluchaet_podpis() {
    let (key, mut client) = start("sign", true).await;

    let identities = client.request_identities().await.expect("список ключей");
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].comment(), "ключ из хранилища");
    assert_eq!(
        identities[0].public_key().key_data(),
        key.public_key().key_data()
    );

    let data = "то, что подписываем".as_bytes();
    let signature: Signature = client
        .sign_request_signature(&key.public_key().clone(), None, data)
        .await
        .expect("подпись");

    Verifier::verify(key.public_key().key_data(), data, &signature).expect("подпись не сошлась");
}

#[tokio::test]
async fn otkaz_cheloveka_viden_klientu_kak_otkaz() {
    let (key, mut client) = start("refuse", false).await;

    assert_eq!(client.request_identities().await.expect("список").len(), 1);

    let result = client
        .sign_request_signature(&key.public_key().clone(), None, "данные".as_bytes())
        .await;
    assert!(result.is_err(), "подпись не должна была получиться");

    assert_eq!(client.request_identities().await.expect("список").len(), 1);
}

#[tokio::test]
async fn dobavlenie_klyucha_cherez_agenta_otvergaetsya() {
    let (_key, mut client) = start("add", true).await;

    let alien =
        PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).expect("ключ");
    let result = client.add_identity(&alien, &[]).await;
    assert!(result.is_err(), "агент не должен принимать ключи снаружи");

    assert_eq!(client.request_identities().await.expect("список").len(), 1);
}

#[tokio::test]
async fn neskolko_zaprosov_v_odnom_soedinenii() {
    let (key, mut client) = start("many", true).await;

    for index in 0..5u8 {
        let data = vec![index; 64 * (index as usize + 1)];
        let signature = client
            .sign_request_signature(&key.public_key().clone(), None, &data)
            .await
            .expect("подпись");
        Verifier::verify(key.public_key().key_data(), &data, &signature)
            .expect("подпись не сошлась");
        assert_eq!(client.request_identities().await.expect("список").len(), 1);
    }
}

#[tokio::test]
async fn rsa_podpisyvaetsya_zaproshennym_heshem() {
    let key = Arc::new(
        PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            Algorithm::Rsa { hash: None },
        )
        .expect("ключ RSA"),
    );

    let address = address("rsa");
    let (asks_tx, asks_rx) = mpsc::unbounded();
    tokio::spawn(answer_asks(asks_rx, key.clone(), true));

    #[allow(unused_mut)]
    let mut listener = srv::Listener::bind(&address).await.expect("адрес занят");
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
            .expect("подключение")
            .dynamic(),
        #[cfg(unix)]
        srv::Address::Socket(path) => AgentClient::connect_uds(path)
            .await
            .expect("подключение")
            .dynamic(),
        #[allow(unreachable_patterns)]
        other => panic!("адрес {other:?} не для этой платформы"),
    };

    for hash in [ssh_key::HashAlg::Sha256, ssh_key::HashAlg::Sha512] {
        let signature = client
            .sign_request_signature(&key.public_key().clone(), Some(hash), b"data")
            .await
            .expect("подпись");
        assert_eq!(
            signature.algorithm(),
            Algorithm::Rsa { hash: Some(hash) },
            "агент подписал не тем хешем, который просили"
        );
        Verifier::verify(key.public_key().key_data(), b"data", &signature)
            .expect("подпись не сошлась");
    }
}

#[tokio::test]
async fn agent_podnimaetsya_potokom_i_osvobozhdaet_adres() {
    let key = Arc::new(
        PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).expect("ключ"),
    );
    let address = address("spawn");

    let (running, asks) = srv::spawn(address.clone()).expect("агент не поднялся");
    assert_eq!(running.address(), &address);

    tokio::spawn(answer_asks(asks, key.clone(), true));

    {
        let mut client = match &address {
            #[cfg(windows)]
            srv::Address::Pipe(name) => AgentClient::connect_named_pipe(name)
                .await
                .expect("подключение")
                .dynamic(),
            #[cfg(unix)]
            srv::Address::Socket(path) => AgentClient::connect_uds(path)
                .await
                .expect("подключение")
                .dynamic(),
            #[allow(unreachable_patterns)]
            other => panic!("адрес {other:?} не для этой платформы"),
        };
        assert_eq!(client.request_identities().await.expect("список").len(), 1);
    }

    drop(running);

    let again = srv::spawn(address).expect("адрес не освободился");
    drop(again);
}
