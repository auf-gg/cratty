mod fake_sshd;

use std::sync::Arc;
use std::time::Duration;

use agent::Identity;
use cratty::agent::{self as srv, Ask, keys};
use cratty::ssh::auth::{AuthPlan, Credential};
use cratty::ssh::{AuthMethod, CloseReason, FromSsh, HostKeyPolicy, SshConfig, spawn_ssh};
use fake_sshd::{AuthMode, FakeSshd};
use futures::StreamExt;
use russh::keys::PrivateKey;
use russh::keys::ssh_key::Algorithm;

const DEADLINE: Duration = Duration::from_secs(10);

fn address(name: &str) -> srv::Address {
    let unique = format!("{}-{name}", std::process::id());
    #[cfg(windows)]
    {
        srv::Address::Pipe(format!(r"\\.\pipe\cratty-agent-client-{unique}"))
    }
    #[cfg(unix)]
    {
        srv::Address::Socket(
            std::env::temp_dir().join(format!("cratty-agent-client-{unique}.sock")),
        )
    }
}

fn start_agent(name: &str, allow: bool) -> (srv::Running, Arc<PrivateKey>) {
    let key = Arc::new(
        PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).expect("ключ"),
    );
    let (running, mut asks) = srv::spawn(address(name)).expect("агент не поднялся");

    let answering = key.clone();
    tokio::spawn(async move {
        let blob = keys::public_blob(answering.public_key()).expect("блоб");
        while let Some(ask) = asks.next().await {
            match ask {
                Ask::Identities { reply } => {
                    let _ = reply.send(vec![Identity::new(blob.clone(), "ключ из хранилища")]);
                }
                Ask::Sign(ask) => {
                    let answer = allow
                        .then(|| keys::sign(&answering, &ask.data, ask.hash).ok())
                        .flatten();
                    let _ = ask.reply.send(answer);
                }
            }
        }
    });

    (running, key)
}

fn config(sshd: &FakeSshd, agent: &srv::Running) -> SshConfig {
    let addr = sshd.addr();
    let plan = AuthPlan {
        order: vec![Credential::Agent],
    };
    let mut config = SshConfig::new(
        addr.ip().to_string(),
        addr.port(),
        sshd.user(),
        AuthMethod::Plan(plan),
    );
    config.host_key_policy = HostKeyPolicy::Fingerprints(vec![sshd.fingerprint()]);
    config.agent = Some(agent.address().clone());
    config
}

async fn outcome(session: &mut cratty::ssh::SshSession) -> Result<(), String> {
    let deadline = tokio::time::sleep(DEADLINE);
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            event = session.events.next() => match event {
                Some(FromSsh::Connected { .. }) => return Ok(()),
                Some(FromSsh::Closed(CloseReason::Error(error))) => return Err(error),
                Some(FromSsh::Closed(other)) => return Err(format!("{other:?}")),
                Some(_) => {}
                None => return Err("канал событий закрылся".into()),
            },
            () = &mut deadline => return Err("подключение не уложилось в срок".into()),
        }
    }
}

#[tokio::test]
async fn klient_vhodit_klyuchom_iz_svoego_agenta() {
    let sshd = FakeSshd::start_with_auth(AuthMode::PublicKeyOnly).await;
    let (agent, key) = start_agent("ok", true);

    let mut session = spawn_ssh(config(&sshd, &agent)).expect("не поднялся поток сессии");
    let result = outcome(&mut session).await;
    assert!(
        result.is_ok(),
        "вход через свой агент не прошёл: {result:?}"
    );

    let expected = key
        .public_key()
        .fingerprint(russh::keys::ssh_key::HashAlg::Sha256)
        .to_string();
    assert_eq!(sshd.public_key(), Some(expected));
}

#[tokio::test]
async fn otkaz_v_podpisi_ne_puskaet_i_ne_veshaet() {
    let sshd = FakeSshd::start_with_auth(AuthMode::PublicKeyOnly).await;
    let (agent, _key) = start_agent("refused", false);

    let mut session = spawn_ssh(config(&sshd, &agent)).expect("не поднялся поток сессии");
    let result = outcome(&mut session).await;

    assert!(result.is_err(), "без подписи входить было нечем");
    let error = result.unwrap_err();
    assert!(
        !error.contains("не уложилось в срок"),
        "отказ должен приходить сразу, а не по таймауту: {error}"
    );
    assert!(
        sshd.public_key().is_none(),
        "сервер никого не должен был пустить"
    );
}
