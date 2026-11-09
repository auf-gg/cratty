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
        PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).expect("key"),
    );
    let (running, mut asks) = srv::spawn(address(name)).expect("agent failed to start");

    let answering = key.clone();
    tokio::spawn(async move {
        let blob = keys::public_blob(answering.public_key()).expect("blob");
        while let Some(ask) = asks.next().await {
            match ask {
                Ask::Identities { reply } => {
                    let _ = reply.send(vec![Identity::new(blob.clone(), "key from the vault")]);
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
                None => return Err("event channel closed".into()),
            },
            () = &mut deadline => return Err("connection did not finish in time".into()),
        }
    }
}

#[tokio::test]
async fn client_logs_in_with_key_from_its_agent() {
    let sshd = FakeSshd::start_with_auth(AuthMode::PublicKeyOnly).await;
    let (agent, key) = start_agent("ok", true);

    let mut session = spawn_ssh(config(&sshd, &agent)).expect("session thread failed to start");
    let result = outcome(&mut session).await;
    assert!(
        result.is_ok(),
        "sign-in through our own agent failed: {result:?}"
    );

    let expected = key
        .public_key()
        .fingerprint(russh::keys::ssh_key::HashAlg::Sha256)
        .to_string();
    assert_eq!(sshd.public_key(), Some(expected));
}

#[tokio::test]
async fn signing_refusal_neither_lets_in_nor_hangs() {
    let sshd = FakeSshd::start_with_auth(AuthMode::PublicKeyOnly).await;
    let (agent, _key) = start_agent("refused", false);

    let mut session = spawn_ssh(config(&sshd, &agent)).expect("session thread failed to start");
    let result = outcome(&mut session).await;

    assert!(result.is_err(), "there was nothing to sign in with without a signature");
    let error = result.unwrap_err();
    assert!(
        !error.contains("did not finish in time"),
        "the refusal must arrive immediately, not by timeout: {error}"
    );
    assert!(
        sshd.public_key().is_none(),
        "server should not have let anyone in"
    );
}
