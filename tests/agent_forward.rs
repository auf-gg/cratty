mod fake_sshd;

use std::sync::Arc;
use std::time::Duration;

use agent::Identity;
use cratty::agent::{self as srv, Ask, keys};
use cratty::ssh::{AuthMethod, FromSsh, HostKeyPolicy, SshConfig, SshSession, spawn_ssh};
use fake_sshd::FakeSshd;
use futures::StreamExt;
use russh::keys::PrivateKey;
use russh::keys::ssh_key::Algorithm;

const DEADLINE: Duration = Duration::from_secs(20);

fn address(name: &str) -> srv::Address {
    let unique = format!("{}-{name}", std::process::id());
    #[cfg(windows)]
    {
        srv::Address::Pipe(format!(r"\\.\pipe\cratty-agent-forward-{unique}"))
    }
    #[cfg(unix)]
    {
        srv::Address::Socket(
            std::env::temp_dir().join(format!("cratty-agent-forward-{unique}.sock")),
        )
    }
}

fn start_agent(name: &str) -> srv::Running {
    let key = Arc::new(
        PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).expect("key"),
    );
    let (running, mut asks) = srv::spawn(address(name)).expect("agent failed to start");
    tokio::spawn(async move {
        let blob = keys::public_blob(key.public_key()).expect("blob");
        while let Some(ask) = asks.next().await {
            match ask {
                Ask::Identities { reply } => {
                    let _ = reply.send(vec![Identity::new(blob.clone(), "key")]);
                }
                Ask::Sign(ask) => {
                    let _ = ask.reply.send(None);
                }
            }
        }
    });
    running
}

fn config(sshd: &FakeSshd, agent: &srv::Running, forward: bool) -> SshConfig {
    let addr = sshd.addr();
    let mut config = SshConfig::new(
        addr.ip().to_string(),
        addr.port(),
        sshd.user(),
        AuthMethod::Password(sshd.password().into()),
    );
    config.host_key_policy = HostKeyPolicy::Fingerprints(vec![sshd.fingerprint()]);
    config.agent = Some(agent.address().clone());
    config.forward_agent = forward;
    config
}

async fn wait_shell(session: &mut SshSession) {
    let mut seen = String::new();
    loop {
        let event = tokio::time::timeout(DEADLINE, session.events.next())
            .await
            .expect("session is silent");
        match event {
            Some(FromSsh::Connected { .. }) => {}
            Some(FromSsh::Output(data)) => {
                seen.push_str(&String::from_utf8_lossy(&data));
                if seen.contains("$ ") {
                    return;
                }
            }
            other => panic!("expected a shell, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn with_forwarding_server_sees_agent_keys() {
    let agent = start_agent("on");
    let sshd = FakeSshd::start().await;
    let mut session = spawn_ssh(config(&sshd, &agent, true)).expect("thread");
    wait_shell(&mut session).await;

    assert!(sshd.agent_requested(), "client did not request forwarding");
    let count = tokio::time::timeout(DEADLINE, sshd.probe_agent())
        .await
        .expect("agent is silent");
    assert_eq!(count, Ok(1));
}

#[tokio::test]
async fn without_forwarding_agent_is_unavailable_to_server() {
    let agent = start_agent("off");
    let sshd = FakeSshd::start().await;
    let mut session = spawn_ssh(config(&sshd, &agent, false)).expect("thread");
    wait_shell(&mut session).await;

    assert!(!sshd.agent_requested());
    let result = tokio::time::timeout(DEADLINE, sshd.probe_agent())
        .await
        .expect("client did not answer the channel open");
    assert!(
        result.is_err(),
        "server reached the agent without forwarding: {result:?}"
    );
}
