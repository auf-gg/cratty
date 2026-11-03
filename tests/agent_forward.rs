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
        PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).expect("ключ"),
    );
    let (running, mut asks) = srv::spawn(address(name)).expect("агент не поднялся");
    tokio::spawn(async move {
        let blob = keys::public_blob(key.public_key()).expect("блоб");
        while let Some(ask) = asks.next().await {
            match ask {
                Ask::Identities { reply } => {
                    let _ = reply.send(vec![Identity::new(blob.clone(), "ключ")]);
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
            .expect("сессия молчит");
        match event {
            Some(FromSsh::Connected { .. }) => {}
            Some(FromSsh::Output(data)) => {
                seen.push_str(&String::from_utf8_lossy(&data));
                if seen.contains("$ ") {
                    return;
                }
            }
            other => panic!("ждали оболочку, получили {other:?}"),
        }
    }
}

#[tokio::test]
async fn s_probrosom_server_vidit_klyuchi_agenta() {
    let agent = start_agent("on");
    let sshd = FakeSshd::start().await;
    let mut session = spawn_ssh(config(&sshd, &agent, true)).expect("поток");
    wait_shell(&mut session).await;

    assert!(sshd.agent_requested(), "клиент не попросил проброс");
    let count = tokio::time::timeout(DEADLINE, sshd.probe_agent())
        .await
        .expect("агент молчит");
    assert_eq!(count, Ok(1));
}

#[tokio::test]
async fn bez_probrosa_agent_nedostupen_serveru() {
    let agent = start_agent("off");
    let sshd = FakeSshd::start().await;
    let mut session = spawn_ssh(config(&sshd, &agent, false)).expect("поток");
    wait_shell(&mut session).await;

    assert!(!sshd.agent_requested());
    let result = tokio::time::timeout(DEADLINE, sshd.probe_agent())
        .await
        .expect("клиент не ответил на открытие канала");
    assert!(
        result.is_err(),
        "сервер добрался до агента без проброса: {result:?}"
    );
}
