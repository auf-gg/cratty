mod docker_sshd;

use std::time::Duration;

use bytes::Bytes;
use cratty::ssh::{
    AuthMethod, CloseReason, FromSsh, HostKeyPolicy, PtySize, SshConfig, SshSession, ToSsh,
    spawn_ssh,
};
use futures::StreamExt;

use docker_sshd::{DockerSshd, PASSWORD, USER};

const DEADLINE: Duration = Duration::from_secs(30);

fn config(sshd: &DockerSshd, password: &str) -> SshConfig {
    let addr = sshd.addr();
    let mut config = SshConfig::new(
        addr.ip().to_string(),
        addr.port(),
        USER,
        AuthMethod::Password(password.into()),
    );
    config.host_key_policy = HostKeyPolicy::Fingerprints(vec![sshd.fingerprint()]);
    config.term = "xterm-256color".into();
    config.pty = PtySize::new(200, 50);
    config
}

async fn next_event(session: &mut SshSession) -> Option<FromSsh> {
    tokio::time::timeout(DEADLINE, session.events.next())
        .await
        .expect("session sent no events within the allotted time")
}

async fn wait_connected(session: &mut SshSession) -> String {
    match next_event(session).await {
        Some(FromSsh::Connected { fingerprint }) => fingerprint,
        other => panic!("expected Connected, got {other:?}"),
    }
}

async fn wait_for_output(session: &mut SshSession, needle: &str) -> String {
    let mut seen = String::new();
    loop {
        match next_event(session).await {
            Some(FromSsh::Output(data)) => {
                seen.push_str(&String::from_utf8_lossy(&data));
                if seen.contains(needle) {
                    return seen;
                }
            }
            Some(FromSsh::Connected { .. }) => {}
            other => panic!("expected '{needle}' in the output, got {other:?}; accumulated: {seen:?}"),
        }
    }
}

async fn wait_closed(session: &mut SshSession) -> CloseReason {
    loop {
        match next_event(session).await {
            Some(FromSsh::Closed(reason)) => return reason,
            Some(_) => {}
            None => panic!("event channel closed without saying why"),
        }
    }
}

fn send(session: &SshSession, command: &'static str) {
    session
        .commands
        .unbounded_send(ToSsh::Input(Bytes::from_static(command.as_bytes())))
        .expect("session already closed");
}

#[tokio::test]
async fn openssh_password_pty_shell_resize_and_exit() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker unavailable — OpenSSH compatibility check skipped");
        return;
    };

    let mut session = spawn_ssh(config(&sshd, PASSWORD)).expect("session thread failed to start");
    assert_eq!(wait_connected(&mut session).await, sshd.fingerprint());

    send(&session, "echo READY-$((6*7))\n");
    wait_for_output(&mut session, "READY-42").await;

    send(&session, "stty size\n");
    wait_for_output(&mut session, "50 200").await;

    send(&session, "echo \"[$TERM]\"\n");
    wait_for_output(&mut session, "[xterm-256color]").await;

    session
        .commands
        .unbounded_send(ToSsh::Resize(PtySize::new(132, 43)))
        .expect("session already closed");
    send(&session, "stty size\n");
    wait_for_output(&mut session, "43 132").await;

    send(&session, "exit 0\n");
    match wait_closed(&mut session).await {
        CloseReason::Remote { exit_status } => assert_eq!(exit_status, Some(0)),
        other => panic!("expected Remote, got {other:?}"),
    }
    session.join();

    let mut session = spawn_ssh(config(&sshd, "wrong password")).expect("session thread failed to start");
    match wait_closed(&mut session).await {
        CloseReason::Error(text) => assert!(
            text.contains("could not sign in") && text.contains(USER),
            "error text is not about authentication: {text}"
        ),
        other => panic!("expected Error, got {other:?}"),
    }

    let mut config = config(&sshd, PASSWORD);
    config.host_key_policy = HostKeyPolicy::Fingerprints(Vec::new());
    let mut session = spawn_ssh(config).expect("session thread failed to start");
    match wait_closed(&mut session).await {
        CloseReason::Error(text) => assert!(
            text.contains(&sshd.fingerprint()),
            "no fingerprint of the presented key in the text: {text}"
        ),
        other => panic!("expected Error, got {other:?}"),
    }
}
