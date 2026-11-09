mod fake_sshd;

use std::time::Duration;

use bytes::Bytes;
use cratty::ssh::{
    AuthMethod, CloseReason, FromSsh, HostKeyPolicy, PtySize, SshConfig, SshSession, ToSsh,
    spawn_ssh,
};
use futures::StreamExt;

use fake_sshd::FakeSshd;

const DEADLINE: Duration = Duration::from_secs(20);

const USER: &str = "tester";
const PASSWORD: &str = "s3cret";

fn config(sshd: &FakeSshd, auth: AuthMethod) -> SshConfig {
    let addr = sshd.addr();
    let mut config = SshConfig::new(addr.ip().to_string(), addr.port(), USER, auth);
    config.host_key_policy = HostKeyPolicy::Fingerprints(vec![sshd.fingerprint()]);
    config.pty = PtySize::new(120, 40);
    config
}

fn password_config(sshd: &FakeSshd) -> SshConfig {
    config(sshd, AuthMethod::Password(PASSWORD.into()))
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

fn error_text(reason: &CloseReason) -> String {
    match reason {
        CloseReason::Error(text) => text.clone(),
        other => panic!("expected CloseReason::Error, got {other:?}"),
    }
}

#[tokio::test]
async fn password_auth_pty_shell_and_echo_roundtrip() {
    let sshd = FakeSshd::start().await;
    let mut session = spawn_ssh(password_config(&sshd)).expect("session thread failed to start");

    let fingerprint = wait_connected(&mut session).await;
    assert_eq!(fingerprint, sshd.fingerprint());

    wait_for_output(&mut session, "$ ").await;

    session
        .commands
        .unbounded_send(ToSsh::Input(Bytes::from_static(b"echo hello\n")))
        .expect("session already closed");

    let output = wait_for_output(&mut session, "hello\r\n").await;
    assert!(
        output.contains("echo hello"),
        "no command echo in the output: {output:?}"
    );
}

#[tokio::test]
async fn pty_request_carries_configured_size_and_term() {
    let sshd = FakeSshd::start().await;
    let mut config = password_config(&sshd);
    config.term = "xterm-256color".into();
    config.pty = PtySize::new(200, 50);

    let mut session = spawn_ssh(config).expect("session thread failed to start");
    wait_connected(&mut session).await;
    wait_for_output(&mut session, "$ ").await;

    let pty = sshd.pty_request().expect("server did not see a PTY request");
    assert_eq!(pty.term, "xterm-256color");
    assert_eq!((pty.cols, pty.rows), (200, 50));
}

#[tokio::test]
async fn resize_reaches_the_server() {
    let sshd = FakeSshd::start().await;
    let mut session = spawn_ssh(password_config(&sshd)).expect("session thread failed to start");
    wait_connected(&mut session).await;
    wait_for_output(&mut session, "$ ").await;

    session
        .commands
        .unbounded_send(ToSsh::Resize(PtySize::new(100, 30)))
        .expect("session already closed");

    session
        .commands
        .unbounded_send(ToSsh::Input(Bytes::from_static(b"echo resized\n")))
        .expect("session already closed");
    wait_for_output(&mut session, "resized\r\n").await;

    assert_eq!(sshd.resizes(), vec![(100, 30)]);
}

#[tokio::test]
async fn disconnect_command_closes_session_locally() {
    let sshd = FakeSshd::start().await;
    let mut session = spawn_ssh(password_config(&sshd)).expect("session thread failed to start");
    wait_connected(&mut session).await;
    wait_for_output(&mut session, "$ ").await;

    session
        .commands
        .unbounded_send(ToSsh::Disconnect)
        .expect("session already closed");

    assert!(matches!(
        wait_closed(&mut session).await,
        CloseReason::Local
    ));
    session.join();
}

#[tokio::test]
async fn remote_exit_is_reported_with_status() {
    let sshd = FakeSshd::start().await;
    let mut session = spawn_ssh(password_config(&sshd)).expect("session thread failed to start");
    wait_connected(&mut session).await;
    wait_for_output(&mut session, "$ ").await;

    session
        .commands
        .unbounded_send(ToSsh::Input(Bytes::from_static(b"exit\n")))
        .expect("session already closed");

    match wait_closed(&mut session).await {
        CloseReason::Remote { exit_status } => assert_eq!(exit_status, Some(0)),
        other => panic!("expected Remote, got {other:?}"),
    }
}

#[tokio::test]
async fn wrong_password_is_an_error_not_a_panic() {
    let sshd = FakeSshd::start().await;
    let config = config(&sshd, AuthMethod::Password("wrong".into()));

    let mut session = spawn_ssh(config).expect("session thread failed to start");
    let text = error_text(&wait_closed(&mut session).await);

    assert!(
        text.contains(USER),
        "no user name in the error text: {text}"
    );
    assert!(
        text.contains("could not sign in"),
        "error text is not about authentication: {text}"
    );
}

#[tokio::test]
async fn unknown_host_key_is_rejected_with_its_fingerprint() {
    let sshd = FakeSshd::start().await;
    let mut config = password_config(&sshd);
    config.host_key_policy = HostKeyPolicy::Fingerprints(Vec::new());

    let mut session = spawn_ssh(config).expect("session thread failed to start");
    let text = error_text(&wait_closed(&mut session).await);

    assert!(
        text.contains(&sshd.fingerprint()),
        "no fingerprint of the presented key in the text: {text}"
    );
    assert!(
        !sshd.saw_auth_attempt(),
        "password was sent to a server whose key we did not accept"
    );
}

#[tokio::test]
async fn refused_connection_is_an_error_not_a_panic() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("could not bind a port");
    let port = listener.local_addr().expect("no address").port();
    drop(listener);

    let mut config = SshConfig::new("127.0.0.1", port, USER, AuthMethod::Password("x".into()));
    config.host_key_policy = HostKeyPolicy::Fingerprints(Vec::new());

    let mut session = spawn_ssh(config).expect("session thread failed to start");
    let text = error_text(&wait_closed(&mut session).await);

    assert!(
        text.contains(&port.to_string()),
        "no address in the error text: {text}"
    );
}

#[tokio::test]
async fn dropping_the_session_shuts_the_thread_down() {
    let sshd = FakeSshd::start().await;
    let mut session = spawn_ssh(password_config(&sshd)).expect("session thread failed to start");
    wait_connected(&mut session).await;
    wait_for_output(&mut session, "$ ").await;

    tokio::time::timeout(DEADLINE, tokio::task::spawn_blocking(move || drop(session)))
        .await
        .expect("session thread did not finish after drop")
        .expect("thread panicked on shutdown");
}
