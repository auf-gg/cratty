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
        .expect("сессия не прислала события в отведённое время")
}

async fn wait_connected(session: &mut SshSession) -> String {
    match next_event(session).await {
        Some(FromSsh::Connected { fingerprint }) => fingerprint,
        other => panic!("ожидали Connected, получили {other:?}"),
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
            other => panic!("ждали «{needle}» в выводе, получили {other:?}; накоплено: {seen:?}"),
        }
    }
}

async fn wait_closed(session: &mut SshSession) -> CloseReason {
    loop {
        match next_event(session).await {
            Some(FromSsh::Closed(reason)) => return reason,
            Some(_) => {}
            None => panic!("канал событий закрылся, не сказав почему"),
        }
    }
}

fn error_text(reason: &CloseReason) -> String {
    match reason {
        CloseReason::Error(text) => text.clone(),
        other => panic!("ожидали CloseReason::Error, получили {other:?}"),
    }
}

#[tokio::test]
async fn password_auth_pty_shell_and_echo_roundtrip() {
    let sshd = FakeSshd::start().await;
    let mut session = spawn_ssh(password_config(&sshd)).expect("не поднялся поток сессии");

    let fingerprint = wait_connected(&mut session).await;
    assert_eq!(fingerprint, sshd.fingerprint());

    wait_for_output(&mut session, "$ ").await;

    session
        .commands
        .unbounded_send(ToSsh::Input(Bytes::from_static(b"echo hello\n")))
        .expect("сессия уже закрыта");

    let output = wait_for_output(&mut session, "hello\r\n").await;
    assert!(
        output.contains("echo hello"),
        "в выводе нет эха команды: {output:?}"
    );
}

#[tokio::test]
async fn pty_request_carries_configured_size_and_term() {
    let sshd = FakeSshd::start().await;
    let mut config = password_config(&sshd);
    config.term = "xterm-256color".into();
    config.pty = PtySize::new(200, 50);

    let mut session = spawn_ssh(config).expect("не поднялся поток сессии");
    wait_connected(&mut session).await;
    wait_for_output(&mut session, "$ ").await;

    let pty = sshd.pty_request().expect("сервер не увидел запроса PTY");
    assert_eq!(pty.term, "xterm-256color");
    assert_eq!((pty.cols, pty.rows), (200, 50));
}

#[tokio::test]
async fn resize_reaches_the_server() {
    let sshd = FakeSshd::start().await;
    let mut session = spawn_ssh(password_config(&sshd)).expect("не поднялся поток сессии");
    wait_connected(&mut session).await;
    wait_for_output(&mut session, "$ ").await;

    session
        .commands
        .unbounded_send(ToSsh::Resize(PtySize::new(100, 30)))
        .expect("сессия уже закрыта");

    session
        .commands
        .unbounded_send(ToSsh::Input(Bytes::from_static(b"echo resized\n")))
        .expect("сессия уже закрыта");
    wait_for_output(&mut session, "resized\r\n").await;

    assert_eq!(sshd.resizes(), vec![(100, 30)]);
}

#[tokio::test]
async fn disconnect_command_closes_session_locally() {
    let sshd = FakeSshd::start().await;
    let mut session = spawn_ssh(password_config(&sshd)).expect("не поднялся поток сессии");
    wait_connected(&mut session).await;
    wait_for_output(&mut session, "$ ").await;

    session
        .commands
        .unbounded_send(ToSsh::Disconnect)
        .expect("сессия уже закрыта");

    assert!(matches!(
        wait_closed(&mut session).await,
        CloseReason::Local
    ));
    session.join();
}

#[tokio::test]
async fn remote_exit_is_reported_with_status() {
    let sshd = FakeSshd::start().await;
    let mut session = spawn_ssh(password_config(&sshd)).expect("не поднялся поток сессии");
    wait_connected(&mut session).await;
    wait_for_output(&mut session, "$ ").await;

    session
        .commands
        .unbounded_send(ToSsh::Input(Bytes::from_static(b"exit\n")))
        .expect("сессия уже закрыта");

    match wait_closed(&mut session).await {
        CloseReason::Remote { exit_status } => assert_eq!(exit_status, Some(0)),
        other => panic!("ожидали Remote, получили {other:?}"),
    }
}

#[tokio::test]
async fn wrong_password_is_an_error_not_a_panic() {
    let sshd = FakeSshd::start().await;
    let config = config(&sshd, AuthMethod::Password("не тот".into()));

    let mut session = spawn_ssh(config).expect("не поднялся поток сессии");
    let text = error_text(&wait_closed(&mut session).await);

    assert!(
        text.contains(USER),
        "в тексте ошибки нет имени пользователя: {text}"
    );
    assert!(
        text.contains("не удалось войти"),
        "текст ошибки не про аутентификацию: {text}"
    );
}

#[tokio::test]
async fn unknown_host_key_is_rejected_with_its_fingerprint() {
    let sshd = FakeSshd::start().await;
    let mut config = password_config(&sshd);
    config.host_key_policy = HostKeyPolicy::Fingerprints(Vec::new());

    let mut session = spawn_ssh(config).expect("не поднялся поток сессии");
    let text = error_text(&wait_closed(&mut session).await);

    assert!(
        text.contains(&sshd.fingerprint()),
        "в тексте нет отпечатка предъявленного ключа: {text}"
    );
    assert!(
        !sshd.saw_auth_attempt(),
        "пароль ушёл на сервер, ключ которого мы не приняли"
    );
}

#[tokio::test]
async fn refused_connection_is_an_error_not_a_panic() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("не удалось занять порт");
    let port = listener.local_addr().expect("нет адреса").port();
    drop(listener);

    let mut config = SshConfig::new("127.0.0.1", port, USER, AuthMethod::Password("x".into()));
    config.host_key_policy = HostKeyPolicy::Fingerprints(Vec::new());

    let mut session = spawn_ssh(config).expect("не поднялся поток сессии");
    let text = error_text(&wait_closed(&mut session).await);

    assert!(
        text.contains(&port.to_string()),
        "в тексте ошибки нет адреса: {text}"
    );
}

#[tokio::test]
async fn dropping_the_session_shuts_the_thread_down() {
    let sshd = FakeSshd::start().await;
    let mut session = spawn_ssh(password_config(&sshd)).expect("не поднялся поток сессии");
    wait_connected(&mut session).await;
    wait_for_output(&mut session, "$ ").await;

    tokio::time::timeout(DEADLINE, tokio::task::spawn_blocking(move || drop(session)))
        .await
        .expect("поток сессии не завершился после drop")
        .expect("поток паниковал при завершении");
}
