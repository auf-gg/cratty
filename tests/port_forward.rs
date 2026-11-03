mod docker_sshd;

use std::time::Duration;

use cratty::ssh::forward::ForwardState;
use cratty::ssh::{AuthMethod, FromSsh, HostKeyPolicy, SshConfig, SshSession, ToSsh, spawn_ssh};
use futures::StreamExt;
use proto::{ForwardKind, PortForward};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use docker_sshd::{DockerSshd, PASSWORD, USER};

const DEADLINE: Duration = Duration::from_secs(30);

async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("порт");
    listener.local_addr().expect("адрес").port()
}

fn rule(kind: ForwardKind, listen_port: u16, target: Option<(&str, u16)>) -> PortForward {
    let (target_host, target_port) =
        target.map_or((String::new(), 0), |(host, port)| (host.into(), port));
    PortForward {
        kind,
        listen_port,
        target_host,
        target_port,
        enabled: true,
    }
}

fn connect(sshd: &DockerSshd, forwards: Vec<PortForward>) -> SshSession {
    let addr = sshd.addr();
    let mut config = SshConfig::new(
        addr.ip().to_string(),
        addr.port(),
        USER,
        AuthMethod::Password(PASSWORD.into()),
    );
    config.host_key_policy = HostKeyPolicy::Fingerprints(vec![sshd.fingerprint()]);
    config.forwards = forwards;
    spawn_ssh(config).expect("поток сессии")
}

async fn states(session: &mut SshSession, count: usize) -> Vec<ForwardState> {
    let mut states = vec![None; count];
    while states.iter().any(Option::is_none) {
        let event = tokio::time::timeout(DEADLINE, session.events.next())
            .await
            .expect("сессия молчит");
        match event {
            Some(FromSsh::Forward { index, state }) => states[index] = Some(state),
            Some(FromSsh::Connected { .. } | FromSsh::Output(_)) => {}
            other => panic!("ждали состояния правил, пришло {other:?}"),
        }
    }
    states.into_iter().flatten().collect()
}

async fn banner(mut stream: impl AsyncReadExt + Unpin) -> String {
    let mut buffer = [0u8; 7];
    tokio::time::timeout(DEADLINE, stream.read_exact(&mut buffer))
        .await
        .expect("нет ответа")
        .expect("чтение");
    String::from_utf8_lossy(&buffer).into_owned()
}

#[tokio::test]
async fn lokalnyy_dinamicheskiy_i_obratnyy() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker недоступен — тест против настоящего sshd пропущен");
        return;
    };

    let echo = TcpListener::bind("127.0.0.1:0").await.expect("эхо");
    let echo_port = echo.local_addr().expect("адрес").port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = echo.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });

    let (local, dynamic, back) = (free_port().await, free_port().await, free_port().await);
    let mut session = connect(
        &sshd,
        vec![
            rule(ForwardKind::Local, local, Some(("127.0.0.1", 22))),
            rule(ForwardKind::Dynamic, dynamic, None),
            rule(ForwardKind::Remote, 9000, Some(("127.0.0.1", echo_port))),
            rule(ForwardKind::Local, back, Some(("127.0.0.1", 9000))),
        ],
    );
    assert_eq!(states(&mut session, 4).await, vec![ForwardState::Active; 4]);

    let stream = TcpStream::connect(("127.0.0.1", local)).await.expect("-L");
    assert_eq!(banner(stream).await, "SSH-2.0");

    let stream = tokio_socks::tcp::Socks5Stream::connect(("127.0.0.1", dynamic), ("localhost", 22))
        .await
        .expect("-D");
    assert_eq!(banner(stream).await, "SSH-2.0");

    let mut stream = TcpStream::connect(("127.0.0.1", back))
        .await
        .expect("-L до -R");
    stream.write_all(b"ping-pong").await.expect("запись");
    let mut answer = [0u8; 9];
    tokio::time::timeout(DEADLINE, stream.read_exact(&mut answer))
        .await
        .expect("эхо молчит")
        .expect("чтение");
    assert_eq!(&answer, b"ping-pong");

    session
        .commands
        .unbounded_send(ToSsh::SetForward {
            index: 0,
            enabled: false,
        })
        .expect("команда");
    loop {
        match tokio::time::timeout(DEADLINE, session.events.next())
            .await
            .expect("молчит")
        {
            Some(FromSsh::Forward { index: 0, state }) => {
                assert_eq!(state, ForwardState::Off);
                break;
            }
            Some(_) => {}
            None => panic!("сессия закрылась"),
        }
    }
    assert!(
        TcpStream::connect(("127.0.0.1", local)).await.is_err(),
        "порт всё ещё слушают"
    );
}

#[tokio::test]
async fn zanyatyy_port_ne_meshaet_sessii() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker недоступен — тест против настоящего sshd пропущен");
        return;
    };
    let busy = TcpListener::bind("127.0.0.1:0").await.expect("занять");
    let port = busy.local_addr().expect("адрес").port();

    let mut session = connect(
        &sshd,
        vec![rule(ForwardKind::Local, port, Some(("127.0.0.1", 22)))],
    );
    match states(&mut session, 1).await.as_slice() {
        [ForwardState::Failed(error)] => assert!(error.contains("занят"), "{error}"),
        other => panic!("ждали ошибку, пришло {other:?}"),
    }
    session
        .commands
        .unbounded_send(ToSsh::Input(bytes::Bytes::from_static(
            b"echo still-alive\n",
        )))
        .expect("ввод");
    let mut seen = String::new();
    while !seen.contains("still-alive\r\n") {
        match tokio::time::timeout(DEADLINE, session.events.next())
            .await
            .expect("молчит")
        {
            Some(FromSsh::Output(data)) => seen.push_str(&String::from_utf8_lossy(&data)),
            Some(_) => {}
            None => panic!("сессия закрылась: {seen}"),
        }
    }
}
