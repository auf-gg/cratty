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
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("port");
    listener.local_addr().expect("address").port()
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
    spawn_ssh(config).expect("session thread")
}

async fn states(session: &mut SshSession, count: usize) -> Vec<ForwardState> {
    let mut states = vec![None; count];
    while states.iter().any(Option::is_none) {
        let event = tokio::time::timeout(DEADLINE, session.events.next())
            .await
            .expect("session is silent");
        match event {
            Some(FromSsh::Forward { index, state }) => states[index] = Some(state),
            Some(FromSsh::Connected { .. } | FromSsh::Output(_)) => {}
            other => panic!("expected rule states, got {other:?}"),
        }
    }
    states.into_iter().flatten().collect()
}

async fn banner(mut stream: impl AsyncReadExt + Unpin) -> String {
    let mut buffer = [0u8; 7];
    tokio::time::timeout(DEADLINE, stream.read_exact(&mut buffer))
        .await
        .expect("no reply")
        .expect("read");
    String::from_utf8_lossy(&buffer).into_owned()
}

#[tokio::test]
async fn local_dynamic_and_reverse() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker unavailable — test against a real sshd skipped");
        return;
    };

    let echo = TcpListener::bind("127.0.0.1:0").await.expect("echo");
    let echo_port = echo.local_addr().expect("address").port();
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
        .expect("-L before -R");
    stream.write_all(b"ping-pong").await.expect("record");
    let mut answer = [0u8; 9];
    tokio::time::timeout(DEADLINE, stream.read_exact(&mut answer))
        .await
        .expect("echo is silent")
        .expect("read");
    assert_eq!(&answer, b"ping-pong");

    session
        .commands
        .unbounded_send(ToSsh::SetForward {
            index: 0,
            enabled: false,
        })
        .expect("command");
    loop {
        match tokio::time::timeout(DEADLINE, session.events.next())
            .await
            .expect("silent")
        {
            Some(FromSsh::Forward { index: 0, state }) => {
                assert_eq!(state, ForwardState::Off);
                break;
            }
            Some(_) => {}
            None => panic!("session closed"),
        }
    }
    assert!(
        TcpStream::connect(("127.0.0.1", local)).await.is_err(),
        "port is still being listened on"
    );
}

#[tokio::test]
async fn busy_port_does_not_break_session() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker unavailable — test against a real sshd skipped");
        return;
    };
    let busy = TcpListener::bind("127.0.0.1:0").await.expect("occupy");
    let port = busy.local_addr().expect("address").port();

    let mut session = connect(
        &sshd,
        vec![rule(ForwardKind::Local, port, Some(("127.0.0.1", 22)))],
    );
    match states(&mut session, 1).await.as_slice() {
        [ForwardState::Failed(error)] => assert!(error.contains("in use"), "{error}"),
        other => panic!("expected an error, got {other:?}"),
    }
    session
        .commands
        .unbounded_send(ToSsh::Input(bytes::Bytes::from_static(
            b"echo still-alive\n",
        )))
        .expect("input");
    let mut seen = String::new();
    while !seen.contains("still-alive\r\n") {
        match tokio::time::timeout(DEADLINE, session.events.next())
            .await
            .expect("silent")
        {
            Some(FromSsh::Output(data)) => seen.push_str(&String::from_utf8_lossy(&data)),
            Some(_) => {}
            None => panic!("session closed: {seen}"),
        }
    }
}
