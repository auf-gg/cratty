//! Подключение к серверу, который принял TCP и молчит: вкладку можно закрыть
//! сразу, не дожидаясь таймаута, — интерфейс ждёт поток SSH при закрытии.

use std::time::{Duration, Instant};

use cratty::ssh::{AuthMethod, SshConfig, sftp::spawn_sftp, spawn_ssh};

fn silent_server() -> (std::net::TcpListener, u16) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("порт");
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

fn config(port: u16) -> SshConfig {
    SshConfig::new(
        "127.0.0.1",
        port,
        "tester",
        AuthMethod::Password("x".into()),
    )
}

#[test]
fn zakrytie_vo_vremya_podklyucheniya_ne_zhdyot_servera() {
    let (_listener, port) = silent_server();
    let session = spawn_ssh(config(port)).expect("поток SSH");
    std::thread::sleep(Duration::from_millis(300));

    let started = Instant::now();
    drop(session);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "закрытие ждало {:?}",
        started.elapsed()
    );
}

#[test]
fn zakrytie_sftp_vo_vremya_podklyucheniya_ne_zhdyot_servera() {
    let (_listener, port) = silent_server();
    let handle = spawn_sftp(config(port)).expect("поток SFTP");
    std::thread::sleep(Duration::from_millis(300));

    let started = Instant::now();
    drop(handle);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "закрытие ждало {:?}",
        started.elapsed()
    );
}
