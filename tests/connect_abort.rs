//! Connecting to a server that accepted TCP and stays silent: the tab can be closed
//! right away without waiting for the timeout — the UI waits for the SSH thread on close.

use std::time::{Duration, Instant};

use cratty::ssh::{AuthMethod, SshConfig, sftp::spawn_sftp, spawn_ssh};

fn silent_server() -> (std::net::TcpListener, u16) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("port");
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
fn closing_while_connecting_does_not_wait_for_server() {
    let (_listener, port) = silent_server();
    let session = spawn_ssh(config(port)).expect("SSH thread");
    std::thread::sleep(Duration::from_millis(300));

    let started = Instant::now();
    drop(session);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "closing waited {:?}",
        started.elapsed()
    );
}

#[test]
fn closing_sftp_while_connecting_does_not_wait_for_server() {
    let (_listener, port) = silent_server();
    let handle = spawn_sftp(config(port)).expect("SFTP thread");
    std::thread::sleep(Duration::from_millis(300));

    let started = Instant::now();
    drop(handle);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "closing waited {:?}",
        started.elapsed()
    );
}
