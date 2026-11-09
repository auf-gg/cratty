mod docker_sshd;

use std::path::{Path, PathBuf};
use std::time::Duration;

use cratty::ssh::sftp::{FromSftp, RemoteEntry, SftpHandle, ToSftp, spawn_sftp};
use cratty::ssh::{AuthMethod, FromSsh, HostKeyPolicy, SshConfig};
use futures::StreamExt;

use docker_sshd::{DockerSshd, PASSWORD, USER};

const DEADLINE: Duration = Duration::from_secs(60);

fn connect(sshd: &DockerSshd) -> SftpHandle {
    let addr = sshd.addr();
    let mut config = SshConfig::new(
        addr.ip().to_string(),
        addr.port(),
        USER,
        AuthMethod::Password(PASSWORD.into()),
    );
    config.host_key_policy = HostKeyPolicy::Fingerprints(vec![sshd.fingerprint()]);
    spawn_sftp(config).expect("sftp thread")
}

async fn next(handle: &mut SftpHandle) -> FromSftp {
    tokio::time::timeout(DEADLINE, handle.events.next())
        .await
        .expect("sftp is silent")
        .expect("event channel closed")
}

async fn ready(handle: &mut SftpHandle) -> String {
    loop {
        match next(handle).await {
            FromSftp::Ssh(FromSsh::Connected { .. }) => {}
            FromSftp::Ready { home } => return home,
            other => panic!("expected Ready, got {other:?}"),
        }
    }
}

async fn list(handle: &mut SftpHandle, path: &str) -> Vec<RemoteEntry> {
    handle
        .commands
        .unbounded_send(ToSftp::List { path: path.into() })
        .expect("command");
    loop {
        match next(handle).await {
            FromSftp::Listing { entries, .. } => return entries,
            FromSftp::Failed(error) => panic!("listing failed: {error}"),
            _ => {}
        }
    }
}

async fn finished(handle: &mut SftpHandle, id: u64) -> (Result<(), String>, usize) {
    let mut reports = 0;
    loop {
        match next(handle).await {
            FromSftp::Progress { id: got, .. } if got == id => reports += 1,
            FromSftp::Finished { id: got, result } if got == id => return (result, reports),
            _ => {}
        }
    }
}

fn temp(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("cratty-sftp-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    path
}

fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

#[tokio::test]
async fn directory_upload_and_download_round_trip() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker unavailable — test against a real sshd skipped");
        return;
    };
    let mut handle = connect(&sshd);
    let home = ready(&mut handle).await;

    let names: Vec<String> = list(&mut handle, &home)
        .await
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert!(names.contains(&"file.txt".to_string()), "{names:?}");
    assert!(names.contains(&"folder".to_string()), "{names:?}");

    let source = temp("up");
    std::fs::create_dir_all(source.join("nested")).expect("directory");
    std::fs::write(source.join("hello.txt"), "hello, server\n").expect("file");
    let big = noise(3 * 1024 * 1024 + 17);
    std::fs::write(source.join("nested").join("big.bin"), &big).expect("file");

    let remote = format!("{home}/upload");
    handle
        .commands
        .unbounded_send(ToSftp::Upload {
            id: 1,
            local: source.clone(),
            remote: remote.clone(),
            overwrite: false,
        })
        .expect("command");
    let (result, reports) = finished(&mut handle, 1).await;
    assert_eq!(result, Ok(()));
    assert!(reports >= 1, "there was not a single progress report");

    let uploaded = list(&mut handle, &remote).await;
    let big_entry = list(&mut handle, &format!("{remote}/nested")).await;
    assert!(uploaded.iter().any(|e| e.name == "nested" && e.is_dir));
    assert_eq!(big_entry[0].size, big.len() as u64);

    handle
        .commands
        .unbounded_send(ToSftp::Upload {
            id: 2,
            local: source.clone(),
            remote: remote.clone(),
            overwrite: false,
        })
        .expect("command");
    assert!(finished(&mut handle, 2).await.0.is_err());

    let back = temp("down");
    handle
        .commands
        .unbounded_send(ToSftp::Download {
            id: 3,
            remote: remote.clone(),
            local: back.clone(),
            overwrite: false,
        })
        .expect("command");
    assert_eq!(finished(&mut handle, 3).await.0, Ok(()));
    assert_eq!(read(&back.join("hello.txt")), b"hello, server\n");
    assert!(
        read(&back.join("nested").join("big.bin")) == big,
        "large file is corrupted"
    );
    assert!(!back.join("nested").join("big.bin.part").exists());

    handle
        .commands
        .unbounded_send(ToSftp::Remove {
            path: remote.clone(),
        })
        .expect("command");
    loop {
        match next(&mut handle).await {
            FromSftp::Changed { .. } => break,
            FromSftp::Failed(error) => panic!("deletion failed: {error}"),
            _ => {}
        }
    }
    let names: Vec<String> = list(&mut handle, &home)
        .await
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert!(!names.contains(&"upload".to_string()));

    let _ = std::fs::remove_dir_all(&source);
    let _ = std::fs::remove_dir_all(&back);
}

#[tokio::test]
async fn cancel_leaves_no_stub_on_server() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker unavailable — test against a real sshd skipped");
        return;
    };
    let mut handle = connect(&sshd);
    let home = ready(&mut handle).await;

    let source = temp("cancel");
    std::fs::create_dir_all(&source).expect("directory");
    let file = source.join("huge.bin");
    std::fs::write(&file, noise(64 * 1024 * 1024)).expect("file");

    let remote = format!("{home}/huge.bin");
    handle
        .commands
        .unbounded_send(ToSftp::Upload {
            id: 7,
            local: file,
            remote: remote.clone(),
            overwrite: false,
        })
        .expect("command");

    loop {
        match next(&mut handle).await {
            FromSftp::Progress { id: 7, .. } => break,
            FromSftp::Finished { id: 7, result } => panic!("finished too early: {result:?}"),
            _ => {}
        }
    }
    handle
        .commands
        .unbounded_send(ToSftp::Cancel { id: 7 })
        .expect("command");
    let (result, _) = finished(&mut handle, 7).await;
    assert_eq!(result, Err("cancelled".to_string()));

    let names: Vec<String> = list(&mut handle, &home)
        .await
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert!(
        !names.contains(&"huge.bin".to_string()),
        "partial file left behind: {names:?}"
    );

    let _ = std::fs::remove_dir_all(&source);
}

async fn read_file(handle: &SftpHandle, path: &str) -> Result<Vec<u8>, String> {
    let (reply, answer) = futures::channel::oneshot::channel();
    handle
        .commands
        .unbounded_send(ToSftp::ReadFile {
            path: path.into(),
            reply,
        })
        .expect("command");
    tokio::time::timeout(DEADLINE, answer)
        .await
        .expect("no reply")
        .expect("reply lost")
}

async fn write_file(handle: &SftpHandle, path: &str, data: &[u8]) -> Result<(), String> {
    let (reply, answer) = futures::channel::oneshot::channel();
    handle
        .commands
        .unbounded_send(ToSftp::WriteFile {
            path: path.into(),
            data: data.to_vec(),
            reply,
        })
        .expect("command");
    tokio::time::timeout(DEADLINE, answer)
        .await
        .expect("no reply")
        .expect("reply lost")
}

#[tokio::test]
async fn files_over_terminal_connection_and_file_edit() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker unavailable — test against a real sshd skipped");
        return;
    };
    let addr = sshd.addr();
    let mut config = SshConfig::new(
        addr.ip().to_string(),
        addr.port(),
        USER,
        AuthMethod::Password(PASSWORD.into()),
    );
    config.host_key_policy = HostKeyPolicy::Fingerprints(vec![sshd.fingerprint()]);
    let mut session = cratty::ssh::spawn_ssh(config).expect("session thread");

    loop {
        let event = tokio::time::timeout(DEADLINE, session.events.next())
            .await
            .expect("session is silent");
        match event {
            Some(FromSsh::Connected { .. }) => break,
            Some(FromSsh::Output(_)) => {}
            other => panic!("expected Connected, got {other:?}"),
        }
    }

    let mut handle = session.open_sftp();
    let home = match next(&mut handle).await {
        FromSftp::Ready { home } => home,
        other => panic!("expected Ready without signing in again, got {other:?}"),
    };

    let path = format!("{home}/note.conf");
    let first = "listen 80;\nserver_name example;\n";
    assert_eq!(write_file(&handle, &path, first.as_bytes()).await, Ok(()));
    assert_eq!(
        read_file(&handle, &path).await,
        Ok(first.as_bytes().to_vec())
    );

    assert_eq!(write_file(&handle, &path, b"x\n").await, Ok(()));
    assert_eq!(read_file(&handle, &path).await, Ok(b"x\n".to_vec()));

    let big = temp("big-edit");
    std::fs::create_dir_all(&big).expect("directory");
    std::fs::write(big.join("big.bin"), noise(5 * 1024 * 1024)).expect("file");
    handle
        .commands
        .unbounded_send(ToSftp::Upload {
            id: 1,
            local: big.join("big.bin"),
            remote: format!("{home}/big.bin"),
            overwrite: true,
        })
        .expect("command");
    assert_eq!(finished(&mut handle, 1).await.0, Ok(()));
    let refused = read_file(&handle, &format!("{home}/big.bin")).await;
    assert!(refused.is_err_and(|error| error.contains("too large")));

    assert!(read_file(&handle, &home).await.is_err());

    let _ = std::fs::remove_dir_all(&big);
}
