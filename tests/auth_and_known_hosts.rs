mod docker_sshd;

use std::path::PathBuf;
use std::time::Duration;

use cratty::ssh::auth::{AuthPlan, Credential};
use cratty::ssh::{
    Answer, AuthMethod, CloseReason, FromSsh, HostKeyDecision, HostKeyPolicy, PtySize, SecretKind,
    SshConfig, SshSession, spawn_ssh,
};
use futures::StreamExt;

use docker_sshd::{DockerSshd, PASSWORD, USER};

const DEADLINE: Duration = Duration::from_secs(30);

const GRID: PtySize = PtySize {
    cols: 80,
    rows: 24,
    pixel_width: 0,
    pixel_height: 0,
};

fn base_config(sshd: &DockerSshd, auth: AuthMethod) -> SshConfig {
    let addr = sshd.addr();
    let mut config = SshConfig::new(addr.ip().to_string(), addr.port(), USER, auth);
    config.host_key_policy = HostKeyPolicy::Fingerprints(vec![sshd.fingerprint()]);
    config.pty = GRID;
    config
}

async fn next_event(session: &mut SshSession) -> Option<FromSsh> {
    tokio::time::timeout(DEADLINE, session.events.next())
        .await
        .expect("session sent no events within the allotted time")
}

async fn connect_answering(
    session: &mut SshSession,
    mut answer: impl FnMut(&FromSsh) -> Option<Answer>,
) -> Result<String, String> {
    loop {
        match next_event(session).await {
            Some(FromSsh::Connected { fingerprint }) => return Ok(fingerprint),
            Some(FromSsh::Closed(CloseReason::Error(text))) => return Err(text),
            Some(FromSsh::Closed(other)) => return Err(format!("{other:?}")),
            Some(event) => {
                if let Some(reply) = answer(&event) {
                    session
                        .answers
                        .unbounded_send(reply)
                        .expect("session already closed");
                }
            }
            None => return Err("event channel closed silently".into()),
        }
    }
}

fn make_key(name: &str, passphrase: Option<&str>) -> (PathBuf, String) {
    use russh::keys::{Algorithm, PrivateKey, ssh_key::LineEnding};

    let key =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("could not generate key");
    let public = key
        .public_key()
        .to_openssh()
        .expect("could not serialize public key");

    let serialized = match passphrase {
        Some(phrase) => key
            .encrypt(&mut rand::rng(), phrase)
            .expect("could not encrypt key")
            .to_openssh(LineEnding::LF)
            .expect("could not serialize key"),
        None => key
            .to_openssh(LineEnding::LF)
            .expect("could not serialize key"),
    };

    let path = std::env::temp_dir().join(format!("cratty-test-{name}"));
    std::fs::write(&path, serialized.as_bytes()).expect("could not write key");
    (path, public)
}

#[tokio::test]
async fn public_key_auth_works_against_openssh() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker unavailable — key sign-in check skipped");
        return;
    };

    let (path, public) = make_key("plain-key", None);
    sshd.authorize_key(&public);

    let plan = AuthPlan {
        order: vec![Credential::Key(path.clone())],
    };
    let mut session =
        spawn_ssh(base_config(&sshd, AuthMethod::Plan(plan))).expect("session thread failed to start");

    let result = connect_answering(&mut session, |_| None).await;
    assert!(result.is_ok(), "key sign-in failed: {result:?}");

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn encrypted_key_asks_for_the_passphrase_and_then_works() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker unavailable — passphrase check skipped");
        return;
    };

    let (path, public) = make_key("encrypted-key", Some("key-password"));
    sshd.authorize_key(&public);

    let plan = AuthPlan {
        order: vec![Credential::Key(path.clone())],
    };
    let mut session =
        spawn_ssh(base_config(&sshd, AuthMethod::Plan(plan))).expect("session thread failed to start");

    let mut asked = false;
    let result = connect_answering(&mut session, |event| match event {
        FromSsh::NeedSecret { kind, prompt, .. } => {
            assert_eq!(*kind, SecretKind::Passphrase, "asked for something other than a passphrase");
            assert!(
                prompt.contains("encrypted-key"),
                "prompt does not show which file the passphrase is for: {prompt}"
            );
            asked = true;
            Some(Answer::Secret(Some("key-password".into())))
        }
        _ => None,
    })
    .await;

    assert!(
        result.is_ok(),
        "sign-in with the encrypted key failed: {result:?}"
    );
    assert!(asked, "passphrase was never asked for");

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn a_wrong_passphrase_is_reported_and_does_not_hang() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker unavailable — wrong passphrase check skipped");
        return;
    };

    let (path, public) = make_key("wrong-passphrase-key", Some("correct"));
    sshd.authorize_key(&public);

    let plan = AuthPlan {
        order: vec![Credential::Key(path.clone())],
    };
    let mut session =
        spawn_ssh(base_config(&sshd, AuthMethod::Plan(plan))).expect("session thread failed to start");

    let error = connect_answering(&mut session, |event| match event {
        FromSsh::NeedSecret { .. } => Some(Answer::Secret(Some("incorrect".into()))),
        _ => None,
    })
    .await
    .expect_err("signing in with a wrong passphrase should have failed");

    assert!(
        error.contains("passphrase"),
        "error text does not explain the cause: {error}"
    );

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn password_is_asked_only_after_the_other_methods_fail() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker unavailable — password prompt check skipped");
        return;
    };

    let (path, _public) = make_key("unauthorized-key", None);
    let plan = AuthPlan {
        order: vec![Credential::Key(path.clone()), Credential::Password],
    };
    let mut session =
        spawn_ssh(base_config(&sshd, AuthMethod::Plan(plan))).expect("session thread failed to start");

    let mut asked_for = Vec::new();
    let result = connect_answering(&mut session, |event| match event {
        FromSsh::NeedSecret { kind, .. } => {
            asked_for.push(*kind);
            Some(Answer::Secret(Some(PASSWORD.into())))
        }
        _ => None,
    })
    .await;

    assert!(result.is_ok(), "password sign-in failed: {result:?}");
    assert_eq!(
        asked_for,
        vec![SecretKind::Password],
        "asked for the wrong thing or in the wrong order"
    );

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn a_wrong_password_is_asked_again_with_an_error() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker unavailable — repeated password check skipped");
        return;
    };

    let mut session = spawn_ssh(base_config(
        &sshd,
        AuthMethod::Plan(AuthPlan::password_only()),
    ))
    .expect("session thread failed to start");

    let mut errors = Vec::new();
    let result = connect_answering(&mut session, |event| match event {
        FromSsh::NeedSecret { error, .. } => {
            errors.push(error.clone());
            let answer = if errors.len() == 1 {
                "incorrect"
            } else {
                PASSWORD
            };
            Some(Answer::Secret(Some(answer.into())))
        }
        _ => None,
    })
    .await;

    assert!(result.is_ok(), "did not sign in on the second attempt: {result:?}");
    assert_eq!(errors.len(), 2, "password was not asked for exactly twice: {errors:?}");
    assert!(errors[0].is_none(), "first prompt already carries an error");
    assert!(errors[1].is_some(), "repeated prompt without an explanation");
}

#[tokio::test]
async fn cancelling_the_password_prompt_stops_instead_of_hanging() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker unavailable — cancellation check skipped");
        return;
    };

    let mut session = spawn_ssh(base_config(
        &sshd,
        AuthMethod::Plan(AuthPlan::password_only()),
    ))
    .expect("session thread failed to start");

    let error = connect_answering(&mut session, |event| match event {
        FromSsh::NeedSecret { .. } => Some(Answer::Secret(None)),
        _ => None,
    })
    .await
    .expect_err("connecting must fail after refusing to enter the password");

    assert!(
        error.contains("cancelled"),
        "unclear reason for the failure: {error}"
    );
}

#[tokio::test]
async fn unknown_host_key_is_confirmed_remembered_and_not_asked_again() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker unavailable — known_hosts check skipped");
        return;
    };

    let known_hosts = std::env::temp_dir().join("cratty-test-known-hosts");
    let _ = std::fs::remove_file(&known_hosts);

    let config = || {
        let addr = sshd.addr();
        let mut config = SshConfig::new(
            addr.ip().to_string(),
            addr.port(),
            USER,
            AuthMethod::Password(PASSWORD.into()),
        );
        config.host_key_policy = HostKeyPolicy::KnownHostsFile(known_hosts.clone());
        config.pty = GRID;
        config
    };

    let mut session = spawn_ssh(config()).expect("session thread failed to start");
    let mut asked = false;
    let result = connect_answering(&mut session, |event| match event {
        FromSsh::NeedHostKey {
            fingerprint,
            changed,
            ..
        } => {
            assert!(!changed, "a new host cannot have a 'key changed' warning");
            assert_eq!(*fingerprint, sshd.fingerprint(), "someone else's fingerprint was shown");
            asked = true;
            Some(Answer::HostKey(HostKeyDecision::Accept { remember: true }))
        }
        _ => None,
    })
    .await;

    assert!(
        result.is_ok(),
        "sign-in failed after confirming the key: {result:?}"
    );
    assert!(asked, "unknown key was accepted without asking");
    drop(session);

    let recorded = std::fs::read_to_string(&known_hosts).expect("known_hosts was not created");
    assert!(
        recorded.contains("ssh-ed25519"),
        "key was not recorded in known_hosts: {recorded:?}"
    );

    let mut session = spawn_ssh(config()).expect("session thread failed to start");
    let result = connect_answering(&mut session, |event| {
        panic!("asked again about an already known key: {event:?}")
    })
    .await;
    assert!(
        result.is_ok(),
        "sign-in with the recorded key failed: {result:?}"
    );

    let _ = std::fs::remove_file(&known_hosts);
}

#[tokio::test]
async fn rejecting_the_host_key_refuses_the_connection() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker unavailable — key rejection check skipped");
        return;
    };

    let known_hosts = std::env::temp_dir().join("cratty-test-known-hosts-reject");
    let _ = std::fs::remove_file(&known_hosts);

    let addr = sshd.addr();
    let mut config = SshConfig::new(
        addr.ip().to_string(),
        addr.port(),
        USER,
        AuthMethod::Password(PASSWORD.into()),
    );
    config.host_key_policy = HostKeyPolicy::KnownHostsFile(known_hosts.clone());
    config.pty = GRID;

    let mut session = spawn_ssh(config).expect("session thread failed to start");
    let error = connect_answering(&mut session, |event| match event {
        FromSsh::NeedHostKey { .. } => Some(Answer::HostKey(HostKeyDecision::Reject)),
        _ => None,
    })
    .await
    .expect_err("there must be no connection after rejecting the key");

    assert!(
        error.contains("rejected"),
        "unclear reason for the failure: {error}"
    );
    assert!(
        !known_hosts.exists(),
        "rejected key was recorded in known_hosts anyway"
    );
}

#[tokio::test]
async fn accepting_without_remembering_leaves_known_hosts_untouched() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker unavailable — one-time consent check skipped");
        return;
    };

    let known_hosts = std::env::temp_dir().join("cratty-test-known-hosts-once");
    let _ = std::fs::remove_file(&known_hosts);

    let addr = sshd.addr();
    let mut config = SshConfig::new(
        addr.ip().to_string(),
        addr.port(),
        USER,
        AuthMethod::Password(PASSWORD.into()),
    );
    config.host_key_policy = HostKeyPolicy::KnownHostsFile(known_hosts.clone());
    config.pty = GRID;

    let mut session = spawn_ssh(config).expect("session thread failed to start");
    let result = connect_answering(&mut session, |event| match event {
        FromSsh::NeedHostKey { .. } => {
            Some(Answer::HostKey(HostKeyDecision::Accept { remember: false }))
        }
        _ => None,
    })
    .await;

    assert!(result.is_ok(), "one-time consent did not let us in: {result:?}");
    assert!(
        !known_hosts.exists(),
        "'just this once' was recorded in known_hosts anyway"
    );
}
