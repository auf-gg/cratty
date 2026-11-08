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
        .expect("сессия не прислала события в отведённое время")
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
                        .expect("сессия уже закрыта");
                }
            }
            None => return Err("канал событий закрылся молча".into()),
        }
    }
}

fn make_key(name: &str, passphrase: Option<&str>) -> (PathBuf, String) {
    use russh::keys::{Algorithm, PrivateKey, ssh_key::LineEnding};

    let key =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("не сгенерировать ключ");
    let public = key
        .public_key()
        .to_openssh()
        .expect("не сериализовать открытый ключ");

    let serialized = match passphrase {
        Some(phrase) => key
            .encrypt(&mut rand::rng(), phrase)
            .expect("не зашифровать ключ")
            .to_openssh(LineEnding::LF)
            .expect("не сериализовать ключ"),
        None => key
            .to_openssh(LineEnding::LF)
            .expect("не сериализовать ключ"),
    };

    let path = std::env::temp_dir().join(format!("cratty-test-{name}"));
    std::fs::write(&path, serialized.as_bytes()).expect("не записать ключ");
    (path, public)
}

#[tokio::test]
async fn public_key_auth_works_against_openssh() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker недоступен — проверка входа по ключу пропущена");
        return;
    };

    let (path, public) = make_key("plain-key", None);
    sshd.authorize_key(&public);

    let plan = AuthPlan {
        order: vec![Credential::Key(path.clone())],
    };
    let mut session =
        spawn_ssh(base_config(&sshd, AuthMethod::Plan(plan))).expect("не поднялся поток сессии");

    let result = connect_answering(&mut session, |_| None).await;
    assert!(result.is_ok(), "вход по ключу не прошёл: {result:?}");

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn encrypted_key_asks_for_the_passphrase_and_then_works() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker недоступен — проверка passphrase пропущена");
        return;
    };

    let (path, public) = make_key("encrypted-key", Some("пароль-к-ключу"));
    sshd.authorize_key(&public);

    let plan = AuthPlan {
        order: vec![Credential::Key(path.clone())],
    };
    let mut session =
        spawn_ssh(base_config(&sshd, AuthMethod::Plan(plan))).expect("не поднялся поток сессии");

    let mut asked = false;
    let result = connect_answering(&mut session, |event| match event {
        FromSsh::NeedSecret { kind, prompt, .. } => {
            assert_eq!(*kind, SecretKind::Passphrase, "спросили не passphrase");
            assert!(
                prompt.contains("encrypted-key"),
                "в подсказке не видно, к какому файлу passphrase: {prompt}"
            );
            asked = true;
            Some(Answer::Secret(Some("пароль-к-ключу".into())))
        }
        _ => None,
    })
    .await;

    assert!(
        result.is_ok(),
        "вход по зашифрованному ключу не прошёл: {result:?}"
    );
    assert!(asked, "passphrase не спросили вовсе");

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn a_wrong_passphrase_is_reported_and_does_not_hang() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker недоступен — проверка неверного passphrase пропущена");
        return;
    };

    let (path, public) = make_key("wrong-passphrase-key", Some("правильный"));
    sshd.authorize_key(&public);

    let plan = AuthPlan {
        order: vec![Credential::Key(path.clone())],
    };
    let mut session =
        spawn_ssh(base_config(&sshd, AuthMethod::Plan(plan))).expect("не поднялся поток сессии");

    let error = connect_answering(&mut session, |event| match event {
        FromSsh::NeedSecret { .. } => Some(Answer::Secret(Some("неправильный".into()))),
        _ => None,
    })
    .await
    .expect_err("с неверным passphrase войти не должно было получиться");

    assert!(
        error.contains("passphrase"),
        "текст ошибки не объясняет причину: {error}"
    );

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn password_is_asked_only_after_the_other_methods_fail() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker недоступен — проверка запроса пароля пропущена");
        return;
    };

    let (path, _public) = make_key("unauthorized-key", None);
    let plan = AuthPlan {
        order: vec![Credential::Key(path.clone()), Credential::Password],
    };
    let mut session =
        spawn_ssh(base_config(&sshd, AuthMethod::Plan(plan))).expect("не поднялся поток сессии");

    let mut asked_for = Vec::new();
    let result = connect_answering(&mut session, |event| match event {
        FromSsh::NeedSecret { kind, .. } => {
            asked_for.push(*kind);
            Some(Answer::Secret(Some(PASSWORD.into())))
        }
        _ => None,
    })
    .await;

    assert!(result.is_ok(), "вход по паролю не прошёл: {result:?}");
    assert_eq!(
        asked_for,
        vec![SecretKind::Password],
        "спросили не то или не в том порядке"
    );

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn a_wrong_password_is_asked_again_with_an_error() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker недоступен — проверка повторного пароля пропущена");
        return;
    };

    let mut session = spawn_ssh(base_config(
        &sshd,
        AuthMethod::Plan(AuthPlan::password_only()),
    ))
    .expect("не поднялся поток сессии");

    let mut errors = Vec::new();
    let result = connect_answering(&mut session, |event| match event {
        FromSsh::NeedSecret { error, .. } => {
            errors.push(error.clone());
            let answer = if errors.len() == 1 {
                "неправильный"
            } else {
                PASSWORD
            };
            Some(Answer::Secret(Some(answer.into())))
        }
        _ => None,
    })
    .await;

    assert!(result.is_ok(), "со второй попытки не вошли: {result:?}");
    assert_eq!(errors.len(), 2, "пароль спросили не дважды: {errors:?}");
    assert!(errors[0].is_none(), "первый запрос уже с ошибкой");
    assert!(errors[1].is_some(), "повторный запрос без объяснения");
}

#[tokio::test]
async fn cancelling_the_password_prompt_stops_instead_of_hanging() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker недоступен — проверка отмены пропущена");
        return;
    };

    let mut session = spawn_ssh(base_config(
        &sshd,
        AuthMethod::Plan(AuthPlan::password_only()),
    ))
    .expect("не поднялся поток сессии");

    let error = connect_answering(&mut session, |event| match event {
        FromSsh::NeedSecret { .. } => Some(Answer::Secret(None)),
        _ => None,
    })
    .await
    .expect_err("после отказа вводить пароль подключиться нельзя");

    assert!(
        error.contains("отменён"),
        "невнятная причина отказа: {error}"
    );
}

#[tokio::test]
async fn unknown_host_key_is_confirmed_remembered_and_not_asked_again() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker недоступен — проверка known_hosts пропущена");
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

    let mut session = spawn_ssh(config()).expect("не поднялся поток сессии");
    let mut asked = false;
    let result = connect_answering(&mut session, |event| match event {
        FromSsh::NeedHostKey {
            fingerprint,
            changed,
            ..
        } => {
            assert!(!changed, "для нового хоста не может быть «ключ изменился»");
            assert_eq!(*fingerprint, sshd.fingerprint(), "показан чужой отпечаток");
            asked = true;
            Some(Answer::HostKey(HostKeyDecision::Accept { remember: true }))
        }
        _ => None,
    })
    .await;

    assert!(
        result.is_ok(),
        "после подтверждения ключа вход не прошёл: {result:?}"
    );
    assert!(asked, "неизвестный ключ приняли, ничего не спросив");
    drop(session);

    let recorded = std::fs::read_to_string(&known_hosts).expect("known_hosts не создан");
    assert!(
        recorded.contains("ssh-ed25519"),
        "ключ не записан в known_hosts: {recorded:?}"
    );

    let mut session = spawn_ssh(config()).expect("не поднялся поток сессии");
    let result = connect_answering(&mut session, |event| {
        panic!("повторно спросили про уже известный ключ: {event:?}")
    })
    .await;
    assert!(
        result.is_ok(),
        "с записанным ключом вход не прошёл: {result:?}"
    );

    let _ = std::fs::remove_file(&known_hosts);
}

#[tokio::test]
async fn rejecting_the_host_key_refuses_the_connection() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker недоступен — проверка отказа от ключа пропущена");
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

    let mut session = spawn_ssh(config).expect("не поднялся поток сессии");
    let error = connect_answering(&mut session, |event| match event {
        FromSsh::NeedHostKey { .. } => Some(Answer::HostKey(HostKeyDecision::Reject)),
        _ => None,
    })
    .await
    .expect_err("после отказа от ключа соединения быть не должно");

    assert!(
        error.contains("отклонён"),
        "невнятная причина отказа: {error}"
    );
    assert!(
        !known_hosts.exists(),
        "отклонённый ключ всё равно записали в known_hosts"
    );
}

#[tokio::test]
async fn accepting_without_remembering_leaves_known_hosts_untouched() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker недоступен — проверка разового согласия пропущена");
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

    let mut session = spawn_ssh(config).expect("не поднялся поток сессии");
    let result = connect_answering(&mut session, |event| match event {
        FromSsh::NeedHostKey { .. } => {
            Some(Answer::HostKey(HostKeyDecision::Accept { remember: false }))
        }
        _ => None,
    })
    .await;

    assert!(result.is_ok(), "разовое согласие не пустило: {result:?}");
    assert!(
        !known_hosts.exists(),
        "«только в этот раз» всё равно записали в known_hosts"
    );
}
