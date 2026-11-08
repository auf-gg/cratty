mod fake_socks;
mod fake_sshd;

use std::time::Duration;

use cratty::ssh::auth::AuthPlan;
use cratty::ssh::{
    Answer, AuthMethod, CloseReason, FromSsh, Hop, HostKeyPolicy, JumpHost, SecretKind, Socks5Hop,
    SshConfig, SshSession, spawn_ssh,
};
use futures::StreamExt;

use fake_socks::FakeSocks;
use fake_sshd::FakeSshd;

const DEADLINE: Duration = Duration::from_secs(20);
const USER: &str = "tester";
const PASSWORD: &str = "s3cret";

fn target(sshd: &FakeSshd, via: Result<Vec<Hop>, String>) -> SshConfig {
    let mut config = SshConfig::new(
        "localhost",
        sshd.addr().port(),
        USER,
        AuthMethod::Password(PASSWORD.into()),
    );
    config.host_key_policy = HostKeyPolicy::Fingerprints(vec![sshd.fingerprint()]);
    config.via = via;
    config
}

fn socks(proxy: &FakeSocks, login: Option<(&str, &str)>) -> Hop {
    Hop::Socks5(Socks5Hop {
        host: "127.0.0.1".into(),
        port: proxy.addr().port(),
        user: login.map(|(user, _)| user.to_string()).unwrap_or_default(),
        password: login.map(|(_, password)| proto::Secret::new(password.as_bytes().to_vec())),
    })
}

fn jump(sshd: &FakeSshd, auth: AuthMethod) -> Hop {
    Hop::Jump(JumpHost {
        host: "127.0.0.1".into(),
        port: sshd.addr().port(),
        user: USER.into(),
        auth,
        host_key_policy: HostKeyPolicy::Fingerprints(vec![sshd.fingerprint()]),
        stored_password: None,
    })
}

async fn next_event(session: &mut SshSession) -> Option<FromSsh> {
    tokio::time::timeout(DEADLINE, session.events.next())
        .await
        .expect("сессия не прислала события в отведённое время")
}

async fn wait_shell(session: &mut SshSession) {
    let mut seen = String::new();
    let mut connected = false;
    loop {
        match next_event(session).await {
            Some(FromSsh::Connected { .. }) => connected = true,
            Some(FromSsh::Output(data)) => {
                seen.push_str(&String::from_utf8_lossy(&data));
                if connected && seen.contains("$ ") {
                    return;
                }
            }
            other => panic!("ждали оболочку, получили {other:?}; вывод: {seen:?}"),
        }
    }
}

async fn wait_error(session: &mut SshSession) -> String {
    loop {
        match next_event(session).await {
            Some(FromSsh::Closed(CloseReason::Error(text))) => return text,
            Some(FromSsh::Closed(other)) => panic!("ждали ошибку, закрылось так: {other:?}"),
            Some(_) => {}
            None => panic!("канал событий закрылся, не сказав почему"),
        }
    }
}

#[tokio::test]
async fn cherez_socks5_bez_vhoda() {
    let sshd = FakeSshd::start().await;
    let proxy = FakeSocks::open().await;

    let mut session = spawn_ssh(target(&sshd, Ok(vec![socks(&proxy, None)]))).expect("поток");
    wait_shell(&mut session).await;

    assert_eq!(
        proxy.targets(),
        vec![("localhost".to_string(), sshd.addr().port())]
    );
    assert_eq!(sshd.connections(), 1);
}

#[tokio::test]
async fn cherez_socks5_s_parolem() {
    let sshd = FakeSshd::start().await;
    let proxy = FakeSocks::with_password("dan", "hunter2").await;

    let config = target(&sshd, Ok(vec![socks(&proxy, Some(("dan", "hunter2")))]));
    let mut session = spawn_ssh(config).expect("поток");
    wait_shell(&mut session).await;

    assert_eq!(proxy.users(), vec!["dan".to_string()]);
}

#[tokio::test]
async fn nevernyy_parol_proksi_ne_vedet_napryamuyu() {
    let sshd = FakeSshd::start().await;
    let proxy = FakeSocks::with_password("dan", "hunter2").await;

    let config = target(&sshd, Ok(vec![socks(&proxy, Some(("dan", "wrong")))]));
    let mut session = spawn_ssh(config).expect("поток");
    let error = wait_error(&mut session).await;

    assert!(error.contains("прокси SOCKS5"), "{error}");
    assert_eq!(sshd.connections(), 0, "клиент пошёл к цели мимо прокси");
}

#[tokio::test]
async fn mertvyy_proksi_ne_vedet_napryamuyu() {
    let sshd = FakeSshd::start().await;
    let dead = {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("порт");
        listener.local_addr().expect("адрес").port()
    };
    let hop = Hop::Socks5(Socks5Hop {
        host: "127.0.0.1".into(),
        port: dead,
        user: String::new(),
        password: None,
    });

    let mut session = spawn_ssh(target(&sshd, Ok(vec![hop]))).expect("поток");
    let error = wait_error(&mut session).await;

    assert!(error.contains("прокси SOCKS5"), "{error}");
    assert_eq!(sshd.connections(), 0, "клиент пошёл к цели мимо прокси");
}

#[tokio::test]
async fn nesobrannyy_marshrut_ne_podklyuchaetsya() {
    let sshd = FakeSshd::start().await;
    let config = target(&sshd, Err("прокси №1 из цепочки нет в хранилище".into()));

    let mut session = spawn_ssh(config).expect("поток");
    let error = wait_error(&mut session).await;

    assert!(error.contains("нет в хранилище"), "{error}");
    assert_eq!(sshd.connections(), 0);
}

#[tokio::test]
async fn cepochka_iz_dvuh_socks5() {
    let sshd = FakeSshd::start().await;
    let near = FakeSocks::open().await;
    let far = FakeSocks::open().await;

    let config = target(&sshd, Ok(vec![socks(&near, None), socks(&far, None)]));
    let mut session = spawn_ssh(config).expect("поток");
    wait_shell(&mut session).await;

    assert_eq!(
        near.targets(),
        vec![("127.0.0.1".to_string(), far.addr().port())]
    );
    assert_eq!(
        far.targets(),
        vec![("localhost".to_string(), sshd.addr().port())]
    );
}

#[tokio::test]
async fn cherez_promezhutochnyy_host() {
    let bastion = FakeSshd::start().await;
    let sshd = FakeSshd::start().await;

    let hop = jump(&bastion, AuthMethod::Password(PASSWORD.into()));
    let mut session = spawn_ssh(target(&sshd, Ok(vec![hop]))).expect("поток");
    wait_shell(&mut session).await;

    assert_eq!(
        bastion.tunnels(),
        vec![("localhost".to_string(), u32::from(sshd.addr().port()))]
    );
}

#[tokio::test]
async fn socks5_potom_promezhutochnyy_host() {
    let proxy = FakeSocks::open().await;
    let bastion = FakeSshd::start().await;
    let sshd = FakeSshd::start().await;

    let via = vec![
        socks(&proxy, None),
        jump(&bastion, AuthMethod::Password(PASSWORD.into())),
    ];
    let mut session = spawn_ssh(target(&sshd, Ok(via))).expect("поток");
    wait_shell(&mut session).await;

    assert_eq!(
        proxy.targets(),
        vec![("127.0.0.1".to_string(), bastion.addr().port())]
    );
    assert_eq!(
        bastion.tunnels(),
        vec![("localhost".to_string(), u32::from(sshd.addr().port()))]
    );
}

#[tokio::test]
async fn parol_promezhutochnogo_hosta_sprashivaetsya_s_adresom() {
    let bastion = FakeSshd::start().await;
    let sshd = FakeSshd::start().await;

    let hop = jump(&bastion, AuthMethod::Plan(AuthPlan::password_only()));
    let mut session = spawn_ssh(target(&sshd, Ok(vec![hop]))).expect("поток");

    match next_event(&mut session).await {
        Some(FromSsh::NeedSecret { prompt, kind, .. }) => {
            assert_eq!(kind, SecretKind::Password);
            let address = format!("127.0.0.1:{}", bastion.addr().port());
            assert!(prompt.contains(&address), "в вопросе нет адреса: {prompt}");
        }
        other => panic!("ждали вопрос о пароле, получили {other:?}"),
    }
    session
        .answers
        .unbounded_send(Answer::Secret(Some(PASSWORD.into())))
        .expect("сессия закрыта");

    wait_shell(&mut session).await;
}

#[tokio::test]
async fn chuzhoy_klyuch_promezhutochnogo_hosta_ostanavlivaet_marshrut() {
    let bastion = FakeSshd::start().await;
    let sshd = FakeSshd::start().await;

    let hop = Hop::Jump(JumpHost {
        host: "127.0.0.1".into(),
        port: bastion.addr().port(),
        user: USER.into(),
        auth: AuthMethod::Password(PASSWORD.into()),
        host_key_policy: HostKeyPolicy::Fingerprints(vec![sshd.fingerprint()]),
        stored_password: None,
    });
    let mut session = spawn_ssh(target(&sshd, Ok(vec![hop]))).expect("поток");
    let error = wait_error(&mut session).await;

    assert!(error.contains("промежуточный хост"), "{error}");
    assert!(bastion.tunnels().is_empty());
    assert_eq!(sshd.connections(), 0);
}

#[tokio::test]
async fn promezhutochnyy_khost_vkhodit_sokhranyonnym_parolem() {
    let bastion = FakeSshd::start().await;
    let sshd = FakeSshd::start().await;

    let hop = Hop::Jump(JumpHost {
        host: "127.0.0.1".into(),
        port: bastion.addr().port(),
        user: USER.into(),
        auth: AuthMethod::Plan(AuthPlan::password_only().with_stored_password()),
        host_key_policy: HostKeyPolicy::Fingerprints(vec![bastion.fingerprint()]),
        stored_password: Some(proto::Secret::new(PASSWORD.as_bytes().to_vec())),
    });
    let mut session = spawn_ssh(target(&sshd, Ok(vec![hop]))).expect("поток");
    wait_shell(&mut session).await;

    assert_eq!(bastion.connections(), 1);
    assert_eq!(sshd.connections(), 1);
}
