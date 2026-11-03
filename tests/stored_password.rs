mod fake_sshd;

use std::time::Duration;

use cratty::ssh::{
    Answer, AuthMethod, CloseReason, FromSsh, HostKeyPolicy, PtySize, STORED_PASSWORD_REJECTED,
    SecretKind, SshConfig, spawn_ssh,
};
use fake_sshd::{AuthMode, FakeSshd, OTP};
use futures::StreamExt;

fn pty() -> PtySize {
    PtySize {
        cols: 80,
        rows: 24,
        pixel_width: 0,
        pixel_height: 0,
    }
}

fn config(sshd: &FakeSshd, stored: Option<&str>) -> SshConfig {
    let mut config = SshConfig::new(
        sshd.addr().ip().to_string(),
        sshd.addr().port(),
        sshd.user(),
        AuthMethod::Plan(cratty::ssh::auth::AuthPlan { order: Vec::new() }.with_stored_password()),
    );
    config.stored_password = stored.map(|text| proto::Secret::new(text.as_bytes().to_vec()));
    config.host_key_policy = HostKeyPolicy::Fingerprints(vec![sshd.fingerprint()]);
    config.pty = pty();
    config
}

async fn outcome(
    mut session: cratty::ssh::SshSession,
    mut answer: impl FnMut(&str, SecretKind) -> Option<String>,
) -> Result<Vec<(String, SecretKind)>, String> {
    let answers = session.answers.clone();
    let mut asked = Vec::new();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let event = tokio::time::timeout_at(deadline, session.events.next())
            .await
            .map_err(|_| "сессия не ответила за отведённое время".to_string())?;

        match event {
            Some(FromSsh::Connected { .. }) => return Ok(asked),
            Some(FromSsh::NeedSecret { prompt, kind }) => {
                asked.push((prompt.clone(), kind));
                let _ = answers.unbounded_send(Answer::Secret(answer(&prompt, kind)));
            }
            Some(FromSsh::Closed(CloseReason::Error(text))) => return Err(text),
            Some(FromSsh::Closed(other)) => return Err(format!("{other:?}")),
            Some(_) => {}
            None => return Err("поток сессии закончился молча".into()),
        }
    }
}

#[tokio::test]
async fn sohranennyy_parol_prohodit_cherez_keyboard_interactive() {
    let sshd = FakeSshd::start_with_auth(AuthMode::SinglePrompt).await;
    let password = sshd.password().to_string();
    let session = spawn_ssh(config(&sshd, Some(&password))).expect("поток сессии");

    let asked = outcome(session, |prompt, kind| {
        panic!("человека не должны были спрашивать: {prompt} ({kind:?})")
    })
    .await
    .expect("сессия должна была открыться");

    assert!(asked.is_empty(), "сохранённый пароль спрашивать незачем");
    assert_eq!(
        sshd.interactive_answers(),
        vec![password],
        "в приглашение должен был уйти сохранённый пароль"
    );
}

#[tokio::test]
async fn dva_priglasheniya_eto_vtoroy_faktor_i_ego_sprashivayut() {
    let sshd = FakeSshd::start_with_auth(AuthMode::TwoPrompts).await;
    let password = sshd.password().to_string();
    let session = spawn_ssh(config(&sshd, Some(&password))).expect("поток сессии");

    let typed = password.clone();
    let asked = outcome(session, move |prompt, _| {
        if prompt.contains("Verification") {
            Some(OTP.to_string())
        } else {
            Some(typed.clone())
        }
    })
    .await
    .expect("сессия должна была открыться");

    assert_eq!(
        asked.len(),
        2,
        "оба поля второго фактора обязаны быть спрошены у человека"
    );
    for (_, kind) in &asked {
        assert_eq!(
            *kind,
            SecretKind::Challenge,
            "второй фактор не должен выглядеть как обычный пароль"
        );
    }
    assert_eq!(sshd.interactive_answers(), vec![password, OTP.to_string()]);
}

#[tokio::test]
async fn otvergnutyy_sohranennyy_parol_ostanavlivaet_perebor() {
    let sshd = FakeSshd::start_with_auth(AuthMode::SinglePrompt).await;
    let session = spawn_ssh(config(&sshd, Some("не тот пароль"))).expect("поток сессии");

    let error = outcome(session, |prompt, kind| {
        panic!("после отказа сохранённым паролем спрашивать нельзя: {prompt} ({kind:?})")
    })
    .await
    .expect_err("сессия не должна была открыться");

    assert!(
        error.contains(STORED_PASSWORD_REJECTED),
        "UI узнаёт этот случай по метке в тексте: {error}"
    );
}

#[tokio::test]
async fn sohranennyy_parol_prohodit_obychnym_metodom() {
    let sshd = FakeSshd::start_with_auth(AuthMode::PasswordOnly).await;
    let password = sshd.password().to_string();
    let session = spawn_ssh(config(&sshd, Some(&password))).expect("поток сессии");

    let asked = outcome(session, |prompt, kind| {
        panic!("человека не должны были спрашивать: {prompt} ({kind:?})")
    })
    .await
    .expect("сессия должна была открыться");

    assert!(asked.is_empty());
    assert!(
        sshd.interactive_answers().is_empty(),
        "keyboard-interactive не понадобился"
    );
}
