mod fake_sshd;

use std::time::Duration;

use cratty::ssh::{
    Answer, AuthMethod, CloseReason, FromSsh, HostKeyPolicy, PtySize, stored_password_rejected,
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
            .map_err(|_| "session did not answer in time".to_string())?;

        match event {
            Some(FromSsh::Connected { .. }) => return Ok(asked),
            Some(FromSsh::NeedSecret { prompt, kind, .. }) => {
                asked.push((prompt.clone(), kind));
                let _ = answers.unbounded_send(Answer::Secret(answer(&prompt, kind)));
            }
            Some(FromSsh::Closed(CloseReason::Error(text))) => return Err(text),
            Some(FromSsh::Closed(other)) => return Err(format!("{other:?}")),
            Some(_) => {}
            None => return Err("session thread ended silently".into()),
        }
    }
}

#[tokio::test]
async fn stored_password_passes_through_keyboard_interactive() {
    let sshd = FakeSshd::start_with_auth(AuthMode::SinglePrompt).await;
    let password = sshd.password().to_string();
    let session = spawn_ssh(config(&sshd, Some(&password))).expect("session thread");

    let asked = outcome(session, |prompt, kind| {
        panic!("the user must not be asked: {prompt} ({kind:?})")
    })
    .await
    .expect("session should have opened");

    assert!(asked.is_empty(), "no need to ask for a stored password");
    assert_eq!(
        sshd.interactive_answers(),
        vec![password],
        "the stored password should have been sent to the prompt"
    );
}

#[tokio::test]
async fn two_prompts_mean_second_factor_and_it_is_asked() {
    let sshd = FakeSshd::start_with_auth(AuthMode::TwoPrompts).await;
    let password = sshd.password().to_string();
    let session = spawn_ssh(config(&sshd, Some(&password))).expect("session thread");

    let typed = password.clone();
    let asked = outcome(session, move |prompt, _| {
        if prompt.contains("Verification") {
            Some(OTP.to_string())
        } else {
            Some(typed.clone())
        }
    })
    .await
    .expect("session should have opened");

    assert_eq!(
        asked.len(),
        2,
        "both second-factor fields must be asked of the user"
    );
    for (_, kind) in &asked {
        assert_eq!(
            *kind,
            SecretKind::Challenge,
            "the second factor must not look like a regular password"
        );
    }
    assert_eq!(sshd.interactive_answers(), vec![password, OTP.to_string()]);
}

#[tokio::test]
async fn rejected_stored_password_stops_the_retries() {
    let sshd = FakeSshd::start_with_auth(AuthMode::SinglePrompt).await;
    let session = spawn_ssh(config(&sshd, Some("wrong password"))).expect("session thread");

    let error = outcome(session, |prompt, kind| {
        panic!("must not ask after the stored password was rejected: {prompt} ({kind:?})")
    })
    .await
    .expect_err("session should not have opened");

    assert!(
        error.contains(&stored_password_rejected()),
        "the UI recognises this case by the marker in the text: {error}"
    );
}

#[tokio::test]
async fn stored_password_passes_through_regular_method() {
    let sshd = FakeSshd::start_with_auth(AuthMode::PasswordOnly).await;
    let password = sshd.password().to_string();
    let session = spawn_ssh(config(&sshd, Some(&password))).expect("session thread");

    let asked = outcome(session, |prompt, kind| {
        panic!("the user must not be asked: {prompt} ({kind:?})")
    })
    .await
    .expect("session should have opened");

    assert!(asked.is_empty());
    assert!(
        sshd.interactive_answers().is_empty(),
        "keyboard-interactive was not needed"
    );
}
