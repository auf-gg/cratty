mod docker_sshd;

use std::time::{Duration, Instant};

use bytes::Bytes;
use cratty::ssh::{AuthMethod, FromSsh, HostKeyPolicy, PtySize, SshConfig, SshSession, ToSsh};
use cratty::term::keys::{Key, Mods};
use cratty::term::predict::{Policy, Predictor};
use cratty::term::{Responder, Terminal};
use futures::StreamExt;

use docker_sshd::{DockerSshd, PASSWORD, USER};

const SIZE: PtySize = PtySize {
    cols: 80,
    rows: 24,
    pixel_width: 0,
    pixel_height: 0,
};
const DEADLINE: Duration = Duration::from_secs(30);

struct Screen {
    session: SshSession,
    terminal: Terminal,
    predictor: Predictor,
}

impl Screen {
    fn connect(sshd: &DockerSshd) -> Self {
        let addr = sshd.addr();
        let mut config = SshConfig::new(
            addr.ip().to_string(),
            addr.port(),
            USER,
            AuthMethod::Password(PASSWORD.into()),
        );
        config.host_key_policy = HostKeyPolicy::Fingerprints(vec![sshd.fingerprint()]);
        config.pty = SIZE;
        let session = cratty::ssh::spawn_ssh(config).expect("session thread");
        let terminal = Terminal::new(SIZE, Responder::new(session.commands.clone()));
        Self {
            session,
            terminal,
            predictor: Predictor::new(Policy::Always),
        }
    }

    fn press(&mut self, key: Key) {
        let bytes = self
            .terminal
            .encode_key(key, Mods::NONE)
            .expect("key sends bytes");
        self.predictor
            .key(key, Mods::NONE, &self.terminal, Instant::now());
        self.session
            .commands
            .unbounded_send(ToSsh::Input(Bytes::from(bytes)))
            .expect("session closed");
    }

    async fn pump_until(&mut self, what: &str, mut done: impl FnMut(&Self) -> bool) {
        let deadline = Instant::now() + DEADLINE;
        while !done(self) {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for: {what}\n{}",
                self.dump()
            );
            match tokio::time::timeout(Duration::from_millis(200), self.session.events.next()).await
            {
                Ok(Some(FromSsh::Output(data))) => {
                    self.terminal.advance(&data);
                    self.predictor.observe(&self.terminal, Instant::now());
                }
                Ok(Some(FromSsh::Connected { .. })) => {}
                Ok(Some(other)) => panic!("unexpected event {other:?} while waiting for: {what}"),
                Ok(None) => panic!("session closed while waiting for: {what}"),
                Err(_) => self.predictor.observe(&self.terminal, Instant::now()),
            }
        }
    }

    fn screen_text(&self) -> String {
        self.terminal
            .snapshot()
            .lines
            .iter()
            .map(|line| line.text())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn dump(&self) -> String {
        self.terminal
            .snapshot()
            .lines
            .iter()
            .enumerate()
            .map(|(i, line)| format!("{i:>3}|{}", line.text().trim_end()))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[tokio::test]
async fn readline_confirms_typing_without_a_single_error() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker unavailable — test against a real sshd skipped");
        return;
    };
    let mut screen = Screen::connect(&sshd);
    screen
        .pump_until("prompt", |s| s.screen_text().contains("$ "))
        .await;

    let mut shown_before_echo = 0;
    for ch in "echo prediction works".chars() {
        screen.press(Key::Char(ch));
        if !screen.predictor.overlay().0.is_empty() {
            shown_before_echo += 1;
        }
        screen
            .pump_until("character echo", |s| s.predictor.pending() == 0)
            .await;
    }
    screen.press(Key::Backspace);
    screen
        .pump_until("erase echo", |s| s.predictor.pending() == 0)
        .await;
    screen.press(Key::Char('s'));
    screen
        .pump_until("character echo", |s| s.predictor.pending() == 0)
        .await;

    assert_eq!(
        screen.predictor.misses(),
        0,
        "predictor was wrong\n{}",
        screen.dump()
    );
    assert!(
        screen.predictor.srtt().is_some(),
        "echo latency was not measured"
    );
    assert!(
        shown_before_echo >= 15,
        "only {shown_before_echo} characters shown before the echo"
    );

    screen.press(Key::Char(' '));
    for ch in "fast".chars() {
        screen.press(Key::Char(ch));
    }
    screen
        .pump_until("burst echo", |s| s.predictor.pending() == 0)
        .await;
    assert_eq!(
        screen.predictor.misses(),
        0,
        "wrong on fast typing\n{}",
        screen.dump()
    );
    assert!(screen.screen_text().contains("echo prediction works fast"));
}

#[tokio::test]
async fn read_s_input_does_not_appear_on_screen() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker unavailable — test against a real sshd skipped");
        return;
    };
    let mut screen = Screen::connect(&sshd);
    screen
        .pump_until("prompt", |s| s.screen_text().contains("$ "))
        .await;

    for ch in "read -s -p secret: x".chars() {
        screen.press(Key::Char(ch));
        screen
            .pump_until("echo", |s| s.predictor.pending() == 0)
            .await;
    }
    screen.press(Key::Enter);
    screen
        .pump_until("read prompt", |s| {
            s.screen_text().contains("secret:")
        })
        .await;

    for ch in "hunter2".chars() {
        screen.press(Key::Char(ch));
        assert!(
            screen.predictor.overlay().0.is_empty(),
            "password character was shown by prediction"
        );
        let _ = tokio::time::timeout(
            Duration::from_millis(100),
            screen.pump_until("silence", |_| false),
        )
        .await;
        assert!(screen.predictor.overlay().0.is_empty());
    }
    assert!(!screen.screen_text().contains("hunter2"));
    screen.press(Key::Enter);
    screen
        .pump_until("new prompt", |s| {
            s.screen_text().matches("$ ").count() >= 2
        })
        .await;
}
