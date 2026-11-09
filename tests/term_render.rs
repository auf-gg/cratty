mod docker_sshd;

use std::time::{Duration, Instant};

use bytes::Bytes;
use cratty::ssh::{AuthMethod, FromSsh, HostKeyPolicy, PtySize, SshConfig, SshSession, ToSsh};
use cratty::term::{Responder, Snapshot, Terminal};
use futures::StreamExt;

use docker_sshd::{DockerSshd, PASSWORD, USER};

const GRID: PtySize = PtySize {
    cols: 100,
    rows: 30,
    pixel_width: 0,
    pixel_height: 0,
};

const DEADLINE: Duration = Duration::from_secs(45);

struct Screen {
    session: SshSession,
    terminal: Terminal,
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
        config.term = "xterm-256color".into();
        config.pty = GRID;

        let session = cratty::ssh::spawn_ssh(config).expect("session thread failed to start");
        let terminal = Terminal::new(GRID, Responder::new(session.commands.clone()));

        Self { session, terminal }
    }

    fn send(&self, text: &str) {
        self.session
            .commands
            .unbounded_send(ToSsh::Input(Bytes::from(text.to_owned().into_bytes())))
            .expect("session already closed");
    }

    async fn wait_until(
        &mut self,
        what: &str,
        mut ready: impl FnMut(&Snapshot) -> bool,
    ) -> Snapshot {
        let deadline = Instant::now() + DEADLINE;

        let snapshot = self.terminal.snapshot();
        if ready(&snapshot) {
            return snapshot;
        }

        while Instant::now() < deadline {
            let event =
                match tokio::time::timeout(Duration::from_millis(500), self.session.events.next())
                    .await
                {
                    Ok(Some(event)) => event,
                    Err(_) => continue,
                    Ok(None) => panic!("session closed while waiting for: {what}"),
                };

            match event {
                FromSsh::Output(data) => self.terminal.advance(&data),
                FromSsh::Connected { .. } | FromSsh::Forward { .. } => {}
                other @ (FromSsh::NeedSecret { .. } | FromSsh::NeedHostKey { .. }) => {
                    panic!("unexpected dialog {other:?} while waiting for: {what}")
                }
                FromSsh::Closed(reason) => {
                    panic!("session closed ({reason:?}) while waiting for: {what}")
                }
            }

            let snapshot = self.terminal.snapshot();
            if ready(&snapshot) {
                return snapshot;
            }
        }

        panic!(
            "timed out waiting for '{what}' after {DEADLINE:?}\nscreen now:\n{}",
            dump(&self.terminal)
        );
    }
}

fn dump(terminal: &Terminal) -> String {
    terminal
        .snapshot()
        .lines
        .iter()
        .enumerate()
        .map(|(index, line)| format!("{index:>3}|{}", line.text().trim_end()))
        .collect::<Vec<_>>()
        .join("\n")
}

fn contains(snapshot: &Snapshot, needle: &str) -> bool {
    snapshot
        .lines
        .iter()
        .any(|line| line.text().contains(needle))
}

#[tokio::test]
async fn ls_color_paints_the_directory() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker unavailable — ls --color check skipped");
        return;
    };

    let mut screen = Screen::connect(&sshd);
    screen.send("ls --color=always -1 ~\r");

    let snapshot = screen
        .wait_until("ls output", |snapshot| contains(snapshot, "file.txt"))
        .await;

    let directory = snapshot
        .lines
        .iter()
        .flat_map(|line| &line.runs)
        .find(|run| run.text.contains("folder"))
        .expect("no directory in the output");

    assert_ne!(
        directory.style.fg, snapshot.lines[0].runs[0].style.fg,
        "directory is not highlighted: {:?}",
        directory.style
    );
    assert_eq!(
        directory.style.fg,
        cratty::term::palette::DEFAULT.indexed(4),
        "directory is not colored blue: {:?}",
        directory.style
    );

    let file = snapshot
        .lines
        .iter()
        .flat_map(|line| &line.runs)
        .find(|run| run.text.contains("file.txt"))
        .expect("no file in the output");
    assert_eq!(file.style.fg, cratty::term::palette::DEFAULT.foreground);
}

#[tokio::test]
async fn vim_draws_on_the_alternate_screen_and_leaves_it_clean() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker unavailable — vim check skipped");
        return;
    };

    let mut screen = Screen::connect(&sshd);

    screen.send("echo MARK-BEFORE-VIM\r");
    screen
        .wait_until("the marker before launch", |snapshot| {
            contains(snapshot, "MARK-BEFORE-VIM")
        })
        .await;

    screen.send("vim -u NONE /tmp/probe.txt\r");

    let snapshot = screen
        .wait_until("vim screen", |snapshot| {
            snapshot
                .lines
                .iter()
                .filter(|line| line.text().starts_with('~'))
                .count()
                >= 5
        })
        .await;

    assert!(
        !contains(&snapshot, "MARK-BEFORE-VIM"),
        "vim draws over the main screen instead of the alternate one:\n{}",
        dump(&screen.terminal)
    );

    screen.send("ihello\x1b");
    screen
        .wait_until("inserted text", |snapshot| {
            contains(snapshot, "hello")
        })
        .await;
    screen.send(":q!\r");

    screen
        .wait_until(
            "restored main screen",
            |snapshot| contains(snapshot, "MARK-BEFORE-VIM"),
        )
        .await;
}

#[tokio::test]
async fn htop_paints_a_full_width_header() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker unavailable — htop check skipped");
        return;
    };

    let mut screen = Screen::connect(&sshd);
    screen.send("htop\r");

    let snapshot = screen
        .wait_until("htop screen", |snapshot| {
            contains(snapshot, "Help") && contains(snapshot, "Quit")
        })
        .await;

    let painted = snapshot
        .lines
        .iter()
        .map(|line| {
            line.runs
                .iter()
                .filter(|run| run.style.bg != snapshot.background)
                .map(|run| run.text.chars().count())
                .sum::<usize>()
        })
        .max()
        .unwrap_or(0);

    assert!(
        painted >= snapshot.columns / 2,
        "no htop row is at least half painted (maximum {painted} of {}):\n{}",
        snapshot.columns,
        dump(&screen.terminal)
    );

    screen.send("q");
}
