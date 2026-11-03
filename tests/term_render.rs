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

        let session = cratty::ssh::spawn_ssh(config).expect("не поднялся поток сессии");
        let terminal = Terminal::new(GRID, Responder::new(session.commands.clone()));

        Self { session, terminal }
    }

    fn send(&self, text: &str) {
        self.session
            .commands
            .unbounded_send(ToSsh::Input(Bytes::from(text.to_owned().into_bytes())))
            .expect("сессия уже закрыта");
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
                    Ok(None) => panic!("сессия закрылась, пока ждали: {what}"),
                };

            match event {
                FromSsh::Output(data) => self.terminal.advance(&data),
                FromSsh::Connected { .. } | FromSsh::Forward { .. } => {}
                other @ (FromSsh::NeedSecret { .. } | FromSsh::NeedHostKey { .. }) => {
                    panic!("неожиданный диалог {other:?}, пока ждали: {what}")
                }
                FromSsh::Closed(reason) => {
                    panic!("сессия закрылась ({reason:?}), пока ждали: {what}")
                }
            }

            let snapshot = self.terminal.snapshot();
            if ready(&snapshot) {
                return snapshot;
            }
        }

        panic!(
            "не дождались «{what}» за {DEADLINE:?}\nэкран сейчас:\n{}",
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
        eprintln!("docker недоступен — проверка ls --color пропущена");
        return;
    };

    let mut screen = Screen::connect(&sshd);
    screen.send("ls --color=always -1 ~\r");

    let snapshot = screen
        .wait_until("вывод ls", |snapshot| contains(snapshot, "файл.txt"))
        .await;

    let directory = snapshot
        .lines
        .iter()
        .flat_map(|line| &line.runs)
        .find(|run| run.text.contains("каталог"))
        .expect("в выводе нет каталога");

    assert_ne!(
        directory.style.fg, snapshot.lines[0].runs[0].style.fg,
        "каталог не выделен цветом: {:?}",
        directory.style
    );
    assert_eq!(
        directory.style.fg,
        cratty::term::palette::DEFAULT.indexed(4),
        "каталог раскрашен не синим: {:?}",
        directory.style
    );

    let file = snapshot
        .lines
        .iter()
        .flat_map(|line| &line.runs)
        .find(|run| run.text.contains("файл.txt"))
        .expect("в выводе нет файла");
    assert_eq!(file.style.fg, cratty::term::palette::DEFAULT.foreground);
}

#[tokio::test]
async fn vim_draws_on_the_alternate_screen_and_leaves_it_clean() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker недоступен — проверка vim пропущена");
        return;
    };

    let mut screen = Screen::connect(&sshd);

    screen.send("echo МЕТКА-ДО-VIM\r");
    screen
        .wait_until("метку до запуска", |snapshot| {
            contains(snapshot, "МЕТКА-ДО-VIM")
        })
        .await;

    screen.send("vim -u NONE /tmp/проба.txt\r");

    let snapshot = screen
        .wait_until("экран vim", |snapshot| {
            snapshot
                .lines
                .iter()
                .filter(|line| line.text().starts_with('~'))
                .count()
                >= 5
        })
        .await;

    assert!(
        !contains(&snapshot, "МЕТКА-ДО-VIM"),
        "vim рисует поверх основного экрана, а не в альтернативном:\n{}",
        dump(&screen.terminal)
    );

    screen.send("iпривет\x1b");
    screen
        .wait_until("вставленный текст", |snapshot| {
            contains(snapshot, "привет")
        })
        .await;
    screen.send(":q!\r");

    screen
        .wait_until(
            "восстановленный основной экран",
            |snapshot| contains(snapshot, "МЕТКА-ДО-VIM"),
        )
        .await;
}

#[tokio::test]
async fn htop_paints_a_full_width_header() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker недоступен — проверка htop пропущена");
        return;
    };

    let mut screen = Screen::connect(&sshd);
    screen.send("htop\r");

    let snapshot = screen
        .wait_until("экран htop", |snapshot| {
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
        "ни одна строка htop не закрашена хотя бы наполовину (максимум {painted} из {}):\n{}",
        snapshot.columns,
        dump(&screen.terminal)
    );

    screen.send("q");
}
