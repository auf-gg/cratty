mod docker_sshd;

use std::time::{Duration, Instant};

use bytes::Bytes;
use cratty::ssh::{AuthMethod, FromSsh, HostKeyPolicy, PtySize, SshConfig, SshSession, ToSsh};
use cratty::term::keys::{Key, Mods};
use cratty::term::{Responder, Snapshot, Terminal};
use futures::StreamExt;

use docker_sshd::{DockerSshd, PASSWORD, USER};

const START: PtySize = PtySize {
    cols: 60,
    rows: 20,
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
        config.pty = START;

        let session = cratty::ssh::spawn_ssh(config).expect("не поднялся поток сессии");
        let terminal = Terminal::new(START, Responder::new(session.commands.clone()));
        Self { session, terminal }
    }

    fn raw(&self, bytes: Vec<u8>) {
        self.session
            .commands
            .unbounded_send(ToSsh::Input(Bytes::from(bytes)))
            .expect("сессия уже закрыта");
    }

    fn press(&self, key: Key, mods: Mods) {
        let bytes = self
            .terminal
            .encode_key(key, mods)
            .unwrap_or_else(|| panic!("{key:?} с {mods:?} ничего не отправляет"));
        self.raw(bytes);
    }

    fn type_text(&self, text: &str) {
        for character in text.chars() {
            self.press(Key::Char(character), Mods::NONE);
        }
    }

    fn resize(&mut self, size: PtySize) {
        self.terminal.resize(size);
        self.session
            .commands
            .unbounded_send(ToSsh::Resize(size))
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
            match tokio::time::timeout(Duration::from_millis(500), self.session.events.next()).await
            {
                Ok(Some(FromSsh::Output(data))) => self.terminal.advance(&data),
                Ok(Some(FromSsh::Connected { .. } | FromSsh::Forward { .. })) => {}
                Ok(Some(other @ (FromSsh::NeedSecret { .. } | FromSsh::NeedHostKey { .. }))) => {
                    panic!("неожиданный диалог {other:?}, пока ждали: {what}")
                }
                Ok(Some(FromSsh::Closed(reason))) => {
                    panic!("сессия закрылась ({reason:?}), пока ждали: {what}")
                }
                Ok(None) => panic!("канал событий закрылся, пока ждали: {what}"),
                Err(_) => continue,
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

fn painted_width(snapshot: &Snapshot) -> usize {
    snapshot
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
        .unwrap_or(0)
}

#[tokio::test]
async fn typed_keys_reach_the_shell_and_ctrl_c_interrupts_it() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker недоступен — проверка ввода в оболочку пропущена");
        return;
    };

    let mut screen = Screen::connect(&sshd);

    screen.type_text("echo НАБРАНО-С-КЛАВИАТУРЫ");
    screen.press(Key::Enter, Mods::NONE);
    screen
        .wait_until("вывод набранной команды", |snapshot| {
            snapshot
                .lines
                .iter()
                .filter(|line| line.text().contains("НАБРАНО-С-КЛАВИАТУРЫ"))
                .count()
                >= 2
        })
        .await;

    screen.type_text("echo ЗАПУЩЕНО && sleep 60");
    screen.press(Key::Enter, Mods::NONE);
    screen
        .wait_until("запуск долгой команды", |snapshot| {
            snapshot
                .lines
                .iter()
                .filter(|line| line.text().contains("ЗАПУЩЕНО"))
                .count()
                >= 2
        })
        .await;
    screen.press(Key::Char('c'), Mods::ctrl());

    screen.type_text("echo ПОСЛЕ-ПРЕРЫВАНИЯ");
    screen.press(Key::Enter, Mods::NONE);
    screen
        .wait_until("приглашение после Ctrl+C", |snapshot| {
            snapshot
                .lines
                .iter()
                .filter(|line| line.text().contains("ПОСЛЕ-ПРЕРЫВАНИЯ"))
                .count()
                >= 2
        })
        .await;
}

#[tokio::test]
async fn arrows_steer_vim_in_application_cursor_mode() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker недоступен — проверка управления vim пропущена");
        return;
    };

    let mut screen = Screen::connect(&sshd);
    screen.type_text("vim -u NONE /tmp/клавиши.txt");
    screen.press(Key::Enter, Mods::NONE);

    screen
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
        screen
            .terminal
            .mode()
            .contains(alacritty_terminal::term::TermMode::APP_CURSOR),
        "vim не включил режим курсорных клавиш — стрелки будут закодированы не так"
    );

    screen.press(Key::Char('i'), Mods::NONE);
    screen.type_text("ПРИВЕТ");
    screen.press(Key::Escape, Mods::NONE);
    screen
        .wait_until("набранный в vim текст", |snapshot| {
            contains(snapshot, "ПРИВЕТ")
        })
        .await;

    screen.press(Key::Left, Mods::NONE);
    screen.press(Key::Left, Mods::NONE);
    screen.press(Key::Char('x'), Mods::NONE);

    screen
        .wait_until(
            "текст после удаления стрелками",
            |snapshot| contains(snapshot, "ПРИЕТ"),
        )
        .await;

    screen.press(Key::Home, Mods::NONE);
    screen.press(Key::Char('x'), Mods::NONE);
    screen
        .wait_until(
            "текст после Home и удаления",
            |snapshot| contains(snapshot, "РИЕТ") && !contains(snapshot, "ПРИЕТ"),
        )
        .await;

    screen.type_text(":q!");
    screen.press(Key::Enter, Mods::NONE);
}

#[tokio::test]
async fn htop_repaints_wider_after_a_resize() {
    let Some(sshd) = DockerSshd::start() else {
        eprintln!("docker недоступен — проверка resize пропущена");
        return;
    };

    let mut screen = Screen::connect(&sshd);
    screen.type_text("htop");
    screen.press(Key::Enter, Mods::NONE);

    let narrow = screen
        .wait_until("экран htop на узкой сетке", |snapshot| {
            contains(snapshot, "Help") && contains(snapshot, "Mem")
        })
        .await;

    let narrow_width = painted_width(&narrow);
    assert!(
        narrow_width <= START.cols as usize,
        "htop нарисовал шире, чем сетка: {narrow_width} > {}",
        START.cols
    );

    let wide = PtySize {
        cols: 110,
        rows: 30,
        pixel_width: 0,
        pixel_height: 0,
    };
    screen.resize(wide);

    let snapshot = screen
        .wait_until(
            "перерисовку htop на широкой сетке",
            |snapshot| painted_width(snapshot) > START.cols as usize,
        )
        .await;

    assert!(
        painted_width(&snapshot) > narrow_width,
        "после resize htop рисует не шире прежнего ({} против {narrow_width}):\n{}",
        painted_width(&snapshot),
        dump(&screen.terminal)
    );
    assert_eq!(snapshot.lines.len(), wide.rows as usize);

    screen.press(Key::Char('q'), Mods::NONE);
}
