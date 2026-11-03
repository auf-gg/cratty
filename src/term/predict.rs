use std::time::{Duration, Instant};

use alacritty_terminal::term::TermMode;
use unicode_width::UnicodeWidthChar;

use super::{Key, Line, Mods, Run, Snapshot, Terminal};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Policy {
    #[default]
    Adaptive,
    Always,
    Never,
}

const SHOW_ABOVE: Duration = Duration::from_millis(30);
const HIDE_BELOW: Duration = Duration::from_millis(20);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);
const MIN_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, Debug)]
struct Prediction {
    row: usize,
    column: usize,
    ch: char,
    before: char,
    sent: Instant,
    epoch: u64,
    verifiable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Overlay {
    pub row: usize,
    pub column: usize,
    pub ch: char,
}

pub struct Predictor {
    policy: Policy,
    predictions: Vec<Prediction>,
    cursor: Option<(usize, usize)>,
    epoch: u64,
    confirmed: Option<u64>,
    srtt: Option<Duration>,
    showing: bool,
    misses: u64,
}

impl Predictor {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            predictions: Vec::new(),
            cursor: None,
            epoch: 0,
            confirmed: None,
            srtt: None,
            showing: false,
            misses: 0,
        }
    }

    pub fn policy(&self) -> Policy {
        self.policy
    }

    pub fn set_policy(&mut self, policy: Policy) {
        self.policy = policy;
        if policy == Policy::Never {
            self.reset();
        }
    }

    pub fn srtt(&self) -> Option<Duration> {
        self.srtt
    }

    pub fn misses(&self) -> u64 {
        self.misses
    }

    pub fn pending(&self) -> usize {
        self.predictions.len()
    }

    pub fn visible(&self) -> bool {
        match self.policy {
            Policy::Always => true,
            Policy::Never => false,
            Policy::Adaptive => self.showing,
        }
    }

    pub fn other_input(&mut self) {
        self.tentative();
    }

    fn tentative(&mut self) {
        self.epoch += 1;
        self.cursor = None;
    }

    fn reset(&mut self) {
        self.predictions.clear();
        self.tentative();
    }

    fn usable(term: &Terminal) -> bool {
        term.at_bottom()
            && !term
                .mode()
                .intersects(TermMode::ALT_SCREEN | TermMode::MOUSE_MODE)
    }

    fn position(&self, term: &Terminal) -> Option<(usize, usize)> {
        self.cursor.or_else(|| term.cursor_point())
    }

    fn tail_blank(term: &Terminal, row: usize, column: usize) -> bool {
        (column..term.columns()).all(|c| term.screen_cell(row, c) == Some(' '))
    }

    pub fn key(&mut self, key: Key, mods: Mods, term: &Terminal, now: Instant) {
        if self.policy == Policy::Never {
            return;
        }
        if !Self::usable(term) {
            self.reset();
            return;
        }
        match key {
            Key::Char(ch) if !mods.ctrl && !mods.alt => self.predict_char(ch, term, now),
            Key::Backspace if mods == Mods::NONE => self.predict_backspace(term, now),
            _ => self.tentative(),
        }
    }

    fn predict_char(&mut self, ch: char, term: &Terminal, now: Instant) {
        if ch.is_control() || ch.width() != Some(1) {
            return self.tentative();
        }
        let Some((row, column)) = self.position(term) else {
            return self.tentative();
        };
        if column + 1 >= term.columns()
            || !term.row_is_plain(row)
            || !Self::tail_blank(term, row, column)
        {
            return self.tentative();
        }

        let before = term.screen_cell(row, column).unwrap_or(' ');
        self.predictions.push(Prediction {
            row,
            column,
            ch,
            before,
            sent: now,
            epoch: self.epoch,
            verifiable: before != ch,
        });
        self.cursor = Some((row, column + 1));
    }

    fn predict_backspace(&mut self, term: &Terminal, now: Instant) {
        let Some((row, column)) = self.position(term) else {
            return self.tentative();
        };
        if column == 0 || !term.row_is_plain(row) || !Self::tail_blank(term, row, column) {
            return self.tentative();
        }
        let target = column - 1;

        if let Some(index) = self
            .predictions
            .iter()
            .rposition(|p| p.row == row && p.column == target)
        {
            self.predictions.remove(index);
            self.cursor = Some((row, target));
            return;
        }

        let before = term.screen_cell(row, target).unwrap_or(' ');
        if before == ' ' {
            return self.tentative();
        }
        self.predictions.push(Prediction {
            row,
            column: target,
            ch: ' ',
            before,
            sent: now,
            epoch: self.epoch,
            verifiable: true,
        });
        self.cursor = Some((row, target));
    }

    fn timeout(&self) -> Duration {
        match self.srtt {
            Some(srtt) => (srtt * 4).clamp(MIN_TIMEOUT, MAX_TIMEOUT),
            None => DEFAULT_TIMEOUT,
        }
    }

    pub fn observe(&mut self, term: &Terminal, now: Instant) {
        if self.predictions.is_empty() {
            self.cursor = None;
            return;
        }
        if !Self::usable(term) {
            self.reset();
            return;
        }

        let timeout = self.timeout();
        let real_cursor = term.cursor_point();
        let mut samples = Vec::new();
        let mut failed = false;

        self.predictions.retain(|p| {
            let expired = now.saturating_duration_since(p.sent) > timeout;
            if !p.verifiable {
                let passed = matches!(real_cursor, Some((r, c)) if r == p.row && c > p.column);
                if expired && !passed {
                    failed = true;
                }
                return !passed && !expired;
            }
            match term.screen_cell(p.row, p.column) {
                Some(real) if real == p.ch => {
                    samples.push((p.epoch, now.saturating_duration_since(p.sent)));
                    false
                }
                Some(real) if real == p.before => {
                    if expired {
                        failed = true;
                    }
                    true
                }
                _ => {
                    failed = true;
                    false
                }
            }
        });

        for (epoch, rtt) in samples {
            self.confirmed = Some(self.confirmed.map_or(epoch, |seen| seen.max(epoch)));
            self.sample(rtt);
        }
        if failed {
            self.misses += 1;
            self.reset();
        }
        if self.predictions.is_empty() {
            self.cursor = None;
        }
    }

    fn sample(&mut self, rtt: Duration) {
        let srtt = match self.srtt {
            Some(old) => (old * 7 + rtt) / 8,
            None => rtt,
        };
        self.srtt = Some(srtt);
        if srtt > SHOW_ABOVE {
            self.showing = true;
        } else if srtt < HIDE_BELOW {
            self.showing = false;
        }
    }

    fn displayable(&self, epoch: u64) -> bool {
        self.visible() && self.confirmed.is_some_and(|confirmed| confirmed >= epoch)
    }

    pub fn overlay(&self) -> (Vec<Overlay>, Option<(usize, usize)>) {
        let cells = self
            .predictions
            .iter()
            .filter(|p| p.verifiable && self.displayable(p.epoch))
            .map(|p| Overlay {
                row: p.row,
                column: p.column,
                ch: p.ch,
            })
            .collect();
        let cursor = match (self.cursor, self.predictions.last()) {
            (Some(cursor), Some(last)) if self.displayable(last.epoch) => Some(cursor),
            _ => None,
        };
        (cells, cursor)
    }

    pub fn paint(&self, snapshot: &mut Snapshot) {
        if snapshot.display_offset != 0 {
            return;
        }
        let (cells, cursor) = self.overlay();
        for cell in cells {
            if let Some(line) = snapshot.lines.get_mut(cell.row) {
                set_cell(line, cell.column, cell.ch, snapshot.columns);
            }
        }
        if let (Some((row, column)), Some(shown)) = (cursor, snapshot.cursor.as_mut()) {
            shown.line = row;
            shown.column = column;
        }
    }
}

fn set_cell(line: &mut Line, column: usize, ch: char, columns: usize) {
    let mut cells: Vec<(char, super::Style)> = line
        .runs
        .iter()
        .flat_map(|run| run.text.chars().map(move |c| (c, run.style)))
        .collect();
    if column >= columns {
        return;
    }
    while cells.len() <= column {
        let style = cells.last().map(|(_, style)| *style).unwrap_or_default();
        cells.push((' ', style));
    }
    let mut style = cells[column].1;
    style.underline = true;
    cells[column] = (ch, style);

    let mut runs: Vec<Run> = Vec::new();
    for (c, style) in cells {
        match runs.last_mut() {
            Some(run) if run.style == style => run.text.push(c),
            _ => runs.push(Run {
                text: String::from(c),
                style,
            }),
        }
    }
    line.runs = runs;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::{PtySize, ToSsh};
    use crate::term::Responder;
    use futures::channel::mpsc;

    fn shell() -> (Terminal, mpsc::UnboundedReceiver<ToSsh>) {
        let (tx, rx) = mpsc::unbounded();
        let mut term = Terminal::new(PtySize::new(40, 5), Responder::new(tx));
        term.advance(b"$ ");
        (term, rx)
    }

    fn type_char(predictor: &mut Predictor, term: &Terminal, ch: char, at: Instant) {
        predictor.key(Key::Char(ch), Mods::NONE, term, at);
    }

    fn row_text(snapshot: &Snapshot, row: usize) -> String {
        snapshot.lines[row].text().trim_end().to_string()
    }

    #[test]
    fn posle_podtverzhdeniya_simvoly_vidny_srazu() {
        let (mut term, _rx) = shell();
        let mut predictor = Predictor::new(Policy::Always);
        let t0 = Instant::now();

        type_char(&mut predictor, &term, 'l', t0);
        assert!(predictor.overlay().0.is_empty());

        term.advance(b"l");
        predictor.observe(&term, t0 + Duration::from_millis(80));
        assert_eq!(predictor.srtt(), Some(Duration::from_millis(80)));

        type_char(&mut predictor, &term, 's', t0 + Duration::from_millis(100));
        let (cells, cursor) = predictor.overlay();
        assert_eq!(
            cells,
            vec![Overlay {
                row: 0,
                column: 3,
                ch: 's'
            }]
        );
        assert_eq!(cursor, Some((0, 4)));

        let mut snapshot = term.snapshot();
        predictor.paint(&mut snapshot);
        assert_eq!(row_text(&snapshot, 0), "$ ls");
        let underlined: String = snapshot.lines[0]
            .runs
            .iter()
            .filter(|run| run.style.underline)
            .map(|run| run.text.as_str())
            .collect();
        assert_eq!(underlined, "s", "предсказанное обязано быть отличимым");
    }

    #[test]
    fn parol_ne_poyavlyaetsya_na_ekrane() {
        let (mut term, _rx) = shell();
        let mut predictor = Predictor::new(Policy::Always);
        let t0 = Instant::now();

        type_char(&mut predictor, &term, 's', t0);
        term.advance(b"s");
        predictor.observe(&term, t0 + Duration::from_millis(50));

        predictor.key(Key::Enter, Mods::NONE, &term, t0);
        term.advance(b"\r\nPassword: ");
        predictor.observe(&term, t0 + Duration::from_millis(60));

        for (i, ch) in "hunter2".chars().enumerate() {
            let at = t0 + Duration::from_millis(100 + i as u64 * 10);
            type_char(&mut predictor, &term, ch, at);
            assert!(predictor.overlay().0.is_empty(), "символ пароля на экране");
            predictor.observe(&term, at);
        }

        predictor.observe(&term, t0 + Duration::from_secs(5));
        assert!(predictor.overlay().0.is_empty());
        let mut snapshot = term.snapshot();
        predictor.paint(&mut snapshot);
        assert_eq!(row_text(&snapshot, 1), "Password:");
    }

    #[test]
    fn probel_ne_podtverzhdaet_epohu() {
        let (mut term, _rx) = shell();
        let mut predictor = Predictor::new(Policy::Always);
        let t0 = Instant::now();

        predictor.key(Key::Enter, Mods::NONE, &term, t0);
        term.advance(b"\r\nPassword: ");
        predictor.observe(&term, t0);

        type_char(&mut predictor, &term, ' ', t0);
        predictor.observe(&term, t0 + Duration::from_millis(50));
        type_char(&mut predictor, &term, 'x', t0 + Duration::from_millis(60));
        assert!(predictor.overlay().0.is_empty());
    }

    #[test]
    fn oshibka_snimaet_predskazaniya() {
        let (mut term, _rx) = shell();
        let mut predictor = Predictor::new(Policy::Always);
        let t0 = Instant::now();

        type_char(&mut predictor, &term, 'a', t0);
        term.advance(b"a");
        predictor.observe(&term, t0 + Duration::from_millis(40));
        type_char(&mut predictor, &term, 'b', t0);
        assert_eq!(predictor.overlay().0.len(), 1);

        term.advance(b"Z");
        predictor.observe(&term, t0 + Duration::from_millis(80));
        assert!(predictor.overlay().0.is_empty());
        assert_eq!(predictor.overlay().1, None);
    }

    #[test]
    fn v_vim_ne_predskazyvaem() {
        let (mut term, _rx) = shell();
        let mut predictor = Predictor::new(Policy::Always);
        let t0 = Instant::now();

        type_char(&mut predictor, &term, 'a', t0);
        term.advance(b"a");
        predictor.observe(&term, t0);

        term.advance(b"\x1b[?1049h");
        predictor.observe(&term, t0);
        type_char(&mut predictor, &term, 'i', t0);
        assert!(predictor.overlay().0.is_empty());
        assert!(predictor.predictions.is_empty());
    }

    #[test]
    fn poseredine_stroki_ne_predskazyvaem() {
        let (mut term, _rx) = shell();
        let mut predictor = Predictor::new(Policy::Always);
        term.advance(b"echo hi\x1b[3D");
        type_char(&mut predictor, &term, 'x', Instant::now());
        assert!(predictor.predictions.is_empty());
    }

    #[test]
    fn backspace_stiraet_podcherknuto() {
        let (mut term, _rx) = shell();
        let mut predictor = Predictor::new(Policy::Always);
        let t0 = Instant::now();

        type_char(&mut predictor, &term, 'a', t0);
        term.advance(b"a");
        predictor.observe(&term, t0 + Duration::from_millis(40));
        type_char(&mut predictor, &term, 'b', t0);
        term.advance(b"b");
        predictor.observe(&term, t0 + Duration::from_millis(80));

        predictor.key(
            Key::Backspace,
            Mods::NONE,
            &term,
            t0 + Duration::from_millis(90),
        );
        let mut snapshot = term.snapshot();
        predictor.paint(&mut snapshot);
        assert_eq!(row_text(&snapshot, 0), "$ a");
        assert_eq!(snapshot.cursor.map(|c| c.column), Some(3));

        term.advance(b"\x08 \x08");
        predictor.observe(&term, t0 + Duration::from_millis(130));
        assert!(predictor.predictions.is_empty());
    }

    #[test]
    fn probel_derzhit_mesto_kursora() {
        let (mut term, _rx) = shell();
        let mut predictor = Predictor::new(Policy::Always);
        let t0 = Instant::now();

        type_char(&mut predictor, &term, 'l', t0);
        term.advance(b"l");
        predictor.observe(&term, t0 + Duration::from_millis(40));

        type_char(&mut predictor, &term, ' ', t0);
        predictor.observe(&term, t0 + Duration::from_millis(45));
        type_char(&mut predictor, &term, '-', t0);
        assert_eq!(
            predictor.overlay().0,
            vec![Overlay {
                row: 0,
                column: 4,
                ch: '-'
            }]
        );

        term.advance(b" -");
        predictor.observe(&term, t0 + Duration::from_millis(90));
        assert!(predictor.predictions.is_empty());
    }

    #[test]
    fn adaptivnyy_rezhim_smotrit_na_zaderzhku() {
        let mut predictor = Predictor::new(Policy::Adaptive);
        predictor.sample(Duration::from_millis(5));
        assert!(!predictor.visible());
        for _ in 0..40 {
            predictor.sample(Duration::from_millis(100));
        }
        assert!(predictor.visible());
        predictor.srtt = Some(Duration::from_millis(25));
        predictor.sample(Duration::from_millis(25));
        assert!(predictor.visible());
        for _ in 0..60 {
            predictor.sample(Duration::from_millis(2));
        }
        assert!(!predictor.visible());
    }

    #[test]
    fn nikogda_znachit_nikogda() {
        let (mut term, _rx) = shell();
        let mut predictor = Predictor::new(Policy::Never);
        let t0 = Instant::now();
        type_char(&mut predictor, &term, 'a', t0);
        term.advance(b"a");
        predictor.observe(&term, t0);
        type_char(&mut predictor, &term, 'b', t0);
        assert!(predictor.predictions.is_empty());
    }

    #[test]
    fn u_pravogo_kraya_ne_predskazyvaem() {
        let (mut term, _rx) = shell();
        let mut predictor = Predictor::new(Policy::Always);
        term.advance(&[b'x'; 37]);
        type_char(&mut predictor, &term, 'y', Instant::now());
        assert!(predictor.predictions.is_empty());
    }
}
