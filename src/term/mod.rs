pub mod keys;
pub mod links;
pub mod mouse;
pub mod palette;
pub mod predict;

use rust_i18n::t;
use alacritty_terminal::Term;
use alacritty_terminal::event::{Event, EventListener, WindowSize};
use alacritty_terminal::grid::Dimensions;
use alacritty_terminal::index::Point;
use alacritty_terminal::term::cell::Flags;
use alacritty_terminal::term::{Config, TermMode};
use alacritty_terminal::vte::ansi::{CursorShape, Processor};
use bytes::Bytes;
use futures::channel::mpsc::UnboundedSender;
use std::sync::{Arc, Mutex};

use crate::ssh::{PtySize, ToSsh};
pub use keys::{Key, Mods};
pub use palette::{Palette, Rgb};

const MAX_CLIPBOARD: usize = 1024 * 1024;

const SCROLLBACK: usize = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Style {
    pub fg: Rgb,
    pub bg: Rgb,
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub strikeout: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    pub text: String,
    pub style: Style,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Line {
    pub runs: Vec<Run>,
}

impl Line {
    pub fn text(&self) -> String {
        self.runs.iter().map(|run| run.text.as_str()).collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    pub line: usize,
    pub column: usize,
    pub shape: CursorShape,
}

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub lines: Vec<Line>,
    pub cursor: Option<Cursor>,
    pub columns: usize,
    pub background: Rgb,
    pub display_offset: usize,
}

#[derive(Clone)]
pub struct Responder {
    to_ssh: UnboundedSender<ToSsh>,
    shared: Arc<Shared>,
}

struct Shared {
    title: Mutex<Option<String>>,
    window: Mutex<WindowSize>,
    bell: Mutex<bool>,
    clipboard: Mutex<Option<String>>,
}

impl Default for Shared {
    fn default() -> Self {
        Self {
            title: Mutex::new(None),
            window: Mutex::new(WindowSize {
                num_lines: 24,
                num_cols: 80,
                cell_width: 0,
                cell_height: 0,
            }),
            bell: Mutex::new(false),
            clipboard: Mutex::new(None),
        }
    }
}

impl Responder {
    pub fn new(to_ssh: UnboundedSender<ToSsh>) -> Self {
        Self {
            to_ssh,
            shared: Arc::new(Shared::default()),
        }
    }

    pub fn title(&self) -> Option<String> {
        lock(&self.shared.title).clone()
    }

    pub fn take_bell(&self) -> bool {
        std::mem::take(&mut *lock(&self.shared.bell))
    }

    pub fn take_clipboard(&self) -> Option<String> {
        lock(&self.shared.clipboard).take()
    }

    fn set_window(&self, size: WindowSize) {
        *lock(&self.shared.window) = size;
    }

    fn reply(&self, text: String) {
        let _ = self
            .to_ssh
            .unbounded_send(ToSsh::Input(Bytes::from(text.into_bytes())));
    }
}

impl EventListener for Responder {
    fn send_event(&self, event: Event) {
        match event {
            Event::PtyWrite(text) => self.reply(text),
            Event::TextAreaSizeRequest(format) => {
                let size = *lock(&self.shared.window);
                self.reply(format(size));
            }
            Event::ColorRequest(index, format) => {
                let color = palette::DEFAULT.indexed(index as u8);
                self.reply(format(alacritty_terminal::vte::ansi::Rgb {
                    r: color.r,
                    g: color.g,
                    b: color.b,
                }));
            }
            Event::Title(title) => *lock(&self.shared.title) = Some(title),
            Event::ResetTitle => *lock(&self.shared.title) = None,
            Event::Bell => *lock(&self.shared.bell) = true,
            Event::ClipboardStore(_, text) if text.len() <= MAX_CLIPBOARD => {
                *lock(&self.shared.clipboard) = Some(text);
            }
            _ => {}
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Clone, Copy, Debug)]
struct GridSize {
    columns: usize,
    screen_lines: usize,
}

impl Dimensions for GridSize {
    fn total_lines(&self) -> usize {
        self.screen_lines
    }

    fn screen_lines(&self) -> usize {
        self.screen_lines
    }

    fn columns(&self) -> usize {
        self.columns
    }
}

pub struct Terminal {
    term: Term<Responder>,
    parser: Processor,
    responder: Responder,
    palette: Palette,
    size: PtySize,
    search: Option<Search>,
}

struct Search {
    query: String,
    regex: alacritty_terminal::term::search::RegexSearch,
    last: Option<alacritty_terminal::term::search::Match>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Found {
    pub start: (usize, usize),
    pub end: (usize, usize),
}

fn escape_regex(text: &str) -> String {
    let mut out = String::with_capacity(text.len() * 2);
    for ch in text.chars() {
        if "\\.+*?()|[]{}^$#&-~".contains(ch) {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

impl Terminal {
    pub fn new(size: PtySize, responder: Responder) -> Self {
        let grid = GridSize {
            columns: size.cols as usize,
            screen_lines: size.rows as usize,
        };
        let config = Config {
            scrolling_history: SCROLLBACK,
            osc52: alacritty_terminal::term::Osc52::OnlyCopy,
            ..Default::default()
        };

        responder.set_window(window_size(size));

        Self {
            term: Term::new(config, &grid, responder.clone()),
            parser: Processor::new(),
            responder,
            palette: Palette::default(),
            size,
            search: None,
        }
    }

    pub fn advance(&mut self, bytes: &[u8]) {
        self.parser.advance(&mut self.term, bytes);
    }

    pub fn resize(&mut self, size: PtySize) {
        if size.cols == self.size.cols && size.rows == self.size.rows {
            return;
        }
        self.size = size;
        self.responder.set_window(window_size(size));
        self.term.resize(GridSize {
            columns: size.cols as usize,
            screen_lines: size.rows as usize,
        });
    }

    pub fn size(&self) -> PtySize {
        self.size
    }

    pub fn palette(&self) -> &Palette {
        &self.palette
    }

    pub fn set_palette(&mut self, palette: Palette) {
        self.palette = palette;
    }

    pub fn mode(&self) -> TermMode {
        *self.term.mode()
    }

    pub fn encode_key(&self, key: keys::Key, mods: keys::Mods) -> Option<Vec<u8>> {
        keys::encode(key, mods, self.mode())
    }

    pub fn responder(&self) -> &Responder {
        &self.responder
    }

    pub fn scroll(&mut self, lines: i32) {
        use alacritty_terminal::grid::Scroll;
        self.term.scroll_display(Scroll::Delta(lines));
    }

    pub fn scroll_to_bottom(&mut self) {
        use alacritty_terminal::grid::Scroll;
        self.term.scroll_display(Scroll::Bottom);
    }

    pub fn link_at(&self, row: usize, column: usize) -> Option<String> {
        if row >= self.term.screen_lines() || column >= self.term.columns() {
            return None;
        }
        let offset = self.term.grid().display_offset() as i32;
        let line = alacritty_terminal::index::Line(row as i32 - offset);
        let cells = &self.term.grid()[line];

        if let Some(link) = cells[alacritty_terminal::index::Column(column)].hyperlink() {
            let uri = link.uri().to_string();
            return links::is_openable(&uri).then_some(uri);
        }

        let text: Vec<char> = (0..self.term.columns())
            .map(|c| cells[alacritty_terminal::index::Column(c)].c)
            .collect();
        links::url_at(&text, column)
    }

    pub fn find(&mut self, query: &str, older: bool) -> Result<Option<Found>, String> {
        use alacritty_terminal::index::{Boundary, Direction, Side};
        use alacritty_terminal::term::search::RegexSearch;

        if query.is_empty() {
            self.search = None;
            return Ok(None);
        }
        if self
            .search
            .as_ref()
            .is_none_or(|search| search.query != query)
        {
            let regex = RegexSearch::new(&format!("(?i){}", escape_regex(query)))
                .map_err(|error| t!("term.search_build_failed", error = error).into_owned())?;
            self.search = Some(Search {
                query: query.to_owned(),
                regex,
                last: None,
            });
        }
        let Some(search) = self.search.as_mut() else {
            return Ok(None);
        };

        let direction = if older {
            Direction::Left
        } else {
            Direction::Right
        };
        let origin = match &search.last {
            Some(last) if older => last.start().sub(&self.term, Boundary::None, 1),
            Some(last) => last.start().add(&self.term, Boundary::None, 1),
            None => self.term.grid().cursor.point,
        };

        let Some(found) =
            self.term
                .search_next(&mut search.regex, origin, direction, Side::Left, None)
        else {
            search.last = None;
            return Ok(None);
        };
        search.last = Some(found.clone());

        self.term.scroll_to_point(*found.start());
        let offset = self.term.grid().display_offset() as i32;
        let to_screen = |point: Point| {
            let row = (point.line.0 + offset).max(0) as usize;
            (row, point.column.0)
        };
        Ok(Some(Found {
            start: to_screen(*found.start()),
            end: to_screen(*found.end()),
        }))
    }

    pub fn end_search(&mut self) {
        self.search = None;
    }

    pub fn at_bottom(&self) -> bool {
        self.term.grid().display_offset() == 0
    }

    pub fn screen_lines(&self) -> usize {
        self.term.screen_lines()
    }

    pub fn columns(&self) -> usize {
        self.term.columns()
    }

    pub fn screen_cell(&self, row: usize, column: usize) -> Option<char> {
        if row >= self.term.screen_lines() || column >= self.term.columns() {
            return None;
        }
        let point = Point::new(
            alacritty_terminal::index::Line(row as i32),
            alacritty_terminal::index::Column(column),
        );
        Some(self.term.grid()[point].c)
    }

    pub fn row_is_plain(&self, row: usize) -> bool {
        if row >= self.term.screen_lines() {
            return false;
        }
        let line = &self.term.grid()[alacritty_terminal::index::Line(row as i32)];
        (0..self.term.columns()).all(|column| {
            let cell = &line[alacritty_terminal::index::Column(column)];
            !cell.flags.intersects(
                Flags::WIDE_CHAR | Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER,
            ) && cell.zerowidth().is_none()
        })
    }

    pub fn cursor_point(&self) -> Option<(usize, usize)> {
        if !self.term.mode().contains(TermMode::SHOW_CURSOR) {
            return None;
        }
        let point = self.term.grid().cursor.point;
        let row = usize::try_from(point.line.0).ok()?;
        Some((row, point.column.0))
    }

    pub fn snapshot(&self) -> Snapshot {
        let content = self.term.renderable_content();
        let columns = self.term.columns();
        let screen_lines = self.term.screen_lines();
        let display_offset = content.display_offset;
        let overrides = content.colors;

        let mut lines = vec![Line::default(); screen_lines];

        for indexed in content.display_iter {
            if indexed
                .cell
                .flags
                .intersects(Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER)
            {
                continue;
            }

            let Some(row) = screen_row(indexed.point, display_offset, screen_lines) else {
                continue;
            };

            let style = self.style_of(indexed.cell, overrides);
            let character = if indexed.cell.flags.contains(Flags::HIDDEN) {
                ' '
            } else {
                indexed.cell.c
            };

            let line = &mut lines[row];
            match line.runs.last_mut() {
                Some(run) if run.style == style => run.text.push(character),
                _ => line.runs.push(Run {
                    text: String::from(character),
                    style,
                }),
            }

            if let Some(zerowidth) = indexed.cell.zerowidth()
                && let Some(run) = line.runs.last_mut()
            {
                run.text.extend(zerowidth);
            }
        }

        Snapshot {
            lines,
            cursor: self.cursor(&content.cursor, display_offset, screen_lines),
            columns,
            background: self.palette.resolve(
                alacritty_terminal::vte::ansi::Color::Named(
                    alacritty_terminal::vte::ansi::NamedColor::Background,
                ),
                overrides,
            ),
            display_offset,
        }
    }

    fn cursor(
        &self,
        cursor: &alacritty_terminal::term::RenderableCursor,
        display_offset: usize,
        screen_lines: usize,
    ) -> Option<Cursor> {
        if !self.term.mode().contains(TermMode::SHOW_CURSOR) {
            return None;
        }
        if cursor.shape == CursorShape::Hidden {
            return None;
        }

        let row = screen_row(cursor.point, display_offset, screen_lines)?;
        Some(Cursor {
            line: row,
            column: cursor.point.column.0,
            shape: cursor.shape,
        })
    }

    fn style_of(
        &self,
        cell: &alacritty_terminal::term::cell::Cell,
        overrides: &alacritty_terminal::term::color::Colors,
    ) -> Style {
        let mut fg = self.palette.resolve(cell.fg, overrides);
        let mut bg = self.palette.resolve(cell.bg, overrides);

        if cell.flags.contains(Flags::DIM) {
            fg = self.palette.dim(fg);
        }
        if cell.flags.contains(Flags::INVERSE) {
            std::mem::swap(&mut fg, &mut bg);
        }

        Style {
            fg,
            bg,
            bold: cell.flags.contains(Flags::BOLD),
            italic: cell.flags.contains(Flags::ITALIC),
            underline: cell.flags.intersects(Flags::ALL_UNDERLINES),
            strikeout: cell.flags.contains(Flags::STRIKEOUT),
        }
    }
}

fn screen_row(point: Point, display_offset: usize, screen_lines: usize) -> Option<usize> {
    let row = point.line.0 + display_offset as i32;
    if row < 0 || row as usize >= screen_lines {
        return None;
    }
    Some(row as usize)
}

fn window_size(size: PtySize) -> WindowSize {
    WindowSize {
        num_lines: size.rows,
        num_cols: size.cols,
        cell_width: size.pixel_width / size.cols.max(1),
        cell_height: size.pixel_height / size.rows.max(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use futures::channel::mpsc;

    fn terminal(cols: u16, rows: u16) -> (Terminal, mpsc::UnboundedReceiver<ToSsh>) {
        let (tx, rx) = mpsc::unbounded();
        (
            Terminal::new(PtySize::new(cols, rows), Responder::new(tx)),
            rx,
        )
    }

    #[test]
    fn osc8_link_with_text() {
        let (mut term, _rx) = terminal(60, 5);
        term.advance(
            b"\x1b]8;;https://example.com/docs\x07docs\x1b]8;;\x07 and http://plain.org\r\n",
        );
        assert_eq!(
            term.link_at(0, 1).as_deref(),
            Some("https://example.com/docs")
        );
        assert_eq!(term.link_at(0, 12).as_deref(), Some("http://plain.org"));
        assert_eq!(term.link_at(0, 6), None);

        term.advance(b"\x1b]8;;file:///etc/passwd\x07readme\x1b]8;;\x07");
        assert_eq!(term.link_at(1, 2), None);
    }

    #[test]
    fn osc52_copies_but_does_not_read() {
        let (mut term, mut rx) = terminal(40, 5);
        term.advance(b"\x1b]52;c;aMOpbGxv\x07");
        assert_eq!(term.responder().take_clipboard().as_deref(), Some("héllo"));

        term.advance(b"\x1b]52;c;?\x07");
        assert!(rx.try_recv().is_err(), "the terminal replied with the clipboard contents");
    }

    #[test]
    fn search_through_history() {
        let (mut term, _rx) = terminal(40, 5);
        for index in 0..30 {
            term.advance(format!("line {index}\r\n").as_bytes());
        }
        term.advance(b"needle one\r\n");
        for index in 30..60 {
            term.advance(format!("line {index}\r\n").as_bytes());
        }
        term.advance(b"NEEDLE two\r\n$ ");

        let found = term.find("needle", true).expect("search").expect("found");
        let snapshot = term.snapshot();
        let row = &snapshot.lines[found.start.0];
        assert!(row.text().starts_with("NEEDLE two"), "{:?}", row.text());

        let found = term.find("needle", true).expect("search").expect("found");
        let snapshot = term.snapshot();
        assert!(
            snapshot.display_offset > 0,
            "the screen did not scroll to the match"
        );
        assert!(
            snapshot.lines[found.start.0]
                .text()
                .starts_with("needle one")
        );
        assert_eq!(found.end.1 - found.start.1, 5);

        assert_eq!(term.find("line (", true).expect("search"), None);
        assert!(term.find("nothing here", true).expect("search").is_none());
    }

    #[test]
    fn program_enables_and_disables_mouse() {
        let (mut term, _rx) = terminal(80, 24);
        let click = mouse::Event {
            button: mouse::Button::Left,
            action: mouse::Action::Press,
            column: 4,
            row: 2,
            mods: mouse::Mods::default(),
        };
        assert_eq!(mouse::encode(term.mode(), &click), None);

        term.advance(b"\x1b[?1000h\x1b[?1006h");
        assert_eq!(
            mouse::encode(term.mode(), &click),
            Some(b"\x1b[<0;5;3M".to_vec())
        );

        term.advance(b"\x1b[?1000l");
        assert_eq!(mouse::encode(term.mode(), &click), None);
    }

    fn lines(term: &Terminal) -> Vec<String> {
        term.snapshot()
            .lines
            .iter()
            .map(|line| line.text().trim_end().to_string())
            .collect()
    }

    #[test]
    fn plain_text_lands_on_the_grid() {
        let (mut term, _rx) = terminal(20, 3);
        term.advance(b"hello\r\nworld");
        assert_eq!(lines(&term), vec!["hello", "world", ""]);
    }

    #[test]
    fn cursor_follows_the_text() {
        let (mut term, _rx) = terminal(20, 3);
        term.advance(b"abc");
        let cursor = term.snapshot().cursor.expect("the cursor should be visible");
        assert_eq!((cursor.line, cursor.column), (0, 3));
    }

    #[test]
    fn civis_hides_the_cursor_and_cnorm_brings_it_back() {
        let (mut term, _rx) = terminal(20, 3);
        term.advance(b"\x1b[?25l");
        assert!(term.snapshot().cursor.is_none());
        term.advance(b"\x1b[?25h");
        assert!(term.snapshot().cursor.is_some());
    }

    #[test]
    fn sgr_colors_split_the_line_into_runs() {
        let (mut term, _rx) = terminal(20, 1);
        term.advance(b"\x1b[01;34mdir\x1b[0m file");

        let snapshot = term.snapshot();
        let runs = &snapshot.lines[0].runs;
        assert_eq!(runs[0].text, "dir");
        assert!(runs[0].style.bold);
        assert_eq!(runs[0].style.fg, palette::DEFAULT.indexed(4));

        assert!(runs[1].text.starts_with(" file"));
        assert!(!runs[1].style.bold);
        assert_eq!(runs[1].style.fg, palette::DEFAULT.foreground);
    }

    #[test]
    fn indexed_256_colors_resolve_through_the_palette() {
        let (mut term, _rx) = terminal(20, 1);
        term.advance(b"\x1b[38;5;196mX");
        let snapshot = term.snapshot();
        assert_eq!(snapshot.lines[0].runs[0].style.fg, Rgb::new(255, 0, 0));
    }

    #[test]
    fn truecolor_resolves_verbatim() {
        let (mut term, _rx) = terminal(20, 1);
        term.advance(b"\x1b[38;2;1;2;3mX");
        let snapshot = term.snapshot();
        assert_eq!(snapshot.lines[0].runs[0].style.fg, Rgb::new(1, 2, 3));
    }

    #[test]
    fn inverse_swaps_foreground_and_background() {
        let (mut term, _rx) = terminal(20, 1);
        term.advance(b"\x1b[7mX");
        let style = term.snapshot().lines[0].runs[0].style;
        assert_eq!(style.fg, palette::DEFAULT.background);
        assert_eq!(style.bg, palette::DEFAULT.foreground);
    }

    #[test]
    fn clear_screen_and_home_wipes_the_grid() {
        let (mut term, _rx) = terminal(10, 3);
        term.advance(b"one\r\ntwo\r\nthree");
        term.advance(b"\x1b[2J\x1b[H");
        assert_eq!(lines(&term), vec!["", "", ""]);
        let cursor = term.snapshot().cursor.expect("cursor visible");
        assert_eq!((cursor.line, cursor.column), (0, 0));
    }

    #[test]
    fn cursor_addressing_puts_text_where_asked() {
        let (mut term, _rx) = terminal(10, 3);
        term.advance(b"\x1b[2;3fX");
        assert_eq!(lines(&term)[1], "  X");
    }

    #[test]
    fn scrolling_past_the_bottom_moves_lines_up() {
        let (mut term, _rx) = terminal(10, 2);
        term.advance(b"one\r\ntwo\r\nthree");
        assert_eq!(lines(&term), vec!["two", "three"]);
    }

    #[test]
    fn wide_chars_do_not_produce_a_phantom_cell() {
        let (mut term, _rx) = terminal(10, 1);
        term.advance("wide→漢字".as_bytes());
        assert_eq!(lines(&term)[0], "wide→漢字");
    }

    #[test]
    fn combining_marks_stay_in_their_cell() {
        let (mut term, _rx) = terminal(10, 1);
        term.advance("e\u{0301}".as_bytes());
        assert_eq!(lines(&term)[0], "e\u{0301}");
    }

    #[test]
    fn alt_screen_is_entered_and_left_without_losing_the_main_grid() {
        let (mut term, _rx) = terminal(10, 2);
        term.advance(b"main");
        term.advance(b"\x1b[?1049h");
        term.advance(b"\x1b[2J\x1b[Halt");
        assert_eq!(lines(&term)[0], "alt");
        term.advance(b"\x1b[?1049l");
        assert_eq!(lines(&term)[0], "main");
    }

    #[test]
    fn resize_reflows_the_grid() {
        let (mut term, _rx) = terminal(10, 3);
        term.advance(b"hello");
        term.resize(PtySize::new(5, 2));
        assert_eq!(term.size().cols, 5);
        assert_eq!(term.snapshot().lines.len(), 2);
    }

    #[tokio::test]
    async fn cursor_position_request_is_answered_to_the_pty() {
        let (mut term, mut rx) = terminal(80, 24);
        term.advance(b"\x1b[3;5H");
        term.advance(b"\x1b[6n");

        let reply = rx.next().await.expect("no reply was sent");
        match reply {
            ToSsh::Input(bytes) => assert_eq!(&bytes[..], b"\x1b[3;5R"),
            other => panic!("expected Input, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn device_attributes_request_is_answered() {
        let (mut term, mut rx) = terminal(80, 24);
        term.advance(b"\x1b[c");

        let reply = rx.next().await.expect("no reply was sent");
        match reply {
            ToSsh::Input(bytes) => assert!(
                bytes.starts_with(b"\x1b[?"),
                "unexpected reply to DA: {:?}",
                String::from_utf8_lossy(&bytes)
            ),
            other => panic!("expected Input, got {other:?}"),
        }
    }

    #[test]
    fn osc_title_reaches_the_responder() {
        let (mut term, _rx) = terminal(20, 1);
        term.advance(b"\x1b]0;h\xc3\xa9llo\x07");
        assert_eq!(term.responder().title().as_deref(), Some("héllo"));
    }

    #[test]
    fn bell_is_recorded_once() {
        let (mut term, _rx) = terminal(20, 1);
        term.advance(b"\x07");
        assert!(term.responder().take_bell());
        assert!(!term.responder().take_bell());
    }

    #[test]
    fn scrollback_is_reachable_and_shifts_the_visible_rows() {
        let (mut term, _rx) = terminal(10, 2);
        term.advance(b"one\r\ntwo\r\nthree");
        assert_eq!(lines(&term), vec!["two", "three"]);

        term.scroll(1);
        assert_eq!(lines(&term), vec!["one", "two"]);
        assert_eq!(term.snapshot().display_offset, 1);
    }
}
