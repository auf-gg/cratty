use alacritty_terminal::term::TermMode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    Char(char),
    Enter,
    Tab,
    Backspace,
    Escape,
    Delete,
    Insert,
    Up,
    Down,
    Right,
    Left,
    Home,
    End,
    PageUp,
    PageDown,
    Function(u8),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Mods {
    pub ctrl: bool,
    pub alt: bool,
    pub shift: bool,
}

impl Mods {
    pub const NONE: Self = Self {
        ctrl: false,
        alt: false,
        shift: false,
    };

    pub const fn ctrl() -> Self {
        Self {
            ctrl: true,
            alt: false,
            shift: false,
        }
    }

    pub const fn alt() -> Self {
        Self {
            ctrl: false,
            alt: true,
            shift: false,
        }
    }

    pub const fn shift() -> Self {
        Self {
            ctrl: false,
            alt: false,
            shift: true,
        }
    }

    fn any(self) -> bool {
        self.ctrl || self.alt || self.shift
    }

    fn csi_param(self) -> u8 {
        1 + u8::from(self.shift) + 2 * u8::from(self.alt) + 4 * u8::from(self.ctrl)
    }
}

const ESC: u8 = 0x1b;

pub fn encode(key: Key, mods: Mods, mode: TermMode) -> Option<Vec<u8>> {
    match key {
        Key::Char(character) => char_bytes(character, mods),

        Key::Enter => {
            let base: &[u8] = if mode.contains(TermMode::LINE_FEED_NEW_LINE) {
                b"\r\n"
            } else {
                b"\r"
            };
            Some(with_alt(base, mods))
        }

        Key::Tab if mods.shift => Some(b"\x1b[Z".to_vec()),
        Key::Tab => Some(with_alt(b"\t", mods)),

        Key::Backspace if mods.ctrl => Some(with_alt(b"\x08", mods)),
        Key::Backspace => Some(with_alt(b"\x7f", mods)),

        Key::Escape => Some(with_alt(b"\x1b", mods)),

        Key::Up | Key::Down | Key::Right | Key::Left | Key::Home | Key::End => {
            Some(cursor_key(key, mods, mode))
        }

        Key::Insert => Some(tilde_key(2, mods)),
        Key::Delete => Some(tilde_key(3, mods)),
        Key::PageUp => Some(tilde_key(5, mods)),
        Key::PageDown => Some(tilde_key(6, mods)),

        Key::Function(number) => function_key(number, mods),
    }
}

fn char_bytes(character: char, mods: Mods) -> Option<Vec<u8>> {
    let mut bytes = if mods.ctrl {
        vec![control_code(character)?]
    } else {
        let mut buffer = [0u8; 4];
        character.encode_utf8(&mut buffer).as_bytes().to_vec()
    };

    if mods.alt {
        bytes.insert(0, ESC);
    }
    Some(bytes)
}

fn control_code(character: char) -> Option<u8> {
    let code = match character.to_ascii_lowercase() {
        letter @ 'a'..='z' => letter as u8 - b'a' + 1,
        ' ' | '@' | '2' => 0x00,
        '[' | '3' => 0x1b,
        '\\' | '4' => 0x1c,
        ']' | '5' => 0x1d,
        '^' | '6' => 0x1e,
        '_' | '7' | '/' => 0x1f,
        '?' | '8' => 0x7f,
        _ => return None,
    };
    Some(code)
}

fn with_alt(base: &[u8], mods: Mods) -> Vec<u8> {
    if mods.alt {
        let mut bytes = Vec::with_capacity(base.len() + 1);
        bytes.push(ESC);
        bytes.extend_from_slice(base);
        bytes
    } else {
        base.to_vec()
    }
}

fn cursor_key(key: Key, mods: Mods, mode: TermMode) -> Vec<u8> {
    let final_byte = match key {
        Key::Up => b'A',
        Key::Down => b'B',
        Key::Right => b'C',
        Key::Left => b'D',
        Key::Home => b'H',
        Key::End => b'F',
        _ => unreachable!("cursor_key вызывают только для стрелок, Home и End"),
    };

    if mods.any() {
        return format!("\x1b[1;{}{}", mods.csi_param(), final_byte as char).into_bytes();
    }

    if mode.contains(TermMode::APP_CURSOR) {
        vec![ESC, b'O', final_byte]
    } else {
        vec![ESC, b'[', final_byte]
    }
}

fn tilde_key(number: u8, mods: Mods) -> Vec<u8> {
    if mods.any() {
        format!("\x1b[{number};{}~", mods.csi_param()).into_bytes()
    } else {
        format!("\x1b[{number}~").into_bytes()
    }
}

fn function_key(number: u8, mods: Mods) -> Option<Vec<u8>> {
    if (1..=4).contains(&number) {
        let final_byte = b'P' + (number - 1);
        return Some(if mods.any() {
            format!("\x1b[1;{}{}", mods.csi_param(), final_byte as char).into_bytes()
        } else {
            vec![ESC, b'O', final_byte]
        });
    }

    let code = match number {
        5 => 15,
        6 => 17,
        7 => 18,
        8 => 19,
        9 => 20,
        10 => 21,
        11 => 23,
        12 => 24,
        13 => 25,
        14 => 26,
        15 => 28,
        16 => 29,
        17 => 31,
        18 => 32,
        19 => 33,
        20 => 34,
        _ => return None,
    };
    Some(tilde_key(code, mods))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(key: Key) -> Vec<u8> {
        encode(key, Mods::NONE, TermMode::empty()).expect("клавиша должна что-то слать")
    }

    fn app(key: Key) -> Vec<u8> {
        encode(key, Mods::NONE, TermMode::APP_CURSOR).expect("клавиша должна что-то слать")
    }

    fn with(key: Key, mods: Mods) -> Vec<u8> {
        encode(key, mods, TermMode::empty()).expect("клавиша должна что-то слать")
    }

    #[test]
    fn letters_go_as_utf8() {
        assert_eq!(plain(Key::Char('a')), b"a");
        assert_eq!(plain(Key::Char('ж')), "ж".as_bytes());
        assert_eq!(plain(Key::Char('😀')), "😀".as_bytes());
    }

    #[test]
    fn ctrl_letters_map_to_control_codes() {
        assert_eq!(with(Key::Char('a'), Mods::ctrl()), vec![0x01]);
        assert_eq!(with(Key::Char('c'), Mods::ctrl()), vec![0x03]);
        assert_eq!(with(Key::Char('C'), Mods::ctrl()), vec![0x03]);
        assert_eq!(with(Key::Char('z'), Mods::ctrl()), vec![0x1a]);
        assert_eq!(with(Key::Char('d'), Mods::ctrl()), vec![0x04]);
    }

    #[test]
    fn ctrl_punctuation_follows_the_xterm_table() {
        assert_eq!(with(Key::Char(' '), Mods::ctrl()), vec![0x00]);
        assert_eq!(with(Key::Char('['), Mods::ctrl()), vec![0x1b]);
        assert_eq!(with(Key::Char('\\'), Mods::ctrl()), vec![0x1c]);
        assert_eq!(with(Key::Char(']'), Mods::ctrl()), vec![0x1d]);
        assert_eq!(with(Key::Char('_'), Mods::ctrl()), vec![0x1f]);
        assert_eq!(with(Key::Char('?'), Mods::ctrl()), vec![0x7f]);
    }

    #[test]
    fn ctrl_with_a_key_without_a_control_code_sends_nothing() {
        assert_eq!(
            encode(Key::Char('ж'), Mods::ctrl(), TermMode::empty()),
            None
        );
    }

    #[test]
    fn alt_is_an_escape_prefix() {
        assert_eq!(with(Key::Char('b'), Mods::alt()), vec![ESC, b'b']);
        let ctrl_alt = Mods {
            ctrl: true,
            alt: true,
            shift: false,
        };
        assert_eq!(with(Key::Char('c'), ctrl_alt), vec![ESC, 0x03]);
    }

    #[test]
    fn enter_sends_carriage_return_and_respects_lnm() {
        assert_eq!(plain(Key::Enter), b"\r");
        assert_eq!(
            encode(Key::Enter, Mods::NONE, TermMode::LINE_FEED_NEW_LINE).expect("шлёт"),
            b"\r\n"
        );
        assert_eq!(with(Key::Enter, Mods::alt()), vec![ESC, b'\r']);
    }

    #[test]
    fn backspace_sends_del_and_ctrl_makes_it_bs() {
        assert_eq!(plain(Key::Backspace), vec![0x7f]);
        assert_eq!(with(Key::Backspace, Mods::ctrl()), vec![0x08]);
        assert_eq!(with(Key::Backspace, Mods::alt()), vec![ESC, 0x7f]);
    }

    #[test]
    fn tab_and_shift_tab_differ() {
        assert_eq!(plain(Key::Tab), b"\t");
        assert_eq!(with(Key::Tab, Mods::shift()), b"\x1b[Z");
    }

    #[test]
    fn escape_passes_through() {
        assert_eq!(plain(Key::Escape), vec![ESC]);
        assert_eq!(with(Key::Escape, Mods::alt()), vec![ESC, ESC]);
    }

    #[test]
    fn arrows_switch_form_with_app_cursor_mode() {
        assert_eq!(plain(Key::Up), b"\x1b[A");
        assert_eq!(plain(Key::Down), b"\x1b[B");
        assert_eq!(plain(Key::Right), b"\x1b[C");
        assert_eq!(plain(Key::Left), b"\x1b[D");

        assert_eq!(app(Key::Up), b"\x1bOA");
        assert_eq!(app(Key::Left), b"\x1bOD");
    }

    #[test]
    fn modified_arrows_always_use_the_csi_form() {
        assert_eq!(with(Key::Right, Mods::ctrl()), b"\x1b[1;5C");
        assert_eq!(with(Key::Left, Mods::shift()), b"\x1b[1;2D");
        assert_eq!(with(Key::Up, Mods::alt()), b"\x1b[1;3A");

        assert_eq!(
            encode(Key::Right, Mods::ctrl(), TermMode::APP_CURSOR).expect("шлёт"),
            b"\x1b[1;5C"
        );
    }

    #[test]
    fn modifier_parameter_matches_the_xterm_formula() {
        let all = Mods {
            ctrl: true,
            alt: true,
            shift: true,
        };
        assert_eq!(with(Key::Up, all), b"\x1b[1;8A");
    }

    #[test]
    fn home_and_end_behave_like_arrows() {
        assert_eq!(plain(Key::Home), b"\x1b[H");
        assert_eq!(plain(Key::End), b"\x1b[F");
        assert_eq!(app(Key::Home), b"\x1bOH");
        assert_eq!(with(Key::End, Mods::ctrl()), b"\x1b[1;5F");
    }

    #[test]
    fn navigation_keys_use_the_tilde_form() {
        assert_eq!(plain(Key::Insert), b"\x1b[2~");
        assert_eq!(plain(Key::Delete), b"\x1b[3~");
        assert_eq!(plain(Key::PageUp), b"\x1b[5~");
        assert_eq!(plain(Key::PageDown), b"\x1b[6~");
        assert_eq!(with(Key::PageUp, Mods::ctrl()), b"\x1b[5;5~");
    }

    #[test]
    fn f1_to_f4_are_ss3_but_switch_to_csi_when_modified() {
        assert_eq!(plain(Key::Function(1)), b"\x1bOP");
        assert_eq!(plain(Key::Function(4)), b"\x1bOS");
        assert_eq!(with(Key::Function(1), Mods::shift()), b"\x1b[1;2P");
    }

    #[test]
    fn f5_and_above_use_the_historical_numbering() {
        assert_eq!(plain(Key::Function(5)), b"\x1b[15~");
        assert_eq!(plain(Key::Function(6)), b"\x1b[17~");
        assert_eq!(plain(Key::Function(11)), b"\x1b[23~");
        assert_eq!(plain(Key::Function(12)), b"\x1b[24~");
        assert_eq!(with(Key::Function(5), Mods::ctrl()), b"\x1b[15;5~");
    }

    #[test]
    fn function_keys_beyond_the_table_send_nothing() {
        assert_eq!(
            encode(Key::Function(21), Mods::NONE, TermMode::empty()),
            None
        );
        assert_eq!(
            encode(Key::Function(0), Mods::NONE, TermMode::empty()),
            None
        );
    }
}
