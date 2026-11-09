use alacritty_terminal::term::TermMode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Button {
    Left,
    Middle,
    Right,
    None,
    WheelUp,
    WheelDown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Press,
    Release,
    Motion,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Mods {
    pub shift: bool,
    pub alt: bool,
    pub ctrl: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub button: Button,
    pub action: Action,
    pub column: usize,
    pub row: usize,
    pub mods: Mods,
}

pub fn wants(mode: TermMode, event: &Event) -> bool {
    if !mode.intersects(TermMode::MOUSE_MODE) || event.mods.shift {
        return false;
    }
    match event.action {
        Action::Press | Action::Release => true,
        Action::Motion => match event.button {
            Button::None => mode.contains(TermMode::MOUSE_MOTION),
            _ => mode.intersects(TermMode::MOUSE_DRAG | TermMode::MOUSE_MOTION),
        },
    }
}

pub fn encode(mode: TermMode, event: &Event) -> Option<Vec<u8>> {
    if !wants(mode, event) {
        return None;
    }

    let base: u32 = match event.button {
        Button::Left => 0,
        Button::Middle => 1,
        Button::Right => 2,
        Button::None => 3,
        Button::WheelUp => 64,
        Button::WheelDown => 65,
    };
    let mut code = base;
    if event.action == Action::Motion {
        code += 32;
    }
    if event.mods.alt {
        code += 8;
    }
    if event.mods.ctrl {
        code += 16;
    }

    let column = u32::try_from(event.column).ok()?.checked_add(1)?;
    let row = u32::try_from(event.row).ok()?.checked_add(1)?;

    if mode.contains(TermMode::SGR_MOUSE) {
        let end = if event.action == Action::Release {
            'm'
        } else {
            'M'
        };
        return Some(format!("\x1b[<{code};{column};{row}{end}").into_bytes());
    }

    if event.action == Action::Release {
        if matches!(event.button, Button::WheelUp | Button::WheelDown) {
            return None;
        }
        code = 3 + (code & !3);
    }

    let mut out = b"\x1b[M".to_vec();
    if mode.contains(TermMode::UTF8_MOUSE) {
        for value in [code, column, row] {
            let ch = char::from_u32(value.checked_add(32)?).filter(|_| value <= 2015)?;
            let mut buf = [0u8; 4];
            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        }
    } else {
        for value in [code, column, row] {
            let byte = u8::try_from(value.checked_add(32)?).ok()?;
            out.push(byte);
        }
    }
    Some(out)
}

pub fn wheel_as_arrows(mode: TermMode, up: bool, lines: usize) -> Option<Vec<u8>> {
    if mode.intersects(TermMode::MOUSE_MODE)
        || !mode.contains(TermMode::ALT_SCREEN | TermMode::ALTERNATE_SCROLL)
        || lines == 0
    {
        return None;
    }
    let arrow: &[u8] = match (up, mode.contains(TermMode::APP_CURSOR)) {
        (true, true) => b"\x1bOA",
        (true, false) => b"\x1b[A",
        (false, true) => b"\x1bOB",
        (false, false) => b"\x1b[B",
    };
    Some(arrow.repeat(lines))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(button: Button, column: usize, row: usize) -> Event {
        Event {
            button,
            action: Action::Press,
            column,
            row,
            mods: Mods::default(),
        }
    }

    const CLICK: TermMode = TermMode::MOUSE_REPORT_CLICK;

    fn sgr() -> TermMode {
        TermMode::MOUSE_REPORT_CLICK | TermMode::SGR_MOUSE
    }

    #[test]
    fn without_mode_program_gets_no_mouse() {
        assert_eq!(encode(TermMode::empty(), &press(Button::Left, 0, 0)), None);
    }

    #[test]
    fn shift_leaves_selection_to_the_terminal() {
        let mut event = press(Button::Left, 3, 4);
        event.mods.shift = true;
        assert_eq!(encode(sgr(), &event), None);
    }

    #[test]
    fn sgr_press_and_release() {
        assert_eq!(
            encode(sgr(), &press(Button::Left, 9, 4)),
            Some(b"\x1b[<0;10;5M".to_vec())
        );
        let release = Event {
            action: Action::Release,
            ..press(Button::Right, 0, 0)
        };
        assert_eq!(encode(sgr(), &release), Some(b"\x1b[<2;1;1m".to_vec()));
    }

    #[test]
    fn sgr_reaches_far_columns() {
        assert_eq!(
            encode(sgr(), &press(Button::Left, 499, 0)),
            Some(b"\x1b[<0;500;1M".to_vec())
        );
    }

    #[test]
    fn classic_encoding() {
        assert_eq!(
            encode(CLICK, &press(Button::Left, 9, 4)),
            Some(vec![0x1b, b'[', b'M', 32, 42, 37])
        );
        let release = Event {
            action: Action::Release,
            ..press(Button::Right, 0, 0)
        };
        assert_eq!(
            encode(CLICK, &release),
            Some(vec![0x1b, b'[', b'M', 35, 33, 33])
        );
    }

    #[test]
    fn classic_stays_silent_beyond_the_limit() {
        assert_eq!(encode(CLICK, &press(Button::Left, 223, 0)), None);
        assert!(encode(CLICK, &press(Button::Left, 222, 0)).is_some());
    }

    #[test]
    fn utf8_encodes_far_columns_as_characters() {
        let mode = CLICK | TermMode::UTF8_MOUSE;
        let bytes = encode(mode, &press(Button::Left, 299, 0)).expect("report");
        let mut expected = b"\x1b[M".to_vec();
        expected.push(32);
        expected.extend_from_slice('\u{14c}'.to_string().as_bytes());
        expected.push(33);
        assert_eq!(bytes, expected);
    }

    #[test]
    fn modifiers_and_wheel() {
        let mut event = press(Button::WheelUp, 0, 0);
        event.mods.ctrl = true;
        assert_eq!(encode(sgr(), &event), Some(b"\x1b[<80;1;1M".to_vec()));
        event.mods = Mods {
            alt: true,
            ..Mods::default()
        };
        event.button = Button::WheelDown;
        assert_eq!(encode(sgr(), &event), Some(b"\x1b[<73;1;1M".to_vec()));
    }

    #[test]
    fn dragging_only_when_requested() {
        let drag = Event {
            action: Action::Motion,
            ..press(Button::Left, 1, 1)
        };
        assert_eq!(encode(sgr(), &drag), None, "?1000 does not ask for drags");

        let mode = sgr() | TermMode::MOUSE_DRAG;
        assert_eq!(encode(mode, &drag), Some(b"\x1b[<32;2;2M".to_vec()));

        let hover = Event {
            button: Button::None,
            ..drag
        };
        assert_eq!(encode(mode, &hover), None);
        let all = sgr() | TermMode::MOUSE_MOTION;
        assert_eq!(encode(all, &hover), Some(b"\x1b[<35;2;2M".to_vec()));
    }

    #[test]
    fn wheel_in_less_turns_into_arrows() {
        let mode = TermMode::ALT_SCREEN | TermMode::ALTERNATE_SCROLL;
        assert_eq!(
            wheel_as_arrows(mode, true, 3),
            Some(b"\x1b[A\x1b[A\x1b[A".to_vec())
        );
        assert_eq!(
            wheel_as_arrows(mode | TermMode::APP_CURSOR, false, 1),
            Some(b"\x1bOB".to_vec())
        );
        assert_eq!(wheel_as_arrows(TermMode::ALTERNATE_SCROLL, true, 1), None);
        assert_eq!(wheel_as_arrows(mode | CLICK, true, 1), None);
    }
}
