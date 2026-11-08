use alacritty_terminal::term::color::Colors;
use alacritty_terminal::vte::ansi::{Color, NamedColor};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Rgb {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Rgb {
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }

    const fn from_hex(hex: u32) -> Self {
        Self::new(
            ((hex >> 16) & 0xff) as u8,
            ((hex >> 8) & 0xff) as u8,
            (hex & 0xff) as u8,
        )
    }

    pub const fn to_hex(self) -> u32 {
        ((self.r as u32) << 16) | ((self.g as u32) << 8) | self.b as u32
    }

    fn dimmed(self) -> Self {
        Self::new(
            (self.r as u16 * 2 / 3) as u8,
            (self.g as u16 * 2 / 3) as u8,
            (self.b as u16 * 2 / 3) as u8,
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Palette {
    pub foreground: Rgb,
    pub background: Rgb,
    pub cursor: Rgb,
    ansi: [Rgb; 16],
}

pub const DEFAULT: Palette = Palette {
    foreground: Rgb::from_hex(0xc0caf5),
    background: Rgb::from_hex(0x1a1b26),
    cursor: Rgb::from_hex(0xc0caf5),
    ansi: [
        Rgb::from_hex(0x15161e),
        Rgb::from_hex(0xf7768e),
        Rgb::from_hex(0x9ece6a),
        Rgb::from_hex(0xe0af68),
        Rgb::from_hex(0x7aa2f7),
        Rgb::from_hex(0xbb9af7),
        Rgb::from_hex(0x7dcfff),
        Rgb::from_hex(0xa9b1d6),
        Rgb::from_hex(0x414868),
        Rgb::from_hex(0xff899d),
        Rgb::from_hex(0x9fe044),
        Rgb::from_hex(0xfaba4a),
        Rgb::from_hex(0x8db0ff),
        Rgb::from_hex(0xc7a9ff),
        Rgb::from_hex(0xa4daff),
        Rgb::from_hex(0xc0caf5),
    ],
};

pub const CRATTY: Palette = Palette {
    foreground: Rgb::from_hex(0xf3ede6),
    background: Rgb::from_hex(0x15110e),
    cursor: Rgb::from_hex(0x7ee787),
    ansi: [
        Rgb::from_hex(0x15110e),
        Rgb::from_hex(0xf85149),
        Rgb::from_hex(0x7ee787),
        Rgb::from_hex(0xe3b341),
        Rgb::from_hex(0x79c0ff),
        Rgb::from_hex(0xe8643a),
        Rgb::from_hex(0x56d4dd),
        Rgb::from_hex(0xa89f96),
        Rgb::from_hex(0x5e554d),
        Rgb::from_hex(0xff7b72),
        Rgb::from_hex(0x9aeda1),
        Rgb::from_hex(0xf2cc60),
        Rgb::from_hex(0xa5d6ff),
        Rgb::from_hex(0xf07a53),
        Rgb::from_hex(0x76e3ea),
        Rgb::from_hex(0xf3ede6),
    ],
};

pub const SYNTHWAVE: Palette = Palette {
    foreground: Rgb::from_hex(0xf4eefc),
    background: Rgb::from_hex(0x262335),
    cursor: Rgb::from_hex(0x03edf9),
    ansi: [
        Rgb::from_hex(0x171520),
        Rgb::from_hex(0xfe4450),
        Rgb::from_hex(0x72f1b8),
        Rgb::from_hex(0xf3e70f),
        Rgb::from_hex(0x03edf9),
        Rgb::from_hex(0xff7edb),
        Rgb::from_hex(0x03edf9),
        Rgb::from_hex(0xf4eefc),
        Rgb::from_hex(0x614d85),
        Rgb::from_hex(0xfe4450),
        Rgb::from_hex(0x72f1b8),
        Rgb::from_hex(0xfede5d),
        Rgb::from_hex(0x03edf9),
        Rgb::from_hex(0xff7edb),
        Rgb::from_hex(0x03edf9),
        Rgb::from_hex(0xffffff),
    ],
};

impl Default for Palette {
    fn default() -> Self {
        DEFAULT
    }
}

impl Palette {
    pub const fn new(foreground: Rgb, background: Rgb, cursor: Rgb, ansi: [Rgb; 16]) -> Self {
        Self {
            foreground,
            background,
            cursor,
            ansi,
        }
    }

    pub fn themed(self, background: Rgb, foreground: Rgb, cursor: Rgb) -> Self {
        Self {
            foreground,
            background,
            cursor,
            ..self
        }
    }

    pub fn indexed(&self, index: u8) -> Rgb {
        match index {
            0..=15 => self.ansi[index as usize],
            16..=231 => {
                let index = index as u16 - 16;
                let level = |value: u16| -> u8 {
                    if value == 0 {
                        0
                    } else {
                        (value * 40 + 55) as u8
                    }
                };
                Rgb::new(level(index / 36), level((index / 6) % 6), level(index % 6))
            }
            232..=255 => {
                let value = 8 + (index as u16 - 232) * 10;
                Rgb::new(value as u8, value as u8, value as u8)
            }
        }
    }

    pub fn resolve(&self, color: Color, overrides: &Colors) -> Rgb {
        match color {
            Color::Spec(rgb) => Rgb::new(rgb.r, rgb.g, rgb.b),
            Color::Indexed(index) => overrides[index as usize]
                .map(|rgb| Rgb::new(rgb.r, rgb.g, rgb.b))
                .unwrap_or_else(|| self.indexed(index)),
            Color::Named(named) => overrides[named]
                .map(|rgb| Rgb::new(rgb.r, rgb.g, rgb.b))
                .unwrap_or_else(|| self.named(named)),
        }
    }

    fn named(&self, color: NamedColor) -> Rgb {
        use NamedColor::*;
        match color {
            Black => self.ansi[0],
            Red => self.ansi[1],
            Green => self.ansi[2],
            Yellow => self.ansi[3],
            Blue => self.ansi[4],
            Magenta => self.ansi[5],
            Cyan => self.ansi[6],
            White => self.ansi[7],
            BrightBlack => self.ansi[8],
            BrightRed => self.ansi[9],
            BrightGreen => self.ansi[10],
            BrightYellow => self.ansi[11],
            BrightBlue => self.ansi[12],
            BrightMagenta => self.ansi[13],
            BrightCyan => self.ansi[14],
            BrightWhite => self.ansi[15],
            Foreground => self.foreground,
            Background => self.background,
            Cursor => self.cursor,
            BrightForeground => self.foreground,
            DimForeground => self.foreground.dimmed(),
            DimBlack => self.ansi[0].dimmed(),
            DimRed => self.ansi[1].dimmed(),
            DimGreen => self.ansi[2].dimmed(),
            DimYellow => self.ansi[3].dimmed(),
            DimBlue => self.ansi[4].dimmed(),
            DimMagenta => self.ansi[5].dimmed(),
            DimCyan => self.ansi[6].dimmed(),
            DimWhite => self.ansi[7].dimmed(),
        }
    }

    pub fn dim(&self, color: Rgb) -> Rgb {
        let _ = self;
        color.dimmed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cube_corners_match_xterm() {
        assert_eq!(DEFAULT.indexed(16), Rgb::new(0, 0, 0));
        assert_eq!(DEFAULT.indexed(231), Rgb::new(255, 255, 255));
        assert_eq!(DEFAULT.indexed(21), Rgb::new(0, 0, 255));
        assert_eq!(DEFAULT.indexed(196), Rgb::new(255, 0, 0));
    }

    #[test]
    fn grayscale_ramp_matches_xterm() {
        assert_eq!(DEFAULT.indexed(232), Rgb::new(8, 8, 8));
        assert_eq!(DEFAULT.indexed(255), Rgb::new(238, 238, 238));
    }

    #[test]
    fn first_sixteen_indices_are_the_ansi_colors() {
        for index in 0..16u8 {
            assert_eq!(DEFAULT.indexed(index), DEFAULT.ansi[index as usize]);
        }
    }

    #[test]
    fn osc_override_wins_over_the_scheme() {
        let mut overrides = Colors::default();
        overrides[1usize] = Some(alacritty_terminal::vte::ansi::Rgb { r: 1, g: 2, b: 3 });
        assert_eq!(
            DEFAULT.resolve(Color::Indexed(1), &overrides),
            Rgb::new(1, 2, 3)
        );
        assert_eq!(
            DEFAULT.resolve(Color::Indexed(2), &overrides),
            DEFAULT.indexed(2)
        );
    }
}
