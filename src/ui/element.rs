use gpui_kit::{
    App, Bounds, Element, ElementId, Font, FontStyle, FontWeight, GlobalElementId, Hitbox,
    HitboxBehavior, Hsla, InspectorElementId, IntoElement, LayoutId, Pixels, Point, ShapedLine,
    SharedString, StrikethroughStyle, Style, TextRun, UnderlineStyle, Window, point, px, size,
};

use crate::term::{Rgb, Snapshot, Style as CellStyle};
use crate::ui::terminal::CellMetrics;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selection {
    pub anchor: Cell,
    pub head: Cell,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cell {
    pub row: usize,
    pub column: usize,
}

impl Selection {
    pub fn new(anchor: Cell) -> Self {
        Self {
            anchor,
            head: anchor,
        }
    }

    pub fn ordered(&self) -> (Cell, Cell) {
        if self.anchor <= self.head {
            (self.anchor, self.head)
        } else {
            (self.head, self.anchor)
        }
    }

    pub fn is_empty(&self) -> bool {
        self.anchor == self.head
    }

    fn contains(&self, row: usize, column: usize) -> bool {
        let (start, end) = self.ordered();
        let cell = Cell { row, column };
        cell >= start && cell <= end
    }

    pub fn text(&self, snapshot: &Snapshot) -> String {
        let (start, end) = self.ordered();
        let mut result = String::new();

        for row in start.row..=end.row.min(snapshot.lines.len().saturating_sub(1)) {
            let Some(line) = snapshot.lines.get(row) else {
                break;
            };
            let text: Vec<char> = line.text().chars().collect();

            let from = if row == start.row { start.column } else { 0 };
            let to = if row == end.row {
                (end.column + 1).min(text.len())
            } else {
                text.len()
            };

            if from < to {
                let piece: String = text[from..to].iter().collect();
                result.push_str(piece.trim_end());
            }
            if row < end.row {
                result.push('\n');
            }
        }
        result
    }
}

pub struct TerminalElement {
    snapshot: Snapshot,
    metrics: CellMetrics,
    font: Font,
    font_size: Pixels,
    focused: bool,
    selection: Option<Selection>,
    selection_color: Rgb,
    selection_foreground: Rgb,
    cursor_color: Rgb,
    /// Шрифт значков. Значки рисуются отдельно, вписанными в ячейку: у шрифтов
    /// значков ширина глифа больше ячейки, и в строке они наезжали бы на соседей.
    icons: Option<Font>,
}

/// Значок в ячейке сетки: рисуется поверх строки, на месте пробела.
struct IconCell {
    row: usize,
    column: usize,
    character: char,
    color: Hsla,
    /// За значком пробел: значок можно растянуть на две ячейки, как в kitty.
    wide: bool,
}

impl TerminalElement {
    pub fn new(
        snapshot: Snapshot,
        metrics: CellMetrics,
        font: Font,
        font_size: Pixels,
        focused: bool,
    ) -> Self {
        Self {
            snapshot,
            metrics,
            font,
            font_size,
            focused,
            selection: None,
            selection_color: Rgb::new(0x33, 0x46, 0x7c),
            selection_foreground: Rgb::new(0xff, 0xff, 0xff),
            cursor_color: Rgb::new(0xc0, 0xca, 0xf5),
            icons: None,
        }
    }

    pub fn icons(mut self, icons: Option<Font>) -> Self {
        self.icons = icons;
        self
    }

    pub fn colors(mut self, cursor: Rgb, selection: Rgb, selection_foreground: Rgb) -> Self {
        self.cursor_color = cursor;
        self.selection_color = selection;
        self.selection_foreground = selection_foreground;
        self
    }

    pub fn selection(mut self, selection: Option<Selection>) -> Self {
        self.selection = selection;
        self
    }

    pub fn cell_at(
        metrics: CellMetrics,
        origin: Point<Pixels>,
        position: Point<Pixels>,
        snapshot: &Snapshot,
    ) -> Cell {
        let x = (position.x - origin.x).max(px(0.));
        let y = (position.y - origin.y).max(px(0.));

        let column = (x / metrics.width).floor() as usize;
        let row = (y / metrics.height).floor() as usize;

        Cell {
            row: row.min(snapshot.lines.len().saturating_sub(1)),
            column: column.min(snapshot.columns.saturating_sub(1)),
        }
    }

    fn shape_row(&self, row: usize, window: &Window, icons: &mut Vec<IconCell>) -> ShapedLine {
        let line = &self.snapshot.lines[row];

        let mut text = String::new();
        let mut runs: Vec<TextRun> = Vec::with_capacity(line.runs.len());
        let mut column = 0usize;

        for run in &line.runs {
            for character in run.text.chars() {
                let selected = self
                    .selection
                    .is_some_and(|selection| selection.contains(row, column));

                let start = text.len();
                let width = cell_width(character);
                if self.icons.is_some() && is_icon(character) {
                    // В строке — пробел с тем же фоном, сам значок дорисуем.
                    text.push(' ');
                    let fg = if selected {
                        self.selection_foreground
                    } else {
                        run.style.fg
                    };
                    icons.push(IconCell {
                        row,
                        column,
                        character,
                        color: hsla(fg),
                        wide: false,
                    });
                } else {
                    text.push(character);
                }
                if width == 2 {
                    text.push(' ');
                }
                let len = text.len() - start;

                let style = self.text_run(run.style, selected, len);
                match runs.last_mut() {
                    Some(last) if mergeable(last, &style) => last.len += len,
                    _ => runs.push(style),
                }
                column += width;
            }
        }

        // Значок, за которым пробел, займёт и его ячейку.
        let row_text: Vec<char> = text.chars().collect();
        for icon in icons.iter_mut().filter(|icon| icon.row == row) {
            icon.wide = row_text.get(icon.column + 1) == Some(&' ');
        }

        window.text_system().shape_line(
            SharedString::from(text),
            self.font_size,
            &runs,
            Some(self.metrics.width),
        )
    }

    fn text_run(&self, style: CellStyle, selected: bool, len: usize) -> TextRun {
        let mut font = self.font.clone();
        if style.bold {
            font.weight = FontWeight::BOLD;
        }
        if style.italic {
            font.style = FontStyle::Italic;
        }

        let background = if selected {
            Some(self.selection_color)
        } else if style.bg != self.snapshot.background {
            Some(style.bg)
        } else {
            None
        };

        TextRun {
            len,
            font,
            color: hsla(if selected {
                self.selection_foreground
            } else {
                style.fg
            }),
            background_color: background.map(hsla),
            underline: style.underline.then(|| UnderlineStyle {
                thickness: px(1.),
                color: Some(hsla(style.fg)),
                wavy: false,
            }),
            strikethrough: style.strikeout.then(|| StrikethroughStyle {
                thickness: px(1.),
                color: Some(hsla(style.fg)),
            }),
        }
    }

    fn cursor_bounds(&self, origin: Point<Pixels>) -> Option<Bounds<Pixels>> {
        use alacritty_terminal::vte::ansi::CursorShape;

        let cursor = self.snapshot.cursor?;
        let left = origin.x + self.metrics.width * cursor.column as f32;
        let top = origin.y + self.metrics.height * cursor.line as f32;

        Some(match cursor.shape {
            CursorShape::Beam => Bounds {
                origin: point(left, top),
                size: size(px(2.), self.metrics.height),
            },
            CursorShape::Underline => Bounds {
                origin: point(left, top + self.metrics.height - px(2.)),
                size: size(self.metrics.width, px(2.)),
            },
            _ => Bounds {
                origin: point(left, top),
                size: size(self.metrics.width, self.metrics.height),
            },
        })
    }
}

impl TerminalElement {
    /// Значок, уменьшенный до ширины ячейки и отцентрованный по высоте.
    fn paint_icon(
        &self,
        icon: &IconCell,
        font: &Font,
        cell: Bounds<Pixels>,
        window: &mut Window,
        cx: &mut App,
    ) {
        let text_system = window.text_system().clone();
        let font_id = text_system.resolve_font(font);
        let advance = text_system
            .advance(font_id, self.font_size, icon.character)
            .map(|advance| advance.width)
            .unwrap_or(self.font_size);
        let scale = if advance > px(0.) {
            (cell.size.width / advance).min(1.)
        } else {
            1.
        };
        let size = self.font_size * scale;
        let run = TextRun {
            len: icon.character.len_utf8(),
            font: font.clone(),
            color: icon.color,
            background_color: None,
            underline: None,
            strikethrough: None,
        };
        let shaped = text_system.shape_line(
            SharedString::from(icon.character.to_string()),
            size,
            &[run],
            None,
        );
        let width = shaped.width;
        let origin = point(
            cell.origin.x + (cell.size.width - width).max(px(0.)) / 2.,
            cell.origin.y,
        );
        let _ = shaped.paint(
            origin,
            cell.size.height,
            gpui_kit::TextAlign::default(),
            None,
            window,
            cx,
        );
    }
}

/// Значки Nerd Font живут в областях частного использования Юникода.
fn is_icon(character: char) -> bool {
    matches!(
        character as u32,
        0xE000..=0xF8FF | 0xF0000..=0xFFFFD | 0x100000..=0x10FFFD
    )
}

/// Разделители powerline рисуем фигурами на всю ячейку, как kitty: глифом
/// их не вписать в ячейку без зазоров между цветными сегментами промпта.
fn paint_powerline(
    character: char,
    cell: Bounds<Pixels>,
    color: Hsla,
    window: &mut Window,
) -> bool {
    use gpui_kit::PathBuilder;

    // Чуть шире ячейки, чтобы на стыке с соседним фоном не было щели.
    let overlap = px(0.5);
    let (left, right) = (
        cell.origin.x - overlap,
        cell.origin.x + cell.size.width + overlap,
    );
    let (top, bottom) = (cell.origin.y, cell.origin.y + cell.size.height);
    let middle = cell.origin.y + cell.size.height / 2.;
    let width = cell.size.width;

    let mut builder = match character {
        '\u{e0b0}' | '\u{e0b2}' | '\u{e0b4}' | '\u{e0b6}' => PathBuilder::fill(),
        '\u{e0b1}' | '\u{e0b3}' | '\u{e0b5}' | '\u{e0b7}' => PathBuilder::stroke(px(1.)),
        _ => return false,
    };
    match character {
        // ▶ и тонкая стрелка вправо
        '\u{e0b0}' => {
            builder.move_to(point(left, top));
            builder.line_to(point(right, middle));
            builder.line_to(point(left, bottom));
            builder.close();
        }
        '\u{e0b1}' => {
            builder.move_to(point(cell.origin.x, top));
            builder.line_to(point(cell.origin.x + width, middle));
            builder.line_to(point(cell.origin.x, bottom));
        }
        // ◀ и тонкая стрелка влево
        '\u{e0b2}' => {
            builder.move_to(point(right, top));
            builder.line_to(point(left, middle));
            builder.line_to(point(right, bottom));
            builder.close();
        }
        '\u{e0b3}' => {
            builder.move_to(point(cell.origin.x + width, top));
            builder.line_to(point(cell.origin.x, middle));
            builder.line_to(point(cell.origin.x + width, bottom));
        }
        // Полукруг выпуклостью вправо
        '\u{e0b4}' => {
            builder.move_to(point(left, top));
            builder.curve_to(point(left, bottom), point(right + width, middle));
            builder.close();
        }
        '\u{e0b5}' => {
            builder.move_to(point(cell.origin.x, top));
            builder.curve_to(
                point(cell.origin.x, bottom),
                point(cell.origin.x + width * 2., middle),
            );
        }
        // Полукруг выпуклостью влево
        '\u{e0b6}' => {
            builder.move_to(point(right, top));
            builder.curve_to(point(right, bottom), point(left - width, middle));
            builder.close();
        }
        _ => {
            builder.move_to(point(cell.origin.x + width, top));
            builder.curve_to(
                point(cell.origin.x + width, bottom),
                point(cell.origin.x - width, middle),
            );
        }
    }
    if let Ok(path) = builder.build() {
        window.paint_path(path, color);
    }
    true
}

fn mergeable(last: &TextRun, next: &TextRun) -> bool {
    last.color == next.color
        && last.background_color == next.background_color
        && last.underline == next.underline
        && last.strikethrough == next.strikethrough
        && last.font == next.font
}

fn hsla(rgb: Rgb) -> Hsla {
    gpui_kit::rgb(rgb.to_hex()).into()
}

fn cell_width(character: char) -> usize {
    use unicode_width::UnicodeWidthChar;
    character.width().unwrap_or(0)
}

pub struct Prepainted {
    lines: Vec<ShapedLine>,
    icons: Vec<IconCell>,
    cursor: Option<Bounds<Pixels>>,
    hitbox: Hitbox,
}

impl Prepainted {
    pub fn hitbox(&self) -> &Hitbox {
        &self.hitbox
    }
}

impl IntoElement for TerminalElement {
    type Element = Self;

    fn into_element(self) -> Self::Element {
        self
    }
}

impl Element for TerminalElement {
    type RequestLayoutState = ();
    type PrepaintState = Prepainted;

    fn id(&self) -> Option<ElementId> {
        None
    }

    fn source_location(&self) -> Option<&'static std::panic::Location<'static>> {
        None
    }

    fn request_layout(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&InspectorElementId>,
        window: &mut Window,
        cx: &mut App,
    ) -> (LayoutId, ()) {
        let mut style = Style::default();
        style.size.width = gpui_kit::relative(1.).into();
        style.size.height = gpui_kit::relative(1.).into();
        (window.request_layout(style, [], cx), ())
    }

    fn prepaint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&InspectorElementId>,
        bounds: Bounds<Pixels>,
        _request_layout: &mut (),
        window: &mut Window,
        cx: &mut App,
    ) -> Prepainted {
        let _ = cx;
        let mut icons = Vec::new();
        let lines = (0..self.snapshot.lines.len())
            .map(|row| self.shape_row(row, window, &mut icons))
            .collect();

        Prepainted {
            lines,
            icons,
            cursor: self.cursor_bounds(bounds.origin),
            hitbox: window.insert_hitbox(bounds, HitboxBehavior::Normal),
        }
    }
    fn paint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&InspectorElementId>,
        bounds: Bounds<Pixels>,
        _request_layout: &mut (),
        prepaint: &mut Prepainted,
        window: &mut Window,
        cx: &mut App,
    ) {
        let _ = bounds;

        for (row, shaped) in prepaint.lines.iter().enumerate() {
            let origin = point(
                bounds.origin.x,
                bounds.origin.y + self.metrics.height * row as f32,
            );
            let _ = shaped.paint_background(
                origin,
                self.metrics.height,
                gpui_kit::TextAlign::default(),
                None,
                window,
                cx,
            );
        }

        for (row, shaped) in prepaint.lines.iter().enumerate() {
            let origin = point(
                bounds.origin.x,
                bounds.origin.y + self.metrics.height * row as f32,
            );
            let _ = shaped.paint(
                origin,
                self.metrics.height,
                gpui_kit::TextAlign::default(),
                None,
                window,
                cx,
            );
        }

        if let Some(font) = &self.icons {
            for icon in &prepaint.icons {
                let cell = Bounds {
                    origin: point(
                        bounds.origin.x + self.metrics.width * icon.column as f32,
                        bounds.origin.y + self.metrics.height * icon.row as f32,
                    ),
                    size: size(self.metrics.width, self.metrics.height),
                };
                if !paint_powerline(icon.character, cell, icon.color, window) {
                    let mut area = cell;
                    if icon.wide {
                        area.size.width = self.metrics.width * 2.;
                    }
                    self.paint_icon(icon, font, area, window, cx);
                }
            }
        }

        if let Some(cursor) = prepaint.cursor {
            let color = hsla(self.cursor_color);
            if self.focused {
                window.paint_quad(gpui_kit::fill(cursor, color.opacity(0.6)));
            } else {
                window.paint_quad(gpui_kit::outline(
                    cursor,
                    color,
                    gpui_kit::BorderStyle::Solid,
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::PtySize;
    use crate::term::{Responder, Terminal};

    fn snapshot_of(text: &[u8], cols: u16, rows: u16) -> Snapshot {
        let (tx, _rx) = futures::channel::mpsc::unbounded();
        let mut term = Terminal::new(PtySize::new(cols, rows), Responder::new(tx));
        term.advance(text);
        term.snapshot()
    }

    fn cell(row: usize, column: usize) -> Cell {
        Cell { row, column }
    }

    #[test]
    fn selection_reads_in_order_regardless_of_drag_direction() {
        let snapshot = snapshot_of(b"abcdef", 10, 2);

        let forward = Selection {
            anchor: cell(0, 1),
            head: cell(0, 3),
        };
        let backward = Selection {
            anchor: cell(0, 3),
            head: cell(0, 1),
        };

        assert_eq!(forward.text(&snapshot), "bcd");
        assert_eq!(backward.text(&snapshot), "bcd");
    }

    #[test]
    fn selection_spans_lines_and_drops_trailing_padding() {
        let snapshot = snapshot_of(b"one\r\ntwo\r\nthree", 20, 3);
        let selection = Selection {
            anchor: cell(0, 0),
            head: cell(2, 4),
        };
        assert_eq!(selection.text(&snapshot), "one\ntwo\nthree");
    }

    #[test]
    fn single_cell_selection_takes_that_cell() {
        let snapshot = snapshot_of(b"abc", 10, 1);
        let selection = Selection::new(cell(0, 1));
        assert!(selection.is_empty());
        assert_eq!(selection.text(&snapshot), "b");
    }

    #[test]
    fn selection_beyond_the_grid_is_clamped_not_panicking() {
        let snapshot = snapshot_of(b"abc", 10, 2);
        let selection = Selection {
            anchor: cell(0, 0),
            head: cell(99, 99),
        };
        assert!(selection.text(&snapshot).starts_with("abc"));
    }

    #[test]
    fn cell_at_maps_pixels_to_the_grid_and_clamps_at_the_edges() {
        let snapshot = snapshot_of(b"abc", 10, 4);
        let metrics = CellMetrics::new(px(10.), px(20.));
        let origin = point(px(100.), px(50.));

        assert_eq!(
            TerminalElement::cell_at(metrics, origin, point(px(125.), px(95.)), &snapshot),
            cell(2, 2)
        );
        assert_eq!(
            TerminalElement::cell_at(metrics, origin, point(px(0.), px(0.)), &snapshot),
            cell(0, 0)
        );
        assert_eq!(
            TerminalElement::cell_at(metrics, origin, point(px(9999.), px(9999.)), &snapshot),
            cell(3, 9)
        );
    }
}
