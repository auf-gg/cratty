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
        }
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

    fn shape_row(&self, row: usize, window: &Window, _cx: &App) -> ShapedLine {
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
                text.push(character);
                let width = cell_width(character);
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
        let lines = (0..self.snapshot.lines.len())
            .map(|row| self.shape_row(row, window, cx))
            .collect();

        Prepainted {
            lines,
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
