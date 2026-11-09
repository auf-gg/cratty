use std::hint::black_box;
use std::time::{Duration, Instant};

use cratty::ssh::PtySize;
use cratty::term::{Responder, Snapshot, Terminal};
use cratty::ui::element::TerminalElement;
use cratty::ui::terminal::{CellMetrics, FONT_SIZE, LINE_HEIGHT, grid_element};
use gpui_kit::{
    AvailableSpace, TestAppContext, VisualTestContext, div, point, prelude::*, px, size,
};

const GRID: PtySize = PtySize {
    cols: 200,
    rows: 50,
    pixel_width: 1600,
    pixel_height: 800,
};

const PARSER_BYTES: usize = 32 * 1024 * 1024;

const CHUNK: usize = 32 * 1024;

fn main() {
    println!("grid {}×{}\n", GRID.cols, GRID.rows);

    let parser = bench_parser();

    let typical = cat_like_data(256 * 1024);
    let busy = busy_screen();

    let snapshot_typical = bench_snapshot("cat output", &typical);
    let snapshot_busy = bench_snapshot("colorful screen", &busy);
    let frame_typical = bench_frame("cat output", &typical);
    let frame_busy = bench_frame("colorful screen", &busy);
    let element_typical = bench_element("cat output", &typical);
    let element_busy = bench_element("colorful screen", &busy);

    println!("\n{:-<62}", "");
    println!("{:<34}{:>26}", "parser (byte stream)", parser.summary());
    println!(
        "{:<34}{:>26}",
        "snapshot — cat output",
        snapshot_typical.summary()
    );
    println!(
        "{:<34}{:>26}",
        "snapshot — colorful screen",
        snapshot_busy.summary()
    );
    println!(
        "{:<34}{:>26}",
        "tree — cat output",
        frame_typical.summary()
    );
    println!(
        "{:<34}{:>26}",
        "tree — colorful screen",
        frame_busy.summary()
    );
    println!(
        "{:<34}{:>26}",
        "Element — cat output",
        element_typical.summary()
    );
    println!(
        "{:<34}{:>26}",
        "Element — colorful screen",
        element_busy.summary()
    );
    println!("{:-<62}", "");
    println!(
        "\nthe element tree is measured on the test platform's NoopTextSystem:\n\
         this is the layout and element overhead, without shaping."
    );
}

struct Measurement {
    label: &'static str,
    median: Duration,
    throughput: Option<f64>,
}

impl Measurement {
    fn summary(&self) -> String {
        match self.throughput {
            Some(mb) => format!("{mb:.0} MiB/s"),
            None => format!("{:.3} ms", self.median.as_secs_f64() * 1000.),
        }
    }

    fn report(&self) {
        println!("  {:<28}{}", self.label, self.summary());
    }
}

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn cat_like_data(bytes: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(bytes + 1024);
    let mut line = 0usize;
    while data.len() < bytes {
        line += 1;
        match line % 8 {
            0 => data.extend_from_slice(
                format!("\x1b[1;32m==> section {line}\x1b[0m — heading with non-ASCII\r\n").as_bytes(),
            ),
            3 => data.extend_from_slice(
                format!(
                    "{line:>8}  \x1b[38;5;{}mcolored column\x1b[0m  ",
                    line % 256
                )
                .as_bytes(),
            ),
            5 => data.extend_from_slice(b"\r\n"),
            _ => data.extend_from_slice(
                format!(
                    "{line:>8}  {:width$}\r\n",
                    "lorem ipsum dolor sit amet consectetur",
                    width = 40 + line % 30
                )
                .as_bytes(),
            ),
        }
    }
    data.truncate(bytes);
    data
}

fn busy_screen() -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(b"\x1b[2J\x1b[H");
    for row in 0..GRID.rows as usize {
        for col in 0..GRID.cols as usize {
            let color = (row * 7 + col * 3) % 216 + 16;
            data.extend_from_slice(format!("\x1b[38;5;{color}m#").as_bytes());
        }
        if row + 1 < GRID.rows as usize {
            data.extend_from_slice(b"\r\n");
        }
    }
    data
}

fn terminal() -> Terminal {
    let (tx, rx) = futures::channel::mpsc::unbounded();
    std::mem::forget(rx);
    Terminal::new(GRID, Responder::new(tx))
}

fn bench_parser() -> Measurement {
    println!("parser:");
    let data = cat_like_data(PARSER_BYTES);
    let mut term = terminal();

    for chunk in data.chunks(CHUNK).take(64) {
        term.advance(chunk);
    }

    let start = Instant::now();
    for chunk in data.chunks(CHUNK) {
        term.advance(black_box(chunk));
    }
    let elapsed = start.elapsed();

    let throughput = data.len() as f64 / elapsed.as_secs_f64() / (1024. * 1024.);
    let measurement = Measurement {
        label: "byte stream",
        median: elapsed,
        throughput: Some(throughput),
    };
    println!(
        "  {:<28}{:.2} s per {} MiB",
        "time",
        elapsed.as_secs_f64(),
        data.len() / (1024 * 1024)
    );
    measurement.report();
    measurement
}

fn bench_snapshot(label: &'static str, screen: &[u8]) -> Measurement {
    println!("\ngrid snapshot — {label}:");
    let mut term = terminal();
    term.advance(screen);

    for _ in 0..32 {
        black_box(term.snapshot());
    }

    let samples = (0..200)
        .map(|_| {
            let start = Instant::now();
            black_box(term.snapshot());
            start.elapsed()
        })
        .collect();

    let measurement = Measurement {
        label: "median",
        median: median(samples),
        throughput: None,
    };
    let snapshot = term.snapshot();
    println!(
        "  {:<28}{}",
        "spans per frame",
        snapshot
            .lines
            .iter()
            .map(|line| line.runs.len())
            .sum::<usize>()
    );
    measurement.report();
    measurement
}

fn bench_frame(label: &'static str, screen: &[u8]) -> Measurement {
    println!("\nelement tree — {label}:");

    let mut term = terminal();
    term.advance(screen);
    let snapshot = term.snapshot();
    let elements: usize = snapshot.lines.iter().map(|line| line.runs.len() + 1).sum();

    let mut cx = TestAppContext::single();
    let visual = cx.add_empty_window();

    let metrics = CellMetrics::new(FONT_SIZE * 0.6, FONT_SIZE * LINE_HEIGHT);
    let space = size(
        AvailableSpace::Definite(px(GRID.pixel_width as f32)),
        AvailableSpace::Definite(px(GRID.pixel_height as f32)),
    );

    let draw_once = |visual: &mut VisualTestContext, snapshot: Snapshot| {
        visual.draw(point(px(0.), px(0.)), space, move |_window, _cx| {
            div()
                .size_full()
                .text_size(FONT_SIZE)
                .child(grid_element(&snapshot, metrics))
                .into_any_element()
        });
    };

    for _ in 0..8 {
        draw_once(visual, snapshot.clone());
    }

    let samples = (0..40)
        .map(|_| {
            let copy = snapshot.clone();
            let start = Instant::now();
            draw_once(visual, copy);
            start.elapsed()
        })
        .collect();

    let measurement = Measurement {
        label: "median",
        median: median(samples),
        throughput: None,
    };
    println!("  {:<28}{elements}", "elements per frame");
    measurement.report();
    measurement
}

fn bench_element(label: &'static str, screen: &[u8]) -> Measurement {
    println!("\ncustom Element — {label}:");

    let mut term = terminal();
    term.advance(screen);
    let snapshot = term.snapshot();

    let mut cx = TestAppContext::single();
    let visual = cx.add_empty_window();

    let metrics = CellMetrics::new(FONT_SIZE * 0.6, FONT_SIZE * LINE_HEIGHT);
    let space = size(
        AvailableSpace::Definite(px(GRID.pixel_width as f32)),
        AvailableSpace::Definite(px(GRID.pixel_height as f32)),
    );

    let draw_once = |visual: &mut VisualTestContext, snapshot: Snapshot| {
        visual.draw(point(px(0.), px(0.)), space, move |_window, _cx| {
            TerminalElement::new(
                snapshot,
                metrics,
                gpui_kit::font("monospace"),
                FONT_SIZE,
                true,
            )
            .into_any_element()
        });
    };

    for _ in 0..8 {
        draw_once(visual, snapshot.clone());
    }

    let samples = (0..40)
        .map(|_| {
            let copy = snapshot.clone();
            let start = Instant::now();
            draw_once(visual, copy);
            start.elapsed()
        })
        .collect();

    let measurement = Measurement {
        label: "median",
        median: median(samples),
        throughput: None,
    };
    println!("  {:<28}{}", "elements per frame", 1);
    measurement.report();
    measurement
}
