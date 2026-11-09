// На Windows релизная сборка — GUI-приложение без окна консоли.
// В debug консоль остаётся, чтобы видеть eprintln и паники.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use cratty::ui;
use gpui_kit::App;

fn main() {
    gpui_kit::application()
        .with_assets(ui::assets::Assets)
        .run(|cx: &mut App| {
            if let Err(err) = ui::open_main_window(cx) {
                eprintln!("не удалось открыть окно: {err:#}");
                cx.quit();
                return;
            }
            cx.activate(true);
        });
}
