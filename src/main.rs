// On Windows, the release build is a GUI application without a console window.
// In debug builds the console stays so eprintln output and panics are visible.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use cratty::ui;
use gpui_kit::App;

fn main() {
    gpui_kit::application()
        .with_assets(ui::assets::Assets)
        .run(|cx: &mut App| {
            if let Err(err) = ui::open_main_window(cx) {
                eprintln!("failed to open window: {err:#}");
                cx.quit();
                return;
            }
            cx.activate(true);
        });
}
