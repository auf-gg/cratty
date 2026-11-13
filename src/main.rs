// On Windows, the release build is a GUI application without a console window.
// In debug builds the console stays so eprintln output and panics are visible.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use cratty::{instance, ui};
use gpui_kit::App;

fn main() {
    // Only one copy runs: copies would overwrite each other's vault records and settings.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if instance::hand_over(&args) {
        return;
    }
    // Fails quietly when the address cannot be taken: this copy still starts.
    let primary = instance::listen().ok();

    gpui_kit::application()
        .with_assets(ui::assets::Assets)
        .run(move |cx: &mut App| {
            if let Err(err) = ui::open_main_window(primary, cx) {
                eprintln!("failed to open window: {err:#}");
                cx.quit();
                return;
            }
            cx.activate(true);
        });
}
