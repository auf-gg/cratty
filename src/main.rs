use cratty::ui;
use gpui::{App, Application};

fn main() {
    Application::new()
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
