//! Окно «Доступно обновление» (только Windows: на Linux обновляет пакетный
//! менеджер).

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use gpui_kit::component::{
    ActiveTheme, Disableable, StyledExt,
    button::{Button, ButtonVariants},
    h_flex,
    label::Label,
    scroll::ScrollableElement,
    v_flex,
};
use gpui_kit::{AnyElement, Context, MouseButton, SharedString, div, prelude::*, px};

use super::AppView;
use crate::update::Release;

/// Как часто проверять новые релизы.
const CHECK_EVERY: Duration = Duration::from_secs(6 * 3600);

#[derive(Default)]
pub(super) struct UpdateState {
    release: Option<Release>,
    /// Окно показано; «Позже» его скрывает до следующей новой версии.
    open: bool,
    installing: bool,
    /// Доли от 0 до 1000.
    progress: Arc<AtomicU32>,
    error: Option<SharedString>,
    _check: Option<gpui_kit::Task<()>>,
}

impl AppView {
    /// Периодически спрашивает GitHub о новом релизе.
    pub(super) fn start_update_checks(&mut self, cx: &mut Context<Self>) {
        if !cfg!(windows) {
            return;
        }
        let task = cx.spawn(async move |this, cx| {
            loop {
                let found = cx
                    .background_executor()
                    .spawn(async move { crate::update::check() })
                    .await;
                let alive = this.update(cx, |this, cx| {
                    if let Ok(Some(release)) = found {
                        let state = &mut this.updater;
                        let known = state
                            .release
                            .as_ref()
                            .is_some_and(|r| r.version == release.version);
                        if !known && !state.installing {
                            state.release = Some(release);
                            state.open = true;
                            state.error = None;
                            cx.notify();
                        }
                    }
                });
                if alive.is_err() {
                    break;
                }
                cx.background_executor().timer(CHECK_EVERY).await;
            }
        });
        self.updater._check = Some(task);
    }

    fn install_update(&mut self, cx: &mut Context<Self>) {
        let Some(release) = self.updater.release.clone() else {
            return;
        };
        if self.updater.installing {
            return;
        }
        self.updater.installing = true;
        self.updater.error = None;
        let progress = self.updater.progress.clone();
        progress.store(0, Ordering::Relaxed);
        let install = cx
            .background_executor()
            .spawn(async move { crate::update::install(&release, &progress) });
        // Перерисовка ради полосы загрузки, пока идёт скачивание.
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(200))
                    .await;
                let going = this.update(cx, |this, cx| {
                    cx.notify();
                    this.updater.installing
                });
                if !matches!(going, Ok(true)) {
                    break;
                }
            }
        })
        .detach();
        cx.spawn(async move |this, cx| {
            let result = install.await;
            let _ = this.update(cx, |this, cx| match result {
                // Установщик ждёт, пока освободится exe, и сам запустит новую версию.
                Ok(()) => cx.quit(),
                Err(err) => {
                    this.updater.installing = false;
                    this.updater.error = Some(format!("{err:#}").into());
                    cx.notify();
                }
            });
        })
        .detach();
        cx.notify();
    }

    pub(super) fn update_dialog(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let state = &self.updater;
        let release = state.release.as_ref().filter(|_| state.open)?;
        let theme = cx.theme().clone();
        let percent = state.progress.load(Ordering::Relaxed) / 10;

        let notes: Vec<AnyElement> = release
            .notes
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(|line| {
                Label::new(SharedString::from(line.to_string()))
                    .text_sm()
                    .text_color(theme.muted_foreground)
                    .into_any_element()
            })
            .collect();

        let go = if state.installing {
            Button::new("update-go")
                .primary()
                .label(format!("Загрузка… {percent}%"))
                .disabled(true)
        } else {
            Button::new("update-go")
                .primary()
                .label("Обновить и перезапустить")
                .on_click(cx.listener(|this, _, _, cx| this.install_update(cx)))
        };

        Some(
            div()
                .absolute()
                .occlude()
                .top_0()
                .left_0()
                .size_full()
                .flex()
                .items_center()
                .justify_center()
                .bg(gpui_kit::hsla(0., 0., 0., 0.5))
                .on_mouse_down(MouseButton::Left, |_, _, _| {})
                .child(
                    v_flex()
                        .w(px(460.))
                        .p_4()
                        .gap_3()
                        .rounded_lg()
                        .bg(theme.background)
                        .border_1()
                        .border_color(theme.border)
                        .child(
                            Label::new(SharedString::from(format!(
                                "Доступна версия {}",
                                release.version
                            )))
                            .font_semibold(),
                        )
                        .child(
                            Label::new(SharedString::from(format!(
                                "Установлена {}. Открытые сеансы будут закрыты.",
                                env!("CARGO_PKG_VERSION")
                            )))
                            .text_sm()
                            .text_color(theme.muted_foreground),
                        )
                        .when(!notes.is_empty(), |this| {
                            this.child(
                                v_flex()
                                    .id("update-notes")
                                    .max_h(px(260.))
                                    .overflow_y_scrollbar()
                                    .gap_1()
                                    .children(notes),
                            )
                        })
                        .when(state.installing, |this| {
                            this.child(
                                div()
                                    .h(px(4.))
                                    .w_full()
                                    .rounded_full()
                                    .bg(theme.muted)
                                    .child(
                                        div()
                                            .h_full()
                                            .rounded_full()
                                            .bg(theme.primary)
                                            .w(gpui_kit::relative(percent as f32 / 100.)),
                                    ),
                            )
                        })
                        .when_some(state.error.clone(), |this, err| {
                            this.child(
                                Label::new(SharedString::from(format!(
                                    "Не удалось обновить: {err}"
                                )))
                                .text_sm()
                                .text_color(theme.danger),
                            )
                        })
                        .child(
                            h_flex().gap_2().child(go).child(
                                Button::new("update-later")
                                    .outline()
                                    .label("Позже")
                                    .disabled(state.installing)
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.updater.open = false;
                                        cx.notify();
                                    })),
                            ),
                        ),
                )
                .into_any_element(),
        )
    }
}
