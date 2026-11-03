use crate::ui::theme::MainAction;
use futures::channel::{mpsc, oneshot};
use gpui::{
    Context, Entity, EventEmitter, IntoElement, KeyDownEvent, Render, SharedString, Subscription,
    Window, div, prelude::*, px,
};
use gpui_component::{
    ActiveTheme, Icon, Sizable,
    button::{Button, ButtonVariants},
    h_flex,
    input::{Input, InputEvent, InputState},
    label::Label,
    v_flex,
};

use crate::ssh::sftp::ToSftp;

pub enum EditorEvent {
    Close,
    Expand(bool),
}

impl EventEmitter<EditorEvent> for EditorView {}

pub struct EditorView {
    path: String,
    name: String,
    commands: mpsc::UnboundedSender<ToSftp>,
    input: Option<Entity<InputState>>,
    pending: Option<String>,
    crlf: bool,
    dirty: bool,
    saving: bool,
    status: Option<(SharedString, bool)>,
    confirm_close: bool,
    docked: bool,
    expanded: bool,
    _subscription: Option<Subscription>,
}

fn is_crlf(text: &str) -> bool {
    let crlf = text.matches("\r\n").count();
    crlf > 0 && crlf == text.matches('\n').count() && crlf == text.matches('\r').count()
}

fn language_of(name: &str) -> String {
    name.rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .unwrap_or_else(|| "text".into())
}

impl EditorView {
    pub fn new(
        path: String,
        name: String,
        content: String,
        commands: mpsc::UnboundedSender<ToSftp>,
    ) -> Self {
        let crlf = is_crlf(&content);
        let text = if crlf {
            content.replace("\r\n", "\n")
        } else {
            content
        };
        Self {
            path,
            name,
            commands,
            input: None,
            pending: Some(text),
            crlf,
            dirty: false,
            saving: false,
            status: None,
            confirm_close: false,
            docked: false,
            expanded: false,
            _subscription: None,
        }
    }

    pub fn docked(mut self) -> Self {
        self.docked = true;
        self
    }

    fn request_close(&mut self, cx: &mut Context<Self>) {
        if self.dirty {
            self.ask_close(cx);
        } else {
            cx.emit(EditorEvent::Close);
        }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn ask_close(&mut self, cx: &mut Context<Self>) {
        self.confirm_close = true;
        cx.notify();
    }

    fn ensure_input(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(text) = self.pending.take() else {
            return;
        };
        let language = language_of(&self.name);
        let input = cx.new(|cx| {
            let mut state = InputState::new(window, cx)
                .code_editor(language)
                .line_number(true);
            state.set_value(text, window, cx);
            state
        });
        window.focus(&gpui::Focusable::focus_handle(&input, cx));
        self._subscription = Some(cx.subscribe(&input, |this, _, event: &InputEvent, cx| {
            if matches!(event, InputEvent::Change) && !this.dirty {
                this.dirty = true;
                this.status = None;
                cx.notify();
            }
        }));
        self.input = Some(input);
    }

    fn save(&mut self, close_after: bool, cx: &mut Context<Self>) {
        if self.saving {
            return;
        }
        let Some(input) = &self.input else {
            return;
        };
        let mut text = input.read(cx).value().to_string();
        if self.crlf {
            text = text.replace('\n', "\r\n");
        }

        let (reply, answer) = oneshot::channel();
        if self
            .commands
            .unbounded_send(ToSftp::WriteFile {
                path: self.path.clone(),
                data: text.into_bytes(),
                reply,
            })
            .is_err()
        {
            self.status = Some(("Соединение закрыто. Сохранение невозможно.".into(), true));
            cx.notify();
            return;
        }
        self.saving = true;
        self.status = None;
        cx.notify();

        cx.spawn(async move |this: gpui::WeakEntity<Self>, cx| {
            let result = answer.await;
            let _ = this.update(cx, |this, cx| {
                this.saving = false;
                match result {
                    Ok(Ok(())) => {
                        this.dirty = false;
                        this.confirm_close = false;
                        this.status = Some(("Сохранено".into(), false));
                        if close_after {
                            cx.emit(EditorEvent::Close);
                        }
                    }
                    Ok(Err(error)) => this.status = Some((error.into(), true)),
                    Err(_) => {
                        this.status = Some(("Соединение закрыто. Файл не сохранён.".into(), true))
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn on_key(&mut self, event: &KeyDownEvent, _window: &mut Window, cx: &mut Context<Self>) {
        if event.keystroke.modifiers.secondary() && event.keystroke.key.as_str() == "s" {
            self.save(false, cx);
            cx.stop_propagation();
        }
    }
}

impl Render for EditorView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.ensure_input(window, cx);
        let theme = cx.theme().clone();
        let mono = crate::ui::font::MonoFont::get(cx).family.clone();

        let status = match (&self.status, self.saving, self.dirty) {
            (_, true, _) => Some(("Сохранение…".into(), theme.muted_foreground)),
            (Some((text, true)), _, _) => Some((text.clone(), theme.danger)),
            (Some((text, false)), _, _) => Some((text.clone(), theme.success)),
            _ => None,
        };

        let (folder, file) = match self.path.rfind('/') {
            Some(cut) => (
                self.path[..=cut].to_string(),
                self.path[cut + 1..].to_string(),
            ),
            None => (String::new(), self.path.clone()),
        };
        let unsaved = self.dirty && !self.saving;

        v_flex()
            .size_full()
            .on_key_down(cx.listener(Self::on_key))
            .child(
                h_flex()
                    .px_3()
                    .py_1p5()
                    .gap_3()
                    .items_center()
                    .bg(theme.secondary)
                    .border_b_1()
                    .border_color(theme.border)
                    .child(
                        h_flex()
                            .id("editor-path")
                            .flex_grow()
                            .min_w(px(0.))
                            .gap_1p5()
                            .items_center()
                            .overflow_hidden()
                            .tooltip({
                                let path = SharedString::from(self.path.clone());
                                move |window, cx| {
                                    gpui_component::tooltip::Tooltip::new(path.clone())
                                        .build(window, cx)
                                }
                            })
                            .child(
                                div()
                                    .flex_shrink_0()
                                    .text_sm()
                                    .font_weight(gpui::FontWeight::MEDIUM)
                                    .whitespace_nowrap()
                                    .child(SharedString::from(file)),
                            )
                            .when(unsaved, |this| {
                                this.child(
                                    div()
                                        .flex_shrink_0()
                                        .size(px(6.))
                                        .rounded_full()
                                        .bg(theme.warning),
                                )
                            })
                            .child(
                                div()
                                    .min_w(px(0.))
                                    .overflow_hidden()
                                    .text_xs()
                                    .text_color(theme.muted_foreground)
                                    .line_clamp(1)
                                    .text_ellipsis()
                                    .child(SharedString::from(folder)),
                            ),
                    )
                    .children(status.map(|(text, color)| {
                        div()
                            .flex_shrink_0()
                            .text_xs()
                            .text_color(color)
                            .whitespace_nowrap()
                            .child(text)
                    }))
                    .child(
                        Button::new("editor-save")
                            .small()
                            .label("Сохранить")
                            .tooltip("Сохранить на сервере (Ctrl+S)")
                            .main_action(self.dirty && !self.saving)
                            .on_click(cx.listener(|this, _, _window, cx| this.save(false, cx))),
                    )
                    .when(self.docked, |this| {
                        let expanded = self.expanded;
                        this.child(
                            Button::new("editor-expand")
                                .ghost()
                                .small()
                                .icon(Icon::empty().path(if expanded {
                                    "icons/window-restore.svg"
                                } else {
                                    "icons/window-maximize.svg"
                                }))
                                .tooltip(if expanded {
                                    "Показать рядом с терминалом"
                                } else {
                                    "Развернуть"
                                })
                                .on_click(cx.listener(move |this, _, _window, cx| {
                                    this.expanded = !expanded;
                                    cx.emit(EditorEvent::Expand(this.expanded));
                                    cx.notify();
                                })),
                        )
                        .child(
                            Button::new("editor-close")
                                .ghost()
                                .small()
                                .icon(Icon::empty().path("icons/close.svg"))
                                .tooltip("Закрыть файл")
                                .on_click(
                                    cx.listener(|this, _, _window, cx| this.request_close(cx)),
                                ),
                        )
                    }),
            )
            .when(self.confirm_close, |this| {
                this.child(
                    v_flex()
                        .px_3()
                        .py_2()
                        .gap_2()
                        .bg(theme.muted)
                        .border_b_1()
                        .border_color(theme.warning)
                        .child(
                            Label::new("Файл содержит несохранённые изменения. Закрыть его?")
                                .text_sm(),
                        )
                        .child(
                            h_flex()
                                .flex_wrap()
                                .gap_2()
                                .child(
                                    Button::new("editor-save-close")
                                        .primary()
                                        .small()
                                        .label("Сохранить и закрыть")
                                        .on_click(
                                            cx.listener(|this, _, _window, cx| this.save(true, cx)),
                                        ),
                                )
                                .child(
                                    Button::new("editor-discard")
                                        .danger()
                                        .small()
                                        .label("Закрыть без сохранения")
                                        .on_click(cx.listener(|_, _, _window, cx| {
                                            cx.emit(EditorEvent::Close)
                                        })),
                                )
                                .child(
                                    Button::new("editor-keep")
                                        .ghost()
                                        .small()
                                        .label("Отмена")
                                        .on_click(cx.listener(|this, _, _window, cx| {
                                            this.confirm_close = false;
                                            cx.notify();
                                        })),
                                ),
                        ),
                )
            })
            .child(
                div()
                    .flex_grow()
                    .min_h(px(0.))
                    .font_family(mono)
                    .text_size(px(13.))
                    .children(
                        self.input
                            .as_ref()
                            .map(|input| Input::new(input).h_full().appearance(false)),
                    ),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn koncy_strok_opredelyayutsya_tolko_esli_oni_vse_odinakovye() {
        assert!(is_crlf("a\r\nb\r\n"));
        assert!(!is_crlf("a\nb\n"));
        assert!(!is_crlf("без переводов"));
        assert!(!is_crlf("a\r\nb\n"));
        assert!(!is_crlf("a\rb\r\n"));
    }

    #[test]
    fn yazyk_po_rasshireniyu() {
        assert_eq!(language_of("nginx.CONF"), "conf");
        assert_eq!(language_of("config.json"), "json");
        assert_eq!(language_of("Makefile"), "text");
    }
}
