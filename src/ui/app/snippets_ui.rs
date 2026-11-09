use gpui_kit::component::{
    ActiveTheme, Icon, IconName, Selectable, Sizable, StyledExt,
    button::{Button, ButtonVariants},
    h_flex,
    input::{Input, InputState, Textarea, TextareaState},
    label::Label,
    scroll::ScrollableElement,
    v_flex,
};
use gpui_kit::{AnyElement, Context, Entity, SharedString, Window, div, prelude::*, px};
use proto::{RecordId, SnippetRecord};
use rust_i18n::t;

use super::{AppView, ROW_TITLE_CHARS, TabKind, shorten};

pub(super) struct SnippetForm {
    pub label: Entity<InputState>,
    pub command: Entity<TextareaState>,
    pub run: bool,
    pub editing: Option<RecordId>,
    pub open: bool,
}

impl SnippetForm {
    pub fn new(window: &mut Window, cx: &mut Context<AppView>) -> Self {
        Self {
            label: cx
                .new(|cx| InputState::new(window, cx).placeholder(t!("snippets.name_placeholder"))),
            command: cx.new(|cx| {
                TextareaState::new(window, cx)
                    .auto_grow(3, 12)
                    .placeholder(t!("snippets.command_placeholder"))
            }),
            run: true,
            editing: None,
            open: false,
        }
    }
}

impl AppView {
    fn snippet_new(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.snippet_clear(window, cx);
        self.snippet_form.open = true;
        self.error = None;
        cx.notify();
    }

    fn snippet_edit(
        &mut self,
        entry: &crate::vault_session::SnippetEntry,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let form = &self.snippet_form;
        let snippet = entry.snippet.clone();
        form.label
            .update(cx, |state, cx| state.set_value(snippet.label, window, cx));
        form.command
            .update(cx, |state, cx| state.set_value(snippet.command, window, cx));
        self.snippet_form.run = snippet.run;
        self.snippet_form.editing = Some(entry.id.clone());
        self.snippet_form.open = true;
        self.error = None;
        cx.notify();
    }

    fn snippet_clear(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let form = &self.snippet_form;
        form.label
            .update(cx, |state, cx| state.set_value("", window, cx));
        form.command
            .update(cx, |state, cx| state.set_value("", window, cx));
        self.snippet_form.run = true;
        self.snippet_form.editing = None;
        self.snippet_form.open = false;
        cx.notify();
    }

    fn snippet_save(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let snippet = SnippetRecord {
            label: self.snippet_form.label.read(cx).value().trim().to_string(),
            command: self.snippet_form.command.read(cx).value().to_string(),
            run: self.snippet_form.run,
        };
        if !snippet.is_usable() {
            self.error = Some(t!("snippets.err_command").to_string().into());
            cx.notify();
            return;
        }
        let editing = self.snippet_form.editing.clone();
        self.persist_current(cx, move |unlocked, store| {
            unlocked.upsert_snippet(store, editing, snippet).map(|_| ())
        });
        if self.error.is_none() {
            self.snippet_clear(window, cx);
        }
    }

    fn snippet_remove(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(id) = self.snippet_form.editing.clone() else {
            return;
        };
        self.persist_current(cx, move |unlocked, store| {
            unlocked.remove_snippet(store, &id)
        });
        if self.error.is_none() {
            self.snippet_clear(window, cx);
        }
    }

    fn snippet_insert(&mut self, index: usize, snippet: &SnippetRecord, cx: &mut Context<Self>) {
        let Some(tab) = self.tabs.get(index) else {
            return;
        };
        let targets = match &tab.kind {
            TabKind::Terminal { split, .. } if split.broadcast => tab.terminals(),
            _ => tab.focused_terminal().into_iter().collect(),
        };
        let bytes = snippet.keystrokes();
        for view in targets {
            let bytes = bytes.clone();
            view.update(cx, |view, cx| view.type_bytes(bytes, cx));
        }
        self.snippets_open = false;
        cx.notify();
    }

    pub(super) fn snippets_popover(
        &self,
        index: usize,
        cx: &mut Context<Self>,
    ) -> Option<AnyElement> {
        if !self.snippets_open {
            return None;
        }
        let theme = cx.theme().clone();
        let muted = theme.muted_foreground;
        let snippets = self.current_unlocked().map(|unlocked| unlocked.snippets());
        let body: AnyElement =
            match snippets {
                None => Label::new(t!("snippets.locked"))
                    .text_sm()
                    .text_color(muted)
                    .into_any_element(),
                Some(list) if list.is_empty() => {
                    Label::new(t!("snippets.popover_empty"))
                        .text_sm()
                        .text_color(muted)
                        .into_any_element()
                }
                Some(list) => v_flex()
                    .id("snippets-list")
                    .max_h(px(360.))
                    .overflow_y_scrollbar()
                    .gap_0p5()
                    .children(list.into_iter().enumerate().map(|(row, entry)| {
                        let snippet = entry.snippet;
                        let first_line = snippet
                            .command
                            .lines()
                            .next()
                            .unwrap_or_default()
                            .to_string();
                        let run = snippet.run;
                        v_flex()
                            .id(SharedString::from(format!("snippet-row-{row}")))
                            .px_2()
                            .py_1()
                            .rounded_md()
                            .hover(|style| style.bg(theme.secondary_hover))
                            .child(
                                h_flex()
                                    .gap_2()
                                    .child(
                                        Label::new(SharedString::from(shorten(
                                            &snippet.title(),
                                            ROW_TITLE_CHARS,
                                        )))
                                        .text_sm()
                                        .flex_grow_1(),
                                    )
                                    .child(
                                        Label::new(if run {
                                            t!("snippets.run")
                                        } else {
                                            t!("snippets.insert")
                                        })
                                        .text_xs()
                                        .text_color(if run { theme.warning } else { muted }),
                                    ),
                            )
                            .child(
                                Label::new(SharedString::from(shorten(&first_line, 48)))
                                    .text_xs()
                                    .text_color(muted),
                            )
                            .on_click(cx.listener(move |this, _, _window, cx| {
                                this.snippet_insert(index, &snippet, cx)
                            }))
                    }))
                    .into_any_element(),
            };
        Some(
            Self::popover(t!("snippets.title"), px(340.), cx)
                .child(body)
                .into_any_element(),
        )
    }

    pub(super) fn snippets_page(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let muted = theme.muted_foreground;
        let Some(unlocked) = self.current_unlocked() else {
            return div().into_any_element();
        };
        let mono = crate::ui::font::MonoFont::get(cx).family.clone();

        let header = h_flex()
            .px_6()
            .pt_5()
            .pb_3()
            .justify_between()
            .items_center()
            .child(Label::new(t!("snippets.title")).text_xl().font_semibold())
            .child(
                Button::new("new-snippet")
                    .primary()
                    .icon(Icon::new(IconName::Plus))
                    .label(t!("snippets.new"))
                    .on_click(cx.listener(|this, _, window, cx| this.snippet_new(window, cx))),
            );

        let cards: Vec<AnyElement> = unlocked
            .snippets()
            .into_iter()
            .map(|entry| {
                let first_line = entry
                    .snippet
                    .command
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_string();
                let run = entry.snippet.run;
                let title = entry.snippet.title();
                let card_id = SharedString::from(format!("snippet-card-{}", entry.id));
                v_flex()
                    .id(card_id)
                    .w(px(280.))
                    .p_3()
                    .gap_1()
                    .rounded_lg()
                    .border_1()
                    .border_color(theme.border)
                    .bg(theme.secondary)
                    .hover(|style| style.bg(theme.secondary_hover))
                    .child(
                        h_flex()
                            .gap_2()
                            .items_center()
                            .child(
                                Icon::empty()
                                    .path("icons/square-terminal.svg")
                                    .small()
                                    .text_color(theme.primary),
                            )
                            .child(
                                Label::new(SharedString::from(shorten(&title, ROW_TITLE_CHARS)))
                                    .font_semibold(),
                            ),
                    )
                    .child(
                        Label::new(SharedString::from(shorten(&first_line, 40)))
                            .text_xs()
                            .font_family(mono.clone())
                            .text_color(muted),
                    )
                    .child(
                        Label::new(if run {
                            t!("snippets.runs_immediately")
                        } else {
                            t!("snippets.insert_only")
                        })
                        .text_xs()
                        .text_color(muted),
                    )
                    .on_click(
                        cx.listener(move |this, _, window, cx| {
                            this.snippet_edit(&entry, window, cx)
                        }),
                    )
                    .into_any_element()
            })
            .collect();
        let empty = cards.is_empty();

        div()
            .relative()
            .size_full()
            .child(
                v_flex()
                    .size_full()
                    .child(header)
                    .children(self.vault_picker(cx))
                    .child(
                        v_flex()
                            .id("snippets-grid")
                            .flex_grow_1()
                            .min_h(px(0.))
                            .overflow_y_scrollbar()
                            .px_6()
                            .pb_6()
                            .gap_3()
                            .child(
                                Label::new(t!("snippets.intro"))
                                    .text_sm()
                                    .text_color(muted),
                            )
                            .when(empty, |this| {
                                this.child(
                                    v_flex()
                                        .py_10()
                                        .items_center()
                                        .gap_2()
                                        .child(Icon::empty().path("icons/square-terminal.svg").size(px(36.)).text_color(muted))
                                        .child(Label::new(t!("snippets.empty_title")))
                                        .child(
                                            Label::new(t!("snippets.empty_hint"))
                                                .text_sm()
                                                .text_color(muted),
                                        ),
                                )
                            })
                            .child(h_flex().flex_wrap().gap_3().children(cards)),
                    ),
            )
            .when(self.snippet_form.open, |this| this.child(self.snippet_drawer(cx)))
            .into_any_element()
    }

    fn snippet_drawer(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let muted = theme.muted_foreground;
        let form = &self.snippet_form;
        let editing = form.editing.is_some();
        let run = form.run;
        let mono = crate::ui::font::MonoFont::get(cx).family.clone();

        div()
            .absolute()
            .occlude()
            .top_0()
            .right_0()
            .h_full()
            .w(px(460.))
            .max_w_full()
            .bg(crate::ui::theme::solid_background(cx))
            .border_l_1()
            .border_color(theme.border)
            .shadow_lg()
            .child(
                v_flex()
                    .size_full()
                    .child(
                        h_flex()
                            .px_4()
                            .py_3()
                            .justify_between()
                            .items_center()
                            .border_b_1()
                            .border_color(theme.border)
                            .child(
                                Label::new(if editing {
                                    t!("snippets.edit_title")
                                } else {
                                    t!("snippets.new_title")
                                })
                                .text_lg()
                                .font_semibold(),
                            )
                            .child(
                                Button::new("snippet-close")
                                    .ghost()
                                    .small()
                                    .icon(Icon::new(IconName::Close))
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.snippet_clear(window, cx)
                                    })),
                            ),
                    )
                    .child(
                        v_flex()
                            .id("snippet-editor-body")
                            .flex_grow_1()
                            .min_h(px(0.))
                            .overflow_y_scrollbar()
                            .px_4()
                            .py_3()
                            .gap_3()
                            .child(
                                v_flex()
                                    .gap_1()
                                    .child(Self::field_label(t!("snippets.name"), muted))
                                    .child(Input::new(&form.label)),
                            )
                            .child(
                                v_flex()
                                    .gap_1()
                                    .child(Self::field_label(t!("snippets.command"), muted))
                                    .child(
                                        div().font_family(mono).child(Textarea::new(&form.command)),
                                    ),
                            )
                            .child(
                                h_flex()
                                    .gap_1()
                                    .child(
                                        Button::new("snippet-run")
                                            .ghost()
                                            .xsmall()
                                            .selected(run)
                                            .label(t!("snippets.run_immediately"))
                                            .tooltip(t!("snippets.run_tooltip"))
                                            .on_click(cx.listener(|this, _, _window, cx| {
                                                this.snippet_form.run = true;
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        Button::new("snippet-type")
                                            .ghost()
                                            .xsmall()
                                            .selected(!run)
                                            .label(t!("snippets.insert_only"))
                                            .tooltip(t!("snippets.insert_tooltip"))
                                            .on_click(cx.listener(|this, _, _window, cx| {
                                                this.snippet_form.run = false;
                                                cx.notify();
                                            })),
                                    ),
                            )
                            .children(
                                self.error.clone().map(|error| {
                                    Label::new(error).text_sm().text_color(theme.danger)
                                }),
                            ),
                    )
                    .child(
                        h_flex()
                            .px_4()
                            .py_3()
                            .gap_2()
                            .border_t_1()
                            .border_color(theme.border)
                            .child(
                                Button::new("snippet-save")
                                    .primary()
                                    .label(t!("snippets.save"))
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.snippet_save(window, cx)
                                    })),
                            )
                            .child(div().flex_grow_1())
                            .when(editing, |this| {
                                this.child(
                                    Button::new("snippet-remove")
                                        .danger()
                                        .ghost()
                                        .label(t!("snippets.delete"))
                                        .on_click(cx.listener(|this, _, window, cx| {
                                            this.snippet_remove(window, cx)
                                        })),
                                )
                            }),
                    ),
            )
            .into_any_element()
    }
}
