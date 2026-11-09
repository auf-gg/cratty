//! "Vault" window: name, master password change, location and move.

use super::*;

pub(super) struct VaultEditor {
    id: String,
    name: Entity<InputState>,
    current: Entity<InputState>,
    password: Entity<InputState>,
    repeat: Entity<InputState>,
    busy: bool,
    error: Option<SharedString>,
    notice: Option<SharedString>,
    _task: Option<gpui_kit::Task<()>>,
}

impl AppView {
    pub(super) fn open_vault_editor(
        &mut self,
        id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(ix) = self.vault_ix(id) else {
            return;
        };
        let name = self.vaults[ix].name.clone();
        let masked = |placeholder: String, window: &mut Window, cx: &mut Context<Self>| {
            cx.new(|cx| {
                InputState::new(window, cx)
                    .masked(true)
                    .placeholder(placeholder)
            })
        };
        self.vault_editor = Some(VaultEditor {
            id: id.to_owned(),
            name: cx.new(|cx| InputState::new(window, cx).default_value(name)),
            current: masked(t!("vaults.ph_current").to_string(), window, cx),
            password: masked(t!("vaults.ph_new").to_string(), window, cx),
            repeat: masked(t!("vaults.ph_repeat").to_string(), window, cx),
            busy: false,
            error: None,
            notice: None,
            _task: None,
        });
        cx.notify();
    }

    fn editor_result(&mut self, result: anyhow::Result<SharedString>, cx: &mut Context<Self>) {
        if let Some(editor) = &mut self.vault_editor {
            editor.busy = false;
            match result {
                Ok(notice) => {
                    editor.notice = Some(notice);
                    editor.error = None;
                }
                Err(error) => {
                    editor.error = Some(SharedString::from(format!("{error:#}")));
                    editor.notice = None;
                }
            }
        }
        cx.notify();
    }

    fn rename_vault(&mut self, cx: &mut Context<Self>) {
        let Some(editor) = &self.vault_editor else {
            return;
        };
        let (id, name) = (
            editor.id.clone(),
            editor.name.read(cx).value().trim().to_string(),
        );
        let result = (|| {
            let ix = self
                .vault_ix(&id)
                .ok_or_else(|| anyhow::anyhow!(t!("vaults.vault_disappeared").to_string()))?;
            let store = VaultStore::new(self.vaults[ix].root());
            let unlocked = self.vaults[ix]
                .session
                .unlocked_mut()
                .ok_or_else(|| anyhow::anyhow!(t!("vaults.unlock_first").to_string()))?;
            unlocked.set_vault_name(&store, &name)?;
            self.vaults[ix].name = name.clone();
            self.save_registry();
            anyhow::Ok(SharedString::from(t!("vaults.name_saved").to_string()))
        })();
        self.editor_result(result, cx);
        if self
            .vault_editor
            .as_ref()
            .is_some_and(|e| e.error.is_none())
        {
            self.sync_now(&id, cx);
        }
    }

    fn change_vault_password(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(editor) = &self.vault_editor else {
            return;
        };
        if editor.busy {
            return;
        }
        let id = editor.id.clone();
        let (current, password, repeat) = (
            editor.current.clone(),
            editor.password.clone(),
            editor.repeat.clone(),
        );

        let verdict = vault_ui::check_new_password(
            password.read(cx).value().as_ref(),
            repeat.read(cx).value().as_ref(),
        );
        let problem = match verdict {
            vault_ui::PasswordVerdict::Ok => None,
            vault_ui::PasswordVerdict::TooShort => Some(
                t!("vaults.new_too_short", min = vault_ui::MIN_PASSWORD_LEN).to_string(),
            ),
            vault_ui::PasswordVerdict::Mismatch => Some(t!("vaults.new_mismatch").to_string()),
        };
        if let Some(problem) = problem {
            self.editor_result(Err(anyhow::anyhow!(problem)), cx);
            return;
        }

        let account = match self
            .vault_ix(&id)
            .map(|ix| self.vaults[ix].session.read_account())
        {
            Some(Ok(account)) => account,
            Some(Err(error)) => return self.editor_result(Err(error), cx),
            None => return,
        };
        let mut old = Self::take_password(&current, window, cx);
        let mut new = Self::take_password(&password, window, cx);
        repeat.update(cx, |state, cx| state.set_value("", window, cx));

        let prepare = cx.background_executor().spawn(async move {
            let slot = crate::vault_session::prepare_password_change(
                &account,
                &old,
                &new,
                std::time::Duration::from_millis(750),
            );
            old.zeroize();
            new.zeroize();
            slot
        });

        let task = cx.spawn(async move |this: gpui_kit::WeakEntity<Self>, cx| {
            let slot = prepare.await;
            this.update(cx, |this, cx| {
                let result = slot.and_then(|slot| {
                    let ix = this
                        .vault_ix(&id)
                        .ok_or_else(|| anyhow::anyhow!(t!("vaults.vault_disappeared").to_string()))?;
                    this.vaults[ix].session.replace_password_slot(slot)?;
                    Ok(SharedString::from(t!("vaults.password_changed").to_string()))
                });
                this.editor_result(result, cx);
            })
            .ok();
        });

        if let Some(editor) = &mut self.vault_editor {
            editor.busy = true;
            editor.error = None;
            editor.notice = Some(t!("vaults.checking").to_string().into());
            editor._task = Some(task);
        }
        cx.notify();
    }

    fn pick_vault_location(&mut self, cx: &mut Context<Self>) {
        let Some(editor) = &self.vault_editor else {
            return;
        };
        let id = editor.id.clone();
        let receiver = cx.prompt_for_paths(gpui_kit::PathPromptOptions {
            files: false,
            directories: true,
            multiple: false,
            prompt: Some(t!("vaults.move_here").to_string().into()),
        });
        cx.spawn(async move |this: gpui_kit::WeakEntity<Self>, cx| {
            let Ok(Ok(Some(paths))) = receiver.await else {
                return;
            };
            let Some(target) = paths.into_iter().next() else {
                return;
            };
            this.update(cx, |this, cx| this.move_vault_to(&id, &target, cx))
                .ok();
        })
        .detach();
    }

    fn move_vault_to(&mut self, id: &str, target: &std::path::Path, cx: &mut Context<Self>) {
        let result = (|| {
            let ix = self
                .vault_ix(id)
                .ok_or_else(|| anyhow::anyhow!(t!("vaults.vault_disappeared").to_string()))?;
            let moved = crate::store::move_vault(&self.vaults[ix].root(), target)?;
            self.vaults[ix].session.relocate(moved.clone());
            self.save_registry();
            anyhow::Ok(SharedString::from(
                t!("vaults.moved", path = moved.display().to_string()).to_string(),
            ))
        })();
        self.editor_result(result, cx);
    }

    pub(super) fn vault_editor_dialog(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let editor = self.vault_editor.as_ref()?;
        let ix = self.vault_ix(&editor.id)?;
        let slot = &self.vaults[ix];
        let unlocked = slot.session.state().is_unlocked();
        let theme = cx.theme().clone();
        let root = slot.root();

        let field = |title: String| {
            Label::new(SharedString::from(title))
                .text_xs()
                .text_color(theme.muted_foreground)
        };
        let locked_hint = (!unlocked).then(|| {
            Label::new(t!("vaults.editor_locked_hint").to_string())
                .text_xs()
                .text_color(theme.warning)
        });

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
                        .id("vault-editor")
                        .w(px(480.))
                        .max_h(gpui_kit::relative(0.9))
                        .overflow_y_scroll()
                        .p_4()
                        .gap_3()
                        .rounded_lg()
                        .bg(crate::ui::theme::solid_background(cx))
                        .border_1()
                        .border_color(theme.border)
                        .child(
                            Label::new(SharedString::from(
                                t!("vaults.editor_title", name = slot.name).to_string(),
                            ))
                                .font_semibold(),
                        )
                        .children(locked_hint)
                        .child(field(t!("vaults.editor_name").to_string()))
                        .child(
                            h_flex()
                                .gap_2()
                                .child(div().flex_1().child(Input::new(&editor.name).small()))
                                .child(
                                    Button::new("vault-rename")
                                        .outline()
                                        .small()
                                        .label(t!("vaults.save").to_string())
                                        .disabled(!unlocked)
                                        .on_click(cx.listener(|this, _, _window, cx| {
                                            this.rename_vault(cx)
                                        })),
                                ),
                        )
                        .child(Self::hint(t!("vaults.name_hint").to_string(), cx))
                        .child(field(t!("vaults.master_password").to_string()))
                        .child(Input::new(&editor.current).small())
                        .child(Input::new(&editor.password).small())
                        .child(Input::new(&editor.repeat).small())
                        .child(
                            Button::new("vault-change-password")
                                .outline()
                                .small()
                                .label(if editor.busy {
                                    t!("vaults.changing").to_string()
                                } else {
                                    t!("vaults.change_password").to_string()
                                })
                                .disabled(!unlocked || editor.busy)
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.change_vault_password(window, cx)
                                })),
                        )
                        .child(field(t!("vaults.location").to_string()))
                        .child(
                            div()
                                .px_2()
                                .py_1()
                                .rounded_md()
                                .bg(theme.muted)
                                .font_family(crate::ui::font::MonoFont::get(cx).family.clone())
                                .text_xs()
                                .child(SharedString::from(root.display().to_string())),
                        )
                        .child(
                            Button::new("vault-move")
                                .outline()
                                .small()
                                .label(t!("vaults.move_button").to_string())
                                .disabled(editor.busy)
                                .on_click(cx.listener(|this, _, _window, cx| {
                                    this.pick_vault_location(cx)
                                })),
                        )
                        .child(Self::hint(t!("vaults.move_hint").to_string(), cx))
                        .children(
                            editor
                                .error
                                .clone()
                                .map(|error| Label::new(error).text_sm().text_color(theme.danger)),
                        )
                        .children(
                            editor
                                .notice
                                .clone()
                                .map(|notice| Label::new(notice).text_sm().text_color(theme.success)),
                        )
                        .child(
                            h_flex().justify_end().child(
                                Button::new("vault-editor-close")
                                    .ghost()
                                    .label(t!("vaults.close").to_string())
                                    .on_click(cx.listener(|this, _, _window, cx| {
                                        this.vault_editor = None;
                                        cx.notify();
                                    })),
                            ),
                        ),
                )
                .into_any_element(),
        )
    }
}
