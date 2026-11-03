use super::*;
use crate::ui::theme::MainAction;

impl AppView {
    pub(super) fn take_password(
        input: &Entity<InputState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Vec<u8> {
        let value = input.read(cx).value().to_string();
        input.update(cx, |state, cx| state.set_value("", window, cx));
        value.into_bytes()
    }

    pub(super) fn vault_submit(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        match self.stage.clone() {
            Some(Stage::Create) => self.create_vault(window, cx),
            Some(Stage::Unlock) => self.unlock_vault(window, cx),
            Some(Stage::UnlockWithCode) => self.unlock_with_code(window, cx),
            Some(Stage::Recovery {
                confirmed: true, ..
            }) => {
                self.stage = None;
                self.vault_error = None;
                cx.notify();
            }
            Some(Stage::Recovery { .. }) | None => {}
        }
    }

    pub(super) fn create_vault(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.vault_busy {
            return;
        }

        let mut password = self.vault_form.password.read(cx).value().to_string();
        let mut repeat = self.vault_form.repeat.read(cx).value().to_string();

        let verdict = vault_ui::check_new_password(&password, &repeat);
        password.zeroize();
        repeat.zeroize();

        if let Some(message) = verdict.message() {
            self.vault_error = Some(message.into());
            cx.notify();
            return;
        }

        let import = if self.vault_form.import {
            self.pending_import.clone()
        } else {
            Vec::new()
        };

        let mut secret = Self::take_password(&self.vault_form.password, window, cx);
        self.vault_form
            .repeat
            .update(cx, |state, cx| state.set_value("", window, cx));

        let prepare = cx.background_executor().spawn(async move {
            let prepared = crate::vault_session::prepare_new_vault(
                &secret,
                std::time::Duration::from_millis(750),
            );
            secret.zeroize();
            prepared
        });

        self.vault_busy = true;
        self.vault_error = None;
        cx.notify();

        self.vault_task = Some(cx.spawn(async move |this: gpui::WeakEntity<Self>, cx| {
            let prepared = prepare.await;
            this.update(cx, |this, cx| {
                this.vault_busy = false;
                match prepared.and_then(|prepared| this.vault.install(prepared, import)) {
                    Ok(code) => this.show_recovery_code(&code, cx),
                    Err(error) => this.vault_error = Some(SharedString::from(format!("{error:#}"))),
                }
                cx.notify();
            })
            .ok();
        }));
    }

    pub(super) fn show_recovery_code(
        &mut self,
        code: &vault::RecoveryCode,
        _cx: &mut Context<Self>,
    ) {
        use vault::secrecy::ExposeSecret;

        let shown = code.format_for_user();
        let text = String::from_utf8_lossy(shown.expose_secret()).into_owned();

        if !self.pending_import.is_empty()
            && self.vault_form.import
            && let (Some(path), _) = VaultSession::legacy_hosts()
        {
            match migrate::remove_legacy(&path) {
                Ok(()) => {
                    self.vault_form.notice = Some(vault_ui::MIGRATION_WARNING.into());
                    self.pending_import.clear();
                }
                Err(error) => {
                    self.vault_error = Some(SharedString::from(format!(
                        "Записи перенесены, но произошла ошибка: {error:#}"
                    )));
                }
            }
        }

        self.stage = Some(Stage::Recovery {
            code: SharedString::from(text),
            confirmed: false,
        });
        self.collect_vault_warnings();
    }

    pub(super) fn unlock_vault(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.vault_busy {
            return;
        }
        let account = match self.vault.locked_account() {
            Ok(account) => account,
            Err(error) => {
                self.vault_error = Some(SharedString::from(format!("{error:#}")));
                cx.notify();
                return;
            }
        };

        let mut secret = Self::take_password(&self.vault_form.password, window, cx);

        let derive = cx.background_executor().spawn(async move {
            let result = crate::vault_session::derive_from_password(&account, &secret);
            secret.zeroize();
            result
        });

        self.vault_busy = true;
        self.vault_error = None;
        cx.notify();

        self.vault_task = Some(cx.spawn(async move |this: gpui::WeakEntity<Self>, cx| {
            let derived = derive.await;
            this.update(cx, |this, cx| {
                this.vault_busy = false;
                let result = derived.and_then(|data_key| this.vault.adopt(data_key));
                this.after_unlock(result, cx);
            })
            .ok();
        }));
    }

    pub(super) fn unlock_with_code(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.vault_busy {
            return;
        }
        let account = match self.vault.locked_account() {
            Ok(account) => account,
            Err(error) => {
                self.vault_error = Some(SharedString::from(format!("{error:#}")));
                cx.notify();
                return;
            }
        };

        let typed = self.vault_form.code.read(cx).value().to_string();
        let code = match vault::RecoveryCode::parse(typed.as_bytes()) {
            Ok(code) => code,
            Err(error) => {
                self.vault_error = Some(SharedString::from(format!("{error}")));
                cx.notify();
                return;
            }
        };
        self.vault_form
            .code
            .update(cx, |state, cx| state.set_value("", window, cx));

        let derive = cx
            .background_executor()
            .spawn(async move { crate::vault_session::derive_from_recovery_code(&account, &code) });

        self.vault_busy = true;
        self.vault_error = None;
        cx.notify();

        self.vault_task = Some(cx.spawn(async move |this: gpui::WeakEntity<Self>, cx| {
            let derived = derive.await;
            this.update(cx, |this, cx| {
                this.vault_busy = false;
                let result = derived.and_then(|data_key| this.vault.adopt(data_key));
                this.after_unlock(result, cx);
            })
            .ok();
        }));
    }

    pub(super) fn unlock_with_os_key(&mut self, cx: &mut Context<Self>) {
        if self.vault_busy {
            return;
        }
        let account = match self.vault.locked_account() {
            Ok(account) => account,
            Err(error) => {
                self.vault_error = Some(SharedString::from(format!("{error:#}")));
                cx.notify();
                return;
            }
        };

        let derive = cx
            .background_executor()
            .spawn(async move { crate::vault_session::derive_from_os_key(&account, &OsKeychain) });

        self.vault_busy = true;
        self.vault_error = None;
        cx.notify();

        self.vault_task = Some(cx.spawn(async move |this: gpui::WeakEntity<Self>, cx| {
            let derived = derive.await;
            this.update(cx, |this, cx| {
                this.vault_busy = false;
                let result = derived.and_then(|data_key| this.vault.adopt(data_key));
                this.after_unlock(result, cx);
            })
            .ok();
        }));
    }

    pub(super) fn toggle_os_key(&mut self, cx: &mut Context<Self>) {
        let result = if self.vault.has_os_key() {
            self.vault.disable_os_key(&OsKeychain)
        } else {
            self.vault.enable_os_key(&OsKeychain)
        };

        self.vault_error = match result {
            Ok(()) => None,
            Err(error) => Some(SharedString::from(format!("{error:#}"))),
        };
        cx.notify();
    }

    pub(super) fn after_unlock(&mut self, result: anyhow::Result<()>, cx: &mut Context<Self>) {
        self.auto_unlock = false;
        match result {
            Ok(()) => {
                self.stage = None;
                self.vault_error = None;
                self.collect_vault_warnings();
                self.sync_can_save_secrets(cx);
                self.start_sync_watch(cx);
                self.sync_now(cx);
            }
            Err(error) => self.vault_error = Some(SharedString::from(format!("{error:#}"))),
        }
        cx.notify();
    }

    pub(super) fn collect_vault_warnings(&mut self) {
        let Some(unlocked) = self.vault.unlocked() else {
            return;
        };
        for warning in unlocked.warnings.iter().chain(unlocked.broken.iter()) {
            let warning = SharedString::from(warning.clone());
            if !self.vault_warnings.contains(&warning) {
                self.vault_warnings.push(warning);
            }
        }
    }

    pub(super) fn lock_vault(&mut self, cx: &mut Context<Self>) {
        self.reveal = None;
        self.sync_watch = None;
        self.refuse_all_signs();
        self.proxy_form.editing = None;
        self.vault.lock(None);
        self.stage = Some(Stage::Unlock);
        self.vault_error = None;
        self.sync_can_save_secrets(cx);
        cx.notify();
    }

    pub(super) fn vault_panel(&self, cx: &mut Context<Self>) -> AnyElement {
        let muted = cx.theme().muted_foreground;
        let danger = cx.theme().danger;
        let warning = cx.theme().warning;
        let border = cx.theme().border;

        let Some(stage) = self.stage.clone() else {
            return div().into_any_element();
        };

        if let Some(reason) = self.vault.state().broken_reason() {
            return v_flex()
                .px_3()
                .pt_3()
                .gap_2()
                .child(
                    Label::new("Не удалось прочитать хранилище")
                        .text_sm()
                        .font_semibold()
                        .text_color(danger),
                )
                .child(
                    Label::new(SharedString::from(reason.to_owned()))
                        .text_xs()
                        .text_color(muted),
                )
                .child(
                    Label::new(SharedString::from(format!(
                        "Файл хранилища: {}. Не удаляйте его: повреждённым может оказаться только заголовок, а без файла записи не восстановить.",
                        self.vault.store().root().display()
                    )))
                    .text_xs()
                    .text_color(muted),
                )
                .into_any_element();
        }

        let body = match &stage {
            Stage::Create => {
                let verdict = vault_ui::check_new_password(
                    self.vault_form.password.read(cx).value().as_ref(),
                    self.vault_form.repeat.read(cx).value().as_ref(),
                );
                let typed = !self.vault_form.password.read(cx).value().is_empty();
                let import_count = self.pending_import.len();

                v_flex()
                    .gap_2()
                    .child(
                        Label::new(SharedString::from(vault_ui::create_explainer(import_count)))
                            .text_xs()
                            .text_color(muted),
                    )
                    .child(Input::new(&self.vault_form.password))
                    .child(Input::new(&self.vault_form.repeat))
                    .when(import_count > 0, |this| {
                        this.child(
                            Button::new("vault-import")
                                .ghost()
                                .xsmall()
                                .selected(self.vault_form.import)
                                .label(SharedString::from(format!(
                                    "Будет импортировано записей из hosts.json: {import_count}"
                                )))
                                .on_click(cx.listener(|this, _, _window, cx| {
                                    this.vault_form.import = !this.vault_form.import;
                                    cx.notify();
                                })),
                        )
                    })
                    .child(
                        Button::new("vault-create")
                            .w_full()
                            .label(if self.vault_busy {
                                "Подбор параметров Argon2id…"
                            } else {
                                "Создать хранилище"
                            })
                            .main_action(verdict.is_ok() && !self.vault_busy)
                            .on_click(
                                cx.listener(|this, _, window, cx| this.create_vault(window, cx)),
                            ),
                    )
                    .children(
                        verdict
                            .message()
                            .filter(|_| typed)
                            .map(|message| Label::new(message).text_xs().text_color(muted)),
                    )
            }

            Stage::Recovery { code, confirmed } => {
                let confirmed = *confirmed;
                v_flex()
                    .gap_2()
                    .child(
                        Label::new(vault_ui::RECOVERY_EXPLAINER)
                            .text_xs()
                            .text_color(warning),
                    )
                    .child({
                        let groups: Vec<&str> = code.split('-').collect();
                        let split = groups.len().min(4);
                        let top = groups[..split].join("-");
                        let bottom = groups[split..].join("-");

                        v_flex()
                            .w_full()
                            .p_2()
                            .gap_1()
                            .rounded_md()
                            .border_1()
                            .border_color(border)
                            .child(
                                Label::new(SharedString::from(top))
                                    .text_sm()
                                    .font_family(mono_family(cx)),
                            )
                            .when(!bottom.is_empty(), |this| {
                                this.child(
                                    Label::new(SharedString::from(bottom))
                                        .text_sm()
                                        .font_family(mono_family(cx)),
                                )
                            })
                    })
                    .child(
                        Button::new("vault-code-confirm")
                            .ghost()
                            .xsmall()
                            .selected(confirmed)
                            .label("Код восстановления сохранён")
                            .tooltip("Повторно код не отображается")
                            .on_click(cx.listener(|this, _, _window, cx| {
                                if let Some(Stage::Recovery { confirmed, .. }) = &mut this.stage {
                                    *confirmed = !*confirmed;
                                }
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("vault-code-done")
                            .w_full()
                            .label("Продолжить")
                            .tooltip(if confirmed {
                                "Перейти к хранилищу"
                            } else {
                                "Подтвердите сохранение кода восстановления"
                            })
                            .main_action(confirmed)
                            .on_click(
                                cx.listener(|this, _, window, cx| this.vault_submit(window, cx)),
                            ),
                    )
                    .children(
                        self.vault_form
                            .notice
                            .clone()
                            .map(|notice| Label::new(notice).text_xs().text_color(warning)),
                    )
            }

            Stage::Unlock if self.auto_unlock => v_flex().gap_2().child(
                Label::new("Разблокировка ключом этого компьютера…")
                    .text_sm()
                    .text_color(muted),
            ),

            Stage::Unlock => v_flex()
                .gap_2()
                .child(Label::new(stage.subtitle()).text_xs().text_color(muted))
                .child(Input::new(&self.vault_form.password))
                .child(
                    Button::new("vault-unlock")
                        .w_full()
                        .label(if self.vault_busy {
                            "Разблокировка…"
                        } else {
                            "Разблокировать"
                        })
                        .main_action(!self.vault_busy)
                        .on_click(cx.listener(|this, _, window, cx| this.unlock_vault(window, cx))),
                )
                .when(self.vault_busy, |this| {
                    this.child(
                        Label::new(
                            "Вычисление ключа из пароля занимает около секунды — это защита от перебора.",
                        )
                        .text_xs()
                        .text_color(muted),
                    )
                })
                .when(self.vault.has_os_key(), |this| {
                    this.child(
                        Button::new("vault-unlock-os")
                            .outline()
                            .w_full()
                            .label("Разблокировать без пароля")
                            .tooltip(
                                "Ключом этого компьютера из системного хранилища учётных данных",
                            )
                            .disabled(self.vault_busy)
                            .on_click(
                                cx.listener(|this, _, _window, cx| this.unlock_with_os_key(cx)),
                            ),
                    )
                })
                .child(
                    Button::new("vault-forgot")
                        .ghost()
                        .xsmall()
                        .label("Забыли пароль?")
                        .tooltip("Разблокировать с помощью кода восстановления")
                        .on_click(cx.listener(|this, _, _window, cx| {
                            this.stage = Some(Stage::UnlockWithCode);
                            this.error = None;
                            cx.notify();
                        })),
                ),

            Stage::UnlockWithCode => v_flex()
                .gap_2()
                .child(
                    Label::new(
                        "Код выдан однократно при создании хранилища. Регистр символов и дефисы не учитываются.",
                    )
                    .text_xs()
                    .text_color(muted),
                )
                .child(Input::new(&self.vault_form.code))
                .child(
                    Button::new("vault-unlock-code")
                        .w_full()
                        .label(if self.vault_busy {
                            "Разблокировка…"
                        } else {
                            "Разблокировать"
                        })
                        .main_action(!self.vault_busy)
                        .on_click(
                            cx.listener(|this, _, window, cx| this.unlock_with_code(window, cx)),
                        ),
                )
                .child(
                    Button::new("vault-back")
                        .ghost()
                        .xsmall()
                        .label("Вход по паролю")
                        .on_click(cx.listener(|this, _, _window, cx| {
                            this.stage = Some(Stage::Unlock);
                            this.error = None;
                            cx.notify();
                        })),
                ),
        };

        v_flex()
            .child(Self::panel_title(stage.title(), muted))
            .child(v_flex().px_3().pb_3().child(body))
            .children(self.vault_error.clone().map(|error| {
                v_flex()
                    .px_3()
                    .pb_2()
                    .child(Label::new(error).text_sm().text_color(danger))
            }))
            .children(self.vault_warnings.iter().cloned().map(|text| {
                v_flex()
                    .px_3()
                    .pb_1()
                    .child(Label::new(text).text_xs().text_color(warning))
            }))
            .into_any_element()
    }
}
