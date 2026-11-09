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

        let name = self.vault_form.name.read(cx).value().trim().to_string();
        if name.is_empty() {
            self.vault_error = Some(t!("vaults.name_required").to_string().into());
            cx.notify();
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
            self.import_pending().to_vec()
        } else {
            Vec::new()
        };
        let imported = !import.is_empty();
        let id = self.current_id();

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

        self.vault_task = Some(cx.spawn(async move |this: gpui_kit::WeakEntity<Self>, cx| {
            let prepared = prepare.await;
            this.update(cx, |this, cx| {
                this.vault_busy = false;
                let installed = match this.vault_ix(&id) {
                    Some(ix) => prepared
                        .and_then(|prepared| this.vaults[ix].session.install(prepared, import))
                        .map(|code| (ix, code)),
                    None => Err(anyhow::anyhow!(t!("vaults.deleted_during_creation").to_string())),
                };
                match installed {
                    Ok((ix, code)) => {
                        let slot = &mut this.vaults[ix];
                        slot.name = name;
                        slot.draft = false;
                        this.current = ix;
                        this.save_registry();
                        let id = this.vaults[ix].id.clone();
                        this.reconcile_vault_name(&id);
                        this.show_recovery_code(&code, imported, cx);
                    }
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
        imported: bool,
        _cx: &mut Context<Self>,
    ) {
        use vault::secrecy::ExposeSecret;

        let shown = code.format_for_user();
        let text = String::from_utf8_lossy(shown.expose_secret()).into_owned();

        if imported
            && self.vault_form.import
            && let (Some(path), _) = VaultSession::legacy_hosts()
        {
            match migrate::remove_legacy(&path) {
                Ok(()) => {
                    self.vault_form.notice = Some(vault_ui::migration_warning().into());
                    self.pending_import.clear();
                }
                Err(error) => {
                    self.vault_error = Some(SharedString::from(
                        t!("vaults.import_transfer_error", error = format!("{error:#}")).to_string(),
                    ));
                }
            }
        }

        self.stage = Some(Stage::Recovery {
            code: SharedString::from(text),
            confirmed: false,
        });
        let id = self.current_id();
        self.collect_vault_warnings(&id);
    }

    fn adopt_into(&mut self, id: &str, data_key: vault::DataKey) -> anyhow::Result<()> {
        match self.vault_ix(id) {
            Some(ix) => self.vaults[ix].session.adopt(data_key),
            None => anyhow::bail!(t!("vaults.vault_deleted").to_string()),
        }
    }

    pub(super) fn unlock_vault(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.vault_busy {
            return;
        }
        let account = match self.vault().locked_account() {
            Ok(account) => account,
            Err(error) => {
                self.vault_error = Some(SharedString::from(format!("{error:#}")));
                cx.notify();
                return;
            }
        };
        let id = self.current_id();
        let remember = self.vault_form.remember;

        let mut secret = Self::take_password(&self.vault_form.password, window, cx);

        let derive = cx.background_executor().spawn(async move {
            let result = crate::vault_session::derive_from_password(&account, &secret);
            secret.zeroize();
            result
        });

        self.vault_busy = true;
        self.vault_error = None;
        cx.notify();

        self.vault_task = Some(cx.spawn(async move |this: gpui_kit::WeakEntity<Self>, cx| {
            let derived = derive.await;
            this.update(cx, |this, cx| {
                this.vault_busy = false;
                let result = derived.and_then(|data_key| this.adopt_into(&id, data_key));
                let unlocked = result.is_ok();
                this.after_unlock(&id, result, cx);
                if unlocked
                    && remember
                    && let Some(ix) = this.vault_ix(&id)
                {
                    this.vault_form.remember = false;
                    if let Err(error) = this.vaults[ix].session.enable_os_key(&OsKeychain) {
                        this.vault_error = Some(SharedString::from(
                            t!("vaults.remember_failed", error = format!("{error:#}")).to_string(),
                        ));
                        cx.notify();
                    }
                }
            })
            .ok();
        }));
    }

    pub(super) fn unlock_with_code(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.vault_busy {
            return;
        }
        let account = match self.vault().locked_account() {
            Ok(account) => account,
            Err(error) => {
                self.vault_error = Some(SharedString::from(format!("{error:#}")));
                cx.notify();
                return;
            }
        };
        let id = self.current_id();

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

        self.vault_task = Some(cx.spawn(async move |this: gpui_kit::WeakEntity<Self>, cx| {
            let derived = derive.await;
            this.update(cx, |this, cx| {
                this.vault_busy = false;
                let result = derived.and_then(|data_key| this.adopt_into(&id, data_key));
                this.after_unlock(&id, result, cx);
            })
            .ok();
        }));
    }

    /// Unlock with the key from the system credential store. `interactive` — via the button
    /// on the vault screen (with a busy indicator); otherwise silently, at startup.
    pub(super) fn unlock_with_os_key_for(
        &mut self,
        id: &str,
        interactive: bool,
        cx: &mut Context<Self>,
    ) {
        if interactive && self.vault_busy {
            return;
        }
        let Some(ix) = self.vault_ix(id) else {
            return;
        };
        let account = match self.vaults[ix].session.locked_account() {
            Ok(account) => account,
            Err(error) => {
                if ix == self.current {
                    self.vault_error = Some(SharedString::from(format!("{error:#}")));
                    cx.notify();
                }
                return;
            }
        };

        let derive = cx
            .background_executor()
            .spawn(async move { crate::vault_session::derive_from_os_key(&account, &OsKeychain) });

        if interactive {
            self.vault_busy = true;
            self.vault_error = None;
        } else {
            self.os_unlocking.push(id.to_owned());
        }
        cx.notify();

        let id = id.to_owned();
        let task = cx.spawn(async move |this: gpui_kit::WeakEntity<Self>, cx| {
            let derived = derive.await;
            this.update(cx, |this, cx| {
                if interactive {
                    this.vault_busy = false;
                }
                let result = derived.and_then(|data_key| this.adopt_into(&id, data_key));
                this.after_unlock(&id, result, cx);
            })
            .ok();
        });
        if interactive {
            self.vault_task = Some(task);
        } else {
            self.os_tasks.push(task);
        }
    }

    pub(super) fn toggle_os_key(&mut self, cx: &mut Context<Self>) {
        let current = self.current;
        let result = if self.vaults[current].session.has_os_key() {
            self.vaults[current].session.disable_os_key(&OsKeychain)
        } else {
            self.vaults[current].session.enable_os_key(&OsKeychain)
        };

        self.vault_error = match result {
            Ok(()) => None,
            Err(error) => Some(SharedString::from(format!("{error:#}"))),
        };
        cx.notify();
    }

    pub(super) fn after_unlock(
        &mut self,
        id: &str,
        result: anyhow::Result<()>,
        cx: &mut Context<Self>,
    ) {
        self.os_unlocking.retain(|known| known != id);
        let is_current = self.vault_ix(id) == Some(self.current);
        match result {
            Ok(()) => {
                if is_current {
                    self.stage = None;
                    self.vault_error = None;
                }
                self.collect_vault_warnings(id);
                self.reconcile_vault_name(id);
                self.sync_key_files(id);
                self.sync_can_save_secrets(cx);
                self.start_sync_watch(id, cx);
                self.sync_now(id, cx);
            }
            Err(error) => {
                if is_current {
                    self.vault_error = Some(SharedString::from(format!("{error:#}")));
                }
            }
        }
        cx.notify();
    }

    pub(super) fn collect_vault_warnings(&mut self, id: &str) {
        let Some(unlocked) = self.unlocked_of(id) else {
            return;
        };
        let found: Vec<SharedString> = unlocked
            .warnings
            .iter()
            .chain(unlocked.broken.iter())
            .map(|warning| SharedString::from(warning.clone()))
            .collect();
        for warning in found {
            if !self.vault_warnings.contains(&warning) {
                self.vault_warnings.push(warning);
            }
        }
    }

    pub(super) fn vault_panel(&self, cx: &mut Context<Self>) -> AnyElement {
        let muted = cx.theme().muted_foreground;
        let danger = cx.theme().danger;
        let warning = cx.theme().warning;
        let border = cx.theme().border;

        let Some(stage) = self.stage.clone() else {
            return div().into_any_element();
        };

        if let Some(reason) = self.vault().state().broken_reason() {
            return v_flex()
                .px_3()
                .pt_3()
                .gap_2()
                .child(
                    Label::new(t!("vaults.read_failed_title").to_string())
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
                    Label::new(SharedString::from(
                        t!(
                            "vaults.vault_file_note",
                            path = self.vault().store().root().display().to_string()
                        )
                        .to_string(),
                    ))
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
                let import_count = self.import_pending().len();
                let can_cancel = self.vaults.iter().any(|slot| !slot.draft);

                v_flex()
                    .gap_2()
                    .child(
                        Label::new(SharedString::from(vault_ui::create_explainer(import_count)))
                            .text_xs()
                            .text_color(muted),
                    )
                    .child(Self::field_label(t!("vaults.field_name"), muted))
                    .child(Input::new(&self.vault_form.name))
                    .child(Input::new(&self.vault_form.password))
                    .child(Input::new(&self.vault_form.repeat))
                    .when(import_count > 0, |this| {
                        this.child(
                            Button::new("vault-import")
                                .ghost()
                                .xsmall()
                                .selected(self.vault_form.import)
                                .label(SharedString::from(
                                    t!("vaults.import_entries", count = import_count).to_string(),
                                ))
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
                                t!("vaults.tuning").to_string()
                            } else {
                                t!("vaults.create").to_string()
                            })
                            .main_action(verdict.is_ok() && !self.vault_busy)
                            .on_click(
                                cx.listener(|this, _, window, cx| this.create_vault(window, cx)),
                            ),
                    )
                    .when(can_cancel, |this| {
                        this.child(
                            Button::new("vault-create-cancel")
                                .ghost()
                                .xsmall()
                                .label(t!("vaults.cancel").to_string())
                                .disabled(self.vault_busy)
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.cancel_new_vault(window, cx)
                                })),
                        )
                    })
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
                        Label::new(vault_ui::recovery_explainer())
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
                            .label(t!("vaults.recovery_saved").to_string())
                            .tooltip(t!("vaults.recovery_saved_tooltip").to_string())
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
                            .label(t!("vaults.continue").to_string())
                            .tooltip(if confirmed {
                                t!("vaults.continue_ready").to_string()
                            } else {
                                t!("vaults.continue_confirm").to_string()
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

            Stage::Unlock if self.os_unlocking.contains(&self.vaults[self.current].id) => v_flex().gap_2().child(
                Label::new(t!("vaults.unlocking_os").to_string())
                    .text_sm()
                    .text_color(muted),
            ),

            Stage::Unlock => v_flex()
                .gap_2()
                .child(Label::new(SharedString::from(stage.subtitle())).text_xs().text_color(muted))
                .child(Input::new(&self.vault_form.password))
                .when(!self.vault().has_os_key(), |this| {
                    this.child(
                        gpui_kit::component::checkbox::Checkbox::new("vault-remember")
                            .small()
                            .label(t!("vaults.remember").to_string())
                            .checked(self.vault_form.remember)
                            .tooltip(t!("vaults.remember_tooltip").to_string())
                            .on_click(cx.listener(|this, checked: &bool, _window, cx| {
                                this.vault_form.remember = *checked;
                                cx.notify();
                            })),
                    )
                })
                .child(
                    Button::new("vault-unlock")
                        .w_full()
                        .label(if self.vault_busy {
                            t!("vaults.unlocking").to_string()
                        } else {
                            t!("vaults.unlock").to_string()
                        })
                        .main_action(!self.vault_busy)
                        .on_click(cx.listener(|this, _, window, cx| this.unlock_vault(window, cx))),
                )
                .when(self.vault_busy, |this| {
                    this.child(
                        Label::new(t!("vaults.derive_note").to_string())
                        .text_xs()
                        .text_color(muted),
                    )
                })
                .when(self.vault().has_os_key(), |this| {
                    this.child(
                        Button::new("vault-unlock-os")
                            .outline()
                            .w_full()
                            .label(t!("vaults.unlock_nopass").to_string())
                            .tooltip(t!("vaults.unlock_nopass_tooltip").to_string())
                            .disabled(self.vault_busy)
                            .on_click(cx.listener(|this, _, _window, cx| {
                                let id = this.current_id();
                                this.unlock_with_os_key_for(&id, true, cx)
                            })),
                    )
                })
                .child(
                    Button::new("vault-forgot")
                        .ghost()
                        .xsmall()
                        .label(t!("vaults.forgot").to_string())
                        .tooltip(t!("vaults.forgot_tooltip").to_string())
                        .on_click(cx.listener(|this, _, _window, cx| {
                            this.stage = Some(Stage::UnlockWithCode);
                            this.error = None;
                            cx.notify();
                        })),
                ),

            Stage::UnlockWithCode => v_flex()
                .gap_2()
                .child(
                    Label::new(t!("vaults.code_hint").to_string())
                    .text_xs()
                    .text_color(muted),
                )
                .child(Input::new(&self.vault_form.code))
                .child(
                    Button::new("vault-unlock-code")
                        .w_full()
                        .label(if self.vault_busy {
                            t!("vaults.unlocking").to_string()
                        } else {
                            t!("vaults.unlock").to_string()
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
                        .label(t!("vaults.sign_in_password").to_string())
                        .on_click(cx.listener(|this, _, _window, cx| {
                            this.stage = Some(Stage::Unlock);
                            this.error = None;
                            cx.notify();
                        })),
                ),
        };

        let named = !matches!(stage, Stage::Create);
        v_flex()
            .child(Self::panel_title(stage.title(), muted))
            .when(named, |this| {
                this.child(
                    div().px_3().pb_2().child(
                        Label::new(SharedString::from(
                            t!("vaults.vault_named", name = self.vaults[self.current].name)
                                .to_string(),
                        ))
                        .text_xs()
                        .text_color(muted),
                    ),
                )
            })
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
