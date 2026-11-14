use super::*;

impl AppView {
    /// `code` is a language pack code, or empty to follow the system language.
    pub(super) fn set_language(&mut self, code: &str, window: &mut Window, cx: &mut Context<Self>) {
        self.settings.language = code.to_string();
        self.error = settings::save(&self.settings).err().map(SharedString::from);
        crate::i18n::apply(code);
        self.font_pickers = fonts_ui::FontPickers::new(&self.settings, window, cx);
        self.refresh_placeholders(window, cx);
        window.refresh();
        cx.refresh_windows();
        cx.notify();
    }

    /// Inputs keep the placeholder they were created with, so a language switch re-sets them.
    fn refresh_placeholders(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let inputs = [
            (&self.form.line, "app.search_or_address"),
            (&self.form.label, "app.label_example"),
            (&self.form.group, "app.no_group"),
            (&self.form.host, "app.host_placeholder"),
            (&self.form.user, "app.username"),
            (&self.form.password, "app.password"),
            (&self.form.key_path, "app.key_path"),
            (&self.form.forward_draft.listen, "ports.port_placeholder"),
            (&self.form.forward_draft.target, "ports.target_placeholder"),
            (&self.proxy_form.label, "app.proxy_label_example"),
            (&self.proxy_form.host, "app.host_placeholder"),
            (&self.proxy_form.user, "app.optional"),
            (&self.proxy_form.password, "app.password"),
            (&self.snippet_form.label, "snippets.name_placeholder"),
            (&self.vault_form.name, "app.vault_name_example"),
            (&self.vault_form.password, "app.master_password"),
            (&self.vault_form.repeat, "app.repeat_master_password"),
            (&self.vault_form.code, "app.vault_code"),
            (&self.vault_form.passphrase, "app.key_passphrase"),
            (&self.sync_input, "app.shared_folder"),
        ];
        for (input, key) in inputs {
            input.update(cx, |state, cx| state.set_placeholder(t!(key), window, cx));
        }
    }

    pub(super) fn language_block(&self, cx: &mut Context<Self>) -> AnyElement {
        use crate::i18n::Language;

        let chosen = self.settings.language.trim().to_string();
        let option = |id: &'static str, label: SharedString, code: &'static str| {
            Button::new(id)
                .ghost()
                .small()
                .selected(chosen == code)
                .label(label)
                .on_click(cx.listener(move |this, _, window, cx| this.set_language(code, window, cx)))
        };
        let system = crate::i18n::system_language();

        Self::section(t!("settings.language.title"), cx)
            .child(
                h_flex()
                    .gap_1()
                    .flex_wrap()
                    .child(option(
                        "language-system",
                        t!("settings.language.system", language = system.native_name()).into(),
                        "",
                    ))
                    .children(Language::ALL.into_iter().map(|language| {
                        option(language.code(), language.native_name().into(), language.code())
                    })),
            )
            .into_any_element()
    }

    pub(super) fn nudge_font_size(&mut self, steps: f32, cx: &mut Context<Self>) {
        if !self.settings.nudge_font_size(steps) {
            return;
        }
        self.error = settings::save(&self.settings).err().map(SharedString::from);
        self.apply_appearance(cx);
    }

    pub(super) fn set_prediction(
        &mut self,
        policy: crate::term::predict::Policy,
        cx: &mut Context<Self>,
    ) {
        self.settings.set_prediction(policy);
        self.error = settings::save(&self.settings).err().map(SharedString::from);
        self.apply_appearance(cx);
    }

    pub(super) fn nudge_opacity(
        &mut self,
        steps: i32,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !self.settings.nudge_opacity(steps) {
            return;
        }
        self.error = settings::save(&self.settings).err().map(SharedString::from);
        crate::ui::theme::apply(&self.settings, Some(window), cx);
        self.apply_appearance(cx);
    }

    pub(super) fn toggle_blur(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.settings.blur = !self.settings.blur;
        self.error = settings::save(&self.settings).err().map(SharedString::from);
        crate::ui::theme::apply(&self.settings, Some(window), cx);
        self.apply_appearance(cx);
    }

    pub(super) fn opacity_block(&self, cx: &mut Context<Self>) -> AnyElement {
        let muted = cx.theme().muted_foreground;
        let percent = self.settings.terminal_opacity;
        let solid = percent >= 100;
        Self::section(t!("settings.opacity.title"), cx)
            .child(
                h_flex()
                    .gap_3()
                    .items_center()
                    .child(Self::stepper(
                        "opacity",
                        format!("{percent} %"),
                        percent > settings::MIN_OPACITY,
                        !solid,
                        Box::new(|this, window, cx| this.nudge_opacity(-1, window, cx)),
                        Box::new(|this, window, cx| this.nudge_opacity(1, window, cx)),
                        cx,
                    ))
                    .child(
                        Checkbox::new("opacity-blur")
                            .small()
                            .checked(self.settings.blur)
                            .label(t!("settings.opacity.blur").to_string())
                            .tooltip(if crate::platform::blur_supported() {
                                t!("settings.opacity.blur_tooltip")
                            } else {
                                t!("settings.opacity.blur_unavailable")
                            })
                            .disabled(solid || !crate::platform::blur_supported())
                            .on_click(cx.listener(|this, _: &bool, window, cx| {
                                this.toggle_blur(window, cx)
                            })),
                    ),
            )
            .child(
                Label::new(if solid {
                    t!("settings.opacity.note_solid")
                } else {
                    t!("settings.opacity.note_partial")
                })
                .text_xs()
                .text_color(muted),
            )
            .into_any_element()
    }

    pub(super) fn prediction_block(&self, cx: &mut Context<Self>) -> AnyElement {
        use crate::term::predict::Policy;

        let muted = cx.theme().muted_foreground;
        let current = self.settings.prediction();
        let latency = self
            .active
            .and_then(|index| self.tabs.get(index))
            .and_then(SessionTab::terminal)
            .and_then(|view| view.read(cx).echo_latency());

        let option = |id: &'static str,
                      label: SharedString,
                      tooltip: SharedString,
                      policy: Policy| {
            Button::new(id)
                .ghost()
                .small()
                .selected(current == policy)
                .label(label)
                .tooltip(tooltip)
                .on_click(cx.listener(move |this, _, _window, cx| this.set_prediction(policy, cx)))
        };

        let status = match latency {
            Some(latency) => t!("settings.prediction.latency", ms = latency.as_millis()).to_string(),
            None => t!("settings.prediction.latency_unknown").to_string(),
        };

        Self::section(t!("settings.prediction.title"), cx)
            .child(
                h_flex()
                    .gap_1()
                    .child(option(
                        "prediction-adaptive",
                        t!("settings.prediction.adaptive").into(),
                        t!("settings.prediction.adaptive_tooltip").into(),
                        Policy::Adaptive,
                    ))
                    .child(option(
                        "prediction-always",
                        t!("settings.prediction.always").into(),
                        t!("settings.prediction.always_tooltip").into(),
                        Policy::Always,
                    ))
                    .child(option(
                        "prediction-never",
                        t!("settings.prediction.never").into(),
                        t!("settings.prediction.never_tooltip").into(),
                        Policy::Never,
                    )),
            )
            .child(
                Label::new(t!("settings.prediction.note"))
                .text_xs()
                .text_color(muted),
            )
            .child(
                Label::new(SharedString::from(status))
                    .text_xs()
                    .text_color(muted),
            )
            .into_any_element()
    }

    /// `id` is a shell from `crate::shells`, or empty for the system's default.
    fn set_local_shell(&mut self, id: String, cx: &mut Context<Self>) {
        self.settings.local_shell = id;
        self.error = settings::save(&self.settings).err().map(SharedString::from);
        cx.notify();
    }

    /// The shell of new local terminals.
    pub(super) fn shell_block(&self, cx: &mut Context<Self>) -> AnyElement {
        let section = Self::section(t!("settings.shell.title"), cx);
        let Some(shells) = crate::shells::found() else {
            return section
                .child(Self::hint(t!("rail.shells_searching"), cx))
                .into_any_element();
        };
        let chosen = self.settings.local_shell.clone();
        // A shell chosen earlier but gone now: the default one is used.
        let chosen = if shells.iter().any(|shell| shell.id == chosen) {
            chosen
        } else {
            String::new()
        };
        let default = crate::shells::default_id(shells);
        let default_name = shells
            .iter()
            .find(|shell| shell.id == default)
            .map(|shell| shell.name.clone())
            .unwrap_or_default();

        let option = |index: usize, label: String, id: String| {
            Button::new(("shell-option", index))
                .ghost()
                .small()
                .selected(chosen == id)
                .label(label)
                .on_click(cx.listener(move |this, _, _window, cx| this.set_local_shell(id.clone(), cx)))
        };

        section
            .child(
                h_flex()
                    .gap_1()
                    .flex_wrap()
                    .child(option(
                        0,
                        t!("settings.shell.system", shell = default_name).to_string(),
                        String::new(),
                    ))
                    .children(
                        shells
                            .iter()
                            .enumerate()
                            .map(|(index, shell)| option(index + 1, shell.name.clone(), shell.id.clone())),
                    ),
            )
            .child(Self::hint(t!("settings.shell.hint"), cx))
            .into_any_element()
    }

    fn set_autolock(&mut self, on: bool, cx: &mut Context<Self>) {
        self.settings.autolock = on;
        if on {
            let (now, wall) = (std::time::Instant::now(), crate::store::now_ms());
            for slot in &mut self.vaults {
                slot.session.rearm(now, wall);
            }
        }
        self.error = settings::save(&self.settings).err().map(SharedString::from);
        cx.notify();
    }

    pub(super) fn nudge_autolock(&mut self, steps: i32, cx: &mut Context<Self>) {
        let current = self.settings.autolock_minutes;
        let step = match current {
            0..=5 => 1,
            6..=30 => 5,
            31..=120 => 15,
            _ => 60,
        };
        let next = if steps < 0 {
            let step = match current.saturating_sub(1) {
                0..=5 => 1,
                6..=30 => 5,
                31..=120 => 15,
                _ => 60,
            };
            current.saturating_sub(step)
        } else {
            current.saturating_add(step)
        };

        if !self.settings.set_autolock_minutes(next) {
            return;
        }
        let timeout = self.settings.autolock_timeout();
        for slot in &mut self.vaults {
            slot.session.set_timeout(timeout);
        }
        self.error = settings::save(&self.settings).err().map(SharedString::from);
        cx.notify();
    }

    pub(super) fn apply_appearance(&mut self, cx: &mut Context<Self>) {
        let font_size = px(self.settings.font_size);
        let background = to_rgb(cx.theme().background);
        let foreground = to_rgb(cx.theme().foreground);
        let cursor = to_rgb(cx.theme().caret);
        let selection = to_rgb(cx.theme().primary);
        let selection_foreground = to_rgb(cx.theme().primary_foreground);

        let prediction = self.settings.prediction();
        for view in self.tabs.iter().flat_map(SessionTab::terminals) {
            view.update(cx, |view, cx| {
                view.set_appearance(
                    font_size,
                    background,
                    foreground,
                    cursor,
                    selection,
                    selection_foreground,
                    cx,
                );
                view.set_prediction(prediction, cx);
            });
        }
        cx.notify();
    }

    pub(super) fn settings_panel(&self, tab: SettingsTab, cx: &mut Context<Self>) -> AnyElement {
        let muted = cx.theme().muted_foreground;
        let warning = cx.theme().warning;
        let danger = cx.theme().danger;
        let size = self.settings.font_size;
        let minutes = self.settings.autolock_minutes;
        let autolock = self.settings.autolock;
        let has_os_key = self.vault().has_os_key();
        let vault_unlocked = self.vault().state().is_unlocked();
        let success = cx.theme().success;
        let current_slot = &self.vaults[self.current];
        let syncing_possible = vault_unlocked && current_slot.sync_path().is_some();
        let vault_name = current_slot.name.clone();
        let picker = self.vault_picker(cx);
        let current_id = self.current_id();

        v_flex()
            .py_2()
            .when(tab != SettingsTab::General, |this| {
                this.children(picker.map(|picker| div().pt_2().child(picker)))
            })
            .when(tab == SettingsTab::General, |this| {
                this.child(self.language_block(cx))
            })
            .when(tab == SettingsTab::General, |this| {
                this.child(self.theme_block(cx))
            })
            .when(tab == SettingsTab::General, |this| {
                this.child(self.opacity_block(cx))
            })
            .when(tab == SettingsTab::General, |this| {
                this.child(self.fonts_block(cx))
            })
            .when(tab == SettingsTab::General, |this| {
                this.child(
                    Self::section(t!("settings.font_size.title"), cx)
                        .child(Self::stepper(
                            "font",
                            t!("settings.font_size.value", size = format!("{size:.0}")).to_string(),
                            size > settings::MIN_FONT_SIZE,
                            size < settings::MAX_FONT_SIZE,
                            Box::new(|this, _window, cx| this.nudge_font_size(-1., cx)),
                            Box::new(|this, _window, cx| this.nudge_font_size(1., cx)),
                            cx,
                        ))
                        .child(Self::hint(t!("settings.font_size.hint"), cx)),
                )
            })
            .when(tab == SettingsTab::General, |this| {
                this.child(self.prediction_block(cx))
            })
            .when(tab == SettingsTab::General, |this| {
                this.child(self.shell_block(cx))
            })
            .when(tab == SettingsTab::General, |this| {
                this.child(self.tabs_block(cx))
            })
            .when(tab == SettingsTab::Security, |this| {
                this.child(
                    Self::section(t!("settings.autolock.title"), cx)
                        .child(
                            gpui_kit::component::checkbox::Checkbox::new("autolock-on")
                                .small()
                                .label(t!("settings.autolock.enable").to_string())
                                .checked(autolock)
                                .on_click(cx.listener(|this, checked: &bool, _window, cx| {
                                    this.set_autolock(*checked, cx)
                                })),
                        )
                        .when(autolock, |this| {
                            this.child(Self::hint(t!("settings.autolock.minutes_hint"), cx))
                                .child(Self::stepper(
                                    "autolock",
                                    t!("settings.autolock.minutes_value", minutes = minutes).to_string(),
                                    minutes > settings::MIN_AUTOLOCK_MINUTES,
                                    minutes < settings::MAX_AUTOLOCK_MINUTES,
                                    Box::new(|this, _window, cx| this.nudge_autolock(-1, cx)),
                                    Box::new(|this, _window, cx| this.nudge_autolock(1, cx)),
                                    cx,
                                ))
                        })
                        .child(
                            Label::new(if autolock {
                                t!("settings.autolock.note_on")
                            } else {
                                t!("settings.autolock.note_off")
                            })
                            .text_xs()
                            .text_color(muted),
                        ),
                )
            })
            .when(tab == SettingsTab::Security, |this| {
                this.child(
                    Self::section(t!("settings.os_key.title"), cx)
                        .child(Self::hint(
                            t!("settings.vault_line", name = vault_name.to_string()),
                            cx,
                        ))
                        .child(
                            Button::new("os-key-toggle")
                                .outline()
                                .w_full()
                                .label(if has_os_key {
                                    t!("settings.os_key.disable")
                                } else {
                                    t!("settings.os_key.enable")
                                })
                                .disabled(!has_os_key && !vault_unlocked)
                                .on_click(
                                    cx.listener(|this, _, _window, cx| this.toggle_os_key(cx)),
                                ),
                        )
                        .child(
                            Label::new(if has_os_key {
                                t!("settings.os_key.note_on")
                            } else if vault_unlocked {
                                t!("settings.os_key.note_available")
                            } else {
                                t!("settings.os_key.note_locked")
                            })
                            .text_xs()
                            .text_color(muted),
                        )
                        .when(has_os_key, |this| {
                            this.child(
                                Label::new(t!("settings.os_key.warning"))
                                .text_xs()
                                .text_color(warning),
                            )
                        })
                        .children(
                            self.vault_error
                                .clone()
                                .map(|error| Label::new(error).text_xs().text_color(danger)),
                        ),
                )
            })
            .when(tab == SettingsTab::Sync, |this| {
                this.child(
                    Self::section(t!("settings.sync.title"), cx)
                        .child(Self::hint(
                            t!("settings.vault_line", name = vault_name.to_string()),
                            cx,
                        ))
                        .child(div().w_full().child(Input::new(&self.sync_input)))
                        .child(
                            Button::new("sync-apply")
                                .outline()
                                .w_full()
                                .label(t!("settings.sync.apply"))
                                .on_click(
                                    cx.listener(|this, _, _window, cx| this.apply_sync_folder(cx)),
                                ),
                        )
                        .child(
                            Button::new("sync-now")
                                .ghost()
                                .w_full()
                                .label(if self.syncing.contains(&current_id) {
                                    t!("settings.sync.syncing")
                                } else {
                                    t!("settings.sync.now")
                                })
                                .tooltip(if syncing_possible {
                                    t!("settings.sync.now_tooltip")
                                } else {
                                    t!("settings.sync.now_unavailable")
                                })
                                .disabled(self.syncing.contains(&current_id) || !syncing_possible)
                                .on_click(cx.listener(|this, _, _window, cx| {
                                    let id = this.current_id();
                                    this.sync_now(&id, cx)
                                })),
                        )
                        .child(
                            Label::new(t!("settings.sync.note"))
                            .text_xs()
                            .text_color(muted),
                        )
                        .child(
                            Label::new(t!("settings.sync.note_excluded"))
                            .text_xs()
                            .text_color(muted),
                        )
                        .children(
                            self.sync_status
                                .clone()
                                .map(|status| Label::new(status).text_xs().text_color(success)),
                        )
                        .children(
                            self.sync_error
                                .clone()
                                .map(|error| Label::new(error).text_xs().text_color(warning)),
                        ),
                )
            })
            .when(tab == SettingsTab::General, |this| {
                this.child(
                    Self::section(t!("settings.data.title"), cx)
                        .children(self.listed().map(|(_, slot)| {
                            Label::new(t!(
                                "settings.data.vault",
                                name = slot.name.to_string(),
                                path = slot.root().display().to_string()
                            ))
                            .text_xs()
                            .text_color(muted)
                        }))
                        .child(
                            Label::new(t!(
                                "settings.data.settings",
                                path = settings::directory()
                                    .map(|dir| dir.display().to_string())
                                    .unwrap_or_else(|| t!("settings.data.unknown").to_string())
                            ))
                            .text_xs()
                            .text_color(muted),
                        ),
                )
            })
            .into_any_element()
    }
}
