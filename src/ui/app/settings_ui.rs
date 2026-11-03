use super::*;

impl AppView {
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

    fn set_scheme(
        &mut self,
        scheme: crate::ui::theme::Scheme,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.settings.set_scheme(scheme);
        self.error = settings::save(&self.settings).err().map(SharedString::from);
        crate::ui::theme::apply(&self.settings, Some(window), cx);
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
        Self::section("Прозрачность терминала", cx)
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
                        Button::new("opacity-blur")
                            .ghost()
                            .small()
                            .selected(self.settings.blur)
                            .label("Размытие фона")
                            .tooltip(if crate::platform::blur_supported() {
                                "Размывает изображение под окном терминала для лучшей читаемости."
                            } else {
                                "Недоступно в Windows 10: размытие замедляет перемещение и изменение размера окна."
                            })
                            .disabled(solid || !crate::platform::blur_supported())
                            .on_click(
                                cx.listener(|this, _, window, cx| this.toggle_blur(window, cx)),
                            ),
                    ),
            )
            .child(
                Label::new(if solid {
                    "100 % — непрозрачный фон. При меньшем значении сквозь терминал виден рабочий стол."
                } else {
                    "Прозрачность применяется только к фону терминала."
                })
                .text_xs()
                .text_color(muted),
            )
            .into_any_element()
    }

    pub(super) fn theme_block(&self, cx: &mut Context<Self>) -> AnyElement {
        use crate::ui::theme::Scheme;
        let current = self.settings.scheme();

        Self::section("Оформление", cx)
            .child(
                h_flex().gap_1().children(
                    [
                        Scheme::Cratty,
                        Scheme::Synthwave,
                        Scheme::Graphite,
                        Scheme::Light,
                    ]
                    .into_iter()
                    .map(|scheme| {
                        Button::new(SharedString::from(format!("theme-{}", scheme.as_str())))
                            .ghost()
                            .small()
                            .selected(current == scheme)
                            .label(scheme.title())
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.set_scheme(scheme, window, cx)
                            }))
                    }),
                ),
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
                      label: &'static str,
                      tooltip: &'static str,
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
            Some(latency) => format!("Задержка эха в текущем сеансе: {} мс.", latency.as_millis()),
            None => {
                "Задержка эха ещё не измерена. Измерение выполняется по первым введённым символам."
                    .to_string()
            }
        };

        Self::section("Предсказание ввода", cx)
            .child(
                h_flex()
                    .gap_1()
                    .child(option(
                        "prediction-adaptive",
                        "Адаптивно",
                        "Только при задержке эха более 30 мс",
                        Policy::Adaptive,
                    ))
                    .child(option(
                        "prediction-always",
                        "Всегда",
                        "На любом соединении",
                        Policy::Always,
                    ))
                    .child(option(
                        "prediction-never",
                        "Никогда",
                        "Символ отображается после ответа сервера",
                        Policy::Never,
                    )),
            )
            .child(
                Label::new(
                    "Введённые символы отображаются сразу и подчёркиваются до подтверждения сервером. Ввод паролей не отображается: после Enter символы появляются только после ответа сервера.",
                )
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
        self.vault.set_timeout(self.settings.autolock_timeout());
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
        let has_os_key = self.vault.has_os_key();
        let vault_unlocked = self.vault.state().is_unlocked();
        let success = cx.theme().success;
        let syncing_possible = vault_unlocked && self.settings.sync_folder().is_some();

        v_flex()
            .py_2()
            .when(tab == SettingsTab::General, |this| {
                this.child(self.theme_block(cx))
            })
            .when(tab == SettingsTab::General, |this| {
                this.child(self.opacity_block(cx))
            })
            .when(tab == SettingsTab::General, |this| {
                this.child(
                    Self::section("Размер шрифта в терминале", cx)
                        .child(Self::stepper(
                            "font",
                            format!("{size:.0} px"),
                            size > settings::MIN_FONT_SIZE,
                            size < settings::MAX_FONT_SIZE,
                            Box::new(|this, _window, cx| this.nudge_font_size(-1., cx)),
                            Box::new(|this, _window, cx| this.nudge_font_size(1., cx)),
                            cx,
                        ))
                        .child(Self::hint(
                            "Применяется ко всем открытым сеансам",
                            cx,
                        )),
                )
            })
            .when(tab == SettingsTab::General, |this| {
                this.child(self.prediction_block(cx))
            })
            .when(tab == SettingsTab::Security, |this| {
                this.child(
                    Self::section("Блокировать хранилище после бездействия", cx)
                        .child(Self::stepper(
                            "autolock",
                            format!("{minutes} мин"),
                            minutes > settings::MIN_AUTOLOCK_MINUTES,
                            minutes < settings::MAX_AUTOLOCK_MINUTES,
                            Box::new(|this, _window, cx| this.nudge_autolock(-1, cx)),
                            Box::new(|this, _window, cx| this.nudge_autolock(1, cx)),
                            cx,
                        ))
                        .child(
                            Label::new(
                                "Хранилище также блокируется после перехода компьютера в спящий режим. Открытые сеансы при этом продолжают работать.",
                            )
                            .text_xs()
                            .text_color(muted),
                        ),
                )
            })
            .when(tab == SettingsTab::Security, |this| {
                this.child(
                    Self::section("Разблокировка без пароля на этом компьютере", cx)
                        .child(
                            Button::new("os-key-toggle")
                                .outline()
                                .w_full()
                                .label(if has_os_key {
                                    "Отключить"
                                } else {
                                    "Включить"
                                })
                                .disabled(!has_os_key && !vault_unlocked)
                                .on_click(
                                    cx.listener(|this, _, _window, cx| this.toggle_os_key(cx)),
                                ),
                        )
                        .child(
                            Label::new(if has_os_key {
                                "Хранилище разблокируется без пароля на этом компьютере. Ключ хранится в системном хранилище учётных данных: Keychain (macOS), диспетчер учётных данных (Windows), Secret Service (Linux)."
                            } else if vault_unlocked {
                                "Ключ будет сохранён в системном хранилище учётных данных. Мастер-пароль и код восстановления продолжат действовать; функцию можно отключить в любой момент."
                            } else {
                                "Доступно только при разблокированном хранилище."
                            })
                            .text_xs()
                            .text_color(muted),
                        )
                        .when(has_os_key, |this| {
                            this.child(
                                Label::new(
                                    "Ключ защищён учётной записью операционной системы: после входа в систему он доступен программам, запущенным от вашего имени.",
                                )
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
                    Self::section("Синхронизация через папку", cx)
                        .child(div().w_full().child(Input::new(&self.sync_input)))
                        .child(
                            Button::new("sync-apply")
                                .outline()
                                .w_full()
                                .label("Применить")
                                .on_click(
                                    cx.listener(|this, _, _window, cx| this.apply_sync_folder(cx)),
                                ),
                        )
                        .child(
                            Button::new("sync-now")
                                .ghost()
                                .w_full()
                                .label(if self.syncing {
                                    "Синхронизация…"
                                } else {
                                    "Синхронизировать сейчас"
                                })
                                .tooltip(if syncing_possible {
                                    "Получить изменения из папки и записать свои"
                                } else {
                                    "Требуются разблокированное хранилище и указанная папка"
                                })
                                .disabled(self.syncing || !syncing_possible)
                                .on_click(cx.listener(|this, _, _window, cx| this.sync_now(cx))),
                        )
                        .child(
                            Label::new(concat!(
                                "Записи сохраняются в папку в зашифрованном виде и могут передаваться через Dropbox, Syncthing или сетевой диск. Пустой путь отключает синхронизацию.",
                                "",
                                ""
                            ))
                            .text_xs()
                            .text_color(muted),
                        )
                        .child(
                            Label::new(concat!(
                                "Записи с отметкой «Не синхронизировать» в папку не сохраняются.",
                                ""
                            ))
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
                    Self::section("Расположение данных", cx)
                        .child(
                            Label::new(SharedString::from(format!(
                                "Хранилище: {}",
                                self.vault.store().root().display()
                            )))
                            .text_xs()
                            .text_color(muted),
                        )
                        .child(
                            Label::new(SharedString::from(format!(
                                "Настройки: {}",
                                settings::directory()
                                    .map(|dir| dir.display().to_string())
                                    .unwrap_or_else(|| "Каталог не определён".into())
                            )))
                            .text_xs()
                            .text_color(muted),
                        ),
                )
            })
            .into_any_element()
    }
}
