use super::*;

impl AppView {
    pub(super) fn toggle_agent(&mut self, cx: &mut Context<Self>) {
        if self.agent.is_some() {
            self.stop_agent(cx);
            return;
        }

        let address = match ssh_agent::default_address() {
            Ok(address) => address,
            Err(error) => {
                self.agent_error = Some(SharedString::from(format!("{error:#}")));
                cx.notify();
                return;
            }
        };

        match ssh_agent::spawn(address) {
            Ok((running, asks)) => {
                self.agent = Some(running);
                self.agent_error = None;
                self.agent_task =
                    Some(cx.spawn(async move |this: gpui_kit::WeakEntity<Self>, cx| {
                        let mut asks = asks;
                        while let Some(ask) = asks.next().await {
                            if this
                                .update(cx, |this, cx| this.on_agent_ask(ask, cx))
                                .is_err()
                            {
                                return;
                            }
                        }
                    }));
            }
            Err(error) => self.agent_error = Some(SharedString::from(format!("{error:#}"))),
        }
        cx.notify();
    }

    pub(super) fn stop_agent(&mut self, cx: &mut Context<Self>) {
        self.agent = None;
        self.agent_task = None;
        self.refuse_all_signs();
        self.agent_error = None;
        cx.notify();
    }

    pub(super) fn agent_identities(&self) -> Vec<::agent::Identity> {
        let mut seen: Vec<Vec<u8>> = Vec::new();
        let mut identities = Vec::new();
        for entry in self.all_vault_keys() {
            if seen.contains(&entry.key.public) {
                continue;
            }
            seen.push(entry.key.public.clone());
            identities.push(::agent::Identity::new(
                entry.key.public.clone(),
                entry.key.title(),
            ));
        }
        identities
    }

    pub(super) fn agent_address(&self) -> Option<ssh_agent::Address> {
        self.agent.as_ref().map(|agent| agent.address().clone())
    }

    pub(super) fn vault_keys(&self) -> Vec<StoredKey> {
        self.current_unlocked()
            .map(|unlocked| unlocked.keys())
            .unwrap_or_default()
    }

    pub(super) fn all_vault_keys(&self) -> Vec<StoredKey> {
        self.unlocked_slots()
            .filter_map(|slot| slot.session.unlocked())
            .flat_map(|unlocked| unlocked.keys())
            .collect()
    }

    fn find_key_anywhere(&self, public: &[u8]) -> Option<StoredKey> {
        self.unlocked_slots()
            .filter_map(|slot| slot.session.unlocked())
            .find_map(|unlocked| unlocked.find_key_by_public(public))
    }

    pub(super) fn on_agent_ask(&mut self, ask: ssh_agent::Ask, cx: &mut Context<Self>) {
        match ask {
            ssh_agent::Ask::Identities { reply } => {
                let _ = reply.send(self.agent_identities());
            }
            ssh_agent::Ask::Sign(ask) => {
                let Some(entry) = self.find_key_anywhere(&ask.public) else {
                    let _ = ask.reply.send(None);
                    return;
                };

                let key_title = SharedString::from(entry.key.title());
                let target = self.sign_target(ask.bound.as_ref());
                self.sign_queue.push_back(PendingSign {
                    ask,
                    key_title,
                    target,
                });
                cx.notify();
            }
        }
    }

    pub(super) fn sign_target(&self, bound: Option<&ssh_agent::Bound>) -> SignTarget {
        let Some(bound) = bound else {
            return SignTarget::Unknown;
        };
        let name = ssh_agent::keys::parse_public(&bound.host_key)
            .ok()
            .and_then(|key| self.name_for_host_key(&key))
            .map(SharedString::from);
        SignTarget::Proven {
            name,
            fingerprint: SharedString::from(bound.fingerprint.clone()),
            forwarding: bound.is_forwarding,
        }
    }

    pub(super) fn name_for_host_key(&self, key: &russh::keys::PublicKey) -> Option<String> {
        let policy = crate::ssh::known_hosts::HostKeyPolicy::KnownHosts;
        let hosts: Vec<(String, u16)> = self
            .unlocked_slots()
            .filter_map(|slot| slot.session.unlocked())
            .flat_map(|unlocked| unlocked.hosts())
            .map(|entry| (entry.host.host, entry.host.port))
            .take(256)
            .collect();

        for (host, port) in hosts {
            if host.trim().is_empty() {
                continue;
            }
            if crate::ssh::known_hosts::verify(&policy, &host, port, key).is_trusted() {
                return Some(host);
            }
        }
        None
    }

    pub(super) fn approve_sign(&mut self, cx: &mut Context<Self>) {
        let Some(pending) = self.sign_queue.pop_front() else {
            return;
        };

        let answer = self.sign_with_vault(&pending);
        if answer.is_none() {
            self.error = Some(SharedString::from(
                "Не удалось выполнить подпись ключом из хранилища.",
            ));
        }
        let _ = pending.ask.reply.send(answer);

        self.touch_all();
        cx.notify();
    }

    pub(super) fn sign_with_vault(&self, pending: &PendingSign) -> Option<Vec<u8>> {
        let entry = self.find_key_anywhere(&pending.ask.public)?;
        let private = entry.key.private()?;
        let text = std::str::from_utf8(private.expose()).ok()?;
        let key = ssh_agent::keys::decode_private(text, None).ok()?;
        ssh_agent::keys::sign(&key, &pending.ask.data, pending.ask.hash).ok()
    }

    pub(super) fn refuse_sign(&mut self, cx: &mut Context<Self>) {
        if let Some(pending) = self.sign_queue.pop_front() {
            let _ = pending.ask.reply.send(None);
        }
        cx.notify();
    }

    pub(super) fn refuse_all_signs(&mut self) {
        for pending in std::mem::take(&mut self.sign_queue) {
            let _ = pending.ask.reply.send(None);
        }
    }

    pub(super) fn begin_import(
        &mut self,
        key: &KeyEntry,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.vault_form
            .passphrase
            .update(cx, |state, cx| state.set_value("", window, cx));
        self.importing = Some(PendingImport {
            path: key.path.clone(),
            name: SharedString::from(key.name.clone()),
            encrypted: key.encrypted,
        });
        self.error = None;
        cx.notify();
    }

    pub(super) fn finish_import(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(pending) = self.importing.take() else {
            return;
        };
        let mut passphrase = Self::take_password(&self.vault_form.passphrase, window, cx);

        let result = self.import_key(&pending, &passphrase);
        passphrase.zeroize();

        match result {
            Ok(()) => self.error = None,
            Err(error) => {
                self.error = Some(SharedString::from(format!("{error:#}")));
                self.importing = Some(pending);
            }
        }
        cx.notify();
    }

    pub(super) fn import_key(
        &mut self,
        pending: &PendingImport,
        passphrase: &[u8],
    ) -> anyhow::Result<()> {
        use anyhow::Context as _;

        let text = std::fs::read_to_string(&pending.path)
            .with_context(|| format!("Не удалось прочитать {}.", pending.path.display()))?;
        let passphrase = if passphrase.is_empty() {
            None
        } else {
            Some(
                std::str::from_utf8(passphrase)
                    .context("Парольная фраза содержит недопустимые символы.")?,
            )
        };

        let key = ssh_agent::keys::decode_private(&text, passphrase)?;
        let public = key.public_key();
        let mut record = proto::KeyRecord::new(
            ssh_agent::keys::public_blob(public)?,
            proto::Secret::new(ssh_agent::keys::to_openssh(&key)?),
        );
        record.comment = public.comment().to_string();
        record.algorithm = public.algorithm().to_string();
        record.fingerprint = ssh_agent::keys::fingerprint(public);
        record.source = pending.path.display().to_string();

        let current = self.current;
        let store = VaultStore::new(self.vaults[current].root());
        let unlocked = self.vaults[current]
            .session
            .unlocked_mut()
            .ok_or_else(|| anyhow::anyhow!("Хранилище заблокировано."))?;
        unlocked.upsert_key(&store, record)?;
        Ok(())
    }

    pub(super) fn cancel_import(&mut self, cx: &mut Context<Self>) {
        self.importing = None;
        self.error = None;
        cx.notify();
    }

    pub(super) fn forget_key(&mut self, id: &proto::RecordId, cx: &mut Context<Self>) {
        let current = self.current;
        let store = VaultStore::new(self.vaults[current].root());
        let result = self.vaults[current]
            .session
            .unlocked_mut()
            .ok_or_else(|| anyhow::anyhow!("Хранилище заблокировано."))
            .and_then(|unlocked| unlocked.remove_key(&store, id));
        if let Err(error) = result {
            self.error = Some(SharedString::from(format!("{error:#}")));
        }
        cx.notify();
    }

    pub(super) fn import_form(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let pending = self.importing.as_ref()?;
        let muted = cx.theme().muted_foreground;
        let border = cx.theme().border;

        Some(
            v_flex()
                .mt_1()
                .p_2()
                .gap_2()
                .rounded_md()
                .border_1()
                .border_color(border)
                .child(
                    Label::new(SharedString::from(format!(
                        "Импорт ключа {}",
                        pending.name
                    )))
                    .text_sm(),
                )
                .child(
                    Label::new(concat!(
                        "Ключ будет зашифрован и сохранён в хранилище. Исходный файл не изменяется, парольная фраза ключа больше не потребуется.",
                        ""
                    ))
                    .text_xs()
                    .text_color(muted),
                )
                .when(pending.encrypted, |this| {
                    this.child(Input::new(&self.vault_form.passphrase))
                })
                .child(
                    h_flex()
                        .gap_2()
                        .child(
                            Button::new("import-do")
                                .primary()
                                .label("Импортировать")
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.finish_import(window, cx)
                                })),
                        )
                        .child(
                            Button::new("import-cancel")
                                .ghost()
                                .label("Отмена")
                                .on_click(
                                    cx.listener(|this, _, _window, cx| this.cancel_import(cx)),
                                ),
                        ),
                )
                .into_any_element(),
        )
    }

    pub(super) fn sign_dialog(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let pending = self.sign_queue.front()?;
        let muted = cx.theme().muted_foreground;
        let warning = cx.theme().warning;
        let background = cx.theme().background;
        let border = cx.theme().border;
        let waiting = self.sign_queue.len().saturating_sub(1);

        let target: AnyElement = match &pending.target {
            SignTarget::Proven {
                name,
                fingerprint,
                forwarding,
            } => v_flex()
                .gap_1()
                .child(
                    Label::new(match name {
                        Some(name) => SharedString::from(format!("Сервер: {name}")),
                        None => SharedString::from("Сервер отсутствует в списке хостов"),
                    })
                    .text_sm(),
                )
                .child(
                    Label::new(fingerprint.clone())
                        .text_xs()
                        .font_family(mono_family(cx))
                        .text_color(muted),
                )
                .when(*forwarding, |this| {
                    this.child(
                        Label::new(concat!(
                            "Соединение переадресовано: подпись будет использована не тем сервером, к которому выполнено подключение, а следующим за ним.",
                            ""
                        ))
                        .text_xs()
                        .text_color(warning),
                    )
                })
                .into_any_element(),
            SignTarget::Unknown => v_flex()
                .gap_1()
                .child(Label::new("Сервер не определён").text_sm())
                .child(
                    Label::new(concat!(
                        "Клиент не передал расширение session-bind, поэтому сервер в запросе не указан.",
                        ""
                    ))
                    .text_xs()
                    .text_color(warning),
                )
                .into_any_element(),
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
                        .w(px(420.))
                        .p_4()
                        .gap_3()
                        .rounded_lg()
                        .bg(background)
                        .border_1()
                        .border_color(border)
                        .child(Label::new("Запрос подписи").font_semibold())
                        .child(
                            Label::new(SharedString::from(format!("Ключ: {}", pending.key_title)))
                                .text_sm(),
                        )
                        .child(target)
                        .child(
                            Label::new(concat!(
                                "Подпись подтверждает вход на сервер от вашего имени. Закрытый ключ расшифровывается только на время выполнения подписи.",
                                "",
                                ""
                            ))
                            .text_xs()
                            .text_color(muted),
                        )
                        .when(waiting > 0, |this| {
                            this.child(
                                Label::new(SharedString::from(format!(
                                    "Ожидают обработки: {waiting}"
                                )))
                                .text_xs()
                                .text_color(warning),
                            )
                        })
                        .child(
                            h_flex()
                                .gap_2()
                                .child(
                                    Button::new("sign-approve")
                                        .primary()
                                        .label("Подписать")
                                        .on_click(cx.listener(|this, _, _window, cx| {
                                            this.approve_sign(cx)
                                        })),
                                )
                                .child(
                                    Button::new("sign-refuse")
                                        .outline()
                                        .label("Отклонить")
                                        .on_click(
                                            cx.listener(|this, _, _window, cx| {
                                                this.refuse_sign(cx)
                                            }),
                                        ),
                                ),
                        ),
                )
                .into_any_element(),
        )
    }

    fn key_card(
        title: &'static str,
        hint: Option<&'static str>,
        body: AnyElement,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = cx.theme().clone();
        v_flex()
            .max_w(px(760.))
            .p_4()
            .gap_2()
            .rounded_lg()
            .border_1()
            .border_color(theme.border)
            .bg(theme.secondary)
            .child(Label::new(title).font_semibold())
            .children(hint.map(|hint| {
                Label::new(hint)
                    .text_xs()
                    .text_color(theme.muted_foreground)
            }))
            .child(body)
            .into_any_element()
    }

    pub(super) fn keys_page(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let muted = theme.muted_foreground;
        let running = self.agent.is_some();
        let unlocked = self.vault().state().is_unlocked();

        let address = self
            .agent
            .as_ref()
            .map(|agent| format!("SSH_AUTH_SOCK={}", agent.address().as_text()));
        let agent_body = v_flex()
            .gap_2()
            .child(
                h_flex()
                    .gap_2()
                    .items_center()
                    .child(
                        div()
                            .size(px(8.))
                            .rounded_full()
                            .bg(if running { theme.success } else { muted }),
                    )
                    .child(Label::new(if running { "Работает" } else { "Остановлен" }).text_sm())
                    .child(div().flex_grow_1())
                    .child(
                        Button::new("agent-toggle")
                            .when(running, |button| button.outline())
                            .when(!running, |button| button.primary())
                            .small()
                            .label(if running { "Остановить" } else { "Запустить" })
                            .on_click(cx.listener(|this, _, _window, cx| this.toggle_agent(cx))),
                    ),
            )
            .children(address.map(|address| {
                let copy = address.clone();
                h_flex()
                    .gap_2()
                    .items_center()
                    .child(
                        div()
                            .flex_grow_1()
                            .min_w(px(0.))
                            .px_2()
                            .py_1()
                            .rounded_md()
                            .bg(theme.muted)
                            .overflow_hidden()
                            .child(
                                Label::new(SharedString::from(address))
                                    .text_xs()
                                    .font_family(mono_family(cx)),
                            ),
                    )
                    .child(
                        Button::new("agent-copy")
                            .ghost()
                            .small()
                            .label("Копировать")
                            .tooltip("Команда для оболочки: ssh и git будут использовать этот агент")
                            .on_click(cx.listener(move |_, _, _window, cx| {
                                cx.write_to_clipboard(gpui_kit::ClipboardItem::new_string(copy.clone()));
                            })),
                    )
            }))
            .when(running && cfg!(windows), |this| {
                this.child(
                    Label::new(
                        "В Windows ssh и git не используют эту переменную; агент доступен только Cratty.",
                    )
                    .text_xs()
                    .text_color(theme.warning),
                )
            })
            .children(self.agent_error.clone().map(|error| {
                Label::new(error).text_xs().text_color(theme.danger)
            }))
            .into_any_element();

        let stored = self.vault_keys();
        let stored_body = v_flex()
            .gap_1()
            .when(stored.is_empty(), |this| {
                this.child(
                    Label::new(if unlocked {
                        "Ключей нет. Импортируйте ключ из ~/.ssh."
                    } else {
                        "Хранилище заблокировано."
                    })
                    .text_sm()
                    .text_color(muted),
                )
            })
            .children(stored.into_iter().map(|entry| {
                let id = entry.id.clone();
                h_flex()
                    .gap_2()
                    .items_center()
                    .py_1()
                    .child(
                        Icon::empty()
                            .path("icons/key-round.svg")
                            .small()
                            .text_color(theme.primary),
                    )
                    .child(
                        v_flex()
                            .flex_grow_1()
                            .min_w(px(0.))
                            .child(Label::new(SharedString::from(entry.key.title())).text_sm())
                            .child(
                                Label::new(SharedString::from(format!(
                                    "{} · {}",
                                    entry.key.algorithm, entry.key.fingerprint
                                )))
                                .text_xs()
                                .text_color(muted),
                            ),
                    )
                    .child(
                        Button::new(SharedString::from(format!("key-forget-{id}")))
                            .ghost()
                            .xsmall()
                            .icon(Icon::new(IconName::Delete))
                            .tooltip("Удалить из хранилища. Файл в ~/.ssh сохранится.")
                            .on_click(
                                cx.listener(move |this, _, _window, cx| this.forget_key(&id, cx)),
                            ),
                    )
            }))
            .into_any_element();

        let files_body = v_flex()
            .gap_1()
            .when(self.keys.is_empty(), |this| {
                this.child(Label::new("Ключей не найдено.").text_sm().text_color(muted))
            })
            .children(self.keys.iter().map(|key| {
                let key = key.clone();
                let importing = self
                    .importing
                    .as_ref()
                    .is_some_and(|pending| pending.path == key.path);
                h_flex()
                    .gap_2()
                    .items_center()
                    .py_1()
                    .child(
                        Icon::empty()
                            .path("icons/file.svg")
                            .small()
                            .text_color(muted),
                    )
                    .child(
                        v_flex()
                            .flex_grow_1()
                            .child(Label::new(SharedString::from(key.name.clone())).text_sm())
                            .when(key.encrypted, |this| {
                                this.child(
                                    Label::new("Зашифрован парольной фразой")
                                        .text_xs()
                                        .text_color(theme.warning),
                                )
                            }),
                    )
                    .child(
                        Button::new(SharedString::from(format!("key-import-{}", key.name)))
                            .outline()
                            .xsmall()
                            .label("Импортировать")
                            .tooltip("Зашифровать ключ и сохранить в хранилище")
                            .selected(importing)
                            .disabled(!unlocked)
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.begin_import(&key, window, cx)
                            })),
                    )
            }))
            .children(self.import_form(cx))
            .children(
                self.error
                    .clone()
                    .map(|error| Label::new(error).text_xs().text_color(theme.danger)),
            )
            .into_any_element();

        v_flex()
            .size_full()
            .child(
                h_flex()
                    .px_6()
                    .pt_5()
                    .pb_3()
                    .child(Label::new("Ключи").text_xl().font_semibold()),
            )
            .children(self.vault_picker(cx))
            .child(
                v_flex()
                    .id("keys-page")
                    .flex_grow_1()
                    .min_h(px(0.))
                    .overflow_y_scrollbar()
                    .px_6()
                    .pb_6()
                    .child(
                        v_flex()
                            .gap_3()
                            .child(Self::key_card(
                        "SSH-агент",
                        Some("Предоставляет ключи из хранилища. Каждая подпись требует подтверждения."),
                        agent_body,
                        cx,
                    ))
                    .child(Self::key_card(
                        "Ключи в хранилище",
                        Some("Хранятся в зашифрованном виде, синхронизируются и используются агентом."),
                        stored_body,
                        cx,
                    ))
                    .child(Self::key_card(
                        "Ключи в ~/.ssh",
                        Some("Файлы на диске. Используются при входе; в хранилище добавляются через импорт."),
                        files_body,
                        cx,
                    )),
                    ),
            )
            .into_any_element()
    }
}
