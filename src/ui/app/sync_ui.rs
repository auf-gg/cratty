use super::*;

impl AppView {
    pub(super) fn apply_sync_folder(&mut self, cx: &mut Context<Self>) {
        let typed = self.sync_input.read(cx).value().trim().to_string();
        let id = self.current_id();
        self.vaults[self.current].sync_folder = typed;
        self.save_registry();
        self.sync_status = None;
        self.sync_error = None;

        self.start_sync_watch(&id, cx);
        if self.vaults[self.current].sync_path().is_some() {
            self.sync_now(&id, cx);
        }
        cx.notify();
    }

    pub(super) fn sync_now(&mut self, id: &str, cx: &mut Context<Self>) {
        if self.syncing.contains(id) {
            return;
        }
        let Some(ix) = self.vault_ix(id) else {
            return;
        };
        let slot = &self.vaults[ix];
        let Some(unlocked) = slot.session.unlocked() else {
            return;
        };

        let Some(path) = slot.sync_path() else {
            return;
        };

        let store = VaultStore::new(slot.root());
        let vault_id = unlocked.vault_id().clone();
        let records = match unlocked.records_for_push(&store) {
            Ok(records) => records,
            Err(error) => {
                self.sync_error = Some(SharedString::from(format!("{error:#}")));
                cx.notify();
                return;
            }
        };

        let exchange = cx.background_executor().spawn(async move {
            let mut outcome = SyncOutcome::default();

            match folder_exchange(path, &vault_id, records).await {
                Ok(pulled) => {
                    outcome.records.extend(pulled.records);
                    outcome.broken.extend(pulled.broken);
                }
                Err(error) => outcome
                    .errors
                    .push(format!("Папка синхронизации: {error:#}")),
            }

            outcome
        });

        self.syncing.insert(id.to_owned());
        self.sync_error = None;
        cx.notify();

        let id = id.to_owned();
        let task = cx.spawn({
            let id = id.clone();
            async move |this: gpui_kit::WeakEntity<Self>, cx| {
                let outcome = exchange.await;
                this.update(cx, |this, cx| this.finish_sync(&id, outcome, cx))
                    .ok();
            }
        });
        self.sync_tasks.insert(id, task);
    }

    pub(super) fn finish_sync(&mut self, id: &str, outcome: SyncOutcome, cx: &mut Context<Self>) {
        self.syncing.remove(id);

        let Some(ix) = self.vault_ix(id) else {
            return;
        };
        let store = VaultStore::new(self.vaults[ix].root());
        let Some(unlocked) = self.vaults[ix].session.unlocked_mut() else {
            if ix == self.current {
                self.sync_error = Some(SharedString::from(
                    "Хранилище было заблокировано во время синхронизации.",
                ));
            }
            cx.notify();
            return;
        };

        let report = unlocked.merge(&store, outcome.records);
        self.reconcile_vault_name(id);
        // С другого устройства могли прийти ключи, которых здесь нет на диске.
        self.sync_key_files(id);

        let mut troubles = outcome.errors;
        troubles.extend(outcome.broken);
        troubles.extend(report.broken.iter().cloned());

        if ix == self.current {
            self.sync_status = Some(SharedString::from(format!(
                "Получено записей: {}, локальные новее: {}",
                report.applied, report.kept
            )));
            self.sync_error = troubles.first().map(|first| {
                SharedString::from(if troubles.len() == 1 {
                    first.clone()
                } else {
                    format!("{first} (и ещё {})", troubles.len() - 1)
                })
            });
        }
        cx.notify();
    }

    pub(super) fn start_sync_watch(&mut self, id: &str, cx: &mut Context<Self>) {
        self.sync_watches.remove(id);

        let Some(ix) = self.vault_ix(id) else {
            return;
        };
        let slot = &self.vaults[ix];
        let Some(path) = slot.sync_path() else {
            return;
        };
        let Some(vault_id) = slot.session.unlocked().map(|u| u.vault_id().clone()) else {
            return;
        };
        let Ok(backend) = sync::FolderBackend::open(path, &vault_id) else {
            return;
        };
        use sync::VaultBackend as _;

        let mut changes = backend.watch();
        let id = id.to_owned();
        let watch = cx.spawn({
            let id = id.clone();
            async move |this: gpui_kit::WeakEntity<Self>, cx| {
                drop(backend);
                while changes.next().await.is_some() {
                    cx.background_executor()
                        .timer(std::time::Duration::from_millis(300))
                        .await;
                    if this.update(cx, |this, cx| this.sync_now(&id, cx)).is_err() {
                        return;
                    }
                }
            }
        });
        self.sync_watches.insert(id, watch);
    }
}
