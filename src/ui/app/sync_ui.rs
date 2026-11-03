use super::*;

impl AppView {
    pub(super) fn apply_sync_folder(&mut self, cx: &mut Context<Self>) {
        let typed = self.sync_input.read(cx).value().trim().to_string();
        self.settings.sync_folder = typed;
        if let Err(error) = settings::save(&self.settings) {
            self.error = Some(SharedString::from(format!("{error:#}")));
        }
        self.sync_status = None;
        self.sync_error = None;

        self.start_sync_watch(cx);
        if self.settings.sync_folder().is_some() {
            self.sync_now(cx);
        }
        cx.notify();
    }

    pub(super) fn sync_now(&mut self, cx: &mut Context<Self>) {
        if self.syncing {
            return;
        }
        let Some(unlocked) = self.vault.unlocked() else {
            return;
        };

        let Some(path) = self.settings.sync_folder() else {
            return;
        };

        let store = VaultStore::new(self.vault.store().root().to_path_buf());
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

        self.syncing = true;
        self.sync_error = None;
        cx.notify();

        self.sync_task = Some(cx.spawn(async move |this: gpui::WeakEntity<Self>, cx| {
            let outcome = exchange.await;
            this.update(cx, |this, cx| this.finish_sync(outcome, cx))
                .ok();
        }));
    }

    pub(super) fn finish_sync(&mut self, outcome: SyncOutcome, cx: &mut Context<Self>) {
        self.syncing = false;

        let store = VaultStore::new(self.vault.store().root().to_path_buf());
        let Some(unlocked) = self.vault.unlocked_mut() else {
            self.sync_error = Some(SharedString::from(
                "Хранилище было заблокировано во время синхронизации.",
            ));
            cx.notify();
            return;
        };

        let report = unlocked.merge(&store, outcome.records);

        let mut troubles = outcome.errors;
        troubles.extend(outcome.broken);
        troubles.extend(report.broken.iter().cloned());

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
        cx.notify();
    }

    pub(super) fn start_sync_watch(&mut self, cx: &mut Context<Self>) {
        self.sync_watch = None;

        let Some(path) = self.settings.sync_folder() else {
            return;
        };
        let Some(vault_id) = self.vault.unlocked().map(|u| u.vault_id().clone()) else {
            return;
        };
        let Ok(backend) = sync::FolderBackend::open(path, &vault_id) else {
            return;
        };
        use sync::VaultBackend as _;

        let mut changes = backend.watch();
        self.sync_watch = Some(cx.spawn(async move |this: gpui::WeakEntity<Self>, cx| {
            drop(backend);
            while changes.next().await.is_some() {
                cx.background_executor()
                    .timer(std::time::Duration::from_millis(300))
                    .await;
                if this.update(cx, |this, cx| this.sync_now(cx)).is_err() {
                    return;
                }
            }
        }));
    }
}
