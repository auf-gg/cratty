//! Вход по файлу ключа в форме хоста: выбрать ключ из ~/.ssh, создать новый
//! и добавить открытый ключ на сервер по паролю (как `ssh-copy-id`).

use super::*;
use crate::ssh::keygen;
use gpui_kit::component::menu::{DropdownMenu as _, PopupMenuItem};

/// Каталог ~/.ssh или ~ сокращение пути для показа.
pub(super) fn display_path(path: &std::path::Path) -> String {
    let text = path.display().to_string();
    match std::env::home_dir() {
        Some(home) => match path.strip_prefix(&home) {
            Ok(rest) => format!("~/{}", rest.display()),
            Err(_) => text,
        },
        None => text,
    }
}

pub(super) fn expand_home(path: &str) -> std::path::PathBuf {
    match (path.strip_prefix("~/"), std::env::home_dir()) {
        (Some(rest), Some(home)) => home.join(rest),
        _ => std::path::PathBuf::from(path),
    }
}

fn local_identity() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "cratty".into());
    let host = std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "cratty".into());
    format!("{user}@{host}")
}

impl AppView {
    fn set_key_path(
        &mut self,
        path: &std::path::Path,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let shown = display_path(path);
        self.form
            .key_path
            .update(cx, |state, cx| state.set_value(shown, window, cx));
        cx.notify();
    }

    fn generate_key(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(dir) = crate::ssh::auth::ssh_dir() else {
            self.key_notice = Some("Не найден домашний каталог.".into());
            cx.notify();
            return;
        };
        let host = self.form.host.read(cx).value().trim().to_string();
        match keygen::generate(&dir, &host, &local_identity()) {
            Ok(path) => {
                self.set_key_path(&path, window, cx);
                self.key_notice = Some(
                    format!(
                        "Создан ключ {} (Ed25519, без парольной фразы). Добавьте его на сервер кнопкой ниже.",
                        display_path(&path)
                    )
                    .into(),
                );
            }
            Err(error) => self.key_notice = Some(format!("{error:#}").into()),
        }
        cx.notify();
    }

    /// Вкладка, которая входит на сервер по паролю и дописывает открытый ключ
    /// в ~/.ssh/authorized_keys.
    fn install_key(&mut self, cx: &mut Context<Self>) {
        let raw = self.form.key_path.read(cx).value().trim().to_string();
        if raw.is_empty() {
            self.key_notice = Some("Сначала выберите или создайте ключ.".into());
            cx.notify();
            return;
        }
        let command =
            keygen::public_line(&expand_home(&raw)).and_then(|line| keygen::install_command(&line));
        let command = match command {
            Ok(command) => command,
            Err(error) => {
                self.key_notice = Some(format!("{error:#}").into());
                cx.notify();
                return;
            }
        };
        let (target, mut credentials) = match self.read_form(cx) {
            Ok(parts) => parts,
            Err(error) => {
                self.key_notice = Some(error.into());
                cx.notify();
                return;
            }
        };
        let request = match connect::parse_target(&target) {
            Ok(request) => request,
            Err(error) => {
                self.key_notice = Some(error.into());
                cx.notify();
                return;
            }
        };
        credentials.auth = HostAuth::Password;
        credentials.command = Some(command);
        let vault = Some(self.form.vault.clone()).filter(|id| !id.is_empty());
        self.spawn_tab(request, credentials, vault, cx);
        if let Some(tab) = self.tabs.last_mut() {
            tab.title = format!("Ключ → {target}").into();
        }
        self.key_notice = Some(
            "Открыта вкладка установки ключа: введите там пароль сервера. После этого вход пойдёт по ключу."
                .into(),
        );
        cx.notify();
    }

    pub(super) fn key_fields(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let view = cx.entity();

        let pick = Button::new("key-pick")
            .outline()
            .small()
            .label("Выбрать")
            .tooltip("Ключи из ~/.ssh")
            .dropdown_menu(move |menu, _window, _cx| {
                let keys = crate::ssh::auth::ssh_dir()
                    .map(|dir| keygen::private_keys(&dir))
                    .unwrap_or_default();
                if keys.is_empty() {
                    return menu.item(PopupMenuItem::label("В ~/.ssh нет закрытых ключей"));
                }
                keys.into_iter().fold(menu, |menu, path| {
                    let view = view.clone();
                    let label = path
                        .file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    menu.item(PopupMenuItem::new(label).on_click(move |_, window, cx| {
                        view.update(cx, |this, cx| this.set_key_path(&path, window, cx));
                    }))
                })
            });

        v_flex()
            .gap_2()
            .child(
                h_flex()
                    .gap_1()
                    .child(div().flex_1().child(Input::new(&self.form.key_path)))
                    .child(pick)
                    .child(
                        Button::new("key-generate")
                            .outline()
                            .small()
                            .label("Создать")
                            .tooltip("Новый ключ Ed25519 в ~/.ssh")
                            .on_click(
                                cx.listener(|this, _, window, cx| this.generate_key(window, cx)),
                            ),
                    ),
            )
            .child(
                Button::new("key-install")
                    .ghost()
                    .small()
                    .icon(Icon::empty().path("icons/upload.svg"))
                    .label("Добавить ключ на сервер по паролю")
                    .tooltip("Войти по паролю и дописать открытый ключ в ~/.ssh/authorized_keys")
                    .on_click(cx.listener(|this, _, _window, cx| this.install_key(cx))),
            )
            .children(self.key_notice.clone().map(|notice| {
                Label::new(notice)
                    .text_xs()
                    .text_color(theme.muted_foreground)
            }))
            .child(
                Label::new("Парольная фраза зашифрованного ключа будет запрошена при подключении.")
                    .text_xs()
                    .text_color(theme.muted_foreground),
            )
            .into_any_element()
    }
}
