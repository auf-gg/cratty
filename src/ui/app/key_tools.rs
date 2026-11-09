//! Key file login in the host form: pick a key from ~/.ssh, create a new one
//! and add the public key to the server using a password (like `ssh-copy-id`).

use super::*;
use crate::ssh::keygen;
use gpui_kit::component::menu::{DropdownMenu as _, PopupMenuItem};

/// The ~/.ssh directory, or ~ abbreviation of a path for display.
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
            self.key_notice = Some(t!("keys.home_not_found").to_string().into());
            cx.notify();
            return;
        };
        let host = self.form.host.read(cx).value().trim().to_string();
        match keygen::generate(&dir, &host, &local_identity()) {
            Ok(path) => {
                self.set_key_path(&path, window, cx);
                self.key_notice = Some(
                    t!("keys.created", path = display_path(&path))
                        .to_string()
                        .into(),
                );
            }
            Err(error) => self.key_notice = Some(format!("{error:#}").into()),
        }
        cx.notify();
    }

    /// A tab that logs in to the server with a password and appends the public key
    /// to ~/.ssh/authorized_keys.
    fn install_key(&mut self, cx: &mut Context<Self>) {
        let raw = self.form.key_path.read(cx).value().trim().to_string();
        if raw.is_empty() {
            self.key_notice = Some(t!("keys.select_first").to_string().into());
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
            tab.title = t!("keys.tab_title", target = target).to_string().into();
        }
        self.key_notice = Some(t!("keys.install_open").to_string().into());
        cx.notify();
    }

    pub(super) fn key_fields(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let view = cx.entity();

        let pick = Button::new("key-pick")
            .outline()
            .small()
            .label(t!("keys.choose").to_string())
            .tooltip(t!("keys.choose_tooltip").to_string())
            .dropdown_menu(move |menu, _window, _cx| {
                let keys = crate::ssh::auth::ssh_dir()
                    .map(|dir| keygen::private_keys(&dir))
                    .unwrap_or_default();
                if keys.is_empty() {
                    return menu.item(PopupMenuItem::label(t!("keys.no_private_keys").to_string()));
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
                            .label(t!("keys.create").to_string())
                            .tooltip(t!("keys.create_tooltip").to_string())
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
                    .label(t!("keys.add_to_server").to_string())
                    .tooltip(t!("keys.add_tooltip").to_string())
                    .on_click(cx.listener(|this, _, _window, cx| this.install_key(cx))),
            )
            .children(self.key_notice.clone().map(|notice| {
                Label::new(notice)
                    .text_xs()
                    .text_color(theme.muted_foreground)
            }))
            .child(
                Label::new(t!("keys.passphrase_note").to_string())
                    .text_xs()
                    .text_color(theme.muted_foreground),
            )
            .into_any_element()
    }
}
