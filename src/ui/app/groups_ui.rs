//! Host groups: the group field in the form, the group row in the left menu and the
//! "Edit group" dialog (name and icon).

use super::icons_ui::{IconTarget, icon_asset_path};
use super::*;
use crate::vault_session::HostGroup;
use gpui_kit::component::menu::{ContextMenuExt as _, DropdownMenu as _, PopupMenuItem};
use proto::GroupRecord;

const DEFAULT_GROUP_ICON: &str = "folder";

/// Key of a collapsed group in settings: vault and group name.
fn collapse_key(vault: &str, group: &str) -> String {
    format!("{vault}/{}", GroupRecord::key(group))
}

pub(super) struct GroupEditor {
    vault: String,
    /// Group name before editing — its hosts are found by it.
    old: String,
    name: Entity<InputState>,
    pub(super) icon: String,
    error: Option<SharedString>,
}

impl AppView {
    pub(super) fn is_group_collapsed(&self, vault: &str, group: &str) -> bool {
        self.settings
            .collapsed_groups
            .contains(&collapse_key(vault, group))
    }

    fn toggle_group(&mut self, vault: &str, group: &str, cx: &mut Context<Self>) {
        let key = collapse_key(vault, group);
        let collapsed = &mut self.settings.collapsed_groups;
        match collapsed.iter().position(|item| *item == key) {
            Some(index) => {
                collapsed.remove(index);
            }
            None => collapsed.push(key),
        }
        self.error = settings::save(&self.settings).err().map(SharedString::from);
        cx.notify();
    }

    /// Group row in the left menu: click collapses it, right-click opens the menu.
    pub(super) fn group_row(
        &self,
        vault: &str,
        group: &HostGroup,
        count: usize,
        collapsed: bool,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = cx.theme().clone();
        let view = cx.entity();
        let (toggle_vault, toggle_name) = (vault.to_owned(), group.name.clone());
        let (menu_vault, menu_name) = (vault.to_owned(), group.name.clone());

        let row = Self::rail_row(
            SharedString::from(format!(
                "rail-group-{vault}-{}",
                GroupRecord::key(&group.name)
            )),
            false,
            cx,
        );
        Self::host_drop_target(row, vault, &group.name, None, cx)
            .h(px(30.))
            .gap_1p5()
            .child(
                Icon::empty()
                    .path(if collapsed {
                        "icons/chevron-right.svg"
                    } else {
                        "icons/chevron-down.svg"
                    })
                    .xsmall()
                    .text_color(theme.muted_foreground),
            )
            .child(self.icon_view(vault, &group.icon, DEFAULT_GROUP_ICON, px(18.), cx))
            .child(
                div().flex_1().min_w(px(0.)).overflow_hidden().child(
                    Label::new(SharedString::from(group.name.clone()))
                        .text_sm()
                        .font_medium()
                        .line_clamp(1)
                        .text_ellipsis(),
                ),
            )
            .child(
                Label::new(SharedString::from(count.to_string()))
                    .text_xs()
                    .text_color(theme.muted_foreground),
            )
            .on_click(cx.listener(move |this, _, _window, cx| {
                this.toggle_group(&toggle_vault, &toggle_name, cx)
            }))
            .context_menu(move |menu, _window, _cx| {
                let (view, vault, name) = (view.clone(), menu_vault.clone(), menu_name.clone());
                menu.item(
                    PopupMenuItem::new(t!("groups.edit"))
                        .icon(Icon::empty().path("icons/pencil.svg"))
                        .on_click(move |_, window, cx| {
                            view.update(cx, |this, cx| {
                                this.open_group_editor(&vault, &name, window, cx)
                            });
                        }),
                )
            })
            .into_any_element()
    }

    fn open_group_editor(
        &mut self,
        vault: &str,
        name: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let icon = self
            .unlocked_of(vault)
            .and_then(|unlocked| {
                unlocked
                    .groups()
                    .into_iter()
                    .find(|group| GroupRecord::key(&group.name) == GroupRecord::key(name))
            })
            .map(|group| group.icon)
            .unwrap_or_default();
        let input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder(t!("groups.name_placeholder"))
                .default_value(name.to_owned())
        });
        input.read(cx).focus_handle(cx).focus(window, cx);
        self.group_editor = Some(GroupEditor {
            vault: vault.to_owned(),
            old: name.to_owned(),
            name: input,
            icon,
            error: None,
        });
        cx.notify();
    }

    fn save_group(&mut self, cx: &mut Context<Self>) {
        let Some(editor) = &self.group_editor else {
            return;
        };
        let (vault, old, icon) = (
            editor.vault.clone(),
            editor.old.clone(),
            editor.icon.clone(),
        );
        let name = editor.name.read(cx).value().trim().to_string();
        // Icons of both groups — the renamed one and the one it may
        // merge into: after editing they may become unneeded.
        let old_icons: Vec<String> = self
            .unlocked_of(&vault)
            .map(|unlocked| unlocked.groups())
            .unwrap_or_default()
            .into_iter()
            .filter(|group| {
                let key = GroupRecord::key(&group.name);
                key == GroupRecord::key(&old) || key == GroupRecord::key(&name)
            })
            .map(|group| group.icon)
            .collect();
        let new_icon = self.icon_to_store(&vault, &icon);

        self.persist(&vault, cx, |unlocked, store| {
            if let Some(record) = new_icon {
                unlocked.store_icon(store, record)?;
            }
            unlocked.edit_group(store, &old, &name, &icon)?;
            for old_icon in &old_icons {
                unlocked.release_icon(store, old_icon)?;
            }
            Ok(())
        });
        if let Some(error) = self.error.take() {
            if let Some(editor) = &mut self.group_editor {
                editor.error = Some(error);
            }
            cx.notify();
            return;
        }

        // A collapsed group stays collapsed under its new name.
        let (from, to) = (collapse_key(&vault, &old), collapse_key(&vault, &name));
        if from != to
            && let Some(index) = self
                .settings
                .collapsed_groups
                .iter()
                .position(|key| *key == from)
        {
            self.settings.collapsed_groups.remove(index);
            if !self.settings.collapsed_groups.contains(&to) {
                self.settings.collapsed_groups.push(to);
            }
            self.error = settings::save(&self.settings).err().map(SharedString::from);
        }
        self.group_editor = None;
        cx.notify();
    }

    pub(super) fn group_editor_dialog(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let editor = self.group_editor.as_ref()?;
        let theme = cx.theme().clone();

        let icon_button = self.icon_button(
            "group-icon",
            IconTarget::Group,
            &editor.vault,
            &editor.icon,
            DEFAULT_GROUP_ICON,
            cx,
        );

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
                        .w(px(360.))
                        .p_4()
                        .gap_3()
                        .rounded_lg()
                        .bg(crate::ui::theme::solid_background(cx))
                        .border_1()
                        .border_color(theme.border)
                        .child(Label::new(t!("groups.dialog_title")).font_semibold())
                        .child(Self::field_label(t!("groups.icon_and_name"), theme.muted_foreground))
                        .child(
                            h_flex()
                                .gap_2()
                                .items_center()
                                .child(icon_button)
                                .child(div().flex_1().child(Input::new(&editor.name))),
                        )
                        .children(
                            editor
                                .error
                                .clone()
                                .map(|error| Label::new(error).text_xs().text_color(theme.danger)),
                        )
                        .child(
                            h_flex()
                                .gap_2()
                                .child(
                                    Button::new("group-save")
                                        .primary()
                                        .label(t!("groups.save"))
                                        .on_click(
                                            cx.listener(|this, _, _window, cx| this.save_group(cx)),
                                        ),
                                )
                                .child(
                                    Button::new("group-cancel")
                                        .outline()
                                        .label(t!("groups.cancel"))
                                        .on_click(cx.listener(|this, _, _window, cx| {
                                            this.group_editor = None;
                                            cx.notify();
                                        })),
                                ),
                        ),
                )
                .into_any_element(),
        )
    }

    /// The "Group" field in the host form: the name is typed or chosen
    /// from the groups of this vault.
    pub(super) fn group_field(&self, cx: &mut Context<Self>) -> AnyElement {
        let muted = cx.theme().muted_foreground;
        let groups: Vec<HostGroup> = self
            .unlocked_of(&self.form.vault)
            .map(|unlocked| unlocked.groups())
            .unwrap_or_default();
        let view = cx.entity();
        let input = self.form.group.clone();

        v_flex()
            .gap_1()
            .child(Self::field_label(t!("groups.field"), muted))
            .child(
                h_flex()
                    .gap_1()
                    .child(div().flex_1().child(Input::new(&self.form.group)))
                    .child(
                        Button::new("host-group-pick")
                            .outline()
                            .icon(Icon::empty().path("icons/chevron-down.svg"))
                            .tooltip(if groups.is_empty() {
                                t!("groups.none_yet")
                            } else {
                                t!("groups.choose")
                            })
                            .disabled(groups.is_empty())
                            .dropdown_menu(move |menu, _window, _cx| {
                                groups.iter().fold(menu, |menu, group| {
                                    let (view, input, name) =
                                        (view.clone(), input.clone(), group.name.clone());
                                    menu.item(
                                        PopupMenuItem::new(SharedString::from(group.name.clone()))
                                            .icon(Icon::empty().path(icon_asset_path(
                                                &group.icon,
                                                DEFAULT_GROUP_ICON,
                                            )))
                                            .on_click(move |_, window, cx| {
                                                let name = name.clone();
                                                input.update(cx, |state, cx| {
                                                    state.set_value(name, window, cx)
                                                });
                                                view.update(cx, |_, cx| cx.notify());
                                            }),
                                    )
                                })
                            }),
                    ),
            )
            .into_any_element()
    }
}
