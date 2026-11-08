//! Значки хостов и групп: встроенный набор, каталог selfh.st и окно выбора.
//!
//! Значок записывается строкой: имя встроенного (`database`), `selfhst:<имя>`
//! (светлый и тёмный варианты под тему) или `selfhst:<имя>:color` (один
//! цветной). Скачанный значок до сохранения хоста или группы живёт в памяти,
//! а с сохранением ложится в хранилище записью [`proto::IconRecord`] — так
//! список выглядит одинаково без сети и на других устройствах. В хранилище
//! только используемые значки: переставший быть нужным удаляется.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

use super::*;
use crate::selfhst;
use crate::ui::fontawesome;

/// Значки Font Awesome, которые окно выбора показывает, пока поиск пуст.
const SUGGESTED: &[&str] = &[
    "folder",
    "server",
    "database",
    "cloud",
    "globe",
    "network-wired",
    "house",
    "building",
    "briefcase",
    "users",
    "code",
    "code-branch",
    "terminal",
    "bug",
    "flask",
    "rocket",
    "box",
    "cubes",
    "microchip",
    "hard-drive",
    "desktop",
    "gamepad",
    "shield",
    "lock",
    "wrench",
    "bolt",
    "star",
    "heart",
];

/// Непрозрачность значков хостов и групп: в полную силу они спорят с текстом.
const ICON_OPACITY: f32 = 0.8;

/// Сколько найденных значков selfh.st показывать: дальше — уточнять поиск.
const SHOWN_RESULTS: usize = 60;

/// Сколько значков Font Awesome показывать под запрос: дальше — уточнять.
const SHOWN_FA: usize = 84;

/// Значки первых версий групп (до Font Awesome): чем их заменить из Solid.
fn legacy_icon(icon: &str) -> Option<&'static str> {
    Some(match icon {
        "folder" => "folder",
        "server" => "server",
        "database" => "database",
        "cloud" => "cloud",
        "globe" => "globe",
        "network" => "network-wired",
        "house" => "house",
        "building-2" => "building",
        "briefcase" => "briefcase",
        "users" => "users",
        "code" => "code",
        "git-branch" => "code-branch",
        "square-terminal" => "terminal",
        "bug" => "bug",
        "flask-conical" => "flask",
        "rocket" => "rocket",
        "box" => "box",
        "container" => "cubes",
        "cpu" => "microchip",
        "hard-drive" => "hard-drive",
        "monitor" => "desktop",
        "gamepad-2" => "gamepad",
        "shield" => "shield",
        "lock" => "lock",
        "wrench" => "wrench",
        "zap" => "bolt",
        "star" => "star",
        "heart" => "heart",
        _ => return None,
    })
}

/// Путь к одноцветному значку: Font Awesome по ключу `fa:<стиль>:<имя>` или
/// старому имени; пусто или незнакомо (например, из более новой версии) —
/// `fallback` из значков приложения.
pub(super) fn icon_asset_path(icon: &str, fallback: &str) -> SharedString {
    if let Some(fa) = fontawesome::from_key(icon) {
        return fa.asset_path().into();
    }
    if let Some(name) = legacy_icon(icon) {
        return format!("fa/solid/{name}.svg").into();
    }
    SharedString::from(format!("icons/{fallback}.svg"))
}

/// Чей значок выбирается в окне.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum IconTarget {
    /// Хост в открытой форме.
    Host,
    /// Группа в окне «Группа».
    Group,
}

pub(super) struct IconPicker {
    target: IconTarget,
    vault: String,
    search: Entity<InputState>,
    /// Значок каталога, который сейчас скачивается.
    downloading: Option<String>,
    /// Скачивать цветной вариант вместо светлого и тёмного.
    colored: bool,
    error: Option<SharedString>,
    _search_changes: Subscription,
    _task: Option<gpui_kit::Task<()>>,
}

/// Каталог selfh.st в памяти: загружается из кеша при первом открытии окна.
#[derive(Default)]
pub(super) struct SelfhstState {
    catalog: Option<Arc<selfhst::Catalog>>,
    loaded: bool,
    refreshing: bool,
    notice: Option<SharedString>,
    _task: Option<gpui_kit::Task<()>>,
}

/// Собранные картинки значков из хранилища: ключ — значок, вариант и ревизия
/// записи, чтобы картинка не собиралась заново на каждом кадре.
#[derive(Default)]
pub(super) struct IconImages(RefCell<HashMap<String, Arc<gpui_kit::Image>>>);

/// Скачанные, но ещё не сохранённые значки: в хранилище они попадут вместе с
/// хостом или группой, а без сохранения просто забудутся.
pub(super) type PendingIcons = HashMap<String, proto::IconRecord>;

impl AppView {
    /// Значок хоста или группы размером `size`. Скачанного значка нет в
    /// хранилище (ещё не приехал синхронизацией) — встроенный `fallback`.
    pub(super) fn icon_view(
        &self,
        vault: &str,
        icon: &str,
        fallback: &'static str,
        size: gpui_kit::Pixels,
        cx: &App,
    ) -> AnyElement {
        if icon.starts_with("selfhst:")
            && let Some(image) = self.stored_icon(vault, icon, size, cx)
        {
            return img(image)
                .size(size)
                .flex_shrink_0()
                .opacity(ICON_OPACITY)
                .into_any_element();
        }
        // Одноцветный значок — цвета текста с той же прозрачностью, что и
        // картинки selfh.st: белый логотип и значок Font Awesome рядом выглядят
        // одинаково.
        Icon::empty()
            .path(icon_asset_path(icon, fallback))
            .size(size)
            .flex_shrink_0()
            .text_color(cx.theme().foreground.opacity(ICON_OPACITY))
            .into_any_element()
    }

    fn stored_icon(
        &self,
        vault: &str,
        key: &str,
        size: gpui_kit::Pixels,
        cx: &App,
    ) -> Option<Arc<gpui_kit::Image>> {
        let (rev, record) = self
            .unlocked_of(vault)
            .and_then(|unlocked| unlocked.icon(key))
            .or_else(|| self.pending_icons.get(key).map(|icon| (0, icon)))?;
        let (variant, bytes) = record.for_theme(cx.theme().mode.is_dark());
        // Растр с запасом под HiDPI: на обычном экране он уменьшится вдвое —
        // это видеокарта сглаживает чисто, в отличие от 512 пикселей в 16.
        let pixels = (f32::from(size) * 2.).ceil().clamp(16., 256.) as u32;
        let cache_key = format!("{vault}/{key}/{variant:?}/{rev}/{}/{pixels}", bytes.len());
        let mut images = self.icon_images.0.borrow_mut();
        if let Some(image) = images.get(&cache_key) {
            return Some(image.clone());
        }
        let image = Arc::new(raster(&record.format, bytes, pixels)?);
        images.insert(cache_key, image.clone());
        Some(image)
    }

    pub(super) fn open_icon_picker(
        &mut self,
        target: IconTarget,
        vault: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let search = cx.new(|cx| InputState::new(window, cx).placeholder("Поиск значка"));
        let search_changes = cx.subscribe(&search, |_, _, event: &InputEvent, cx| {
            if matches!(event, InputEvent::Change) {
                cx.notify();
            }
        });
        search.read(cx).focus_handle(cx).focus(window, cx);
        let colored = self.picked_icon(target).ends_with(":color");
        self.icon_picker = Some(IconPicker {
            target,
            vault: vault.to_owned(),
            search,
            downloading: None,
            colored,
            error: None,
            _search_changes: search_changes,
            _task: None,
        });

        if !self.selfhst.loaded {
            self.selfhst.loaded = true;
            self.selfhst.catalog = selfhst::cached().map(Arc::new);
            // Каталога нет даже в кеше — без него выбирать не из чего.
            if self.selfhst.catalog.is_none() {
                self.refresh_catalog(cx);
            }
        }
        cx.notify();
    }

    /// Сверяет каталог с сервером по ETag: не изменился — ничего не скачивается.
    fn refresh_catalog(&mut self, cx: &mut Context<Self>) {
        if self.selfhst.refreshing {
            return;
        }
        self.selfhst.refreshing = true;
        self.selfhst.notice = None;
        let etag = self
            .selfhst
            .catalog
            .as_ref()
            .and_then(|catalog| catalog.etag.clone());
        let work = cx
            .background_executor()
            .spawn(async move { selfhst::refresh(etag.as_deref()) });
        self.selfhst._task = Some(cx.spawn(async move |this: gpui_kit::WeakEntity<Self>, cx| {
            let result = work.await;
            this.update(cx, |this, cx| {
                this.selfhst.refreshing = false;
                this.selfhst.notice = Some(match result {
                    Ok(selfhst::Refresh::Unchanged) => "Каталог не изменился.".into(),
                    Ok(selfhst::Refresh::Updated(catalog)) => {
                        let count = catalog.entries.len();
                        this.selfhst.catalog = Some(Arc::new(catalog));
                        format!("Каталог обновлён: {count} значков.").into()
                    }
                    Err(error) => format!("{error:#}").into(),
                });
                cx.notify();
            })
            .ok();
        }));
        cx.notify();
    }

    /// Значок, который сейчас стоит у цели окна выбора.
    fn picked_icon(&self, target: IconTarget) -> String {
        match target {
            IconTarget::Host => self.form.icon.clone(),
            IconTarget::Group => self
                .group_editor
                .as_ref()
                .map(|editor| editor.icon.clone())
                .unwrap_or_default(),
        }
    }

    /// Есть ли картинка значка: в хранилище или скачана и ждёт сохранения.
    fn has_icon(&self, vault: &str, key: &str) -> bool {
        self.pending_icons.contains_key(key)
            || self
                .unlocked_of(vault)
                .is_some_and(|unlocked| unlocked.icon(key).is_some())
    }

    /// Скачанный значок `key`, если его ещё нет в хранилище `vault`: его
    /// сохранение кладёт туда и значок.
    pub(super) fn icon_to_store(&self, vault: &str, key: &str) -> Option<proto::IconRecord> {
        let stored = self
            .unlocked_of(vault)
            .is_some_and(|unlocked| unlocked.icon(key).is_some());
        (!stored)
            .then(|| self.pending_icons.get(key).cloned())
            .flatten()
    }

    /// Выбор значка: встроенный ставится сразу, значок каталога сначала
    /// скачивается.
    fn choose_icon(&mut self, icon: String, cx: &mut Context<Self>) {
        let Some(picker) = &self.icon_picker else {
            return;
        };
        match picker.target {
            IconTarget::Host => self.form.icon = icon,
            IconTarget::Group => {
                if let Some(editor) = &mut self.group_editor {
                    editor.icon = icon;
                }
            }
        }
        self.icon_picker = None;
        cx.notify();
    }

    fn download_icon(&mut self, entry: selfhst::Entry, cx: &mut Context<Self>) {
        let Some(picker) = &mut self.icon_picker else {
            return;
        };
        if picker.downloading.is_some() {
            return;
        }
        let colored = picker.colored;
        picker.downloading = Some(entry.reference.clone());
        picker.error = None;
        let work = cx
            .background_executor()
            .spawn(async move { selfhst::download(&entry, colored) });
        picker._task = Some(cx.spawn(async move |this: gpui_kit::WeakEntity<Self>, cx| {
            let result = work.await;
            this.update(cx, |this, cx| match result {
                Ok(icon) => {
                    let key = icon.key();
                    this.pending_icons.insert(key.clone(), icon);
                    this.choose_icon(key, cx);
                }
                Err(error) => {
                    if let Some(picker) = &mut this.icon_picker {
                        picker.downloading = None;
                        picker.error = Some(format!("{error:#}").into());
                    }
                    cx.notify();
                }
            })
            .ok();
        }));
        cx.notify();
    }

    /// Кнопка с текущим значком: открывает окно выбора.
    pub(super) fn icon_button(
        &self,
        id: &'static str,
        target: IconTarget,
        vault: &str,
        icon: &str,
        fallback: &'static str,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = cx.theme().clone();
        let vault_id = vault.to_owned();
        div()
            .id(id)
            .size(px(36.))
            .flex_shrink_0()
            .flex()
            .items_center()
            .justify_center()
            .rounded(px(7.))
            .border_1()
            .border_color(theme.input)
            .cursor_pointer()
            .hover(|style| style.bg(theme.secondary_hover))
            .child(self.icon_view(vault, icon, fallback, px(22.), cx))
            .tooltip(|window, cx| {
                gpui_kit::component::tooltip::Tooltip::new("Выбрать значок").build(window, cx)
            })
            .on_click(cx.listener(move |this, _, window, cx| {
                this.open_icon_picker(target, &vault_id, window, cx)
            }))
            .into_any_element()
    }

    pub(super) fn icon_picker_dialog(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let picker = self.icon_picker.as_ref()?;
        let theme = cx.theme().clone();
        let current = self.picked_icon(picker.target);
        let fallback = match picker.target {
            IconTarget::Host => "server",
            IconTarget::Group => "folder",
        };

        let query = picker.search.read(cx).value().to_string();
        let (fa_icons, fa_more): (Vec<&fontawesome::FaIcon>, usize) = if query.trim().is_empty() {
            (
                SUGGESTED
                    .iter()
                    .filter_map(|name| fontawesome::find("solid", name))
                    .collect(),
                0,
            )
        } else {
            let found = fontawesome::search(&query);
            let more = found.len().saturating_sub(SHOWN_FA);
            (found.into_iter().take(SHOWN_FA).collect(), more)
        };
        let fa_buttons = std::iter::once(None)
            .filter(|_| query.trim().is_empty())
            .chain(fa_icons.into_iter().map(Some))
            .map(|icon| {
                let key = icon.map(fontawesome::FaIcon::key).unwrap_or_default();
                let tip = match icon {
                    None => "По умолчанию".to_owned(),
                    Some(icon) => format!("{} · {}", icon.label, icon.style),
                };
                let path = icon_asset_path(&key, fallback);
                Button::new(SharedString::from(format!("icon-fa-{key}")))
                    .ghost()
                    .small()
                    .icon(Icon::empty().path(path))
                    .tooltip(tip)
                    .selected(current == key)
                    .on_click(
                        cx.listener(move |this, _, _window, cx| this.choose_icon(key.clone(), cx)),
                    )
                    .into_any_element()
            })
            .collect::<Vec<_>>();
        let fa_empty = fa_buttons.is_empty();

        let catalog_rows: Vec<AnyElement> = match &self.selfhst.catalog {
            None => vec![
                Self::hint(
                    if self.selfhst.refreshing {
                        "Загружаем каталог…"
                    } else {
                        "Каталога пока нет: нажмите «Обновить»."
                    },
                    cx,
                )
                .into_any_element(),
            ],
            Some(catalog) => {
                let found = catalog.search(&query);
                let total = found.len();
                let mut rows: Vec<AnyElement> = found
                    .into_iter()
                    .take(SHOWN_RESULTS)
                    .map(|entry| self.catalog_row(entry, &current, picker, cx))
                    .collect();
                if total == 0 {
                    rows.push(Self::hint("Ничего не нашлось.", cx).into_any_element());
                } else if total > SHOWN_RESULTS {
                    rows.push(
                        Self::hint(
                            format!("И ещё {} — уточните поиск.", total - SHOWN_RESULTS),
                            cx,
                        )
                        .into_any_element(),
                    );
                }
                rows
            }
        };
        let count = self
            .selfhst
            .catalog
            .as_ref()
            .map(|catalog| format!("{} значков", catalog.entries.len()))
            .unwrap_or_default();

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
                        .w(px(480.))
                        .max_h(gpui_kit::relative(0.9))
                        .p_4()
                        .gap_3()
                        .rounded_lg()
                        .bg(crate::ui::theme::solid_background(cx))
                        .border_1()
                        .border_color(theme.border)
                        .child(Label::new("Значок").font_semibold())
                        .child(Input::new(&picker.search).small())
                        .child(Label::new("Font Awesome").text_sm().font_medium())
                        .child(
                            div()
                                .id("icon-fa")
                                .max_h(px(136.))
                                .overflow_y_scroll()
                                .child(h_flex().flex_wrap().gap_1().children(fa_buttons)),
                        )
                        .when(fa_empty, |this| {
                            this.child(Self::hint("Ничего не нашлось.", cx))
                        })
                        .when(fa_more > 0, |this| {
                            this.child(Self::hint(
                                format!("И ещё {fa_more} — уточните поиск."),
                                cx,
                            ))
                        })
                        .child(
                            h_flex()
                                .gap_2()
                                .items_center()
                                .child(
                                    div()
                                        .flex_1()
                                        .child(Label::new("selfh.st").text_sm().font_medium()),
                                )
                                .child(Self::hint(count, cx))
                                .child(
                                    Button::new("icon-catalog-refresh")
                                        .ghost()
                                        .small()
                                        .icon(Icon::empty().path("icons/refresh-cw.svg"))
                                        .tooltip("Обновить каталог")
                                        .loading(self.selfhst.refreshing)
                                        .on_click(cx.listener(|this, _, _window, cx| {
                                            this.refresh_catalog(cx)
                                        })),
                                ),
                        )
                        .child(Self::hint(
                            "Значки приложений. Выбранный скачивается в хранилище и виден без сети.",
                            cx,
                        ))
                        .children(
                            self.selfhst
                                .notice
                                .clone()
                                .map(|notice| Self::hint(notice, cx)),
                        )
                        .child(
                            gpui_kit::component::checkbox::Checkbox::new("icon-colored")
                                .label("Цветной значок — один вариант для любой темы")
                                .checked(picker.colored)
                                .on_click(cx.listener(|this, checked: &bool, _window, cx| {
                                    if let Some(picker) = &mut this.icon_picker {
                                        picker.colored = *checked;
                                    }
                                    cx.notify();
                                })),
                        )
                        .child(
                            v_flex()
                                .id("icon-catalog")
                                .h(px(200.))
                                .overflow_y_scroll()
                                .gap_px()
                                .children(catalog_rows),
                        )
                        .children(picker.error.clone().map(|error| {
                            Label::new(error).text_xs().text_color(theme.danger)
                        }))
                        .child(
                            h_flex().justify_end().child(
                                Button::new("icon-picker-close")
                                    .outline()
                                    .label("Отмена")
                                    .on_click(cx.listener(|this, _, _window, cx| {
                                        this.icon_picker = None;
                                        cx.notify();
                                    })),
                            ),
                        ),
                )
                .into_any_element(),
        )
    }

    /// Строка значка каталога: имя и категория, без картинки — она скачается,
    /// только если значок выбрать.
    fn catalog_row(
        &self,
        entry: &selfhst::Entry,
        current: &str,
        picker: &IconPicker,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = cx.theme().clone();
        let key = entry.key(picker.colored);
        let chosen = current == key;
        let downloading = picker.downloading.as_deref() == Some(entry.reference.as_str());
        let busy = picker.downloading.is_some();
        let stored = self.has_icon(&picker.vault, &key);
        let detail = [entry.category.as_str(), entry.tags.as_str()]
            .into_iter()
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join(" · ");
        let pick = entry.clone();

        Self::rail_row(
            SharedString::from(format!("icon-catalog-{}", entry.reference)),
            chosen,
            cx,
        )
        .h(px(32.))
        .flex_shrink_0()
        .cursor_pointer()
        .children(stored.then(|| self.icon_view(&picker.vault, &key, "server", px(16.), cx)))
        .child(
            div().flex_1().min_w(px(0.)).overflow_hidden().child(
                Label::new(SharedString::from(entry.name.clone()))
                    .text_sm()
                    .line_clamp(1),
            ),
        )
        .child(
            Label::new(SharedString::from(if downloading {
                "Скачиваем…".to_owned()
            } else {
                detail
            }))
            .text_xs()
            .text_color(theme.muted_foreground)
            .line_clamp(1),
        )
        .when(!busy, |this| {
            this.on_click(cx.listener(move |this, _, _window, cx| {
                // Уже скачан — качать заново незачем.
                let Some(picker) = &this.icon_picker else {
                    return;
                };
                let key = pick.key(picker.colored);
                if this.has_icon(&picker.vault, &key) {
                    this.choose_icon(key, cx);
                } else {
                    this.download_icon(pick.clone(), cx);
                }
            }))
        })
        .into_any_element()
    }
}

/// Картинка значка размером `pixels`: SVG получает этот размер в корневом
/// теге, PNG уменьшается. Не вышло — исходные байты как есть.
fn raster(format: &str, bytes: &[u8], pixels: u32) -> Option<gpui_kit::Image> {
    use gpui_kit::ImageFormat;
    match format {
        "svg" => {
            let bytes = sized_svg(bytes, pixels).unwrap_or_else(|| bytes.to_vec());
            Some(gpui_kit::Image::from_bytes(ImageFormat::Svg, bytes))
        }
        "png" => {
            let bytes = smaller_png(bytes, pixels).unwrap_or_else(|| bytes.to_vec());
            Some(gpui_kit::Image::from_bytes(ImageFormat::Png, bytes))
        }
        _ => None,
    }
}

/// SVG с размером `pixels`×`pixels`: прежние `width` и `height` корневого
/// тега убираются, масштаб задаёт `viewBox`. Без `viewBox` размер менять
/// нельзя — картинка обрежется, а не уменьшится.
fn sized_svg(bytes: &[u8], pixels: u32) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(bytes).ok()?;
    let start = text.find("<svg")?;
    let end = start + text[start..].find('>')?;
    let tag = &text[start..end];
    if !tag.contains("viewBox") {
        return None;
    }
    let tag = without_attribute(&without_attribute(tag, "width"), "height");
    let tag = tag.trim_end_matches('/').trim_end();
    Some(
        format!(
            "{}{tag} width=\"{pixels}\" height=\"{pixels}\"{}",
            &text[..start],
            &text[end..]
        )
        .into_bytes(),
    )
}

/// Тег без атрибута `name="…"`. `stroke-width` и подобные не трогаются:
/// перед именем должен стоять пробел.
fn without_attribute(tag: &str, name: &str) -> String {
    let mut out = tag.to_owned();
    let needle = format!("{name}=");
    let mut from = 0;
    while let Some(found) = out[from..].find(&needle).map(|at| from + at) {
        let after_space = out[..found]
            .chars()
            .next_back()
            .is_some_and(char::is_whitespace);
        let value = found + needle.len();
        let quote = out[value..].chars().next();
        match (after_space, quote) {
            (true, Some(quote @ ('"' | '\''))) => {
                let Some(close) = out[value + 1..].find(quote) else {
                    break;
                };
                out.replace_range(found - 1..value + 1 + close + 1, "");
                from = found - 1;
            }
            _ => from = value,
        }
    }
    out
}

/// PNG, уменьшенный до `pixels` по большей стороне.
fn smaller_png(bytes: &[u8], pixels: u32) -> Option<Vec<u8>> {
    let image = image::load_from_memory_with_format(bytes, image::ImageFormat::Png).ok()?;
    if image.width().max(image.height()) <= pixels {
        return None;
    }
    let small = image.resize(pixels, pixels, image::imageops::FilterType::Lanczos3);
    let mut out = std::io::Cursor::new(Vec::new());
    small.write_to(&mut out, image::ImageFormat::Png).ok()?;
    Some(out.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn svg_poluchaet_razmer_v_kornevom_tege() {
        let svg = br#"<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" width="512" height='512' viewBox="0 0 512 512"><path stroke-width="2"/></svg>"#;
        let sized = String::from_utf8(sized_svg(svg, 40).expect("размер")).expect("utf8");
        assert_eq!(
            sized,
            r#"<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="40" height="40"><path stroke-width="2"/></svg>"#
        );
        // Без viewBox размер не трогаем.
        assert!(sized_svg(br#"<svg width="24" height="24"></svg>"#, 40).is_none());
        assert!(sized_svg(b"not svg", 40).is_none());
    }

    #[test]
    fn png_umenshaetsya() {
        let png = |width, height| {
            let mut bytes = std::io::Cursor::new(Vec::new());
            image::DynamicImage::new_rgba8(width, height)
                .write_to(&mut bytes, image::ImageFormat::Png)
                .expect("png");
            bytes.into_inner()
        };
        let small = smaller_png(&png(512, 256), 40).expect("уменьшен");
        let small = image::load_from_memory(&small).expect("читается");
        assert_eq!((small.width(), small.height()), (40, 20));
        assert!(
            smaller_png(&png(16, 16), 40).is_none(),
            "маленький не трогаем"
        );
    }

    #[test]
    fn put_k_znachku() {
        assert_eq!(
            icon_asset_path("fa:brands:github", "server"),
            "fa/brands/github.svg"
        );
        // Имена первых версий ведут к замене из Font Awesome.
        assert_eq!(
            icon_asset_path("database", "folder"),
            "fa/solid/database.svg"
        );
        assert_eq!(icon_asset_path("из-будущего", "folder"), "icons/folder.svg");
        assert_eq!(
            icon_asset_path("fa:brands:нет-такого", "folder"),
            "icons/folder.svg"
        );
        assert_eq!(icon_asset_path("", "server"), "icons/server.svg");
        assert_eq!(
            icon_asset_path("selfhst:github", "server"),
            "icons/server.svg"
        );
    }

    #[test]
    fn znachki_otdayutsya_zagruzchikom() {
        use gpui_kit::AssetSource as _;
        let assets = crate::ui::assets::Assets;
        let load = |path: &str| assets.load(path).ok().flatten().is_some();
        for name in SUGGESTED {
            assert!(load(&format!("fa/solid/{name}.svg")), "нет fa/solid/{name}");
        }
        for old in ["database", "container", "zap", "square-terminal"] {
            assert!(load(&icon_asset_path(old, "folder")), "нет замены {old}");
        }
        assert!(load("icons/server.svg") && load("icons/folder.svg"));
    }
}
