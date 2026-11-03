use gpui::{AnyElement, App, Div, SharedString, div, prelude::*};
use gpui_component::{ActiveTheme, Icon, Sizable, StyledExt, h_flex, label::Label, v_flex};
use proto::{ForwardKind, PortForward};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    You,
    Hop,
    Server,
    Network,
}

impl Place {
    fn icon(self) -> &'static str {
        match self {
            Self::You => "icons/monitor.svg",
            Self::Hop => "icons/route.svg",
            Self::Server => "icons/server.svg",
            Self::Network => "icons/globe.svg",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct End {
    pub place: Place,
    pub title: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardView {
    pub from: End,
    pub via: String,
    pub to: End,
}

pub fn kind_title(kind: ForwardKind) -> &'static str {
    match kind {
        ForwardKind::Local => "Локальный",
        ForwardKind::Remote => "Удалённый",
        ForwardKind::Dynamic => "Динамический",
        ForwardKind::Unsupported => "Неизвестный",
    }
}

fn end(place: Place, title: impl Into<String>, detail: impl Into<String>) -> End {
    End {
        place,
        title: title.into(),
        detail: detail.into(),
    }
}

pub fn forward_view(rule: &PortForward, server: &str) -> ForwardView {
    let server = if server.trim().is_empty() {
        "сервер"
    } else {
        server
    };
    let listen = rule.listen_port;
    match rule.kind {
        ForwardKind::Local => ForwardView {
            from: end(Place::You, "Этот компьютер", format!("127.0.0.1:{listen}")),
            via: format!("через {server}"),
            to: end(Place::Network, rule.target(), "Адрес в сети сервера"),
        },
        ForwardKind::Remote => ForwardView {
            from: end(Place::Server, server, format!("Порт {listen} на сервере")),
            via: "на этот компьютер".into(),
            to: end(Place::You, rule.target(), "Адрес в локальной сети"),
        },
        ForwardKind::Dynamic => ForwardView {
            from: end(Place::You, "SOCKS5", format!("127.0.0.1:{listen}")),
            via: format!("через {server}"),
            to: end(Place::Network, "Любой адрес", "Выход в сеть через сервер"),
        },
        ForwardKind::Unsupported => ForwardView {
            from: end(Place::You, "?", ""),
            via: String::new(),
            to: end(Place::Network, "Правило неизвестного типа", ""),
        },
    }
}

pub fn node(
    place: Place,
    title: impl Into<SharedString>,
    detail: impl Into<SharedString>,
    cx: &App,
) -> Div {
    let theme = cx.theme();
    let color = match place {
        Place::You => theme.success,
        Place::Hop => theme.muted_foreground,
        Place::Server => theme.primary,
        Place::Network => theme.info,
    };
    let detail = detail.into();
    h_flex()
        .gap_1p5()
        .items_center()
        .px_2()
        .py_1()
        .rounded_md()
        .border_1()
        .border_color(theme.border)
        .bg(theme.background)
        .child(Icon::empty().path(place.icon()).small().text_color(color))
        .child(
            v_flex()
                .child(Label::new(title.into()).text_xs().font_semibold())
                .when(!detail.is_empty(), |this| {
                    this.child(
                        Label::new(detail)
                            .text_xs()
                            .text_color(theme.muted_foreground),
                    )
                }),
        )
}

pub fn arrow(note: impl Into<SharedString>, cx: &App) -> AnyElement {
    let muted = cx.theme().muted_foreground;
    let note = note.into();
    v_flex()
        .items_center()
        .px_1()
        .when(!note.is_empty(), |this| {
            this.child(Label::new(note).text_xs().text_color(muted))
        })
        .child(Label::new("→").text_sm().text_color(muted))
        .into_any_element()
}

pub fn flow(steps: Vec<AnyElement>, cx: &App) -> Div {
    let mut row = h_flex().flex_wrap().items_center().gap_1();
    for (index, step) in steps.into_iter().enumerate() {
        if index > 0 {
            row = row.child(arrow("", cx));
        }
        row = row.child(step);
    }
    row
}

pub fn forward_line(rule: &PortForward, server: &str, cx: &App) -> Div {
    let view = forward_view(rule, server);
    let theme = cx.theme();
    let letter = match rule.kind {
        ForwardKind::Local => "L",
        ForwardKind::Remote => "R",
        ForwardKind::Dynamic => "D",
        ForwardKind::Unsupported => "?",
    };
    v_flex()
        .gap_0p5()
        .child(
            h_flex()
                .gap_1p5()
                .items_center()
                .child(
                    div()
                        .px_1()
                        .rounded_sm()
                        .bg(theme.secondary)
                        .text_xs()
                        .font_semibold()
                        .text_color(theme.muted_foreground)
                        .child(letter),
                )
                .child(Label::new(view.from.detail).text_sm())
                .child(Label::new("→").text_sm().text_color(theme.muted_foreground))
                .child(Label::new(view.to.title).text_sm()),
        )
        .child(
            Label::new(format!("{} · {}", view.via, view.to.detail))
                .text_xs()
                .text_color(theme.muted_foreground),
        )
}

pub fn forward(rule: &PortForward, server: &str, cx: &App) -> Div {
    let view = forward_view(rule, server);
    h_flex()
        .flex_wrap()
        .items_center()
        .gap_1()
        .child(node(view.from.place, view.from.title, view.from.detail, cx))
        .child(arrow(view.via, cx))
        .child(node(view.to.place, view.to.title, view.to.detail, cx))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(kind: ForwardKind) -> PortForward {
        PortForward {
            kind,
            listen_port: 8080,
            target_host: "db.internal".into(),
            target_port: 5432,
            enabled: true,
        }
    }

    #[test]
    fn napravlenie_probrosa_vidno_po_skheme() {
        let local = forward_view(&rule(ForwardKind::Local), "prod-01");
        assert_eq!(local.from.place, Place::You);
        assert_eq!(local.from.detail, "127.0.0.1:8080");
        assert_eq!(local.via, "через prod-01");
        assert_eq!(local.to.title, "db.internal:5432");

        let remote = forward_view(&rule(ForwardKind::Remote), "prod-01");
        assert_eq!(remote.from.place, Place::Server);
        assert_eq!(remote.to.place, Place::You);

        let socks = forward_view(&rule(ForwardKind::Dynamic), "");
        assert_eq!(socks.via, "через сервер");
        assert_eq!(socks.to.place, Place::Network);
    }
}
