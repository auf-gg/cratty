//! Импорт хостов из `~/.ssh/config` в хранилище.
//!
//! Работает с текстом конфигурации и абстрактной «книгой хостов», поэтому
//! проверяется без настоящего домашнего каталога и без настоящего хранилища.

use anyhow::Result;
use proto::{HostAuth, HostRecord, RecordId};

use crate::ui::connect::{self, HostSettings};

const MAX_JUMP_DEPTH: usize = 8;

pub trait HostBook {
    fn find(&self, target: &str) -> Option<RecordId>;
    fn put(&mut self, host: HostRecord) -> Result<RecordId>;
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub imported: usize,
    pub skipped: usize,
    pub warnings: Vec<String>,
}

impl Report {
    pub fn summary(&self) -> String {
        let mut text = format!(
            "Импорт из ~/.ssh/config: добавлено хостов — {}, пропущено (уже есть) — {}",
            self.imported, self.skipped
        );
        if !self.warnings.is_empty() {
            text.push_str(&format!(", предупреждений — {}", self.warnings.len()));
        }
        text.push('.');
        for warning in &self.warnings {
            text.push('\n');
            text.push_str(warning);
        }
        text
    }
}

pub fn import(text: &str, book: &mut dyn HostBook) -> Report {
    let mut report = Report::default();
    let mut made_as_hop: Vec<String> = Vec::new();

    for alias in connect::parse_host_aliases(text) {
        let settings = connect::read_ssh_config_text(text, &alias);
        let mut host = record_for(&alias, &settings, &alias);

        if book.find(&host.target()).is_some() {
            if !made_as_hop.contains(&host.target()) {
                report.skipped += 1;
            }
            continue;
        }

        if settings.proxy_command.is_some() {
            report.warnings.push(format!(
                "{alias}: ProxyCommand не поддерживается, хост импортирован без него."
            ));
        }

        if let Some(jump) = settings.proxy_jump.as_deref()
            && !is_none(jump)
        {
            let mut context = Chain {
                text,
                book: &mut *book,
                report: &mut report,
                made_as_hop: &mut made_as_hop,
            };
            match context.resolve(jump, &mut vec![alias.clone()]) {
                Ok(via) => host.via = via,
                Err(message) => context.report.warnings.push(format!(
                    "{alias}: {message} Хост импортирован без ProxyJump."
                )),
            }
        }

        match book.put(host) {
            Ok(_) => report.imported += 1,
            Err(error) => report
                .warnings
                .push(format!("{alias}: не удалось сохранить: {error:#}")),
        }
    }

    report
}

struct Chain<'a> {
    text: &'a str,
    book: &'a mut dyn HostBook,
    report: &'a mut Report,
    made_as_hop: &'a mut Vec<String>,
}

impl Chain<'_> {
    fn resolve(&mut self, raw: &str, seen: &mut Vec<String>) -> Result<Vec<RecordId>, String> {
        if seen.len() > MAX_JUMP_DEPTH {
            return Err("Цепочка ProxyJump слишком длинная или зациклена.".into());
        }

        let mut ids = Vec::new();
        for item in raw.split(',').map(str::trim) {
            if item.is_empty() {
                return Err(format!("В ProxyJump «{raw}» пустой элемент."));
            }
            let item = item.strip_prefix("ssh://").unwrap_or(item);
            let request = connect::parse_target(item).map_err(|error| error.to_string())?;
            if seen.contains(&request.alias) {
                return Err("Цепочка ProxyJump зациклена.".into());
            }

            let settings = connect::read_ssh_config_text(self.text, &request.alias);
            let mut hop = record_for(&request.alias, &settings, "");
            if let Some(user) = request.user {
                hop.user = user;
            }
            if let Some(port) = request.port {
                hop.port = port;
            }

            let target = hop.target();
            if let Some(id) = self.book.find(&target) {
                ids.push(id);
                continue;
            }

            if let Some(own) = settings.proxy_jump.as_deref()
                && !is_none(own)
            {
                seen.push(request.alias.clone());
                let inner = self.resolve(own, seen);
                seen.pop();
                hop.via = inner?;
            }

            hop.label = request.alias.clone();
            let id = self
                .book
                .put(hop)
                .map_err(|error| format!("не удалось сохранить промежуточный хост: {error:#}"))?;
            self.report.imported += 1;
            self.made_as_hop.push(target);
            ids.push(id);
        }
        Ok(ids)
    }
}

fn is_none(value: &str) -> bool {
    value.trim().eq_ignore_ascii_case("none")
}

fn record_for(alias: &str, settings: &HostSettings, label: &str) -> HostRecord {
    let mut host = HostRecord::new(
        settings
            .hostname
            .clone()
            .unwrap_or_else(|| alias.to_owned()),
    );
    host.label = label.to_owned();
    host.user = settings.user.clone().unwrap_or_default();
    host.port = settings.port.unwrap_or(22);
    if let Some(path) = settings.identity_files.first() {
        host.auth = HostAuth::Key {
            path: path.display().to_string(),
        };
    }
    host
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MemBook {
        hosts: Vec<(RecordId, HostRecord)>,
    }

    impl HostBook for MemBook {
        fn find(&self, target: &str) -> Option<RecordId> {
            self.hosts
                .iter()
                .find(|(_, host)| host.target() == target)
                .map(|(id, _)| id.clone())
        }

        fn put(&mut self, host: HostRecord) -> Result<RecordId> {
            let id = RecordId::generate().map_err(|error| anyhow::anyhow!("{error}"))?;
            self.hosts.push((id.clone(), host));
            Ok(id)
        }
    }

    impl MemBook {
        fn by_label(&self, label: &str) -> &HostRecord {
            &self
                .hosts
                .iter()
                .find(|(_, host)| host.label == label)
                .expect("хост")
                .1
        }
    }

    #[test]
    fn prostoy_host_perenosit_adres_polzovatelya_port_i_klyuch() {
        let mut book = MemBook::default();
        let report = import(
            "Host prod\n  HostName 10.0.0.5\n  User deploy\n  Port 2200\n  IdentityFile /keys/id_prod\n",
            &mut book,
        );

        assert_eq!(report.imported, 1);
        assert_eq!(report.skipped, 0);
        assert!(report.warnings.is_empty());
        let host = book.by_label("prod");
        assert_eq!(host.host, "10.0.0.5");
        assert_eq!(host.user, "deploy");
        assert_eq!(host.port, 2200);
        assert_eq!(
            host.auth,
            HostAuth::Key {
                path: "/keys/id_prod".into()
            }
        );
    }

    #[test]
    fn bez_hostname_adresom_stanovitsya_psevdonim() {
        let mut book = MemBook::default();
        import("Host db.internal\n  User root\n", &mut book);
        let host = book.by_label("db.internal");
        assert_eq!(host.host, "db.internal");
        assert_eq!(host.auth, HostAuth::Auto);
    }

    #[test]
    fn shablony_s_zvezdochkoy_ne_importiruyutsya() {
        let mut book = MemBook::default();
        let report = import(
            "Host *\n  ServerAliveInterval 30\nHost *.corp web\n  User ops\nHost real\n  HostName r.example.com\n",
            &mut book,
        );
        assert_eq!(report.imported, 2);
        let labels: Vec<&str> = book.hosts.iter().map(|(_, h)| h.label.as_str()).collect();
        assert_eq!(labels, ["web", "real"]);
    }

    #[test]
    fn sushchestvuyushchie_hosty_propuskayutsya() {
        let mut book = MemBook::default();
        let text = "Host a\n  HostName a.example.com\nHost b\n  HostName b.example.com\n";
        let first = import(text, &mut book);
        assert_eq!((first.imported, first.skipped), (2, 0));

        let second = import(text, &mut book);
        assert_eq!((second.imported, second.skipped), (0, 2));
        assert_eq!(book.hosts.len(), 2);
    }

    #[test]
    fn proxyjump_sozdaet_ili_nahodit_promezhutochnye_hosty() {
        let mut book = MemBook::default();
        let report = import(
            "Host inner\n  HostName 10.1.1.1\n  ProxyJump bastion,jump2:2222\nHost bastion\n  HostName b.example.com\n  User gate\n",
            &mut book,
        );

        let inner = book.by_label("inner").clone();
        assert_eq!(inner.via.len(), 2);
        let bastion = book.find("gate@b.example.com").expect("бастион");
        assert_eq!(inner.via[0], bastion);
        let jump2 = book.hosts.iter().find(|(id, _)| *id == inner.via[1]);
        assert_eq!(jump2.map(|(_, h)| h.target()), Some("jump2:2222".into()));

        assert_eq!(report.imported, 3, "inner + bastion + jump2");
        assert_eq!(
            report.skipped, 0,
            "бастион из ProxyJump не считается пропущенным"
        );
    }

    #[test]
    fn proxyjump_ispolzuet_uzhe_sohranyonnyy_host() {
        let mut book = MemBook::default();
        let existing = book
            .put({
                let mut host = HostRecord::new("b.example.com");
                host.user = "gate".into();
                host
            })
            .expect("запись");
        import(
            "Host bastion\n  HostName b.example.com\n  User gate\nHost inner\n  ProxyJump bastion\n",
            &mut book,
        );
        assert_eq!(book.by_label("inner").via, vec![existing]);
        assert_eq!(book.hosts.len(), 2);
    }

    #[test]
    fn proxycommand_importiruetsya_bez_nego_s_preduprezhdeniem() {
        let mut book = MemBook::default();
        let report = import(
            "Host tunneled\n  HostName t.example.com\n  ProxyCommand nc -X 5 -x proxy:1080 %h %p\n",
            &mut book,
        );
        assert_eq!(report.imported, 1);
        assert_eq!(report.warnings.len(), 1);
        assert!(report.warnings[0].starts_with("tunneled: ProxyCommand"));
        assert!(book.by_label("tunneled").via.is_empty());
    }

    #[test]
    fn zacyklennyy_proxyjump_ne_zavisaet_a_preduprezhdaet() {
        let mut book = MemBook::default();
        let report = import(
            "Host a\n  HostName a.example.com\n  ProxyJump b\nHost b\n  HostName b.example.com\n  ProxyJump a\n",
            &mut book,
        );
        assert_eq!(report.warnings.len(), 1, "{report:?}");
        assert!(report.warnings[0].starts_with("a: "));
        assert_eq!(book.hosts.len(), 2);
        assert!(book.by_label("a").via.is_empty());
    }

    #[test]
    fn proxyjump_none_ne_sozdaet_cepochku() {
        let mut book = MemBook::default();
        let report = import("Host direct\n  ProxyJump none\n", &mut book);
        assert_eq!(report.imported, 1);
        assert!(book.by_label("direct").via.is_empty());
    }

    #[test]
    fn itog_perechislyaet_chisla_i_preduprezhdeniya() {
        let report = Report {
            imported: 3,
            skipped: 1,
            warnings: vec!["x: плохо".into()],
        };
        let text = report.summary();
        assert!(text.contains("добавлено хостов — 3"));
        assert!(text.contains("пропущено (уже есть) — 1"));
        assert!(text.contains("предупреждений — 1"));
        assert!(text.ends_with("x: плохо"));
    }
}
