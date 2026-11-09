//! Import of hosts from `~/.ssh/config` into the vault.
//!
//! Works with the config text and an abstract "host book", so it
//! can be tested without a real home directory and without a real vault.

use rust_i18n::t;
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
        let mut text = if self.warnings.is_empty() {
            t!(
                "import.summary",
                imported = self.imported,
                skipped = self.skipped
            )
            .to_string()
        } else {
            t!(
                "import.summary_warnings",
                imported = self.imported,
                skipped = self.skipped,
                warnings = self.warnings.len()
            )
            .to_string()
        };
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
            report
                .warnings
                .push(t!("import.proxy_command", alias = alias).to_string());
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
                Err(message) => context
                    .report
                    .warnings
                    .push(t!("import.proxy_jump_dropped", alias = alias, message = message).to_string()),
            }
        }

        match book.put(host) {
            Ok(_) => report.imported += 1,
            Err(error) => report
                .warnings
                .push(t!("import.save_failed", alias = alias, error = format!("{error:#}")).to_string()),
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
            return Err(t!("import.chain_too_long").into());
        }

        let mut ids = Vec::new();
        for item in raw.split(',').map(str::trim) {
            if item.is_empty() {
                return Err(t!("import.empty_element", raw = raw).to_string());
            }
            let item = item.strip_prefix("ssh://").unwrap_or(item);
            let request = connect::parse_target(item).map_err(|error| error.to_string())?;
            if seen.contains(&request.alias) {
                return Err(t!("import.chain_cyclic").into());
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
                .map_err(|error| t!("import.hop_save_failed", error = format!("{error:#}")).to_string())?;
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
                .expect("host")
                .1
        }
    }

    #[test]
    fn simple_host_carries_address_user_port_and_key() {
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
    fn without_hostname_the_alias_becomes_the_address() {
        let mut book = MemBook::default();
        import("Host db.internal\n  User root\n", &mut book);
        let host = book.by_label("db.internal");
        assert_eq!(host.host, "db.internal");
        assert_eq!(host.auth, HostAuth::Auto);
    }

    #[test]
    fn wildcard_patterns_are_not_imported() {
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
    fn existing_hosts_are_skipped() {
        let mut book = MemBook::default();
        let text = "Host a\n  HostName a.example.com\nHost b\n  HostName b.example.com\n";
        let first = import(text, &mut book);
        assert_eq!((first.imported, first.skipped), (2, 0));

        let second = import(text, &mut book);
        assert_eq!((second.imported, second.skipped), (0, 2));
        assert_eq!(book.hosts.len(), 2);
    }

    #[test]
    fn proxyjump_creates_or_finds_intermediate_hosts() {
        let mut book = MemBook::default();
        let report = import(
            "Host inner\n  HostName 10.1.1.1\n  ProxyJump bastion,jump2:2222\nHost bastion\n  HostName b.example.com\n  User gate\n",
            &mut book,
        );

        let inner = book.by_label("inner").clone();
        assert_eq!(inner.via.len(), 2);
        let bastion = book.find("gate@b.example.com").expect("bastion");
        assert_eq!(inner.via[0], bastion);
        let jump2 = book.hosts.iter().find(|(id, _)| *id == inner.via[1]);
        assert_eq!(jump2.map(|(_, h)| h.target()), Some("jump2:2222".into()));

        assert_eq!(report.imported, 3, "inner + bastion + jump2");
        assert_eq!(
            report.skipped, 0,
            "a bastion from ProxyJump does not count as skipped"
        );
    }

    #[test]
    fn proxyjump_uses_already_saved_host() {
        let mut book = MemBook::default();
        let existing = book
            .put({
                let mut host = HostRecord::new("b.example.com");
                host.user = "gate".into();
                host
            })
            .expect("entry");
        import(
            "Host bastion\n  HostName b.example.com\n  User gate\nHost inner\n  ProxyJump bastion\n",
            &mut book,
        );
        assert_eq!(book.by_label("inner").via, vec![existing]);
        assert_eq!(book.hosts.len(), 2);
    }

    #[test]
    fn proxycommand_is_imported_without_it_with_a_warning() {
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
    fn cyclic_proxyjump_does_not_hang_but_warns() {
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
    fn proxyjump_none_does_not_create_a_chain() {
        let mut book = MemBook::default();
        let report = import("Host direct\n  ProxyJump none\n", &mut book);
        assert_eq!(report.imported, 1);
        assert!(book.by_label("direct").via.is_empty());
    }

    #[test]
    fn summary_lists_counts_and_warnings() {
        let report = Report {
            imported: 3,
            skipped: 1,
            warnings: vec!["x: bad".into()],
        };
        let text = report.summary();
        assert!(text.contains("hosts added — 3"));
        assert!(text.contains("skipped (already present) — 1"));
        assert!(text.contains("warnings — 1"));
        assert!(text.ends_with("x: bad"));
    }
}
