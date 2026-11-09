use rust_i18n::t;
use std::path::PathBuf;

use crate::ssh::auth::{self, AuthPlan};
use crate::ssh::{AuthMethod, Hop, HostKeyPolicy, JumpHost, PtySize, Socks5Hop, SshConfig};
use proto::HostAuth;

pub const PASSWORD_ENV: &str = "CRATTY_PASSWORD";
pub const FINGERPRINT_ENV: &str = "CRATTY_FINGERPRINT";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub user: String,
    pub host: String,
    pub port: u16,
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.user, self.host)?;
        if self.port != 22 {
            write!(f, ":{}", self.port)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub alias: String,
    pub user: Option<String>,
    pub port: Option<u16>,
}

pub fn parse_target(raw: &str) -> Result<Request, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(t!("connect.no_address").into());
    }

    let (user, rest) = match raw.rsplit_once('@') {
        Some((user, rest)) if !user.is_empty() => (Some(user.to_string()), rest),
        Some(_) => return Err(t!("connect.empty_user", raw = raw).to_string()),
        None => (None, raw),
    };

    let (alias, port) = if let Some(rest) = rest.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| t!("connect.unclosed_bracket", raw = raw).to_string())?;
        (host.to_string(), parse_port(tail.strip_prefix(':'), raw)?)
    } else {
        match rest.rsplit_once(':') {
            Some((host, _)) if host.contains(':') => (rest.to_string(), None),
            Some((host, port)) => (host.to_string(), parse_port(Some(port), raw)?),
            None => (rest.to_string(), None),
        }
    };

    if alias.is_empty() {
        return Err(t!("connect.no_host", raw = raw).to_string());
    }

    Ok(Request { alias, user, port })
}

fn parse_port(raw: Option<&str>, whole: &str) -> Result<Option<u16>, String> {
    match raw {
        None => Ok(None),
        Some(text) => text
            .parse()
            .map(Some)
            .map_err(|_| t!("connect.invalid_port", raw = whole, port = text).to_string()),
    }
}

pub fn default_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "root".to_string())
}

#[derive(Clone, Debug, Default)]
pub struct HostSettings {
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_files: Vec<PathBuf>,
    pub known_hosts_file: Option<PathBuf>,
    pub proxy_jump: Option<String>,
    pub proxy_command: Option<String>,
}

pub fn read_ssh_config(alias: &str) -> HostSettings {
    russh_config::parse_home(alias)
        .map(settings_from)
        .unwrap_or_default()
}

pub fn read_ssh_config_text(text: &str, alias: &str) -> HostSettings {
    russh_config::parse(text, alias)
        .map(settings_from)
        .unwrap_or_default()
}

fn settings_from(config: russh_config::Config) -> HostSettings {
    let host = config.host_config.hostname.clone();
    HostSettings {
        hostname: host.filter(|name| !name.is_empty()),
        user: config
            .host_config
            .user
            .clone()
            .or_else(|| config.user.clone())
            .filter(|user| !user.is_empty()),
        port: config.host_config.port.or(config.port),
        identity_files: config.host_config.identity_file.clone().unwrap_or_default(),
        known_hosts_file: config.host_config.user_known_hosts_file.clone(),
        proxy_jump: config.host_config.proxy_jump.clone(),
        proxy_command: config.host_config.proxy_command.clone(),
    }
}

const MAX_JUMP_DEPTH: usize = 8;

fn is_none(value: &str) -> bool {
    value.trim().eq_ignore_ascii_case("none")
}

pub fn jumps_from(
    raw: &str,
    lookup: &dyn Fn(&str) -> HostSettings,
) -> Result<Vec<JumpHost>, String> {
    let mut seen = Vec::new();
    jumps_inner(raw, lookup, &mut seen)
}

fn jumps_inner(
    raw: &str,
    lookup: &dyn Fn(&str) -> HostSettings,
    seen: &mut Vec<String>,
) -> Result<Vec<JumpHost>, String> {
    if is_none(raw) {
        return Ok(Vec::new());
    }

    let mut hops = Vec::new();
    for (index, item) in raw.split(',').map(str::trim).enumerate() {
        if item.is_empty() {
            return Err(t!("connect.jump_empty", raw = raw).to_string());
        }
        let item = item.strip_prefix("ssh://").unwrap_or(item);
        let request = parse_target(item).map_err(|error| t!("connect.jump_error", error = error).to_string())?;
        let settings = lookup(&request.alias);

        if index == 0
            && let Some(own) = settings.proxy_jump.as_deref().filter(|own| !is_none(own))
        {
            if seen.contains(&request.alias) || seen.len() >= MAX_JUMP_DEPTH {
                return Err(t!(
                    "connect.jump_cyclic",
                    chain = seen.join(" → "),
                    alias = request.alias
                )
                .to_string());
            }
            seen.push(request.alias.clone());
            hops.extend(jumps_inner(own, lookup, seen)?);
        }

        let target = resolve(&request, &settings);
        hops.push(JumpHost {
            host: target.host,
            port: target.port,
            user: target.user,
            auth: AuthMethod::Plan(AuthPlan::standard(
                &settings.identity_files,
                auth::ssh_dir().as_deref(),
            )),
            host_key_policy: match &settings.known_hosts_file {
                Some(path) => HostKeyPolicy::KnownHostsFile(path.clone()),
                None => HostKeyPolicy::KnownHosts,
            },
            stored_password: None,
        });
    }
    Ok(hops)
}

fn jump_from_record(host: &proto::HostRecord, lookup: &dyn Fn(&str) -> HostSettings) -> JumpHost {
    let request = Request {
        alias: host.host.clone(),
        user: (!host.user.is_empty()).then(|| host.user.clone()),
        port: Some(host.port),
    };
    let settings = lookup(&request.alias);
    let target = resolve(&request, &settings);
    let stored = host.password().cloned();
    JumpHost {
        host: target.host,
        port: target.port,
        user: target.user,
        auth: auth_method(&host.auth, None, stored.is_some(), &settings),
        host_key_policy: match &settings.known_hosts_file {
            Some(path) => HostKeyPolicy::KnownHostsFile(path.clone()),
            None => HostKeyPolicy::KnownHosts,
        },
        stored_password: stored,
    }
}

fn auth_method(
    host_auth: &HostAuth,
    typed: Option<String>,
    has_stored: bool,
    settings: &HostSettings,
) -> AuthMethod {
    let auth = match (host_auth, typed) {
        (HostAuth::Password, Some(password)) => AuthMethod::Password(password),
        (HostAuth::Password, None) => AuthMethod::Plan(AuthPlan::password_only()),
        (HostAuth::Key { path }, _) => AuthMethod::Plan(AuthPlan {
            order: vec![
                auth::Credential::Key(std::path::PathBuf::from(path)),
                auth::Credential::Password,
            ],
        }),
        (HostAuth::Auto, Some(password)) => AuthMethod::Password(password),
        (HostAuth::Auto, None) => AuthMethod::Plan(AuthPlan::standard(
            &settings.identity_files,
            auth::ssh_dir().as_deref(),
        )),
    };

    match (auth, has_stored) {
        (AuthMethod::Plan(plan), true) => AuthMethod::Plan(plan.with_stored_password()),
        (auth, _) => auth,
    }
}

pub fn route_for(
    credentials: &Credentials,
    settings: &HostSettings,
    lookup: &dyn Fn(&str) -> HostSettings,
) -> Result<Vec<Hop>, String> {
    if let Some(error) = &credentials.proxy_error {
        return Err(error.clone());
    }

    let mut hops = Vec::new();
    for item in &credentials.via {
        let proxy = match item {
            crate::vault_session::ViaItem::Proxy(proxy) => proxy,
            crate::vault_session::ViaItem::Host(host) => {
                hops.push(Hop::Jump(jump_from_record(host, lookup)));
                continue;
            }
        };
        match proxy.kind {
            proto::ProxyKind::Socks5 => hops.push(Hop::Socks5(Socks5Hop {
                host: proxy.host.clone(),
                port: proxy.port,
                user: proxy.user.clone(),
                password: proxy.password().cloned(),
            })),
            proto::ProxyKind::Unsupported => {
                return Err(t!("connect.proxy_unsupported", title = proxy.title()).to_string());
            }
        }
    }

    let jump = settings.proxy_jump.as_deref().filter(|raw| !is_none(raw));
    let command = settings
        .proxy_command
        .as_deref()
        .filter(|raw| !is_none(raw));
    match (jump, command) {
        (Some(raw), _) => hops.extend(jumps_from(raw, lookup)?.into_iter().map(Hop::Jump)),
        (None, Some(command)) => {
            return Err(t!("connect.proxy_command", command = command).to_string());
        }
        (None, None) => {}
    }

    Ok(hops)
}

pub fn resolve(request: &Request, settings: &HostSettings) -> Target {
    Target {
        user: request
            .user
            .clone()
            .or_else(|| settings.user.clone())
            .unwrap_or_else(default_user),
        host: settings
            .hostname
            .clone()
            .unwrap_or_else(|| request.alias.clone()),
        port: request.port.or(settings.port).unwrap_or(22),
    }
}

#[derive(Clone, Default)]
pub struct Credentials {
    pub auth: HostAuth,
    pub password: Option<proto::Secret>,
    pub stored: Option<proto::Secret>,
    pub via: Vec<crate::vault_session::ViaItem>,
    pub proxy_error: Option<String>,
    pub forward_agent: bool,
    pub forwards: Vec<proto::PortForward>,
    /// Command instead of a shell (for example, installing a key on the server).
    pub command: Option<String>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("auth", &self.auth)
            .field("password", &self.password.as_ref().map(|_| "<hidden>"))
            .field("stored", &self.stored.as_ref().map(|_| "<hidden>"))
            .field("via", &self.via.len())
            .field("proxy_error", &self.proxy_error)
            .field("forward_agent", &self.forward_agent)
            .finish()
    }
}

pub fn config_for(
    target: &Target,
    settings: &HostSettings,
    credentials: &Credentials,
    pty: PtySize,
    agent: Option<crate::agent::Address>,
) -> SshConfig {
    let typed = credentials
        .password
        .as_ref()
        .and_then(|secret| std::str::from_utf8(secret.expose()).ok())
        .map(str::to_owned)
        .filter(|password| !password.is_empty())
        .or_else(|| std::env::var(PASSWORD_ENV).ok().filter(|p| !p.is_empty()));

    let auth = auth_method(
        &credentials.auth,
        typed,
        credentials.stored.is_some(),
        settings,
    );

    let mut config = SshConfig::new(target.host.clone(), target.port, target.user.clone(), auth);
    config.stored_password = credentials.stored.clone();
    config.pty = pty;
    config.agent = agent;
    config.via = route_for(credentials, settings, &read_ssh_config);
    config.forward_agent = credentials.forward_agent;
    config.forwards = credentials.forwards.clone();
    config.command = credentials.command.clone();

    config.host_key_policy = match std::env::var(FINGERPRINT_ENV) {
        Ok(fingerprint) if !fingerprint.is_empty() => {
            HostKeyPolicy::Fingerprints(vec![fingerprint])
        }
        _ => match &settings.known_hosts_file {
            Some(path) => HostKeyPolicy::KnownHostsFile(path.clone()),
            None => HostKeyPolicy::KnownHosts,
        },
    };

    config
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownHost {
    pub alias: String,
    pub detail: String,
}

pub fn ssh_config_path() -> Option<PathBuf> {
    auth::ssh_dir().map(|dir| dir.join("config"))
}

pub fn list_known_hosts() -> Vec<KnownHost> {
    let Some(path) = ssh_config_path() else {
        return Vec::new();
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    parse_host_aliases(&text)
        .into_iter()
        .map(|alias| {
            let settings = read_ssh_config(&alias);
            let target = resolve(
                &Request {
                    alias: alias.clone(),
                    user: None,
                    port: None,
                },
                &settings,
            );
            KnownHost {
                alias,
                detail: target.to_string(),
            }
        })
        .collect()
}

pub fn parse_host_aliases(text: &str) -> Vec<String> {
    let mut aliases: Vec<String> = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, |c: char| c.is_whitespace() || c == '=');
        let Some(keyword) = parts.next() else {
            continue;
        };
        if !keyword.eq_ignore_ascii_case("host") {
            continue;
        }
        let Some(rest) = parts.next() else { continue };

        for alias in rest.split_whitespace() {
            let alias = alias.trim();
            if alias.is_empty()
                || alias.contains('*')
                || alias.contains('?')
                || alias.starts_with('!')
            {
                continue;
            }
            if !aliases.iter().any(|known| known == alias) {
                aliases.push(alias.to_string());
            }
        }
    }

    aliases
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyEntry {
    pub path: PathBuf,
    pub name: String,
    pub encrypted: bool,
}

pub fn list_keys() -> Vec<KeyEntry> {
    let plan = AuthPlan::standard(&[], auth::ssh_dir().as_deref());
    plan.order
        .into_iter()
        .filter_map(|credential| match credential {
            auth::Credential::Key(path) => Some(path),
            _ => None,
        })
        .map(|path| {
            let name = path
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_else(|| path.display().to_string());
            let encrypted = matches!(
                auth::load_key(&path, None),
                Ok(auth::KeyLoad::NeedsPassphrase)
            );
            KeyEntry {
                path,
                name,
                encrypted,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(alias: &str, user: Option<&str>, port: Option<u16>) -> Request {
        Request {
            alias: alias.into(),
            user: user.map(str::to_string),
            port,
        }
    }

    #[test]
    fn bare_host_leaves_user_and_port_unset() {
        assert_eq!(
            parse_target("example.com"),
            Ok(request("example.com", None, None))
        );
    }

    #[test]
    fn user_and_port_are_picked_up() {
        assert_eq!(
            parse_target("root@10.0.0.1:2222"),
            Ok(request("10.0.0.1", Some("root"), Some(2222)))
        );
    }

    #[test]
    fn ipv6_needs_brackets_to_carry_a_port() {
        assert_eq!(
            parse_target("[::1]:2222"),
            Ok(request("::1", None, Some(2222)))
        );
        assert_eq!(parse_target("::1"), Ok(request("::1", None, None)));
    }

    #[test]
    fn bad_port_is_reported_not_ignored() {
        let error = parse_target("host:not-a-number").expect_err("should be an error");
        assert!(error.contains("port"), "unclear error: {error}");
    }

    #[test]
    fn empty_target_is_rejected() {
        assert!(parse_target("   ").is_err());
    }

    #[test]
    fn empty_user_is_rejected() {
        assert!(parse_target("@host").is_err());
    }

    #[test]
    fn ssh_config_fills_in_what_the_command_line_left_out() {
        let settings = HostSettings {
            hostname: Some("real.example.com".into()),
            user: Some("from-config".into()),
            port: Some(2222),
            ..Default::default()
        };
        let target = resolve(&request("alias", None, None), &settings);

        assert_eq!(target.host, "real.example.com");
        assert_eq!(target.user, "from-config");
        assert_eq!(target.port, 2222);
    }

    #[test]
    fn command_line_wins_over_ssh_config() {
        let settings = HostSettings {
            hostname: Some("real.example.com".into()),
            user: Some("from-config".into()),
            port: Some(2222),
            ..Default::default()
        };
        let target = resolve(&request("alias", Some("explicit"), Some(2022)), &settings);

        assert_eq!(target.host, "real.example.com");
        assert_eq!(target.user, "explicit");
        assert_eq!(target.port, 2022);
    }

    #[test]
    fn without_ssh_config_the_alias_is_the_host() {
        let target = resolve(
            &request("example.com", Some("dan"), None),
            &HostSettings::default(),
        );
        assert_eq!(target.host, "example.com");
        assert_eq!(target.user, "dan");
        assert_eq!(target.port, 22);
    }

    #[test]
    fn display_hides_the_default_port() {
        let target = resolve(
            &request("host", Some("root"), None),
            &HostSettings::default(),
        );
        assert_eq!(target.to_string(), "root@host");
        let target = resolve(
            &request("host", Some("root"), Some(2222)),
            &HostSettings::default(),
        );
        assert_eq!(target.to_string(), "root@host:2222");
    }

    #[test]
    fn host_aliases_are_collected_in_order_without_duplicates() {
        let config = "\
# comment
Host work
    HostName 10.0.0.1

Host server backup
    User dan

Host work
    Port 2222
";
        assert_eq!(
            parse_host_aliases(config),
            vec!["work", "server", "backup"]
        );
    }

    #[test]
    fn patterns_are_not_offered_as_connection_targets() {
        let config = "Host *\n    User dan\n\nHost *.example.com\n\nHost !bad good\n";
        assert_eq!(parse_host_aliases(config), vec!["good"]);
    }

    #[test]
    fn keyword_case_and_equals_separator_are_accepted() {
        let config = "HOST=first\nhost   second\n";
        assert_eq!(parse_host_aliases(config), vec!["first", "second"]);
    }

    fn fake_config(entries: &[(&str, HostSettings)]) -> impl Fn(&str) -> HostSettings + use<> {
        let map: std::collections::HashMap<String, HostSettings> = entries
            .iter()
            .map(|(alias, settings)| (alias.to_string(), settings.clone()))
            .collect();
        move |alias: &str| map.get(alias).cloned().unwrap_or_default()
    }

    fn jump_addresses(hops: &[JumpHost]) -> Vec<String> {
        hops.iter()
            .map(|hop| format!("{}@{}:{}", hop.user, hop.host, hop.port))
            .collect()
    }

    #[test]
    fn proxyjump_list_is_parsed_in_order() {
        let lookup = fake_config(&[]);
        let hops = jumps_from("alice@bastion:2222, ssh://bob@inner", &lookup).expect("parse");
        assert_eq!(
            jump_addresses(&hops),
            vec!["alice@bastion:2222", "bob@inner:22"]
        );
    }

    #[test]
    fn proxyjump_takes_host_settings_from_config() {
        let lookup = fake_config(&[(
            "bastion",
            HostSettings {
                hostname: Some("10.0.0.1".into()),
                user: Some("ops".into()),
                port: Some(2200),
                ..Default::default()
            },
        )]);
        let hops = jumps_from("bastion", &lookup).expect("parse");
        assert_eq!(jump_addresses(&hops), vec!["ops@10.0.0.1:2200"]);
    }

    #[test]
    fn proxyjump_of_first_host_goes_before_it() {
        let lookup = fake_config(&[(
            "inner",
            HostSettings {
                proxy_jump: Some("outer@edge".into()),
                ..Default::default()
            },
        )]);
        let hops = jumps_from("me@inner", &lookup).expect("parse");
        assert_eq!(jump_addresses(&hops), vec!["outer@edge:22", "me@inner:22"]);
    }

    #[test]
    fn cyclic_proxyjump_does_not_loop_forever() {
        let lookup = fake_config(&[
            (
                "a",
                HostSettings {
                    proxy_jump: Some("b".into()),
                    ..Default::default()
                },
            ),
            (
                "b",
                HostSettings {
                    proxy_jump: Some("a".into()),
                    ..Default::default()
                },
            ),
        ]);
        let error = jumps_from("a", &lookup).expect_err("a cycle must be an error");
        assert!(error.contains("cyclic"), "{error}");
    }

    #[test]
    fn proxyjump_none_means_direct() {
        let lookup = fake_config(&[]);
        assert!(jumps_from("none", &lookup).expect("parse").is_empty());
        assert!(jumps_from("None", &lookup).expect("parse").is_empty());
    }

    #[test]
    fn bad_proxyjump_is_an_error_not_a_skip() {
        let lookup = fake_config(&[]);
        assert!(jumps_from("a,,b", &lookup).is_err());
        assert!(jumps_from("host:notaport", &lookup).is_err());
    }

    fn socks(host: &str) -> proto::ProxyRecord {
        proto::ProxyRecord::new(proto::ProxyKind::Socks5, host, 1080)
    }

    #[test]
    fn route_is_proxy_first_then_proxyjump() {
        let lookup = fake_config(&[]);
        let credentials = Credentials {
            via: vec![socks("office-proxy").into()],
            ..Default::default()
        };
        let settings = HostSettings {
            proxy_jump: Some("bastion".into()),
            ..Default::default()
        };

        let hops = route_for(&credentials, &settings, &lookup).expect("route");
        let names: Vec<String> = hops.iter().map(Hop::describe).collect();
        assert_eq!(names.len(), 2);
        assert!(
            names[0].starts_with("SOCKS5 proxy office-proxy"),
            "{names:?}"
        );
        assert!(names[1].starts_with("jump host"), "{names:?}");
    }

    #[test]
    fn unresolved_chain_does_not_turn_into_direct_connection() {
        let lookup = fake_config(&[]);
        let credentials = Credentials {
            proxy_error: Some("proxy #1 in the chain is not in the vault".into()),
            ..Default::default()
        };
        let error = route_for(&credentials, &HostSettings::default(), &lookup)
            .expect_err("the route must fail to build");
        assert!(error.contains("not in the vault"), "{error}");
    }

    #[test]
    fn proxycommand_without_proxyjump_is_refused() {
        let lookup = fake_config(&[]);
        let settings = HostSettings {
            proxy_command: Some("cloudflared access ssh --hostname %h".into()),
            ..Default::default()
        };
        let error = route_for(&Credentials::default(), &settings, &lookup)
            .expect_err("we do not run ProxyCommand and do not connect directly either");
        assert!(error.contains("ProxyCommand"), "{error}");

        let settings = HostSettings {
            proxy_command: Some("none".into()),
            ..Default::default()
        };
        assert!(
            route_for(&Credentials::default(), &settings, &lookup)
                .expect("route")
                .is_empty()
        );
    }

    #[test]
    fn unknown_proxy_kind_is_not_skipped() {
        let lookup = fake_config(&[]);
        let mut proxy = socks("future");
        proxy.kind = proto::ProxyKind::Unsupported;
        let credentials = Credentials {
            via: vec![proxy.into()],
            ..Default::default()
        };
        assert!(route_for(&credentials, &HostSettings::default(), &lookup).is_err());
    }

    #[test]
    fn proxy_password_reaches_the_hop() {
        let lookup = fake_config(&[]);
        let mut proxy = socks("p");
        proxy.user = "dan".into();
        proxy.set_password(proto::Secret::new(b"pw".to_vec()));
        let credentials = Credentials {
            via: vec![proxy.into()],
            ..Default::default()
        };
        let hops = route_for(&credentials, &HostSettings::default(), &lookup).expect("route");
        match &hops[0] {
            Hop::Socks5(hop) => {
                assert_eq!(hop.user, "dan");
                assert_eq!(
                    hop.password.as_ref().map(proto::Secret::expose),
                    Some(&b"pw"[..])
                );
            }
            other => panic!("expected SOCKS5, got {other:?}"),
        }
    }

    #[test]
    fn saved_host_in_chain_is_a_jump_with_its_own_password() {
        let lookup = fake_config(&[(
            "bastion",
            HostSettings {
                hostname: Some("10.0.0.1".into()),
                ..Default::default()
            },
        )]);
        let mut host = proto::HostRecord::new("bastion");
        host.user = "jump".into();
        host.port = 2200;
        host.auth = HostAuth::Password;
        host.set_password(proto::Secret::new(b"pw".to_vec()));
        let credentials = Credentials {
            via: vec![crate::vault_session::ViaItem::Host(host)],
            ..Default::default()
        };
        let hops = route_for(&credentials, &HostSettings::default(), &lookup).expect("route");
        match hops.as_slice() {
            [Hop::Jump(jump)] => {
                assert_eq!(
                    (jump.host.as_str(), jump.port, jump.user.as_str()),
                    ("10.0.0.1", 2200, "jump")
                );
                assert_eq!(
                    jump.stored_password.as_ref().map(proto::Secret::expose),
                    Some(&b"pw"[..])
                );
                assert!(
                    matches!(&jump.auth, AuthMethod::Plan(plan) if plan.order.first() == Some(&auth::Credential::Stored)),
                    "{:?}",
                    jump.auth
                );
            }
            other => panic!("expected a single jump, got {other:?}"),
        }
    }
}
