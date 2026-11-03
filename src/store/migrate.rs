use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use proto::{HostAuth, HostRecord};
use serde::Deserialize;

pub fn legacy_path() -> Option<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| home().map(|home| home.join(".config")))
    };
    Some(base.or_else(home)?.join("cratty").join("hosts.json"))
}

fn home() -> Option<PathBuf> {
    #[allow(deprecated)]
    std::env::home_dir()
}

#[derive(Debug, Default, Deserialize)]
struct LegacyHosts {
    #[serde(default)]
    hosts: Vec<LegacyHost>,
}

#[derive(Debug, Default, Deserialize)]
struct LegacyHost {
    #[serde(default)]
    label: String,
    #[serde(default)]
    host: String,
    #[serde(default = "default_port")]
    port: u16,
    #[serde(default)]
    user: String,
    #[serde(default)]
    auth: LegacyAuth,
    #[serde(default)]
    target: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum LegacyAuth {
    #[default]
    Auto,
    Password,
    Key {
        path: PathBuf,
    },
}

fn default_port() -> u16 {
    22
}

impl LegacyHost {
    fn into_record(mut self) -> Option<HostRecord> {
        if let Some(target) = self.target.take()
            && self.host.is_empty()
        {
            let (user, rest) = match target.rsplit_once('@') {
                Some((user, rest)) if !user.is_empty() => (user.to_string(), rest.to_string()),
                _ => (String::new(), target),
            };
            let (host, port) = match rest.rsplit_once(':') {
                Some((left, _)) if left.contains(':') => (rest.clone(), default_port()),
                Some((host, port)) => (host.to_string(), port.parse().unwrap_or(default_port())),
                None => (rest.clone(), default_port()),
            };
            self.user = user;
            self.host = host;
            self.port = port;
        }

        let record = HostRecord {
            label: self.label,
            host: self.host,
            port: self.port,
            user: self.user,
            auth: match self.auth {
                LegacyAuth::Auto => HostAuth::Auto,
                LegacyAuth::Password => HostAuth::Password,
                LegacyAuth::Key { path } => HostAuth::Key {
                    path: path.to_string_lossy().into_owned(),
                },
            },
            secrets: proto::Secrets::new(),
            via: Vec::new(),
            forward_agent: false,
            forwards: Vec::new(),
        };

        record.is_usable().then_some(record)
    }
}

pub fn read_legacy(path: &Path) -> Vec<HostRecord> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    match serde_json::from_str::<LegacyHosts>(&text) {
        Ok(legacy) => legacy
            .hosts
            .into_iter()
            .filter_map(LegacyHost::into_record)
            .collect(),
        Err(error) => {
            eprintln!("не разобрать {}: {error}", path.display());
            Vec::new()
        }
    }
}

pub fn remove_legacy(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    std::fs::remove_file(path).with_context(|| format!("не удалить {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str, contents: &str) -> PathBuf {
        let unique = proto::DeviceId::generate().expect("CSPRNG");
        let path = std::env::temp_dir().join(format!("cratty-legacy-{name}-{unique}.json"));
        std::fs::write(&path, contents).expect("запись");
        path
    }

    #[test]
    fn perenosit_polnyy_format() {
        let path = temp_file(
            "full",
            r#"{"hosts":[
                {"label":"боевой","host":"prod.example.com","port":2222,
                 "user":"root","auth":{"kind":"password"}},
                {"label":"","host":"dev.example.com","port":22,
                 "user":"","auth":{"kind":"key","path":"/home/u/.ssh/id_ed25519"}}
            ]}"#,
        );

        let hosts = read_legacy(&path);
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].label, "боевой");
        assert_eq!(hosts[0].port, 2222);
        assert_eq!(hosts[0].auth, HostAuth::Password);
        assert_eq!(
            hosts[1].auth,
            HostAuth::Key {
                path: "/home/u/.ssh/id_ed25519".into()
            }
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn perenosit_samyy_staryy_format() {
        let path = temp_file(
            "oldest",
            r#"{"hosts":[
                {"target":"root@prod.example.com:2222"},
                {"target":"dev.example.com"},
                {"target":"fe80::1"}
            ]}"#,
        );

        let hosts = read_legacy(&path);
        assert_eq!(hosts.len(), 3);

        assert_eq!(hosts[0].user, "root");
        assert_eq!(hosts[0].host, "prod.example.com");
        assert_eq!(hosts[0].port, 2222);

        assert_eq!(hosts[1].host, "dev.example.com");
        assert_eq!(hosts[1].port, 22);

        assert_eq!(hosts[2].host, "fe80::1");
        assert_eq!(hosts[2].port, 22);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn zapisi_bez_adresa_ne_perenosyatsya() {
        let path = temp_file(
            "empty",
            r#"{"hosts":[{"label":"пусто"},{"host":"a.example"}]}"#,
        );
        let hosts = read_legacy(&path);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].host, "a.example");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn otsutstvie_fayla_eto_ne_oshibka() {
        assert!(read_legacy(Path::new("нет-такого-файла.json")).is_empty());
        assert!(remove_legacy(Path::new("нет-такого-файла.json")).is_ok());
    }

    #[test]
    fn ispochennyy_fayl_ne_meshaet() {
        let path = temp_file("broken", "{это не json");
        assert!(read_legacy(&path).is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn udalenie_ubiraet_fayl() {
        let path = temp_file("remove", r#"{"hosts":[]}"#);
        assert!(path.exists());
        remove_legacy(&path).expect("удаление");
        assert!(!path.exists());
    }
}
