//! Which agents this computer has and how to start them, and the folder they run in.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentKind {
    Claude,
    OpenCode,
}

impl AgentKind {
    pub const ALL: [AgentKind; 2] = [AgentKind::Claude, AgentKind::OpenCode];

    pub fn title(self) -> &'static str {
        match self {
            Self::Claude => "Claude Code",
            Self::OpenCode => "OpenCode",
        }
    }

    /// What to run in a terminal to sign in.
    pub fn login_command(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::OpenCode => "opencode auth login",
        }
    }
}

/// How to start an agent as an ACP server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentCommand {
    pub kind: AgentKind,
    pub program: PathBuf,
    pub args: Vec<String>,
    /// The search path the agent gets, with the login shell's entries.
    pub path: OsString,
}

/// Why an agent cannot start: the program the user should install.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Missing {
    pub install: &'static str,
}

pub fn find(kind: AgentKind) -> Result<AgentCommand, Missing> {
    let path = search_path().clone();
    let command = |program: PathBuf, args: &[&str]| AgentCommand {
        kind,
        program,
        args: args.iter().map(|arg| (*arg).to_owned()).collect(),
        path: path.clone(),
    };
    match kind {
        // The ACP adapter for Claude Code: installed on its own, or through npx.
        AgentKind::Claude => which("claude-agent-acp", &path)
            .map(|program| command(program, &[]))
            .or_else(|| {
                which("npx", &path)
                    .map(|npx| command(npx, &["-y", "@agentclientprotocol/claude-agent-acp"]))
            })
            .ok_or(Missing {
                install: "Node.js (npx) or claude-agent-acp",
            }),
        AgentKind::OpenCode => which("opencode", &path)
            .map(|program| command(program, &["acp"]))
            .ok_or(Missing {
                install: "opencode",
            }),
    }
}

/// The folder agents run in. It is empty but for their configuration: their own
/// tools, which would act on this computer, are off, and Cratty's MCP tools are on.
pub fn prepare_workdir() -> Result<PathBuf> {
    let base = crate::store::VaultStore::default_base().context("no data folder")?;
    let dir = base.join("agent");
    std::fs::create_dir_all(&dir).with_context(|| dir.display().to_string())?;
    for (name, text) in [
        ("AGENTS.md", INSTRUCTIONS),
        ("CLAUDE.md", INSTRUCTIONS),
        ("opencode.jsonc", OPENCODE_CONFIG),
    ] {
        let file = dir.join(name);
        std::fs::write(&file, text).with_context(|| file.display().to_string())?;
    }
    Ok(dir)
}

const INSTRUCTIONS: &str = "\
# Cratty

You help the user with a remote server over SSH, from the AI tab of Cratty, an SSH client.
This folder is empty on purpose: do not work in it, and do not look for files on this computer.
Use the tools of the `cratty` MCP server: they act on the server of the user's tab.
The user approves every command and file change in Cratty and may deny it.
Answer in the language the user writes in.
";

/// OpenCode reads the configuration of the session's folder: deny every action but
/// Cratty's tools (`<server>_<tool>`), so nothing runs on this computer.
const OPENCODE_CONFIG: &str = r#"{
  "$schema": "https://opencode.ai/config.json",
  "permissions": [
    { "action": "*", "resource": "*", "effect": "deny" },
    { "action": "cratty_*", "resource": "*", "effect": "allow" }
  ]
}
"#;

/// The search path for agents: this process's own, plus the login shell's. An app
/// started from a launcher often lacks `~/.local/bin`, version managers and the like.
pub fn search_path() -> &'static OsString {
    static PATH: OnceLock<OsString> = OnceLock::new();
    PATH.get_or_init(|| {
        let own = std::env::var_os("PATH").unwrap_or_default();
        let mut dirs: Vec<PathBuf> = login_path()
            .map(|path| std::env::split_paths(&path).collect())
            .unwrap_or_default();
        for dir in std::env::split_paths(&own) {
            if !dirs.contains(&dir) {
                dirs.push(dir);
            }
        }
        std::env::join_paths(dirs).unwrap_or(own)
    })
}

#[cfg(unix)]
fn login_path() -> Option<OsString> {
    use std::process::{Command, Stdio};

    let shell = std::env::var_os("SHELL")?;
    // `printenv` rather than `echo $PATH`: fish prints its PATH as a list.
    let mut child = Command::new(shell)
        .args(["-l", "-c", "printenv PATH"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let mut out = String::new();
    std::io::Read::read_to_string(&mut child.stdout.take()?, &mut out).ok()?;
    let path = out.lines().last()?.trim();
    (!path.is_empty()).then(|| OsString::from(path))
}

#[cfg(not(unix))]
fn login_path() -> Option<OsString> {
    None
}

/// Finds a program on a search path, like `which`.
pub fn which(name: &str, path: &OsString) -> Option<PathBuf> {
    let names: Vec<String> = if cfg!(windows) {
        ["exe", "cmd", "bat"]
            .iter()
            .map(|ext| format!("{name}.{ext}"))
            .collect()
    } else {
        vec![name.to_owned()]
    };
    std::env::split_paths(path)
        .flat_map(|dir| names.iter().map(move |name| dir.join(name)))
        .find(|candidate| is_program(candidate))
}

#[cfg(unix)]
fn is_program(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_program(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn which_finds_executables_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("cratty-which-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let tool = dir.join("tool");
        std::fs::write(&tool, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(dir.join("notes"), "").unwrap();

        let path = std::env::join_paths([PathBuf::from("/nonexistent"), dir.clone()]).unwrap();
        assert_eq!(which("tool", &path), Some(tool));
        assert_eq!(which("notes", &path), None);
        assert_eq!(which("absent", &path), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn opencode_config_denies_all_but_cratty() {
        let config: serde_json::Value = serde_json::from_str(OPENCODE_CONFIG).unwrap();
        let rules = config["permissions"].as_array().unwrap();
        // The last matching rule wins.
        assert_eq!(rules[0]["effect"], "deny");
        assert_eq!(
            rules.last().unwrap()["action"],
            format!("{}_*", crate::mcp::SERVER_NAME)
        );
    }
}
