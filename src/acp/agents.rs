//! Which agents this computer has and how to start them, and the folder they run in.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentKind {
    Claude,
    OpenCode,
}

impl AgentKind {
    pub const ALL: [AgentKind; 2] = [AgentKind::Claude, AgentKind::OpenCode];

    /// How the kind is written down in `sessions.json`.
    pub fn id(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::OpenCode => "opencode",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.id() == id)
    }

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
    /// Where the agent keeps its sessions: Cratty's own folder, so they stay out of
    /// the history of the agent the user runs by hand.
    pub env: Vec<(String, OsString)>,
}

impl AgentCommand {
    /// The same agent started with other arguments, such as its sign-in, for a terminal.
    pub fn program_with(&self, args: &[String]) -> crate::ssh::LocalProgram {
        let mut env = self.env.clone();
        env.push(("PATH".into(), self.path.clone()));
        crate::ssh::LocalProgram {
            program: self.program.clone(),
            args: self.args.iter().chain(args).cloned().collect(),
            env,
            cwd: crate::shells::home(),
        }
    }
}

/// Why an agent cannot start: the program the user should install.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Missing {
    pub install: &'static str,
}

pub fn find(kind: AgentKind) -> Result<AgentCommand, Missing> {
    let path = search_path().clone();
    let mut env = agent_env(kind);
    // The adapter's own copy of Claude Code comes as an optional npm package, which an
    // npx install may leave out; the user's installed `claude` is there and up to date.
    if kind == AgentKind::Claude
        && let Some(claude) = claude_executable(&path)
    {
        env.push(("CLAUDE_CODE_EXECUTABLE".into(), claude.into_os_string()));
    }
    let command = |program: PathBuf, args: &[&str]| AgentCommand {
        kind,
        program,
        args: args.iter().map(|arg| (*arg).to_owned()).collect(),
        path: path.clone(),
        env: env.clone(),
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

/// The user's Claude Code, as the adapter can start it. On Windows the adapter starts it
/// without a shell, which Node refuses for a batch file, and its sign-in cannot start a
/// script either; npm puts `claude.cmd` in front of `claude.exe`, so the adapter gets
/// the `.exe`, or nothing and runs its own copy.
fn claude_executable(path: &OsString) -> Option<PathBuf> {
    let claude = which("claude", path)?;
    if !cfg!(windows) || has_extension(&claude, "exe") {
        return Some(claude);
    }
    shim_target(&claude).filter(|target| has_extension(target, "exe"))
}

fn has_extension(path: &Path, extension: &str) -> bool {
    path.extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case(extension))
}

/// The program a batch file of npm, pnpm or Yarn runs: the last quoted path from the
/// batch file's folder (`%dp0%\…` or `%~dp0\…`) that is there and is not Node itself.
fn shim_target(shim: &Path) -> Option<PathBuf> {
    let text = String::from_utf8_lossy(&std::fs::read(shim).ok()?).into_owned();
    let dir = shim.parent()?;
    text.split('"')
        .skip(1)
        .step_by(2)
        .filter_map(|quoted| {
            ["%dp0%", "%~dp0"]
                .iter()
                .find_map(|prefix| quoted.strip_prefix(prefix))
        })
        .map(|rest| rest.trim_start_matches(['\\', '/']))
        .filter(|rest| !rest.is_empty() && !rest.contains('%'))
        .map(|rest| dir.join(rest.replace('\\', std::path::MAIN_SEPARATOR_STR)))
        .filter(|target| {
            target
                .file_name()
                .is_some_and(|name| !name.eq_ignore_ascii_case("node.exe"))
                && target.is_file()
        })
        .last()
}

/// Cratty's folder for agents: their working folder, their sign-in and their
/// sessions. Sessions hold what commands printed on servers, so only the user reads it.
pub fn agents_dir() -> Result<PathBuf> {
    let base = crate::store::VaultStore::default_base().context("no data folder")?;
    let dir = base.join("agents");
    std::fs::create_dir_all(&dir).with_context(|| dir.display().to_string())?;
    restrict(&dir);
    Ok(dir)
}

#[cfg(unix)]
fn restrict(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict(_dir: &Path) {}

/// Claude Code keeps everything, its sign-in included, in its config folder; OpenCode
/// keeps sessions in its database and its sign-in apart, so that sign-in is shared.
fn agent_env(kind: AgentKind) -> Vec<(String, OsString)> {
    let Ok(dir) = agents_dir() else {
        return Vec::new();
    };
    match kind {
        AgentKind::Claude => vec![(
            "CLAUDE_CONFIG_DIR".into(),
            dir.join("claude").into_os_string(),
        )],
        AgentKind::OpenCode => vec![(
            "OPENCODE_DB".into(),
            dir.join("opencode.db").into_os_string(),
        )],
    }
}

/// Removes a saved session from Cratty's folder for an agent that cannot delete it over
/// ACP. Claude Code keeps a session as `<id>.jsonl`, with a folder of the same name
/// beside it, in a folder per working folder under `projects/`.
pub fn delete_saved_session(kind: AgentKind, session: &str) {
    // A session id is a UUID: nothing else may become part of a path.
    let plain = !session.is_empty()
        && session
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if kind != AgentKind::Claude || !plain {
        return;
    }
    let Ok(dir) = agents_dir() else {
        return;
    };
    let Ok(projects) = std::fs::read_dir(dir.join("claude").join("projects")) else {
        return;
    };
    for project in projects.flatten() {
        let project = project.path();
        let _ = std::fs::remove_file(project.join(format!("{session}.jsonl")));
        let _ = std::fs::remove_dir_all(project.join(session));
    }
}

/// Variables that would give the agent another configuration than Cratty's, taken out
/// of the environment it inherits. OpenCode's inline configuration outranks the working
/// folder's, so it could turn the agent's own tools back on.
pub fn foreign_config(kind: AgentKind) -> &'static [&'static str] {
    match kind {
        AgentKind::Claude => &[],
        AgentKind::OpenCode => &["OPENCODE_CONFIG_CONTENT", "OPENCODE_CONFIG"],
    }
}

/// The folder agents run in. It is empty but for their configuration: their own
/// tools, which would act on this computer, are off, and Cratty's MCP tools are on.
pub fn prepare_workdir() -> Result<PathBuf> {
    let dir = agents_dir()?.join("workdir");
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
        let login = login_path().unwrap_or_default();
        // The login shell sets up version managers: its entries go first. On Windows the
        // saved path is the one this process started from: it only adds what came since.
        let (first, then) = if cfg!(windows) {
            (&own, &login)
        } else {
            (&login, &own)
        };
        let mut dirs: Vec<PathBuf> = Vec::new();
        // An empty entry would be the current folder.
        for dir in std::env::split_paths(first).chain(std::env::split_paths(then)) {
            if !dir.as_os_str().is_empty() && !dirs.contains(&dir) {
                dirs.push(dir);
            }
        }
        std::env::join_paths(dirs).unwrap_or(own)
    })
}

#[cfg(unix)]
fn login_path() -> Option<OsString> {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

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

/// The saved search path, the machine's then the user's: a copy started before an
/// install, or by a program with an environment of its own, lacks what was added since.
#[cfg(windows)]
fn login_path() -> Option<OsString> {
    use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

    let saved: Vec<OsString> = [
        (
            HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        ),
        (HKEY_CURRENT_USER, "Environment"),
    ]
    .into_iter()
    .filter_map(|(root, key)| registry_string(root, key, "Path"))
    .collect();
    let dirs: Vec<PathBuf> = saved.iter().flat_map(std::env::split_paths).collect();
    if dirs.is_empty() {
        return None;
    }
    std::env::join_paths(dirs).ok()
}

/// A text value of the registry, its `%VARIABLES%` expanded.
#[cfg(windows)]
fn registry_string(
    root: windows_sys::Win32::System::Registry::HKEY,
    key: &str,
    value: &str,
) -> Option<OsString> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{RRF_RT_REG_SZ, RegGetValueW};

    let wide = |text: &str| text.encode_utf16().chain([0]).collect::<Vec<u16>>();
    let (key, value) = (wide(key), wide(value));
    // Without RRF_NOEXPAND an expandable value is expanded and reads as REG_SZ.
    let read = |data: *mut u16, size: &mut u32| unsafe {
        RegGetValueW(
            root,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            data.cast(),
            size,
        )
    };
    let mut size = 0u32;
    if read(std::ptr::null_mut(), &mut size) != ERROR_SUCCESS {
        return None;
    }
    // Expanding may need more room than the first answer: ask until it fits.
    for _ in 0..4 {
        let mut buffer = vec![0u16; (size as usize).div_ceil(2) + 1];
        let mut got = (buffer.len() * 2) as u32;
        match read(buffer.as_mut_ptr(), &mut got) {
            ERROR_SUCCESS => {
                let end = buffer
                    .iter()
                    .position(|&unit| unit == 0)
                    .unwrap_or(buffer.len());
                return Some(OsString::from_wide(&buffer[..end]));
            }
            _ if got > size => size = got,
            _ => return None,
        }
    }
    None
}

#[cfg(not(any(unix, windows)))]
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
    fn shim_leads_to_the_program_it_runs() {
        let dir = std::env::temp_dir().join(format!("cratty-shim-{}", std::process::id()));
        let package = dir.join("node_modules/@anthropic-ai/claude-code");
        std::fs::create_dir_all(package.join("bin")).unwrap();
        std::fs::write(package.join("bin/claude.exe"), "").unwrap();
        std::fs::write(package.join("cli.js"), "").unwrap();
        std::fs::write(dir.join("node.exe"), "").unwrap();
        let shim = |name: &str, text: &str| {
            let path = dir.join(name);
            std::fs::write(&path, text.replace('\n', "\r\n")).unwrap();
            shim_target(&path)
        };

        // npm, for a native program.
        assert_eq!(
            shim(
                "native.cmd",
                "@ECHO off\nGOTO start\n:find_dp0\nSET dp0=%~dp0\nEXIT /b\n:start\nSETLOCAL\n\
                 CALL :find_dp0\n\"%dp0%\\node_modules\\@anthropic-ai\\claude-code\\bin\\claude.exe\"   %*\n"
            ),
            Some(dir.join("node_modules/@anthropic-ai/claude-code/bin/claude.exe"))
        );
        // npm, for a script: Node is checked for first.
        assert_eq!(
            shim(
                "script.cmd",
                "IF EXIST \"%dp0%\\node.exe\" (\n  SET \"_prog=%dp0%\\node.exe\"\n) ELSE (\n  SET \"_prog=node\"\n)\n\
                 endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & \"%_prog%\"  \"%dp0%\\node_modules\\@anthropic-ai\\claude-code\\cli.js\" %*\n"
            ),
            Some(dir.join("node_modules/@anthropic-ai/claude-code/cli.js"))
        );
        // pnpm, from a folder of its own.
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        assert_eq!(
            shim(
                "bin/pnpm.cmd",
                "@IF EXIST \"%~dp0\\node.exe\" (\n  \"%~dp0\\node.exe\"  \"%~dp0\\..\\node_modules\\@anthropic-ai\\claude-code\\cli.js\" %*\n)\n"
            )
            .map(|target| target.canonicalize().unwrap()),
            Some(package.join("cli.js").canonicalize().unwrap())
        );
        assert_eq!(shim("gone.cmd", "\"%dp0%\\missing\\claude.exe\" %*"), None);
        assert!(has_extension(Path::new("C:/npm/claude.EXE"), "exe"));
        assert!(!has_extension(Path::new("C:/npm/claude.cmd"), "exe"));
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
