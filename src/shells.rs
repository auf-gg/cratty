//! Shells a local terminal can run on this computer: found once, in the background, and
//! offered by the local terminal button and in the settings.
//!
//! On Windows: PowerShell 7, Windows PowerShell, the command prompt, Git Bash, MSYS2,
//! WSL distributions, and Nushell, fish or zsh when they are on the search path. On unix:
//! the shells of `/etc/shells`, the user's login shell and known shells on the search path.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::ssh::LocalProgram;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shell {
    /// Stable name kept in the settings and with saved tabs, such as `pwsh` or `wsl:Ubuntu`.
    pub id: String,
    /// Shown to the user, also as the tab title.
    pub name: String,
    pub program: LocalProgram,
}

static FOUND: OnceLock<Vec<Shell>> = OnceLock::new();

/// The shells of this computer. The first call looks for them, which may take a moment
/// (WSL is asked for its distributions), so the app calls it early in the background.
pub fn available() -> &'static [Shell] {
    FOUND.get_or_init(detect)
}

/// The shells if they have been found already: for drawing, which must not wait.
pub fn found() -> Option<&'static [Shell]> {
    FOUND.get().map(Vec::as_slice)
}

/// The shell to run: the one chosen, if it is still here, or else the system's default.
pub fn resolve(id: &str) -> Option<Shell> {
    let shells = available();
    shells
        .iter()
        .find(|shell| !id.is_empty() && shell.id == id)
        .or_else(|| shells.iter().find(|shell| shell.id == default_id(shells)))
        .or_else(|| shells.first())
        .cloned()
}

/// The shell used when none is chosen: the login shell on unix, PowerShell on Windows.
pub fn default_id(shells: &[Shell]) -> String {
    #[cfg(windows)]
    {
        ["pwsh", "powershell", "cmd"]
            .into_iter()
            .find(|id| shells.iter().any(|shell| shell.id == *id))
            .unwrap_or_default()
            .to_owned()
    }
    #[cfg(not(windows))]
    {
        let login = std::env::var_os("SHELL").map(PathBuf::from);
        login
            .and_then(|login| {
                let real = canonical(&login);
                shells
                    .iter()
                    .find(|shell| canonical(&shell.program.program) == real)
            })
            .or_else(|| shells.first())
            .map(|shell| shell.id.clone())
            .unwrap_or_default()
    }
}

/// The user's home folder.
pub fn home() -> Option<PathBuf> {
    #[allow(deprecated)]
    std::env::home_dir().filter(|dir| dir.is_dir())
}

fn shell(id: impl Into<String>, name: impl Into<String>, program: PathBuf, args: &[&str]) -> Shell {
    Shell {
        id: id.into(),
        name: name.into(),
        program: LocalProgram {
            program,
            args: args.iter().map(|arg| (*arg).to_owned()).collect(),
            env: Vec::new(),
            // A Windows app started from the Start menu is in System32: start at home.
            cwd: if cfg!(windows) { home() } else { None },
        },
    }
}

#[cfg(not(windows))]
fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn search_path() -> OsString {
    std::env::var_os("PATH").unwrap_or_default()
}

fn which(name: &str) -> Option<PathBuf> {
    crate::acp::agents::which(name, &search_path())
}

/// Shells found on the search path on any system, with their display names.
const ON_PATH: &[(&str, &str)] = &[("nu", "Nushell"), ("fish", "fish"), ("zsh", "zsh")];

#[cfg(windows)]
fn detect() -> Vec<Shell> {
    let mut shells = Vec::new();
    let var = |name: &str| std::env::var_os(name).map(PathBuf::from);
    let system_root = var("SystemRoot").unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let system32 = system_root.join("System32");

    let pwsh = which("pwsh").or_else(|| {
        [var("ProgramFiles"), var("ProgramW6432")]
            .into_iter()
            .flatten()
            .map(|dir| dir.join("PowerShell").join("7").join("pwsh.exe"))
            .find(|path| path.is_file())
    });
    if let Some(pwsh) = pwsh {
        shells.push(shell("pwsh", "PowerShell", pwsh, &["-NoLogo"]));
    }

    let powershell = system32
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    if powershell.is_file() {
        shells.push(shell("powershell", "Windows PowerShell", powershell, &["-NoLogo"]));
    }

    let cmd = var("ComSpec")
        .filter(|path| path.is_file())
        .unwrap_or_else(|| system32.join("cmd.exe"));
    if cmd.is_file() {
        shells.push(shell("cmd", "Command Prompt", cmd, &[]));
    }

    if let Some(bash) = git_bash() {
        shells.push(shell("git-bash", "Git Bash", bash, &["--login", "-i"]));
    }

    let msys = PathBuf::from(r"C:\msys64\usr\bin\bash.exe");
    if msys.is_file() {
        let mut msys = shell("msys2", "MSYS2", msys, &["--login", "-i"]);
        msys.program.env = vec![
            ("MSYSTEM".into(), "UCRT64".into()),
            ("CHERE_INVOKING".into(), "1".into()),
        ];
        shells.push(msys);
    }

    let wsl = system32.join("wsl.exe");
    if wsl.is_file() {
        for distribution in wsl_distributions(&wsl) {
            shells.push(shell(
                format!("wsl:{distribution}"),
                format!("{distribution} (WSL)"),
                wsl.clone(),
                &["-d", &distribution, "--cd", "~"],
            ));
        }
    }

    for (id, name) in ON_PATH {
        if let Some(program) = which(id) {
            shells.push(shell(*id, *name, program, &[]));
        }
    }
    shells
}

/// Git for Windows: its `bin\bash.exe` starts bash with Git's environment.
#[cfg(windows)]
fn git_bash() -> Option<PathBuf> {
    let var = |name: &str| std::env::var_os(name).map(PathBuf::from);
    // `git.exe` is in `Git\cmd` (or `Git\bin`, `Git\mingw64\bin`): go up to `Git`.
    let from_git = which("git").and_then(|git| {
        git.ancestors()
            .skip(1)
            .take(3)
            .map(|dir| dir.join("bin").join("bash.exe"))
            .find(|bash| bash.is_file())
    });
    from_git.or_else(|| {
        [
            var("ProgramFiles").map(|dir| dir.join("Git")),
            var("ProgramFiles(x86)").map(|dir| dir.join("Git")),
            var("LOCALAPPDATA").map(|dir| dir.join("Programs").join("Git")),
        ]
        .into_iter()
        .flatten()
        .map(|dir| dir.join("bin").join("bash.exe"))
        .find(|bash| bash.is_file())
    })
}

/// Names of the installed WSL distributions; Docker Desktop's own are left out.
#[cfg(windows)]
fn wsl_distributions(wsl: &Path) -> Vec<String> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let Ok(mut child) = Command::new(wsl)
        .args(["--list", "--quiet"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
    else {
        return Vec::new();
    };
    // Reading first: a full pipe would keep it from exiting.
    let Some(mut stdout) = child.stdout.take() else {
        return Vec::new();
    };
    let reading = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = std::io::Read::read_to_end(&mut stdout, &mut bytes);
        bytes
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let success = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break false;
            }
        }
    };
    let bytes = reading.join().unwrap_or_default();
    if !success {
        return Vec::new();
    }
    parse_wsl_list(&bytes)
}

/// `wsl --list --quiet` prints UTF-16 text, one name per line.
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_wsl_list(bytes: &[u8]) -> Vec<String> {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16_lossy(&units)
        .lines()
        .map(|line| line.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}' || c == '\0'))
        .filter(|name| !name.is_empty() && !name.starts_with("docker-desktop"))
        .map(str::to_owned)
        .collect()
}

#[cfg(not(windows))]
fn detect() -> Vec<Shell> {
    const NOT_SHELLS: &[&str] = &["nologin", "false", "true", "git-shell", "rbash", "screen", "tmux"];

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(login) = std::env::var_os("SHELL") {
        candidates.push(login.into());
    }
    if let Ok(text) = std::fs::read_to_string("/etc/shells") {
        candidates.extend(
            text.lines()
                .map(str::trim)
                .filter(|line| line.starts_with('/'))
                .map(PathBuf::from),
        );
    }
    for name in ["bash", "zsh", "fish", "nu", "pwsh", "xonsh", "elvish", "sh"] {
        if let Some(path) = which(name) {
            candidates.push(path);
        }
    }

    let mut shells: Vec<Shell> = Vec::new();
    let mut seen: Vec<PathBuf> = Vec::new();
    for path in candidates {
        if !path.is_file() {
            continue;
        }
        let Some(id) = path.file_name().map(|name| name.to_string_lossy().into_owned()) else {
            continue;
        };
        let real = canonical(&path);
        if NOT_SHELLS.contains(&id.as_str())
            || seen.contains(&real)
            || shells.iter().any(|shell| shell.id == id)
        {
            continue;
        }
        seen.push(real);
        let name = ON_PATH
            .iter()
            .find(|(known, _)| *known == id)
            .map(|(_, name)| (*name).to_owned())
            .unwrap_or_else(|| match id.as_str() {
                "bash" => "Bash".to_owned(),
                "pwsh" => "PowerShell".to_owned(),
                _ => id.clone(),
            });
        shells.push(shell(id, name, path, &[]));
    }
    if shells.is_empty() {
        shells.push(shell("sh", "sh", "/bin/sh".into(), &[]));
    }
    shells
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn some_shell_is_always_found_and_the_default_is_among_them() {
        let shells = available();
        assert!(!shells.is_empty());
        let default = default_id(shells);
        assert!(shells.iter().any(|shell| shell.id == default), "{default}");
        let ids: Vec<_> = shells.iter().map(|shell| &shell.id).collect();
        let mut unique = ids.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "ids repeat: {ids:?}");
    }

    #[test]
    fn an_unknown_choice_falls_back_to_the_default() {
        let shells = available();
        let fallback = resolve("no-such-shell").expect("a shell");
        assert_eq!(fallback.id, default_id(shells));
        let first = &shells[0];
        assert_eq!(resolve(&first.id).expect("a shell").id, first.id);
    }

    #[test]
    fn wsl_list_is_read_from_utf16() {
        let text = "\u{feff}Ubuntu\r\ndocker-desktop\r\nDebian\r\n\r\n";
        let bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(parse_wsl_list(&bytes), vec!["Ubuntu", "Debian"]);
    }
}
