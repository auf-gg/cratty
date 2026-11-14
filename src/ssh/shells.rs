//! Shells a local terminal tab can run. On Unix they come from `/etc/shells`, and
//! `$SHELL` is the default. On Windows they are looked for where they are installed:
//! PowerShell, cmd, Git Bash and the WSL distributions.

use super::LocalProgram;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::OnceLock;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shell {
    /// Saved with the tab to open the same shell again: the program's path on Unix,
    /// a short name on Windows (`pwsh`, `cmd`, `wsl:Ubuntu`).
    pub id: String,
    /// Shown in the menu and as the tab's title.
    pub name: String,
    pub program: LocalProgram,
}

impl Shell {
    fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        program: PathBuf,
        args: &[&str],
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            program: LocalProgram {
                program,
                args: args.iter().map(|arg| (*arg).to_owned()).collect(),
                env: Vec::new(),
            },
        }
    }
}

struct Found {
    shells: Vec<Shell>,
    default: usize,
}

fn found() -> &'static Found {
    static FOUND: OnceLock<Found> = OnceLock::new();
    FOUND.get_or_init(discover)
}

/// The shells of this computer, the default one among them. Never empty.
pub fn all() -> &'static [Shell] {
    &found().shells
}

/// The shell a local tab runs unless another one is chosen.
pub fn default() -> &'static Shell {
    let found = found();
    &found.shells[found.default]
}

pub fn find(id: &str) -> Option<&'static Shell> {
    all().iter().find(|shell| shell.id == id)
}

#[cfg(unix)]
fn discover() -> Found {
    let listed = std::fs::read_to_string("/etc/shells").unwrap_or_default();
    let user = std::env::var_os("SHELL")
        .map(PathBuf::from)
        .filter(|path| is_program(path))
        .unwrap_or_else(|| "/bin/sh".into());
    unix_shells(&listed, &user, is_program)
}

/// Login-only programs from `/etc/shells` that give no prompt.
#[cfg(unix)]
const NOT_INTERACTIVE: &[&str] = &[
    "nologin",
    "false",
    "true",
    "git-shell",
    "rbash",
    "systemd-home-fallback-shell",
];

/// One entry per name: `/bin/bash` and `/usr/bin/bash` are usually the same file.
/// The user's shell keeps its own path and is added when the list lacks it.
#[cfg(unix)]
fn unix_shells(listed: &str, user: &Path, exists: impl Fn(&Path) -> bool) -> Found {
    let name_of = |path: &Path| {
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
    };
    let user_name = name_of(user).unwrap_or_default();
    let mut shells: Vec<Shell> = Vec::new();
    for line in listed.lines().map(str::trim) {
        let path = Path::new(line);
        let Some(name) = name_of(path).filter(|_| path.is_absolute()) else {
            continue;
        };
        if NOT_INTERACTIVE.contains(&name.as_str()) || shells.iter().any(|shell| shell.name == name)
        {
            continue;
        }
        let path = if name == user_name { user } else { path };
        if exists(path) {
            shells.push(Shell::new(
                path.to_string_lossy(),
                name,
                path.to_path_buf(),
                &[],
            ));
        }
    }
    let default = match shells.iter().position(|shell| shell.name == user_name) {
        Some(index) => index,
        None => {
            shells.insert(
                0,
                Shell::new(user.to_string_lossy(), user_name, user.to_path_buf(), &[]),
            );
            0
        }
    };
    Found { shells, default }
}

#[cfg(unix)]
fn is_program(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// PowerShell 7 when it is installed, otherwise Windows PowerShell, otherwise cmd.
#[cfg(windows)]
fn discover() -> Found {
    let var = |name: &str| std::env::var_os(name).map(PathBuf::from);
    let system = var("SystemRoot")
        .unwrap_or_else(|| r"C:\Windows".into())
        .join("System32");
    let mut roots: Vec<PathBuf> = ["ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"]
        .iter()
        .filter_map(|name| var(name))
        .chain(var("LOCALAPPDATA").map(|dir| dir.join("Programs")))
        .collect();
    roots.dedup();
    let installed = |relative: &str| {
        roots
            .iter()
            .map(|root| root.join(relative))
            .find(|path| path.is_file())
    };

    let mut shells = Vec::new();
    if let Some(pwsh) = installed(r"PowerShell\7\pwsh.exe").or_else(|| on_path("pwsh.exe")) {
        shells.push(Shell::new("pwsh", "PowerShell", pwsh, &["-NoLogo"]));
    }
    let powershell = system.join(r"WindowsPowerShell\v1.0\powershell.exe");
    if powershell.is_file() {
        shells.push(Shell::new(
            "powershell",
            "Windows PowerShell",
            powershell,
            &["-NoLogo"],
        ));
    }
    let cmd = system.join("cmd.exe");
    shells.push(Shell::new(
        "cmd",
        "cmd",
        if cmd.is_file() { cmd } else { "cmd.exe".into() },
        &[],
    ));
    // Git for Windows puts `<root>\cmd\git.exe` on PATH; its bash is `<root>\bin\bash.exe`.
    let git_bash = installed(r"Git\bin\bash.exe").or_else(|| {
        let git = on_path("git.exe")?;
        let bash = git.parent()?.parent()?.join(r"bin\bash.exe");
        bash.is_file().then_some(bash)
    });
    if let Some(bash) = git_bash {
        shells.push(Shell::new("git-bash", "Git Bash", bash, &["--login", "-i"]));
    }
    let wsl = system.join("wsl.exe");
    if wsl.is_file() {
        for distro in wsl_distributions() {
            shells.push(Shell::new(
                format!("wsl:{distro}"),
                format!("WSL: {distro}"),
                wsl.clone(),
                &["-d", &distro, "--cd", "~"],
            ));
        }
    }
    // The first of PowerShell 7, Windows PowerShell and cmd.
    Found { shells, default: 0 }
}

#[cfg(windows)]
fn on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        // A Store app is an execution alias: a reparse point that only opens as a link.
        .find(|candidate| candidate.is_file() || std::fs::symlink_metadata(candidate).is_ok())
}

/// The installed distributions, as WSL records them for the user. Docker Desktop's own
/// ones are not for a prompt.
#[cfg(windows)]
fn wsl_distributions() -> Vec<String> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_READ, RRF_RT_REG_SZ, RegCloseKey, RegEnumKeyExW, RegGetValueW,
        RegOpenKeyExW,
    };

    let wide = |text: &str| text.encode_utf16().chain([0]).collect::<Vec<u16>>();
    let lxss = wide(r"Software\Microsoft\Windows\CurrentVersion\Lxss");
    let value = wide("DistributionName");
    let mut key: HKEY = std::ptr::null_mut();
    if unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, lxss.as_ptr(), 0, KEY_READ, &mut key) }
        != ERROR_SUCCESS
    {
        return Vec::new();
    }
    let mut names = Vec::new();
    for index in 0.. {
        let mut subkey = [0u16; 256];
        let mut length = subkey.len() as u32;
        let status = unsafe {
            RegEnumKeyExW(
                key,
                index,
                subkey.as_mut_ptr(),
                &mut length,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if status != ERROR_SUCCESS {
            break;
        }
        let mut name = [0u16; 256];
        let mut size = std::mem::size_of_val(&name) as u32;
        let status = unsafe {
            RegGetValueW(
                key,
                subkey.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                name.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if status == ERROR_SUCCESS {
            let units = &name[..(size as usize / 2).min(name.len())];
            let name = String::from_utf16_lossy(units)
                .trim_end_matches('\0')
                .to_owned();
            if !name.is_empty() && !name.starts_with("docker-desktop") {
                names.push(name);
            }
        }
    }
    unsafe { RegCloseKey(key) };
    names
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    const ARCH: &str = "# Pathnames of valid login shells.\n\n/bin/sh\n/bin/bash\n/bin/rbash\n\
        /usr/bin/sh\n/usr/bin/bash\n/usr/bin/git-shell\n/usr/bin/fish\n/bin/fish\n/usr/bin/zsh\n";

    fn names(found: &Found) -> Vec<&str> {
        found
            .shells
            .iter()
            .map(|shell| shell.name.as_str())
            .collect()
    }

    #[test]
    fn one_entry_per_shell_and_the_users_own_path() {
        let found = unix_shells(ARCH, Path::new("/usr/bin/fish"), |path| {
            !path.ends_with("zsh")
        });
        assert_eq!(names(&found), ["sh", "bash", "fish"]);
        assert_eq!(
            found.shells[found.default].program.program,
            Path::new("/usr/bin/fish")
        );
        assert_eq!(found.shells[found.default].id, "/usr/bin/fish");
    }

    #[test]
    fn a_shell_missing_from_the_list_comes_first() {
        let found = unix_shells(ARCH, Path::new("/nix/store/x/bin/nu"), |_| true);
        assert_eq!(names(&found), ["nu", "sh", "bash", "fish", "zsh"]);
        assert_eq!(found.default, 0);
    }
}
