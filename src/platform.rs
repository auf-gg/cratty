pub fn awake_clock() -> std::time::Duration {
    #[cfg(windows)]
    {
        use std::sync::OnceLock;
        use windows_sys::Win32::System::WindowsProgramming::QueryUnbiasedInterruptTime;

        fn read() -> Option<u64> {
            let mut ticks = 0u64;
            (unsafe { QueryUnbiasedInterruptTime(&mut ticks) } != 0).then_some(ticks)
        }

        static START: OnceLock<Option<u64>> = OnceLock::new();
        if let (Some(start), Some(now)) = (*START.get_or_init(read), read()) {
            return std::time::Duration::from_nanos(now.saturating_sub(start).saturating_mul(100));
        }
    }

    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START.get_or_init(std::time::Instant::now).elapsed()
}

/// Тайловый оконный менеджер (Hyprland, sway, i3…): окна в нём без заголовков,
/// таскать их мышью не нужно, поэтому свою верхнюю панель не рисуем.
pub fn tiling_wm() -> bool {
    if !cfg!(all(unix, not(target_os = "macos"))) {
        return false;
    }
    [
        "XDG_CURRENT_DESKTOP",
        "XDG_SESSION_DESKTOP",
        "DESKTOP_SESSION",
    ]
    .iter()
    .filter_map(|name| std::env::var(name).ok())
    .any(|value| is_tiling_desktop(&value))
}

fn is_tiling_desktop(value: &str) -> bool {
    const TILING: &[&str] = &[
        "hyprland",
        "sway",
        "i3",
        "niri",
        "river",
        "bspwm",
        "dwm",
        "qtile",
        "awesome",
        "xmonad",
        "herbstluftwm",
        "leftwm",
        "spectrwm",
        "dwl",
        "mango",
    ];
    value
        .split(':')
        .any(|part| TILING.contains(&part.trim().to_ascii_lowercase().as_str()))
}

pub fn blur_supported() -> bool {
    #[cfg(windows)]
    {
        use std::sync::OnceLock;
        use windows_sys::Wdk::System::SystemServices::RtlGetVersion;
        use windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW;

        static SUPPORTED: OnceLock<bool> = OnceLock::new();
        *SUPPORTED.get_or_init(|| {
            let mut info: OSVERSIONINFOW = unsafe { std::mem::zeroed() };
            info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;
            let ok = unsafe { RtlGetVersion(&mut info) } == 0;
            ok && info.dwBuildNumber >= 22000
        })
    }
    #[cfg(not(windows))]
    {
        true
    }
}

pub type Warnings = Vec<String>;

pub fn harden_process() -> Warnings {
    let mut warnings = Warnings::new();
    disable_core_dumps(&mut warnings);
    warnings
}

pub struct LockedPages {
    address: *mut core::ffi::c_void,
    len: usize,
}

unsafe impl Send for LockedPages {}
unsafe impl Sync for LockedPages {}

impl LockedPages {
    pub fn lock<T>(value: &T, warnings: &mut Warnings) -> Option<Self> {
        let address = core::ptr::from_ref(value) as *mut core::ffi::c_void;
        let len = core::mem::size_of::<T>();
        if len == 0 {
            return None;
        }
        lock_range(address, len, warnings)
    }
}

impl Drop for LockedPages {
    fn drop(&mut self) {
        unlock_range(self.address, self.len);
    }
}

impl core::fmt::Debug for LockedPages {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LockedPages(<адрес скрыт>)")
    }
}

#[cfg(unix)]
fn disable_core_dumps(warnings: &mut Warnings) {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let result = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };
    if result != 0 {
        warnings.push("не удалось запретить дампы памяти (RLIMIT_CORE)".into());
    }

    #[cfg(target_os = "linux")]
    {
        let result = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if result != 0 {
            warnings.push("не удалось закрыть процесс от ptrace (PR_SET_DUMPABLE)".into());
        }
    }
}

#[cfg(unix)]
fn lock_range(
    address: *mut core::ffi::c_void,
    len: usize,
    warnings: &mut Warnings,
) -> Option<LockedPages> {
    let result = unsafe { libc::mlock(address, len) };
    if result != 0 {
        warnings.push(
            "ключи не закреплены в памяти: не хватает лимита RLIMIT_MEMLOCK, \
             и страницы могут уйти в своп"
                .into(),
        );
        return None;
    }
    Some(LockedPages { address, len })
}

#[cfg(unix)]
fn unlock_range(address: *mut core::ffi::c_void, len: usize) {
    unsafe {
        libc::munlock(address, len);
    }
}

#[cfg(windows)]
fn disable_core_dumps(warnings: &mut Warnings) {
    use windows_sys::Win32::System::Diagnostics::Debug::{SEM_NOGPFAULTERRORBOX, SetErrorMode};

    unsafe {
        SetErrorMode(SEM_NOGPFAULTERRORBOX);
    }
    let _ = warnings;
}

#[cfg(windows)]
fn lock_range(
    address: *mut core::ffi::c_void,
    len: usize,
    warnings: &mut Warnings,
) -> Option<LockedPages> {
    use windows_sys::Win32::System::ErrorReporting::WerRegisterExcludedMemoryBlock;
    use windows_sys::Win32::System::Memory::VirtualLock;

    if unsafe { VirtualLock(address, len) } == 0 {
        warnings.push(
            "ключи не закреплены в памяти: не хватает квоты рабочего набора, \
             и страницы могут уйти в файл подкачки"
                .into(),
        );
        return None;
    }

    if let Ok(size) = u32::try_from(len) {
        unsafe {
            let _ = WerRegisterExcludedMemoryBlock(address, size);
        }
    }

    Some(LockedPages { address, len })
}

#[cfg(windows)]
fn unlock_range(address: *mut core::ffi::c_void, len: usize) {
    use windows_sys::Win32::System::ErrorReporting::WerUnregisterExcludedMemoryBlock;
    use windows_sys::Win32::System::Memory::VirtualUnlock;

    unsafe {
        let _ = WerUnregisterExcludedMemoryBlock(address);
        VirtualUnlock(address, len);
    }
}

#[cfg(not(any(unix, windows)))]
fn disable_core_dumps(warnings: &mut Warnings) {
    warnings.push("на этой платформе дампы памяти не запрещены".into());
}

#[cfg(not(any(unix, windows)))]
fn lock_range(
    _address: *mut core::ffi::c_void,
    _len: usize,
    warnings: &mut Warnings,
) -> Option<LockedPages> {
    warnings.push("на этой платформе ключи не закрепляются в памяти".into());
    None
}

#[cfg(not(any(unix, windows)))]
fn unlock_range(_address: *mut core::ffi::c_void, _len: usize) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chasy_bodrstvovaniya_idut() {
        let first = awake_clock();
        std::thread::sleep(std::time::Duration::from_millis(50));
        let second = awake_clock();
        let passed = second.saturating_sub(first);
        assert!(passed >= std::time::Duration::from_millis(40), "{passed:?}");
        assert!(passed < std::time::Duration::from_secs(2), "{passed:?}");
    }

    #[test]
    fn nastroyka_processa_ne_padaet() {
        let _ = harden_process();
    }

    #[test]
    fn zapertoe_znachenie_chitaetsya() {
        let secret = Box::new([0xABu8; 4096]);
        let mut warnings = Warnings::new();

        {
            let _locked = LockedPages::lock(secret.as_ref(), &mut warnings);
            assert_eq!(secret[0], 0xAB);
            assert_eq!(secret[4095], 0xAB);
        }

        assert_eq!(secret[0], 0xAB, "значение пережило отпирание страниц");
    }

    #[test]
    fn otkaz_zapirovaniya_eto_preduprezhdenie_a_ne_padenie() {
        let huge = vec![0u8; 8 * 1024 * 1024];
        let mut warnings = Warnings::new();
        let locked = LockedPages::lock(&huge[0], &mut warnings);
        drop(locked);
        assert_eq!(huge[0], 0);
    }

    #[test]
    fn tailovye_wm_uznayutsya() {
        assert!(is_tiling_desktop("Hyprland"));
        assert!(is_tiling_desktop("sway"));
        assert!(is_tiling_desktop("ubuntu:GNOME:i3"));
        assert!(!is_tiling_desktop("GNOME"));
        assert!(!is_tiling_desktop("KDE"));
        assert!(!is_tiling_desktop(""));
    }

    #[test]
    fn debug_ne_pechataet_adres() {
        let secret = Box::new([0u8; 64]);
        let mut warnings = Warnings::new();
        if let Some(locked) = LockedPages::lock(secret.as_ref(), &mut warnings) {
            assert_eq!(format!("{locked:?}"), "LockedPages(<адрес скрыт>)");
        }
    }
}
