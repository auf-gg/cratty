//! Local terminal on Windows: a pseudo console (ConPTY), with the same event protocol as
//! an SSH session. Windows 10 1809 and later have it.
//!
//! Three threads per tab: the control thread takes input, resizes and the end of the tab;
//! a reader passes the console's output on; a waiter tells when the program has exited.
//! A pseudo console keeps its output pipe open after the program exits, so on exit it is
//! closed, and the reader then sees the end of output and closes the session. Closing it
//! may wait for its output to be read, so the reader drains it to the end in any case.

use std::ffi::{OsStr, OsString, c_void};
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use futures::channel::{mpsc, oneshot};
use futures::{FutureExt, SinkExt, StreamExt};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Console::{
    COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON, ResizePseudoConsole,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, PROCESS_INFORMATION,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject,
};

use super::{
    CloseReason, FromSsh, LocalProgram, OUTPUT_CAPACITY, PtySize, SshSession, ToSsh, remote,
};

/// A handle closed when dropped.
struct Owned(HANDLE);

// SAFETY: kernel handles may be used and closed from any thread.
unsafe impl Send for Owned {}
unsafe impl Sync for Owned {}

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
        }
    }
}

impl Owned {
    /// Gives the handle to a `File`, which closes it from then on.
    fn into_file(self) -> std::fs::File {
        let handle = self.0;
        std::mem::forget(self);
        unsafe { std::fs::File::from_raw_handle(handle as RawHandle) }
    }
}

/// The pseudo console, closed once.
struct Console(HPCON);

unsafe impl Send for Console {}

impl Drop for Console {
    fn drop(&mut self) {
        unsafe { ClosePseudoConsole(self.0) };
    }
}

fn coord(size: &PtySize) -> COORD {
    COORD {
        X: size.cols.max(1).min(i16::MAX as u16) as i16,
        Y: size.rows.max(1).min(i16::MAX as u16) as i16,
    }
}

fn pipe() -> std::io::Result<(Owned, Owned)> {
    let mut read: HANDLE = std::ptr::null_mut();
    let mut write: HANDLE = std::ptr::null_mut();
    if unsafe { CreatePipe(&mut read, &mut write, std::ptr::null(), 0) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((Owned(read), Owned(write)))
}

fn hresult(code: i32) -> std::io::Result<()> {
    if code < 0 {
        Err(std::io::Error::from_raw_os_error(code))
    } else {
        Ok(())
    }
}

pub fn spawn(size: PtySize, term: &str, program: &LocalProgram) -> std::io::Result<SshSession> {
    let (input_read, input_write) = pipe()?;
    let (output_read, output_write) = pipe()?;

    let mut handle: HPCON = 0;
    hresult(unsafe {
        CreatePseudoConsole(coord(&size), input_read.0, output_write.0, 0, &mut handle)
    })?;
    let console = Console(handle);

    let (process, thread) = start_process(&console, term, program)?;
    drop(thread);
    // The console has its own copies of these ends; ours would keep the pipes open.
    drop(input_read);
    drop(output_write);

    let (command_tx, command_rx) = mpsc::unbounded();
    let (answer_tx, _answer_rx) = mpsc::unbounded();
    let (event_tx, event_rx) = mpsc::channel(OUTPUT_CAPACITY);

    let thread = std::thread::Builder::new()
        .name("local-pty".into())
        .spawn(move || {
            control(
                console,
                Arc::new(process),
                input_write.into_file(),
                output_read.into_file(),
                command_rx,
                event_tx,
            )
        })?;

    Ok(SshSession {
        commands: command_tx,
        answers: answer_tx,
        events: event_rx,
        thread: Some(thread),
    })
}

fn control(
    console: Console,
    process: Arc<Owned>,
    mut input: std::fs::File,
    output: std::fs::File,
    mut commands: mpsc::UnboundedReceiver<ToSsh>,
    events: mpsc::Sender<FromSsh>,
) {
    let killed = Arc::new(AtomicBool::new(false));
    let (exit_tx, exit_rx) = oneshot::channel::<Option<u32>>();

    let mut connected = events.clone();
    let _ = futures::executor::block_on(connected.send(FromSsh::Connected {
        fingerprint: String::new(),
    }));

    // The waiter: the program's exit code, once it has exited.
    let waited = process.clone();
    let _ = std::thread::Builder::new()
        .name("local-pty-wait".into())
        .spawn(move || {
            let code = (unsafe { WaitForSingleObject(waited.0, INFINITE) } == WAIT_OBJECT_0)
                .then(|| {
                    let mut code = 0u32;
                    (unsafe { GetExitCodeProcess(waited.0, &mut code) } != 0).then_some(code)
                })
                .flatten();
            let _ = exit_tx.send(code);
        });

    // The reader: output until the console is closed, then the end of the session.
    let (status_tx, status_rx) = std::sync::mpsc::channel::<Option<u32>>();
    let reader = std::thread::Builder::new()
        .name("local-pty-read".into())
        .spawn(move || read_output(output, events, status_rx));

    let mut exit = exit_rx.fuse();
    let status = futures::executor::block_on(async {
        loop {
            futures::select! {
                command = commands.next() => match command {
                    Some(ToSsh::Input(bytes)) => {
                        // A write fails only when the console is gone: its exit comes next.
                        let _ = input.write_all(&bytes).and_then(|()| input.flush());
                    }
                    Some(ToSsh::Resize(size)) => unsafe {
                        ResizePseudoConsole(console.0, coord(&size));
                    },
                    Some(ToSsh::OpenSftp(_)) | Some(ToSsh::SetForward { .. }) => {}
                    Some(ToSsh::Exec(request)) => {
                        let _ = request.reply.send(Err(remote::LOCAL_TAB.to_owned()));
                    }
                    Some(ToSsh::Files(request)) => {
                        let _ = request.reply.send(Err(remote::LOCAL_TAB.to_owned()));
                    }
                    Some(ToSsh::Disconnect) => {
                        // As on unix: the rest of the output is still read and the
                        // session ends when the program has gone.
                        killed.store(true, Ordering::Relaxed);
                        unsafe { TerminateProcess(process.0, 1) };
                    }
                    None => {
                        // The tab is closed: nobody reads any more, but the program
                        // must not be left behind.
                        unsafe { TerminateProcess(process.0, 1) };
                        return None;
                    }
                },
                code = exit => {
                    let code = code.ok().flatten();
                    return Some(if killed.load(Ordering::Relaxed) { None } else { code });
                }
            }
        }
    });

    drop(input);
    let closed = status.is_some();
    let _ = status_tx.send(status.flatten());
    // Closing the console ends its output; on older Windows it waits until the output
    // has been read, which the reader keeps doing.
    drop(console);
    if closed && let Ok(reader) = reader {
        let _ = reader.join();
    }
}

fn read_output(
    mut output: std::fs::File,
    mut events: mpsc::Sender<FromSsh>,
    status: std::sync::mpsc::Receiver<Option<u32>>,
) {
    let mut buffer = [0u8; 8192];
    let mut listening = true;
    loop {
        match output.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                if listening
                    && futures::executor::block_on(
                        events.send(FromSsh::Output(Bytes::copy_from_slice(&buffer[..read]))),
                    )
                    .is_err()
                {
                    // Nobody listens, but the console must still be drained.
                    listening = false;
                }
            }
        }
    }
    if !listening {
        return;
    }
    // The end of output comes after the console is closed: the control thread has the
    // exit status by then, unless the tab itself was closed.
    if let Ok(exit_status) = status.recv() {
        let _ = futures::executor::block_on(
            events.send(FromSsh::Closed(CloseReason::Remote { exit_status })),
        );
    }
}

/// Starts the program attached to the console: its process and main thread.
fn start_process(
    console: &Console,
    term: &str,
    program: &LocalProgram,
) -> std::io::Result<(Owned, Owned)> {
    let mut size = 0usize;
    unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size) };
    // usize-aligned storage for the attribute list.
    let mut storage = vec![0usize; size.div_ceil(std::mem::size_of::<usize>()).max(1)];
    let list = storage.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
    if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut size) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    struct List(LPPROC_THREAD_ATTRIBUTE_LIST);
    impl Drop for List {
        fn drop(&mut self) {
            unsafe { DeleteProcThreadAttributeList(self.0) };
        }
    }
    let list = List(list);

    if unsafe {
        UpdateProcThreadAttribute(
            list.0,
            0,
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
            console.0 as *const c_void,
            std::mem::size_of::<HPCON>(),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }

    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    // Without this a program may get this app's own redirected standard handles
    // instead of the console's.
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = INVALID_HANDLE_VALUE;
    startup.StartupInfo.hStdOutput = INVALID_HANDLE_VALUE;
    startup.StartupInfo.hStdError = INVALID_HANDLE_VALUE;
    startup.lpAttributeList = list.0;

    let mut command_line = wide(&command_line(program));
    let environment = environment_block(term, &program.env);
    let directory = program.cwd.as_deref().filter(|dir| dir.is_dir()).map(|dir| wide(dir.as_os_str()));

    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let started = unsafe {
        CreateProcessW(
            std::ptr::null(),
            command_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            environment.as_ptr() as *const c_void,
            directory.as_ref().map_or(std::ptr::null(), |dir| dir.as_ptr()),
            &startup.StartupInfo,
            &mut info,
        )
    };
    if started == 0 {
        let error = std::io::Error::last_os_error();
        return Err(std::io::Error::new(
            error.kind(),
            format!("{}: {error}", program.program.display()),
        ));
    }
    Ok((Owned(info.hProcess), Owned(info.hThread)))
}

fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(std::iter::once(0)).collect()
}

/// The command line: the program and its arguments, quoted for the C runtime's parser.
/// A batch file (such as `npx.cmd`) runs through `cmd.exe`, as Windows requires.
pub(super) fn command_line(program: &LocalProgram) -> OsString {
    let mut line = OsString::new();
    let batch = program
        .program
        .extension()
        .and_then(OsStr::to_str)
        .is_some_and(|ext| ext.eq_ignore_ascii_case("cmd") || ext.eq_ignore_ascii_case("bat"));
    if batch {
        // `/s /c "<whole line>"`: cmd strips the outer quotes and runs the rest as is.
        line.push(quote(&cmd_exe()));
        line.push(" /d /s /c \"");
    }
    line.push(quote(program.program.as_os_str()));
    for arg in &program.args {
        line.push(" ");
        line.push(quote(OsStr::new(arg)));
    }
    if batch {
        line.push("\"");
    }
    line
}

fn cmd_exe() -> OsString {
    std::env::var_os("ComSpec").unwrap_or_else(|| {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        Path::new(&root).join("System32").join("cmd.exe").into_os_string()
    })
}

/// Quotes one argument so `CommandLineToArgvW` and the C runtime read it back unchanged.
fn quote(arg: &OsStr) -> OsString {
    let text = arg.to_string_lossy();
    if !text.is_empty() && !text.contains([' ', '\t', '\n', '\x0b', '"']) {
        return arg.to_owned();
    }
    let mut quoted = String::with_capacity(text.len() + 2);
    quoted.push('"');
    let mut backslashes = 0usize;
    for c in text.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                quoted.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.extend(std::iter::repeat_n('\\', backslashes));
                quoted.push(c);
                backslashes = 0;
            }
        }
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted.into()
}

/// This process's environment with `TERM` and the program's variables set over it.
/// Names are compared without case, as Windows does: `PATH` replaces `Path`.
pub(super) fn environment(term: &str, set: &[(String, OsString)]) -> Vec<(OsString, OsString)> {
    let mut own: Vec<(OsString, OsString)> = vec![("TERM".into(), term.into())];
    own.extend(set.iter().map(|(name, value)| (name.into(), value.clone())));
    let same = |a: &OsStr, b: &OsStr| a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy());

    let mut variables: Vec<(OsString, OsString)> = std::env::vars_os()
        .filter(|(name, _)| !own.iter().any(|(set, _)| same(set, name)))
        .collect();
    for (name, value) in own {
        if let Some(slot) = variables.iter_mut().find(|(other, _)| same(other, &name)) {
            slot.1 = value;
        } else {
            variables.push((name, value));
        }
    }
    variables.sort_by_key(|(name, _)| name.to_string_lossy().to_uppercase());
    variables
}

fn environment_block(term: &str, set: &[(String, OsString)]) -> Vec<u16> {
    let mut block = Vec::new();
    for (name, value) in environment(term, set) {
        block.extend(name.encode_wide());
        block.push(u16::from(b'='));
        block.extend(value.encode_wide());
        block.push(0);
    }
    block.push(0);
    block
}

#[cfg(test)]
mod tests {
    use super::*;

    fn program(path: &str, args: &[&str]) -> LocalProgram {
        LocalProgram {
            program: path.into(),
            args: args.iter().map(|arg| (*arg).to_owned()).collect(),
            env: Vec::new(),
            cwd: None,
        }
    }

    #[test]
    fn arguments_are_quoted_only_when_needed() {
        assert_eq!(quote(OsStr::new("plain")), "plain");
        assert_eq!(quote(OsStr::new("")), "\"\"");
        assert_eq!(quote(OsStr::new("two words")), "\"two words\"");
        assert_eq!(quote(OsStr::new(r#"say "hi""#)), r#""say \"hi\"""#);
        assert_eq!(quote(OsStr::new(r"C:\dir with space\")), r#""C:\dir with space\\""#);
    }

    #[test]
    fn batch_files_run_through_cmd() {
        let line = command_line(&program(r"C:\Program Files\nodejs\npx.cmd", &["-y", "pkg"]));
        let line = line.to_string_lossy();
        assert!(line.ends_with(r#" /d /s /c ""C:\Program Files\nodejs\npx.cmd" -y pkg""#), "{line}");

        let line = command_line(&program(r"C:\Windows\System32\cmd.exe", &[]));
        assert_eq!(line, r"C:\Windows\System32\cmd.exe");
    }

    #[test]
    fn set_variables_replace_inherited_ones_without_case() {
        let path = std::env::vars_os()
            .find(|(name, _)| name.to_string_lossy().eq_ignore_ascii_case("path"))
            .map(|(name, _)| name);
        let variables = environment("xterm-256color", &[("PATH".into(), "C:\\only".into())]);
        let paths: Vec<_> = variables
            .iter()
            .filter(|(name, _)| name.to_string_lossy().eq_ignore_ascii_case("path"))
            .collect();
        assert_eq!(paths.len(), 1, "{paths:?}");
        assert_eq!(paths[0].1, "C:\\only");
        if let Some(path) = path {
            assert_eq!(paths[0].0, path, "the inherited spelling is kept");
        }
        assert!(variables.iter().any(|(name, value)| name == "TERM" && value == "xterm-256color"));
    }

    /// A live console: cmd answers, and its exit ends the session with its code.
    #[test]
    fn console_runs_a_program_and_reports_its_exit() {
        let cmd = cmd_exe();
        let program = LocalProgram {
            program: cmd.into(),
            args: vec!["/d".into(), "/c".into(), "echo cratty-%CRATTY_PROBE%& exit 7".into()],
            env: vec![("CRATTY_PROBE".into(), "marker".into())],
            cwd: Some(std::env::temp_dir()),
        };
        let mut session = spawn(PtySize::new(80, 10), "xterm-256color", &program).expect("spawn");

        let mut output = String::new();
        let mut closed = None;
        for _ in 0..200 {
            while let Ok(event) = session.events.try_recv() {
                match event {
                    FromSsh::Output(data) => output.push_str(&String::from_utf8_lossy(&data)),
                    FromSsh::Closed(reason) => closed = Some(reason),
                    _ => {}
                }
            }
            if closed.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(output.contains("cratty-marker"), "{output:?}");
        assert!(
            matches!(closed, Some(CloseReason::Remote { exit_status: Some(7) })),
            "{closed:?}"
        );
        session.join();
    }

    /// Closing the tab of a program that does not exit by itself returns quickly.
    #[test]
    fn closing_the_tab_ends_a_running_program() {
        let program = LocalProgram {
            program: cmd_exe().into(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
        };
        let session = spawn(PtySize::new(80, 10), "xterm-256color", &program).expect("spawn");
        std::thread::sleep(std::time::Duration::from_millis(300));
        let started = std::time::Instant::now();
        drop(session);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }
}
