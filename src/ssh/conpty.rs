//! The local terminal on Windows: a pseudoconsole (ConPTY, Windows 10 1809 and later)
//! between the program and the tab. Like a Unix PTY it speaks VT sequences over two
//! pipes, so the tab gets the same events as from an SSH session.

#[cfg(windows)]
pub use console::spawn;

/// A command line as programs built with the Microsoft C runtime split it.
/// A batch file is run by cmd (`cmd`), as Windows cannot start it by itself.
fn command_line(program: &[u16], args: &[Vec<u16>], cmd: Option<&[u16]>) -> Vec<u16> {
    let mut line = Vec::new();
    push_quoted(&mut line, program);
    for arg in args {
        line.push(u16::from(b' '));
        push_quoted(&mut line, arg);
    }
    if let Some(cmd) = cmd {
        // `/s` takes the outer quotes off and runs the rest as it is.
        let mut wrapped = Vec::new();
        push_quoted(&mut wrapped, cmd);
        wrapped.extend(" /d /s /c \"".encode_utf16());
        wrapped.append(&mut line);
        wrapped.push(u16::from(b'"'));
        line = wrapped;
    }
    line.push(0);
    line
}

fn push_quoted(line: &mut Vec<u16>, word: &[u16]) {
    let (quote, backslash) = (u16::from(b'"'), u16::from(b'\\'));
    let plain = !word.is_empty()
        && !word
            .iter()
            .any(|&unit| b" \t\n\"".iter().any(|&byte| u16::from(byte) == unit));
    if plain {
        line.extend_from_slice(word);
        return;
    }
    line.push(quote);
    let mut backslashes = 0;
    for &unit in word {
        if unit == backslash {
            backslashes += 1;
        } else {
            // Backslashes count only before a quote: there they are doubled.
            if unit == quote {
                line.extend(std::iter::repeat_n(backslash, backslashes + 1));
            }
            backslashes = 0;
        }
        line.push(unit);
    }
    line.extend(std::iter::repeat_n(backslash, backslashes));
    line.push(quote);
}

/// `NAME=value` strings, each ending in NUL, then one more NUL. Names are compared
/// as Windows does, ignoring case: `PATH` replaces the inherited `Path`.
fn environment_block(
    inherited: impl IntoIterator<Item = (Vec<u16>, Vec<u16>)>,
    set: impl IntoIterator<Item = (Vec<u16>, Vec<u16>)>,
) -> Vec<u16> {
    let key = |name: &[u16]| -> Vec<u16> {
        name.iter()
            .map(|&unit| match u8::try_from(unit) {
                Ok(byte) => u16::from(byte.to_ascii_uppercase()),
                Err(_) => unit,
            })
            .collect()
    };
    let mut vars: Vec<(Vec<u16>, Vec<u16>, Vec<u16>)> = Vec::new();
    for (name, value) in inherited.into_iter().chain(set) {
        let name_key = key(&name);
        vars.retain(|(own, _, _)| *own != name_key);
        vars.push((name_key, name, value));
    }
    // Windows keeps the block sorted by name.
    vars.sort_by(|a, b| a.0.cmp(&b.0));
    let mut block = Vec::new();
    for (_, name, value) in vars {
        block.extend(name);
        block.push(u16::from(b'='));
        block.extend(value);
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    block
}

#[cfg(windows)]
mod console {
    use super::super::{
        CloseReason, FromSsh, LocalProgram, OUTPUT_CAPACITY, PtySize, SshSession, ToSsh, remote,
    };
    use bytes::Bytes;
    use futures::channel::{mpsc, oneshot};
    use futures::{SinkExt, StreamExt};
    use rust_i18n::t;
    use std::ffi::{OsStr, c_void};
    use std::io::{PipeReader, PipeWriter, Read, Write};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::sync::Arc;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Console::{
        COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON, ResizePseudoConsole,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
        EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE,
        InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
        PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
        STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
    };

    /// What `GetExitCodeProcess` reports while the process runs.
    const STILL_ACTIVE: u32 = 259;

    /// The pseudoconsole; closing it ends its output pipe.
    struct Console(HPCON);

    impl Console {
        fn resize(&self, size: &PtySize) {
            unsafe { ResizePseudoConsole(self.0, coord(size)) };
        }
    }

    impl Drop for Console {
        fn drop(&mut self) {
            unsafe { ClosePseudoConsole(self.0) };
        }
    }

    fn coord(size: &PtySize) -> COORD {
        let cells = |count: u16| count.clamp(1, i16::MAX as u16) as i16;
        COORD {
            X: cells(size.cols),
            Y: cells(size.rows),
        }
    }

    fn wide(text: &OsStr) -> Vec<u16> {
        text.encode_wide().collect()
    }

    pub fn spawn(size: PtySize, term: &str, program: &LocalProgram) -> std::io::Result<SshSession> {
        let (input_read, input) = std::io::pipe()?;
        let (output, output_write) = std::io::pipe()?;
        let mut handle: HPCON = 0;
        let result = unsafe {
            CreatePseudoConsole(
                coord(&size),
                input_read.as_raw_handle(),
                output_write.as_raw_handle(),
                0,
                &mut handle,
            )
        };
        if result < 0 {
            return Err(std::io::Error::from_raw_os_error(result));
        }
        let console = Console(handle);
        // The pseudoconsole keeps copies of its own ends of the pipes.
        drop((input_read, output_write));
        let process = Arc::new(start(&console, program, term)?);

        let (command_tx, command_rx) = mpsc::unbounded();
        let (answer_tx, _answer_rx) = mpsc::unbounded();
        let (event_tx, event_rx) = mpsc::channel(OUTPUT_CAPACITY);
        let stopper = process.clone();
        let thread = std::thread::Builder::new()
            .name("local-pty".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread().build() {
                    Ok(runtime) => runtime,
                    Err(err) => {
                        terminate(&process);
                        let mut event_tx = event_tx;
                        let _ = event_tx.try_send(FromSsh::Closed(CloseReason::Error(
                            t!("ssh.runtime_failed", error = err).into_owned(),
                        )));
                        return;
                    }
                };
                runtime.block_on(run(console, process, input, output, command_rx, event_tx));
            })
            .inspect_err(|_| terminate(&stopper))?;

        Ok(SshSession {
            commands: command_tx,
            answers: answer_tx,
            events: event_rx,
            thread: Some(thread),
        })
    }

    /// Starts the program attached to the pseudoconsole, in the user's home folder.
    fn start(
        console: &Console,
        program: &LocalProgram,
        term: &str,
    ) -> std::io::Result<OwnedHandle> {
        let mut size = 0;
        unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size) };
        // u64: the list needs pointer alignment.
        let mut storage = vec![0u64; size.div_ceil(8)];
        let list: LPPROC_THREAD_ATTRIBUTE_LIST = storage.as_mut_ptr().cast();
        if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut size) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        struct Attributes(LPPROC_THREAD_ATTRIBUTE_LIST);
        impl Drop for Attributes {
            fn drop(&mut self) {
                unsafe { DeleteProcThreadAttributeList(self.0) };
            }
        }
        let _attributes = Attributes(list);
        // The attribute's value is the handle itself, not a pointer to it.
        if unsafe {
            UpdateProcThreadAttribute(
                list,
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

        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        // No standard handles of its own: otherwise the program could take this app's
        // ones when they are redirected, instead of the pseudoconsole.
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.lpAttributeList = list;

        let batch = program
            .program
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("cmd") || ext.eq_ignore_ascii_case("bat"));
        let cmd =
            batch.then(|| wide(&std::env::var_os("ComSpec").unwrap_or_else(|| "cmd.exe".into())));
        let args: Vec<Vec<u16>> = program
            .args
            .iter()
            .map(|arg| wide(OsStr::new(arg)))
            .collect();
        let mut line =
            super::command_line(&wide(program.program.as_os_str()), &args, cmd.as_deref());

        let set = std::iter::once(("TERM".into(), term.into()))
            .chain(
                program
                    .env
                    .iter()
                    .map(|(name, value)| (name.into(), value.clone())),
            )
            .map(|(name, value): (std::ffi::OsString, std::ffi::OsString)| {
                (wide(&name), wide(&value))
            });
        let inherited = std::env::vars_os().map(|(name, value)| (wide(&name), wide(&value)));
        let environment = super::environment_block(inherited, set);

        let home = std::env::var_os("USERPROFILE")
            .filter(|dir| std::path::Path::new(dir).is_dir())
            .map(|dir| wide(&dir).into_iter().chain([0]).collect::<Vec<u16>>());

        let mut info = PROCESS_INFORMATION::default();
        let created = unsafe {
            CreateProcessW(
                std::ptr::null(),
                line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                environment.as_ptr().cast(),
                home.as_ref().map_or(std::ptr::null(), |dir| dir.as_ptr()),
                &startup.StartupInfo,
                &mut info,
            )
        };
        if created == 0 {
            let error = std::io::Error::last_os_error();
            return Err(std::io::Error::new(
                error.kind(),
                format!("{}: {error}", program.program.display()),
            ));
        }
        unsafe { CloseHandle(info.hThread) };
        Ok(unsafe { OwnedHandle::from_raw_handle(info.hProcess) })
    }

    fn terminate(process: &OwnedHandle) {
        unsafe { TerminateProcess(process.as_raw_handle(), 1) };
    }

    fn exit_code(process: &OwnedHandle) -> Option<u32> {
        let mut code = 0;
        let read = unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) } != 0;
        (read && code != STILL_ACTIVE).then_some(code)
    }

    /// Pipes block, so reading, writing and waiting for the program each get a thread.
    /// The order at the end: the program exits, the pseudoconsole is closed, its output
    /// ends, and only then the tab learns it is closed, with all the output before it.
    async fn run(
        console: Console,
        process: Arc<OwnedHandle>,
        input: PipeWriter,
        output: PipeReader,
        mut commands: mpsc::UnboundedReceiver<ToSsh>,
        mut events: mpsc::Sender<FromSsh>,
    ) {
        let _ = events
            .send(FromSsh::Connected {
                fingerprint: String::new(),
            })
            .await;

        let (read_done, mut output_done) = oneshot::channel::<()>();
        let mut output_events = events.clone();
        let reader = std::thread::Builder::new()
            .name("local-pty-read".into())
            .spawn(move || {
                let mut output = output;
                let mut buf = [0u8; 8192];
                // A broken pipe reads as the end: the pseudoconsole is closed.
                while let Ok(read @ 1..) = output.read(&mut buf) {
                    let chunk = FromSsh::Output(Bytes::copy_from_slice(&buf[..read]));
                    if futures::executor::block_on(output_events.send(chunk)).is_err() {
                        break;
                    }
                }
                let _ = read_done.send(());
            });

        let (write_tx, write_rx) = std::sync::mpsc::channel::<Bytes>();
        let writer = std::thread::Builder::new()
            .name("local-pty-write".into())
            .spawn(move || {
                let mut input = input;
                for bytes in write_rx {
                    if input.write_all(&bytes).is_err() {
                        break;
                    }
                }
            });

        let (exit_tx, mut exited) = oneshot::channel::<()>();
        let waited = process.clone();
        let waiter = std::thread::Builder::new()
            .name("local-pty-wait".into())
            .spawn(move || {
                unsafe { WaitForSingleObject(waited.as_raw_handle(), INFINITE) };
                let _ = exit_tx.send(());
            });

        if let Err(err) = reader.and(writer).and(waiter) {
            terminate(&process);
            let _ = events
                .send(FromSsh::Closed(CloseReason::Error(
                    t!("ssh.pty_watch_failed", error = err).into_owned(),
                )))
                .await;
            return;
        }

        let mut console = Some(console);
        loop {
            tokio::select! {
                command = commands.next() => match command {
                    Some(ToSsh::Input(bytes)) => {
                        let _ = write_tx.send(bytes);
                    }
                    Some(ToSsh::Resize(size)) => {
                        if let Some(console) = &console {
                            console.resize(&size);
                        }
                    }
                    // A local tab has no SFTP or forwards — ignore them.
                    Some(ToSsh::OpenSftp(_)) | Some(ToSsh::SetForward { .. }) => {}
                    // Tools get the server, not this computer: a local tab has none.
                    Some(ToSsh::Exec(request)) => {
                        let _ = request.reply.send(Err(remote::LOCAL_TAB.to_owned()));
                    }
                    Some(ToSsh::Files(request)) => {
                        let _ = request.reply.send(Err(remote::LOCAL_TAB.to_owned()));
                    }
                    // The rest of the output still comes: the end follows the exit.
                    Some(ToSsh::Disconnect) => terminate(&process),
                    // The tab is closed: nobody reads the events any more.
                    None => {
                        terminate(&process);
                        return;
                    }
                },
                _ = &mut exited, if console.is_some() => {
                    console = None;
                }
                _ = &mut output_done => {
                    let exit_status = exit_code(&process);
                    terminate(&process);
                    let _ = events
                        .send(FromSsh::Closed(CloseReason::Remote { exit_status }))
                        .await;
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn line(program: &str, args: &[&str], cmd: Option<&str>) -> String {
        let args: Vec<Vec<u16>> = args.iter().map(|arg| wide(arg)).collect();
        let cmd = cmd.map(wide);
        let line = command_line(&wide(program), &args, cmd.as_deref());
        assert_eq!(line.last(), Some(&0));
        String::from_utf16(&line[..line.len() - 1]).unwrap()
    }

    #[test]
    fn arguments_are_quoted_as_the_c_runtime_splits_them() {
        assert_eq!(
            line(
                r"C:\Program Files\PowerShell\7\pwsh.exe",
                &["-NoLogo"],
                None
            ),
            r#""C:\Program Files\PowerShell\7\pwsh.exe" -NoLogo"#
        );
        assert_eq!(
            line("wsl.exe", &["-d", "Ubuntu 22.04", "--cd", "~"], None),
            r#"wsl.exe -d "Ubuntu 22.04" --cd ~"#
        );
        assert_eq!(line("a", &[""], None), r#"a """#);
        assert_eq!(line("a", &[r#"say "hi""#], None), r#"a "say \"hi\"""#);
        assert_eq!(
            line("a", &[r"C:\dir with space\"], None),
            r#"a "C:\dir with space\\""#
        );
        assert_eq!(line("a", &[r#"x\"y z"#], None), r#"a "x\\\"y z""#);
        assert_eq!(line("a", &[r"C:\no\space\"], None), r"a C:\no\space\");
    }

    #[test]
    fn a_batch_file_runs_in_cmd() {
        assert_eq!(
            line(
                r"C:\Users\me\AppData\Roaming\npm\npx.cmd",
                &["-y", "pkg"],
                Some(r"C:\Windows\system32\cmd.exe")
            ),
            r#"C:\Windows\system32\cmd.exe /d /s /c "C:\Users\me\AppData\Roaming\npm\npx.cmd -y pkg""#
        );
    }

    #[test]
    fn variables_are_replaced_ignoring_case_and_sorted() {
        let vars = |pairs: &[(&str, &str)]| -> Vec<(Vec<u16>, Vec<u16>)> {
            pairs
                .iter()
                .map(|(name, value)| (wide(name), wide(value)))
                .collect()
        };
        let block = environment_block(
            vars(&[
                ("Path", r"C:\Windows"),
                ("windir", r"C:\Windows"),
                ("TEMP", "t"),
            ]),
            vars(&[("TERM", "xterm-256color"), ("PATH", r"C:\bin")]),
        );
        let text = String::from_utf16(&block).unwrap();
        assert_eq!(
            text,
            "PATH=C:\\bin\0TEMP=t\0TERM=xterm-256color\0windir=C:\\Windows\0\0"
        );
        assert_eq!(environment_block(vec![], vec![]), [0, 0]);
    }
}
