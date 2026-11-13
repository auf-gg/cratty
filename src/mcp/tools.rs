//! The tools an agent gets: their names and arguments, how a call runs, and the text the
//! model reads back. Texts here are read by the model, so they are in English.

use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};

use super::Gate;
use crate::ssh::remote::{self, Exec, ExecOutput, Exit, Listing};

const DEFAULT_TIMEOUT: u64 = 60;
/// Output kept of each stream of a command.
const OUTPUT_LIMIT: usize = 64 * 1024;
const READ_LINES: usize = 2000;
const SCREEN_ROWS: usize = 100;
const MAX_SCREEN_ROWS: usize = 5000;
/// The longest text sent back for one call.
const MAX_ANSWER: usize = 200 * 1024;

/// A call with checked arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    RunCommand {
        command: String,
        cwd: Option<String>,
        timeout: Duration,
    },
    ReadFile {
        path: String,
        offset: usize,
        limit: usize,
    },
    ListDirectory {
        path: String,
    },
    WriteFile {
        path: String,
        content: String,
    },
    EditFile {
        path: String,
        old_text: String,
        new_text: String,
        replace_all: bool,
    },
    ReadTerminal {
        rows: usize,
    },
}

/// What a call is about to do, for the window to decide on and to show the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Run {
        command: String,
        cwd: Option<String>,
    },
    Read {
        path: String,
    },
    List {
        path: String,
    },
    Screen {
        rows: usize,
    },
    Write {
        path: String,
        content: String,
    },
    Edit {
        path: String,
        old_text: String,
        new_text: String,
    },
}

impl Action {
    /// Changes something on the server, so the user approves it first.
    pub fn changes_server(&self) -> bool {
        matches!(
            self,
            Self::Run { .. } | Self::Write { .. } | Self::Edit { .. }
        )
    }
}

pub fn definitions() -> Value {
    json!([
        {
            "name": "run_command",
            "title": "Run a command on the server",
            "description": "Run a shell command on the server and get its exit code, stdout and stderr. \
                The command runs with /bin/sh -c (POSIX sh; call bash -c yourself for bash features) \
                and without a terminal: interactive programs, pagers and password prompts do not work, \
                so use non-interactive flags (sudo -n, apt-get -y, systemctl --no-pager). Every call \
                starts a new shell in the home folder: pass cwd rather than cd in a separate call. \
                The user approves each command in Cratty and may deny it. Output over 64 KB per \
                stream keeps its beginning and its end.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": { "type": "string", "description": "Shell command or script" },
                    "cwd": { "type": "string", "description": "Folder to run in; relative paths and ~ start at the home folder" },
                    "timeout": { "type": "integer", "minimum": 1, "maximum": 600, "description": "Seconds before the command is stopped (default 60)" }
                },
                "required": ["command"]
            },
            "annotations": { "destructiveHint": true, "openWorldHint": true }
        },
        {
            "name": "read_file",
            "title": "Read a file on the server",
            "description": "Read a text file on the server. Returns up to 2000 lines starting at offset; \
                the answer says how to read further. Files over 2 MB cannot be read whole: use \
                run_command with head, tail, grep or sed -n. Relative paths and ~ start at the home folder.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "offset": { "type": "integer", "minimum": 1, "description": "First line to read, from 1 (default 1)" },
                    "limit": { "type": "integer", "minimum": 1, "description": "Number of lines (default 2000)" }
                },
                "required": ["path"]
            },
            "annotations": { "readOnlyHint": true, "openWorldHint": true }
        },
        {
            "name": "list_directory",
            "title": "List a folder on the server",
            "description": "List a folder on the server: type, size, modification time (UTC) and name of each entry. \
                Relative paths and ~ start at the home folder.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Folder (default: the home folder)" }
                }
            },
            "annotations": { "readOnlyHint": true, "openWorldHint": true }
        },
        {
            "name": "write_file",
            "title": "Write a file on the server",
            "description": "Create a file on the server or replace its whole content. For a change in an \
                existing file use edit_file. The user approves each write in Cratty and may deny it.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "content": { "type": "string" }
                },
                "required": ["path", "content"]
            },
            "annotations": { "destructiveHint": true, "openWorldHint": true }
        },
        {
            "name": "edit_file",
            "title": "Edit a file on the server",
            "description": "Replace exact text in a file on the server. old_text must match the file exactly, \
                including whitespace and indentation, and occur once unless replace_all is set: add \
                surrounding lines to make it unique. Read the file first. The user approves each edit \
                in Cratty and may deny it.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "old_text": { "type": "string", "description": "Text to replace" },
                    "new_text": { "type": "string", "description": "Text to put in its place" },
                    "replace_all": { "type": "boolean", "description": "Replace every occurrence (default false)" }
                },
                "required": ["path", "old_text", "new_text"]
            },
            "annotations": { "destructiveHint": true, "openWorldHint": true }
        },
        {
            "name": "read_terminal",
            "title": "Read the user's terminal",
            "description": "Read the last rows of the terminal in the user's Cratty tab for this server: what \
                the user sees, including commands they ran themselves and their output. Use it when the \
                user refers to something on their screen.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "rows": { "type": "integer", "minimum": 1, "maximum": 5000, "description": "Rows from the bottom (default 100)" }
                }
            },
            "annotations": { "readOnlyHint": true }
        }
    ])
}

#[derive(Deserialize)]
struct RunArgs {
    command: String,
    cwd: Option<String>,
    timeout: Option<u64>,
}

#[derive(Deserialize)]
struct ReadArgs {
    path: String,
    offset: Option<usize>,
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct ListArgs {
    path: Option<String>,
}

#[derive(Deserialize)]
struct WriteArgs {
    path: String,
    content: String,
}

#[derive(Deserialize)]
struct EditArgs {
    path: String,
    old_text: String,
    new_text: String,
    replace_all: Option<bool>,
}

#[derive(Deserialize)]
struct ScreenArgs {
    rows: Option<usize>,
}

pub fn parse(name: &str, arguments: Value) -> Result<Call, String> {
    fn args<T: for<'de> Deserialize<'de>>(name: &str, arguments: Value) -> Result<T, String> {
        let arguments = if arguments.is_null() {
            json!({})
        } else {
            arguments
        };
        serde_json::from_value(arguments)
            .map_err(|error| format!("invalid arguments for {name}: {error}"))
    }
    fn path(path: String) -> Result<String, String> {
        if path.trim().is_empty() {
            Err("path is empty".into())
        } else {
            Ok(path)
        }
    }

    Ok(match name {
        "run_command" => {
            let RunArgs {
                command,
                cwd,
                timeout,
            } = args(name, arguments)?;
            if command.trim().is_empty() {
                return Err("command is empty".into());
            }
            let seconds = timeout
                .unwrap_or(DEFAULT_TIMEOUT)
                .clamp(1, remote::MAX_TIMEOUT.as_secs());
            Call::RunCommand {
                command,
                cwd: cwd.filter(|cwd| !cwd.trim().is_empty()),
                timeout: Duration::from_secs(seconds),
            }
        }
        "read_file" => {
            let ReadArgs {
                path: file,
                offset,
                limit,
            } = args(name, arguments)?;
            Call::ReadFile {
                path: path(file)?,
                offset: offset.unwrap_or(1).max(1),
                limit: limit.unwrap_or(READ_LINES).max(1),
            }
        }
        "list_directory" => {
            let ListArgs { path } = args(name, arguments)?;
            Call::ListDirectory {
                path: path
                    .filter(|path| !path.trim().is_empty())
                    .unwrap_or_else(|| ".".into()),
            }
        }
        "write_file" => {
            let WriteArgs {
                path: file,
                content,
            } = args(name, arguments)?;
            if content.len() as u64 > remote::MAX_READ {
                return Err(format!(
                    "content is larger than {} bytes; write it in parts with run_command",
                    remote::MAX_READ
                ));
            }
            Call::WriteFile {
                path: path(file)?,
                content,
            }
        }
        "edit_file" => {
            let EditArgs {
                path: file,
                old_text,
                new_text,
                replace_all,
            } = args(name, arguments)?;
            if old_text.is_empty() {
                return Err("old_text is empty; create a file with write_file".into());
            }
            if old_text == new_text {
                return Err("old_text and new_text are the same".into());
            }
            Call::EditFile {
                path: path(file)?,
                old_text,
                new_text,
                replace_all: replace_all.unwrap_or(false),
            }
        }
        "read_terminal" => {
            let ScreenArgs { rows } = args(name, arguments)?;
            Call::ReadTerminal {
                rows: rows.unwrap_or(SCREEN_ROWS).clamp(1, MAX_SCREEN_ROWS),
            }
        }
        other => return Err(format!("unknown tool: {other}")),
    })
}

/// Runs a call: asks the window for access, then does the work on the server.
pub async fn run(call: Call, gate: &Gate) -> Result<String, String> {
    match call {
        Call::RunCommand {
            command,
            cwd,
            timeout,
        } => {
            let remote = gate
                .remote(Action::Run {
                    command: command.clone(),
                    cwd: cwd.clone(),
                })
                .await?;
            let output = remote
                .exec(Exec {
                    command: remote::sh_command(&command, cwd.as_deref()),
                    stdin: Vec::new(),
                    timeout,
                    limit: OUTPUT_LIMIT,
                })
                .await?;
            Ok(clip_answer(command_answer(&output, timeout)))
        }
        Call::ReadFile {
            path,
            offset,
            limit,
        } => {
            let remote = gate.remote(Action::Read { path: path.clone() }).await?;
            let data = remote.read(&path).await?;
            file_answer(&path, &data, offset, limit).map(clip_answer)
        }
        Call::ListDirectory { path } => {
            let remote = gate.remote(Action::List { path: path.clone() }).await?;
            let listing = remote.list(&path).await?;
            Ok(clip_answer(listing_answer(&listing)))
        }
        Call::WriteFile { path, content } => {
            let remote = gate
                .remote(Action::Write {
                    path: path.clone(),
                    content: content.clone(),
                })
                .await?;
            let size = content.len();
            remote.write(&path, content.into_bytes()).await?;
            Ok(format!("wrote {size} bytes to {path}"))
        }
        Call::EditFile {
            path,
            old_text,
            new_text,
            replace_all,
        } => {
            let reader = gate.remote(Action::Read { path: path.clone() }).await?;
            let before = reader.read(&path).await?;
            let text = std::str::from_utf8(&before)
                .map_err(|_| format!("{path} is not UTF-8 text; change it with run_command"))?;
            let (after, count) = replace(text, &old_text, &new_text, replace_all)
                .map_err(|error| format!("{path}: {error}"))?;

            let remote = gate
                .remote(Action::Edit {
                    path: path.clone(),
                    old_text,
                    new_text,
                })
                .await?;
            // Approval may take a while: do not write over changes made meanwhile.
            if remote.read(&path).await? != before {
                return Err(format!(
                    "{path} changed while the edit waited for approval; read it again"
                ));
            }
            remote.write(&path, after.into_bytes()).await?;
            Ok(match count {
                1 => format!("edited {path}"),
                count => format!("edited {path}: replaced {count} occurrences"),
            })
        }
        Call::ReadTerminal { rows } => {
            let text = gate.screen(rows).await?;
            Ok(clip_answer(if text.is_empty() {
                "(the terminal is empty)".into()
            } else {
                text
            }))
        }
    }
}

fn command_answer(output: &ExecOutput, timeout: Duration) -> String {
    let mut text = match &output.exit {
        Exit::Code(code) => format!("exit code: {code}"),
        Exit::Signal(signal) => format!("killed by signal {signal}"),
        Exit::TimedOut => format!(
            "timed out after {} s and was stopped; pass a larger timeout or run it in the background",
            timeout.as_secs()
        ),
        Exit::Unknown => "the server did not report an exit status".into(),
    };
    if !output.stdout.is_empty() {
        text.push_str("\n--- stdout ---\n");
        text.push_str(output.stdout.text().trim_end());
    }
    if !output.stderr.is_empty() {
        text.push_str("\n--- stderr ---\n");
        text.push_str(output.stderr.text().trim_end());
    }
    if output.stdout.is_empty() && output.stderr.is_empty() {
        text.push_str("\n(no output)");
    }
    text
}

fn file_answer(path: &str, data: &[u8], offset: usize, limit: usize) -> Result<String, String> {
    if data[..data.len().min(8000)].contains(&0) {
        return Err(format!(
            "{path} looks like a binary file ({} bytes); inspect it with run_command (file, xxd | head)",
            data.len()
        ));
    }
    if data.is_empty() {
        return Ok("(empty file)".into());
    }
    let text = String::from_utf8_lossy(data);
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let total = lines.len();
    let start = offset - 1;
    if start >= total {
        return Err(format!(
            "offset {offset} is past the end: {path} has {total} lines"
        ));
    }
    let end = (start + limit).min(total);
    let mut answer: String = lines[start..end].concat();
    if start > 0 || end < total {
        if !answer.ends_with('\n') {
            answer.push('\n');
        }
        answer.push_str(&format!("[lines {}-{end} of {total}", start + 1));
        if end < total {
            answer.push_str(&format!("; read on with offset {}", end + 1));
        }
        answer.push(']');
    }
    Ok(answer)
}

fn listing_answer(listing: &Listing) -> String {
    match listing {
        Listing::Text(text) => text.trim_end().to_owned(),
        Listing::Entries { path, entries } => {
            let mut text = format!("{path}\n");
            if entries.is_empty() {
                text.push_str("(empty folder)");
            }
            for entry in entries {
                let (kind, suffix) = if entry.is_symlink {
                    ("l", "@")
                } else if entry.is_dir {
                    ("d", "/")
                } else {
                    ("f", "")
                };
                let size = if entry.is_dir {
                    "-".to_owned()
                } else {
                    entry.size.to_string()
                };
                let time = entry
                    .modified
                    .map(crate::ui::files::format_time)
                    .unwrap_or_default();
                text.push_str(&format!(
                    "{kind} {size:>12}  {time:16}  {}{suffix}\n",
                    entry.name
                ));
            }
            text.trim_end().to_owned()
        }
    }
}

/// Replaces `old` with `new`. Text written with `\n` also matches a file with `\r\n`.
fn replace(text: &str, old: &str, new: &str, all: bool) -> Result<(String, usize), String> {
    let mut found = text.matches(old).count();
    let (mut old, mut new) = (old.to_owned(), new.to_owned());
    if found == 0 && text.contains("\r\n") && !old.contains('\r') {
        old = old.replace('\n', "\r\n");
        new = new.replace('\n', "\r\n");
        found = text.matches(&old).count();
    }
    match found {
        0 => Err(
            "old_text was not found; read the file again and copy the text exactly, \
                  including whitespace"
                .into(),
        ),
        1 => Ok((text.replacen(&old, &new, 1), 1)),
        count if all => Ok((text.replace(&old, &new), count)),
        count => Err(format!(
            "old_text occurs {count} times; add surrounding lines to make it unique, \
             or set replace_all"
        )),
    }
}

fn clip_answer(mut text: String) -> String {
    if text.len() <= MAX_ANSWER {
        return text;
    }
    let mut cut = MAX_ANSWER;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    let dropped = text.len() - cut;
    text.truncate(cut);
    text.push_str(&format!("\n[… {dropped} more bytes not shown]"));
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::remote::Clipped;

    #[test]
    fn every_definition_has_a_parser() {
        let definitions = definitions();
        for tool in definitions.as_array().expect("array") {
            let name = tool["name"].as_str().expect("name");
            let error = parse(name, json!({})).err().unwrap_or_default();
            assert!(!error.starts_with("unknown tool"), "{name}");
            assert_eq!(tool["inputSchema"]["type"], "object", "{name}");
        }
        assert!(parse("rm_rf", json!({})).is_err());
    }

    #[test]
    fn arguments_get_defaults_and_bounds() {
        assert_eq!(
            parse(
                "run_command",
                json!({"command": "uptime", "timeout": 100000, "cwd": ""})
            ),
            Ok(Call::RunCommand {
                command: "uptime".into(),
                cwd: None,
                timeout: remote::MAX_TIMEOUT,
            })
        );
        assert_eq!(
            parse("read_file", json!({"path": "/etc/hosts", "offset": 0})),
            Ok(Call::ReadFile {
                path: "/etc/hosts".into(),
                offset: 1,
                limit: READ_LINES,
            })
        );
        assert_eq!(
            parse("list_directory", Value::Null),
            Ok(Call::ListDirectory { path: ".".into() })
        );
        assert!(parse("run_command", json!({"command": "  "})).is_err());
        assert!(parse("read_file", json!({"path": 5})).is_err());
        assert!(
            parse(
                "edit_file",
                json!({"path": "a", "old_text": "x", "new_text": "x"})
            )
            .is_err()
        );
    }

    #[test]
    fn only_changes_need_approval() {
        assert!(
            Action::Run {
                command: "ls".into(),
                cwd: None
            }
            .changes_server()
        );
        assert!(
            Action::Write {
                path: "a".into(),
                content: String::new()
            }
            .changes_server()
        );
        assert!(!Action::Read { path: "a".into() }.changes_server());
        assert!(!Action::Screen { rows: 1 }.changes_server());
    }

    #[test]
    fn command_answer_shows_exit_code_and_both_streams() {
        let output = ExecOutput {
            stdout: Clipped {
                head: b"hello\n".to_vec(),
                ..Default::default()
            },
            stderr: Clipped {
                head: b"warning\n".to_vec(),
                ..Default::default()
            },
            exit: Exit::Code(3),
        };
        assert_eq!(
            command_answer(&output, Duration::from_secs(60)),
            "exit code: 3\n--- stdout ---\nhello\n--- stderr ---\nwarning"
        );
        let silent = ExecOutput {
            stdout: Clipped::default(),
            stderr: Clipped::default(),
            exit: Exit::TimedOut,
        };
        assert!(command_answer(&silent, Duration::from_secs(5)).starts_with("timed out after 5 s"));
    }

    #[test]
    fn file_answer_pages_through_lines() {
        let data = b"a\nb\nc\nd\n";
        assert_eq!(file_answer("f", data, 1, 10).unwrap(), "a\nb\nc\nd\n");
        assert_eq!(
            file_answer("f", data, 2, 2).unwrap(),
            "b\nc\n[lines 2-3 of 4; read on with offset 4]"
        );
        assert_eq!(file_answer("f", data, 4, 9).unwrap(), "d\n[lines 4-4 of 4]");
        assert!(file_answer("f", data, 9, 1).is_err());
        assert!(file_answer("f", b"\x7fELF\0\0", 1, 1).is_err());
        assert_eq!(file_answer("f", b"", 1, 1).unwrap(), "(empty file)");
    }

    #[test]
    fn replace_needs_a_unique_match() {
        assert_eq!(replace("a b a", "b", "c", false), Ok(("a c a".into(), 1)));
        assert!(
            replace("a b a", "a", "c", false)
                .unwrap_err()
                .contains("2 times")
        );
        assert_eq!(replace("a b a", "a", "c", true), Ok(("c b c".into(), 2)));
        assert!(replace("a b a", "z", "c", false).is_err());
        assert_eq!(
            replace("x\r\ny\r\n", "x\ny", "x\nz", false),
            Ok(("x\r\nz\r\n".into(), 1))
        );
    }

    #[test]
    fn listing_marks_folders_and_links() {
        let entry = |name: &str, is_dir: bool, is_symlink: bool| crate::ssh::sftp::RemoteEntry {
            name: name.into(),
            path: format!("/srv/{name}"),
            is_dir,
            is_symlink,
            size: 42,
            modified: Some(std::time::SystemTime::UNIX_EPOCH),
        };
        let text = listing_answer(&Listing::Entries {
            path: "/srv".into(),
            entries: vec![
                entry("www", true, false),
                entry("app.log", false, false),
                entry("current", false, true),
            ],
        });
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "/srv");
        assert!(lines[1].starts_with("d ") && lines[1].ends_with("www/"));
        assert!(lines[2].contains(" 42  1970-01-01 00:00") && lines[2].ends_with("app.log"));
        assert!(lines[3].starts_with("l ") && lines[3].ends_with("current@"));
    }

    #[test]
    fn long_answers_are_cut_on_a_character_boundary() {
        let text = "я".repeat(MAX_ANSWER);
        let clipped = clip_answer(text);
        assert!(clipped.len() < MAX_ANSWER + 100);
        assert!(clipped.ends_with("more bytes not shown]"));
    }
}
