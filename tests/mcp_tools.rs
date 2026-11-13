//! Tools for AI agents end to end: the MCP server, the window's decisions and the SSH
//! session underneath, against the test sshd. It has no SFTP, so files go through the
//! fallback with commands. Unix only: the test sshd runs commands with the local `sh`.
#![cfg(unix)]

mod fake_sshd;

use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cratty::mcp::{self, Action, Ask, Grant, SessionInfo};
use cratty::ssh::remote::{self, Exec, Exit, Listing, Remote};
use cratty::ssh::{AuthMethod, FromSsh, HostKeyPolicy, SshConfig, SshSession, spawn_ssh};
use futures::StreamExt;
use futures::channel::mpsc;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use fake_sshd::FakeSshd;

const DEADLINE: Duration = Duration::from_secs(20);
const TOKEN: &str = "test-token";

async fn connect(sshd: &FakeSshd) -> (SshSession, Remote) {
    let addr = sshd.addr();
    let mut config = SshConfig::new(
        addr.ip().to_string(),
        addr.port(),
        sshd.user(),
        AuthMethod::Password(sshd.password().into()),
    );
    config.host_key_policy = HostKeyPolicy::Fingerprints(vec![sshd.fingerprint()]);
    let mut session = spawn_ssh(config).expect("ssh thread");
    let mut events = std::mem::replace(&mut session.events, cratty::ssh::closed_events());
    match tokio::time::timeout(DEADLINE, events.next()).await {
        Ok(Some(FromSsh::Connected { .. })) => {}
        other => panic!("expected Connected, got {other:?}"),
    }
    // The terminal's output must be read, or the session stops serving requests.
    tokio::spawn(async move { while events.next().await.is_some() {} });
    let remote = Remote::new(session.commands.clone());
    (session, remote)
}

fn exec(script: &str) -> Exec {
    Exec {
        command: remote::sh_command(script, None),
        stdin: Vec::new(),
        timeout: Duration::from_secs(10),
        limit: 64 * 1024,
    }
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("cratty-mcp-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

#[tokio::test(flavor = "multi_thread")]
async fn command_gets_its_own_channel_with_streams_and_exit_code() {
    let sshd = FakeSshd::start().await;
    let (_session, remote) = connect(&sshd).await;

    let output = remote
        .exec(exec("echo out; echo err >&2; exit 3"))
        .await
        .expect("exec");
    assert_eq!(output.stdout.text(), "out\n");
    assert_eq!(output.stderr.text(), "err\n");
    assert_eq!(output.exit, Exit::Code(3));

    let mut upper = exec("tr a-z A-Z");
    upper.stdin = b"hello".to_vec();
    let output = remote.exec(upper).await.expect("exec with input");
    assert_eq!(output.stdout.text(), "HELLO");

    let dir = temp_dir("cwd");
    let mut pwd = exec("pwd");
    pwd.command = remote::sh_command("pwd", Some(dir.to_str().unwrap()));
    let output = remote.exec(pwd).await.expect("exec in a folder");
    assert_eq!(
        std::fs::canonicalize(output.stdout.text().trim()).unwrap(),
        std::fs::canonicalize(&dir).unwrap()
    );

    // Pagers and colors are off for tools.
    let output = remote
        .exec(exec("echo \"$PAGER:$TERM\""))
        .await
        .expect("env");
    assert_eq!(output.stdout.text(), "cat:dumb\n");
    assert!(
        sshd.execs()
            .iter()
            .all(|command| command.starts_with("sh -c '"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn command_over_its_time_is_stopped() {
    let sshd = FakeSshd::start().await;
    let (_session, remote) = connect(&sshd).await;

    let mut slow = exec("sleep 30");
    slow.timeout = Duration::from_secs(1);
    let started = Instant::now();
    let output = remote.exec(slow).await.expect("exec");
    assert_eq!(output.exit, Exit::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[tokio::test(flavor = "multi_thread")]
async fn files_go_through_commands_when_there_is_no_sftp() {
    let sshd = FakeSshd::start().await;
    let (_session, remote) = connect(&sshd).await;
    let dir = temp_dir("files");
    let file = dir.join("it's notes.txt");
    let path = file.to_str().unwrap();

    remote
        .write(path, b"first\nsecond\n".to_vec())
        .await
        .expect("write");
    assert_eq!(std::fs::read(&file).unwrap(), b"first\nsecond\n");
    assert_eq!(remote.read(path).await.expect("read"), b"first\nsecond\n");

    match remote.list(dir.to_str().unwrap()).await.expect("list") {
        Listing::Text(text) => assert!(text.contains("it's notes.txt"), "{text}"),
        other => panic!("expected ls output, got {other:?}"),
    }

    let missing = remote.read(&format!("{}/nope", dir.display())).await;
    assert!(missing.is_err());
    let folder = remote.read(dir.to_str().unwrap()).await.unwrap_err();
    assert!(folder.contains("folder"), "{folder}");
}

/// Stands in for the window: knows one token, records what was asked and answers.
fn window(
    remote: Remote,
    deny_changes: bool,
) -> (mpsc::UnboundedSender<Ask>, Arc<Mutex<Vec<String>>>) {
    let (asks, mut incoming) = mpsc::unbounded::<Ask>();
    let log = Arc::new(Mutex::new(Vec::new()));
    let seen = log.clone();
    tokio::spawn(async move {
        let mut parked = Vec::new();
        while let Some(ask) = incoming.next().await {
            match ask {
                Ask::Hello { token, reply } => {
                    let _ = reply.send((token == TOKEN).then(|| SessionInfo {
                        title: "prod".into(),
                        target: "tester@prod".into(),
                    }));
                }
                Ask::Call(call) => {
                    seen.lock().unwrap().push(format!("{:?}", call.action));
                    let reply = match &call.action {
                        Action::Run { command, .. } if command == "wait for me" => {
                            // Never answered: the agent cancels it.
                            parked.push(call);
                            continue;
                        }
                        action if deny_changes && action.changes_server() => {
                            Err("the user denied this in Cratty".to_owned())
                        }
                        Action::Screen { .. } => Ok(Grant::Screen("$ uptime\n up 3 days".into())),
                        _ => Ok(Grant::Remote(remote.clone())),
                    };
                    let _ = call.reply.send(reply);
                }
                Ask::Withdraw { id } => seen.lock().unwrap().push(format!("withdraw {id}")),
            }
        }
    });
    (asks, log)
}

struct Client<S> {
    reader: BufReader<tokio::io::ReadHalf<S>>,
    writer: tokio::io::WriteHalf<S>,
    next_id: u64,
}

impl<S: AsyncRead + AsyncWrite> Client<S> {
    fn new(stream: S) -> Self {
        let (read, writer) = tokio::io::split(stream);
        Self {
            reader: BufReader::new(read),
            writer,
            next_id: 1,
        }
    }

    async fn send(&mut self, message: Value) {
        let mut line = serde_json::to_vec(&message).unwrap();
        line.push(b'\n');
        self.writer.write_all(&line).await.unwrap();
        self.writer.flush().await.unwrap();
    }

    async fn receive(&mut self) -> Value {
        let mut line = String::new();
        tokio::time::timeout(DEADLINE, self.reader.read_line(&mut line))
            .await
            .expect("no answer in time")
            .unwrap();
        serde_json::from_str(&line).unwrap_or_else(|_| panic!("not JSON: {line:?}"))
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await;
        loop {
            let message = self.receive().await;
            if message["id"] == json!(id) {
                return message;
            }
        }
    }

    async fn tool(&mut self, name: &str, arguments: Value) -> (String, bool) {
        let reply = self
            .request("tools/call", json!({"name": name, "arguments": arguments}))
            .await;
        let result = &reply["result"];
        (
            result["content"][0]["text"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            result["isError"].as_bool().unwrap_or(false),
        )
    }

    async fn hello(&mut self, token: &str) -> Value {
        self.send(json!({"token": token})).await;
        self.receive().await
    }
}

fn serve(asks: mpsc::UnboundedSender<Ask>) -> Client<tokio::io::DuplexStream> {
    let (client, server) = tokio::io::duplex(1024 * 1024);
    tokio::spawn(mcp::serve_connection(
        server,
        asks,
        Arc::new(AtomicU64::new(1)),
    ));
    Client::new(client)
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_works_on_the_server_through_mcp() {
    let sshd = FakeSshd::start().await;
    let (_session, remote) = connect(&sshd).await;
    let (asks, log) = window(remote, false);
    let mut client = serve(asks);

    assert_eq!(client.hello(TOKEN).await, json!({"ok": true}));
    let init = client
        .request("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}))
        .await;
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert!(
        init["result"]["instructions"]
            .as_str()
            .unwrap()
            .contains("tester@prod")
    );
    client
        .send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;

    let tools = client.request("tools/list", json!({})).await;
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "run_command",
            "read_file",
            "list_directory",
            "write_file",
            "edit_file",
            "read_terminal"
        ]
    );

    let (text, error) = client
        .tool("run_command", json!({"command": "echo hi; exit 2"}))
        .await;
    assert!(!error);
    assert_eq!(text, "exit code: 2\n--- stdout ---\nhi");

    let dir = temp_dir("agent");
    let path = dir.join("app.conf");
    let path_text = path.to_str().unwrap();
    let (text, error) = client
        .tool(
            "write_file",
            json!({"path": path_text, "content": "port = 80\nhost = a\n"}),
        )
        .await;
    assert!(!error, "{text}");

    let (text, error) = client
        .tool(
            "edit_file",
            json!({"path": path_text, "old_text": "port = 80", "new_text": "port = 8080"}),
        )
        .await;
    assert!(!error, "{text}");
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "port = 8080\nhost = a\n"
    );

    let (text, error) = client
        .tool(
            "edit_file",
            json!({"path": path_text, "old_text": "missing", "new_text": "x"}),
        )
        .await;
    assert!(error && text.contains("not found"), "{text}");

    let (text, error) = client
        .tool("read_file", json!({"path": path_text, "offset": 2}))
        .await;
    assert!(!error);
    assert_eq!(text, "host = a\n[lines 2-2 of 2]");

    let (text, error) = client
        .tool("list_directory", json!({"path": dir.to_str().unwrap()}))
        .await;
    assert!(!error && text.contains("app.conf"), "{text}");

    let (text, _) = client.tool("read_terminal", json!({"rows": 5})).await;
    assert_eq!(text, "$ uptime\n up 3 days");

    let (text, error) = client.tool("format_disk", json!({})).await;
    assert!(error && text.contains("unknown tool"));

    let actions = log.lock().unwrap().clone();
    assert!(actions[0].starts_with("Run {"), "{actions:?}");
    assert!(actions.iter().any(|action| action.starts_with("Edit {")));
    assert!(actions.iter().any(|action| action.starts_with("Screen {")));
}

#[tokio::test(flavor = "multi_thread")]
async fn denied_change_is_a_tool_error_and_runs_nothing() {
    let sshd = FakeSshd::start().await;
    let (_session, remote) = connect(&sshd).await;
    let (asks, _log) = window(remote, true);
    let mut client = serve(asks);
    client.hello(TOKEN).await;

    let (text, error) = client
        .tool("run_command", json!({"command": "touch /tmp/never"}))
        .await;
    assert!(error);
    assert!(text.contains("denied"));
    assert!(sshd.execs().is_empty(), "nothing may reach the server");
}

#[tokio::test]
async fn unknown_token_is_turned_away() {
    let (asks, _log) = window(Remote::new(mpsc::unbounded().0), false);
    let mut client = serve(asks);
    let answer = client.hello("guess").await;
    assert!(
        answer["error"]
            .as_str()
            .unwrap()
            .contains("no agent access")
    );
}

#[tokio::test]
async fn cancelled_call_is_taken_back_from_the_window() {
    let (asks, log) = window(Remote::new(mpsc::unbounded().0), false);
    let mut client = serve(asks);
    client.hello(TOKEN).await;

    client
        .send(json!({"jsonrpc": "2.0", "id": 41, "method": "tools/call", "params": {"name": "run_command", "arguments": {"command": "wait for me"}}}))
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    client
        .send(json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 41}}))
        .await;

    let deadline = Instant::now() + DEADLINE;
    while !log
        .lock()
        .unwrap()
        .iter()
        .any(|entry| entry.starts_with("withdraw"))
    {
        assert!(
            Instant::now() < deadline,
            "the window never heard of the cancellation"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The real executable as an agent starts it: stdio on one side, the socket on the other.
#[tokio::test(flavor = "multi_thread")]
async fn bridge_passes_messages_between_agent_and_app() {
    let dir = temp_dir("bridge");
    let address = cratty::agent::Address::Socket(dir.join("mcp.sock"));
    let listener = cratty::agent::Listener::bind(&address).await.expect("bind");
    let (asks, _log) = window(Remote::new(mpsc::unbounded().0), false);
    tokio::spawn(async move {
        while let Ok(stream) = listener.accept().await {
            tokio::spawn(mcp::serve_connection(
                stream,
                asks.clone(),
                Arc::new(AtomicU64::new(1)),
            ));
        }
    });

    let mut bridge = tokio::process::Command::new(env!("CARGO_BIN_EXE_cratty"))
        .arg(mcp::bridge::FLAG)
        .env(mcp::bridge::TOKEN_VAR, TOKEN)
        .env(mcp::bridge::ADDRESS_VAR, address.as_text())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("start the bridge");
    let stdin = bridge.stdin.take().unwrap();
    let stdout = bridge.stdout.take().unwrap();
    let mut client = Client::new(tokio::io::join(stdout, stdin));

    let ping = client.request("ping", json!({})).await;
    assert_eq!(ping["result"], json!({}));
    let init = client
        .request("initialize", json!({"protocolVersion": "2025-03-26"}))
        .await;
    assert_eq!(init["result"]["serverInfo"]["name"], "cratty");

    drop(client);
    let status = tokio::time::timeout(DEADLINE, bridge.wait())
        .await
        .expect("the bridge must exit when the agent closes its input")
        .unwrap();
    assert!(status.success());
}

#[tokio::test(flavor = "multi_thread")]
async fn bridge_explains_a_refused_token() {
    let dir = temp_dir("refused");
    let address = cratty::agent::Address::Socket(dir.join("mcp.sock"));
    let listener = cratty::agent::Listener::bind(&address).await.expect("bind");
    let (asks, _log) = window(Remote::new(mpsc::unbounded().0), false);
    tokio::spawn(async move {
        while let Ok(stream) = listener.accept().await {
            tokio::spawn(mcp::serve_connection(
                stream,
                asks.clone(),
                Arc::new(AtomicU64::new(1)),
            ));
        }
    });

    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_cratty"))
        .arg(mcp::bridge::FLAG)
        .env(mcp::bridge::TOKEN_VAR, "stale")
        .env(mcp::bridge::ADDRESS_VAR, address.as_text())
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .expect("run the bridge");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no agent access"));
}
