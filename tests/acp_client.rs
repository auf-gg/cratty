//! The ACP client against a scripted agent over in-memory streams.

use std::time::Duration;

use cratty::acp::{self, FromAgent, McpServer, Setup, ToAgent, Update};
use futures::StreamExt;
use futures::channel::mpsc;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, ReadHalf, WriteHalf};

const DEADLINE: Duration = Duration::from_secs(10);

fn setup() -> Setup {
    setup_resuming(None)
}

fn setup_resuming(resume: Option<&str>) -> Setup {
    Setup {
        resume: resume.map(str::to_owned),
        cwd: "/tmp/cratty-agent".into(),
        mcp: McpServer {
            name: "cratty".into(),
            command: "/usr/bin/cratty".into(),
            args: vec!["--mcp-bridge".into()],
            env: vec![("CRATTY_MCP_TOKEN".into(), "secret".into())],
        },
        login: "opencode auth login".into(),
    }
}

/// The agent's side of the streams.
struct Agent {
    reader: BufReader<ReadHalf<DuplexStream>>,
    writer: WriteHalf<DuplexStream>,
}

impl Agent {
    async fn receive(&mut self) -> Value {
        let mut line = String::new();
        tokio::time::timeout(DEADLINE, self.reader.read_line(&mut line))
            .await
            .expect("the client sent nothing")
            .unwrap();
        serde_json::from_str(&line).unwrap_or_else(|_| panic!("not JSON: {line:?}"))
    }

    async fn send(&mut self, message: Value) {
        let mut line = serde_json::to_vec(&message).unwrap();
        line.push(b'\n');
        self.writer.write_all(&line).await.unwrap();
    }

    async fn answer(&mut self, request: &Value, result: Value) {
        self.send(json!({"jsonrpc": "2.0", "id": request["id"], "result": result}))
            .await;
    }

    async fn update(&mut self, update: Value) {
        self.send(json!({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": "s1", "update": update}}))
            .await;
    }

    /// Initialize and session/new, checking what the client asks for.
    async fn start(&mut self) {
        let init = self.receive().await;
        assert_eq!(init["method"], "initialize");
        assert_eq!(init["params"]["clientCapabilities"]["terminal"], false);
        self.answer(&init, json!({"protocolVersion": 1, "agentInfo": {"name": "fake", "title": "Fake Agent", "version": "1.0"}}))
            .await;

        let new = self.receive().await;
        assert_eq!(new["method"], "session/new");
        assert_eq!(new["params"]["cwd"], "/tmp/cratty-agent");
        assert_eq!(new["params"]["mcpServers"][0]["name"], "cratty");
        assert_eq!(
            new["params"]["_meta"]["claudeCode"]["options"]["tools"],
            json!([])
        );
        self.answer(&new, json!({"sessionId": "s1"})).await;
    }
}

fn ready(session: &str, resumed: bool) -> FromAgent {
    FromAgent::Ready {
        agent: "Fake Agent 1.0".into(),
        session: session.into(),
        resumed,
    }
}

struct Client {
    commands: mpsc::UnboundedSender<ToAgent>,
    events: mpsc::Receiver<FromAgent>,
    done: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Client {
    async fn next(&mut self) -> FromAgent {
        tokio::time::timeout(DEADLINE, self.events.next())
            .await
            .expect("no event in time")
            .expect("events closed")
    }
}

fn connect() -> (Client, Agent) {
    connect_with(setup())
}

fn connect_with(setup: Setup) -> (Client, Agent) {
    let (client_side, agent_side) = tokio::io::duplex(64 * 1024);
    let (client_read, client_write) = tokio::io::split(client_side);
    let (agent_read, agent_write) = tokio::io::split(agent_side);
    let (commands, commands_rx) = mpsc::unbounded();
    let (events_tx, events) = mpsc::channel(64);
    let done = tokio::spawn(async move {
        acp::run(client_read, client_write, &setup, commands_rx, events_tx).await
    });
    (
        Client {
            commands,
            events,
            done,
        },
        Agent {
            reader: BufReader::new(agent_read),
            writer: agent_write,
        },
    )
}

#[tokio::test]
async fn prompt_turn_streams_text_tools_and_permission() {
    let (mut client, mut agent) = connect();
    agent.start().await;
    assert_eq!(client.next().await, ready("s1", false));

    client
        .commands
        .unbounded_send(ToAgent::Prompt("check the disk".into()))
        .unwrap();
    let prompt = agent.receive().await;
    assert_eq!(prompt["method"], "session/prompt");
    assert_eq!(prompt["params"]["prompt"][0]["text"], "check the disk");

    agent
        .update(json!({"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "Checking"}}))
        .await;
    agent
        .update(json!({"sessionUpdate": "tool_call", "toolCallId": "t1", "title": "mcp__cratty__run_command", "kind": "execute", "rawInput": {"command": "df -h"}}))
        .await;
    agent
        .send(json!({"jsonrpc": "2.0", "id": "perm-1", "method": "session/request_permission", "params": {
            "sessionId": "s1",
            "toolCall": {"toolCallId": "t1", "title": "Run df", "rawInput": {"command": "df -h"}},
            "options": [{"optionId": "yes", "name": "Allow", "kind": "allow_once"}, {"optionId": "no", "name": "Reject", "kind": "reject_once"}],
        }}))
        .await;

    assert_eq!(
        client.next().await,
        FromAgent::Update(Update::AgentText("Checking".into()))
    );
    let FromAgent::Update(Update::ToolCall(call)) = client.next().await else {
        panic!("expected a tool call");
    };
    assert_eq!(call.id, "t1");
    let FromAgent::Permission { request, ask } = client.next().await else {
        panic!("expected a permission request");
    };
    assert_eq!(ask.detail.as_deref(), Some("df -h"));

    client
        .commands
        .unbounded_send(ToAgent::Permission {
            request,
            option: Some("yes".into()),
        })
        .unwrap();
    let answer = agent.receive().await;
    assert_eq!(answer["id"], "perm-1");
    assert_eq!(answer["result"]["outcome"]["optionId"], "yes");

    agent
        .update(
            json!({"sessionUpdate": "tool_call_update", "toolCallId": "t1", "status": "completed",
            "content": [{"type": "content", "content": {"type": "text", "text": "exit code: 0"}}]}),
        )
        .await;
    agent
        .answer(&prompt, json!({"stopReason": "end_turn"}))
        .await;

    let FromAgent::Update(Update::ToolCallUpdate(update)) = client.next().await else {
        panic!("expected a tool call update");
    };
    assert_eq!(update.output.as_deref(), Some("exit code: 0"));
    assert_eq!(
        client.next().await,
        FromAgent::TurnEnded {
            stop_reason: "end_turn".into()
        }
    );

    // Closing the session ends the client cleanly.
    drop(client.commands);
    assert!(client.done.await.unwrap().is_ok());
}

#[tokio::test]
async fn cancel_tells_the_agent_and_answers_open_permissions() {
    let (mut client, mut agent) = connect();
    agent.start().await;
    client.next().await;

    client
        .commands
        .unbounded_send(ToAgent::Prompt("long job".into()))
        .unwrap();
    let prompt = agent.receive().await;
    agent
        .send(json!({"jsonrpc": "2.0", "id": 9, "method": "session/request_permission", "params": {
            "sessionId": "s1", "toolCall": {"toolCallId": "t2"}, "options": [{"optionId": "a", "name": "Allow", "kind": "allow_once"}]}}))
        .await;
    assert!(matches!(client.next().await, FromAgent::Permission { .. }));

    client.commands.unbounded_send(ToAgent::Cancel).unwrap();
    let first = agent.receive().await;
    let second = agent.receive().await;
    let (cancel, permission) = if first["method"] == "session/cancel" {
        (first, second)
    } else {
        (second, first)
    };
    assert_eq!(cancel["params"]["sessionId"], "s1");
    assert_eq!(permission["id"], 9);
    assert_eq!(permission["result"]["outcome"]["outcome"], "cancelled");

    agent
        .answer(&prompt, json!({"stopReason": "cancelled"}))
        .await;
    assert_eq!(
        client.next().await,
        FromAgent::TurnEnded {
            stop_reason: "cancelled".into()
        }
    );
}

#[tokio::test]
async fn sign_in_error_names_the_login_command() {
    let (client, mut agent) = connect();
    let init = agent.receive().await;
    agent.answer(&init, json!({"protocolVersion": 1})).await;
    let new = agent.receive().await;
    agent
        .send(json!({"jsonrpc": "2.0", "id": new["id"], "error": {"code": -32000, "message": "Authentication required"}}))
        .await;

    let error = client.done.await.unwrap().unwrap_err().to_string();
    assert!(error.contains("opencode auth login"), "{error}");
}

#[tokio::test]
async fn file_system_requests_are_refused() {
    let (mut client, mut agent) = connect();
    agent.start().await;
    client.next().await;

    agent
        .send(json!({"jsonrpc": "2.0", "id": 77, "method": "fs/read_text_file", "params": {"sessionId": "s1", "path": "/etc/passwd"}}))
        .await;
    let answer = agent.receive().await;
    assert_eq!(answer["id"], 77);
    assert_eq!(answer["error"]["code"], -32601);
}

#[tokio::test]
async fn other_protocol_version_is_refused() {
    let (client, mut agent) = connect();
    let init = agent.receive().await;
    agent.answer(&init, json!({"protocolVersion": 2})).await;
    let error = client.done.await.unwrap().unwrap_err().to_string();
    assert!(error.contains("ACP version"), "{error}");
}

#[tokio::test]
async fn agent_exit_is_an_error() {
    let (client, agent) = connect();
    drop(agent);
    let error = client.done.await.unwrap().unwrap_err().to_string();
    assert!(error.contains("exited"), "{error}");
}

const INIT_LOADING: &str = r#"{"protocolVersion": 1, "agentInfo": {"title": "Fake Agent", "name": "fake", "version": "1.0"},
    "agentCapabilities": {"loadSession": true, "sessionCapabilities": {"delete": {}}},
    "authMethods": [{"id": "login", "name": "Claude Subscription", "type": "terminal", "args": ["--cli", "auth", "login"]}]}"#;

#[tokio::test]
async fn saved_session_comes_back_with_its_conversation() {
    let (mut client, mut agent) = connect_with(setup_resuming(Some("old-1")));
    let init = agent.receive().await;
    agent
        .answer(&init, serde_json::from_str(INIT_LOADING).unwrap())
        .await;

    let load = agent.receive().await;
    assert_eq!(load["method"], "session/load");
    assert_eq!(load["params"]["sessionId"], "old-1");
    assert_eq!(load["params"]["mcpServers"][0]["name"], "cratty");
    assert_eq!(
        load["params"]["_meta"]["claudeCode"]["options"]["tools"],
        json!([])
    );
    agent
        .send(json!({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": "old-1", "update":
            {"sessionUpdate": "user_message_chunk", "content": {"type": "text", "text": "disk?"}}}}))
        .await;
    agent
        .send(json!({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": "old-1", "update":
            {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "42% used"}}}}))
        .await;
    agent.answer(&load, json!({})).await;

    assert_eq!(
        client.next().await,
        FromAgent::Update(Update::UserText {
            text: "disk?".into(),
            message: None
        })
    );
    assert_eq!(
        client.next().await,
        FromAgent::Update(Update::AgentText("42% used".into()))
    );
    assert_eq!(client.next().await, ready("old-1", true));

    // Prompts go to the loaded session.
    client
        .commands
        .unbounded_send(ToAgent::Prompt("and now?".into()))
        .unwrap();
    let prompt = agent.receive().await;
    assert_eq!(prompt["params"]["sessionId"], "old-1");
}

#[tokio::test]
async fn lost_session_gives_way_to_a_new_one() {
    let (mut client, mut agent) = connect_with(setup_resuming(Some("gone")));
    let init = agent.receive().await;
    agent
        .answer(&init, serde_json::from_str(INIT_LOADING).unwrap())
        .await;
    let load = agent.receive().await;
    agent
        .send(json!({"jsonrpc": "2.0", "id": load["id"], "error": {"code": -32002, "message": "Resource not found"}}))
        .await;
    let new = agent.receive().await;
    assert_eq!(new["method"], "session/new");
    agent.answer(&new, json!({"sessionId": "fresh"})).await;
    assert_eq!(client.next().await, ready("fresh", false));
}

#[tokio::test]
async fn agent_without_loading_starts_anew() {
    let (mut client, mut agent) = connect_with(setup_resuming(Some("old-1")));
    agent.start().await;
    assert_eq!(client.next().await, ready("s1", false));
}

#[tokio::test]
async fn chats_switch_inside_one_agent_process() {
    let (mut client, mut agent) = connect();
    let init = agent.receive().await;
    agent
        .answer(&init, serde_json::from_str(INIT_LOADING).unwrap())
        .await;
    let new = agent.receive().await;
    agent.answer(&new, json!({"sessionId": "first"})).await;
    assert_eq!(client.next().await, ready("first", false));

    // An older chat: loaded and replayed, no new process.
    client
        .commands
        .unbounded_send(ToAgent::Switch(Some("older".into())))
        .unwrap();
    let load = agent.receive().await;
    assert_eq!(load["method"], "session/load");
    assert_eq!(load["params"]["sessionId"], "older");
    agent
        .send(json!({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": "older", "update":
            {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "from before"}}}}))
        .await;
    agent.answer(&load, json!({})).await;
    assert_eq!(
        client.next().await,
        FromAgent::Update(Update::AgentText("from before".into()))
    );
    assert_eq!(client.next().await, ready("older", true));

    // A new chat, then the first one deleted.
    client
        .commands
        .unbounded_send(ToAgent::Switch(None))
        .unwrap();
    let second = agent.receive().await;
    assert_eq!(second["method"], "session/new");
    agent.answer(&second, json!({"sessionId": "second"})).await;
    assert_eq!(client.next().await, ready("second", false));

    client
        .commands
        .unbounded_send(ToAgent::Delete("first".into()))
        .unwrap();
    let delete = agent.receive().await;
    assert_eq!(delete["method"], "session/delete");
    assert_eq!(delete["params"]["sessionId"], "first");
}

#[tokio::test]
async fn prompts_wait_while_a_chat_switches() {
    let (mut client, mut agent) = connect();
    let init = agent.receive().await;
    agent
        .answer(&init, serde_json::from_str(INIT_LOADING).unwrap())
        .await;
    let new = agent.receive().await;
    agent.answer(&new, json!({"sessionId": "first"})).await;
    client.next().await;

    client
        .commands
        .unbounded_send(ToAgent::Switch(Some("older".into())))
        .unwrap();
    client
        .commands
        .unbounded_send(ToAgent::Prompt("too early".into()))
        .unwrap();
    let load = agent.receive().await;
    assert_eq!(load["method"], "session/load");
    assert_eq!(
        client.next().await,
        FromAgent::TurnFailed("the agent is busy".into())
    );
}

#[tokio::test]
async fn sign_in_is_offered_the_agent_s_way() {
    let (mut client, mut agent) = connect();
    let init = agent.receive().await;
    agent
        .answer(&init, serde_json::from_str(INIT_LOADING).unwrap())
        .await;
    let new = agent.receive().await;
    agent
        .send(json!({"jsonrpc": "2.0", "id": new["id"], "error": {"code": -32000, "message": "Authentication required"}}))
        .await;
    let FromAgent::LoginRequired(methods) = client.next().await else {
        panic!("expected a sign-in request");
    };
    assert_eq!(methods[0].name, "Claude Subscription");
    assert_eq!(methods[0].args, vec!["--cli", "auth", "login"]);
    assert!(client.done.await.unwrap().is_err());
}

#[tokio::test]
async fn settings_come_with_the_session_and_can_be_changed() {
    let (mut client, mut agent) = connect();
    let init = agent.receive().await;
    agent
        .answer(&init, serde_json::from_str(INIT_LOADING).unwrap())
        .await;
    let new = agent.receive().await;
    agent
        .answer(&new, json!({"sessionId": "s1", "configOptions": [
            {"id": "model", "name": "Model", "category": "model", "type": "select", "currentValue": "a",
             "options": [{"value": "a", "name": "A"}, {"value": "b", "name": "B"}]}]}))
        .await;
    assert_eq!(client.next().await, ready("s1", false));
    let FromAgent::Config(options) = client.next().await else {
        panic!("expected the settings");
    };
    assert_eq!(options[0].current, "a");

    client
        .commands
        .unbounded_send(ToAgent::SetConfig {
            id: "model".into(),
            value: "b".into(),
        })
        .unwrap();
    let set = agent.receive().await;
    assert_eq!(set["method"], "session/set_config_option");
    assert_eq!(set["params"]["sessionId"], "s1");
    assert_eq!(set["params"]["configId"], "model");
    assert_eq!(set["params"]["value"], "b");
    agent
        .answer(&set, json!({"configOptions": [
            {"id": "model", "name": "Model", "currentValue": "b", "options": [{"value": "a", "name": "A"}, {"value": "b", "name": "B"}]}]}))
        .await;
    let FromAgent::Config(options) = client.next().await else {
        panic!("expected the new settings");
    };
    assert_eq!(options[0].current, "b");

    // A refused change is told, and the session goes on.
    client
        .commands
        .unbounded_send(ToAgent::SetConfig {
            id: "model".into(),
            value: "zzz".into(),
        })
        .unwrap();
    let set = agent.receive().await;
    agent
        .send(json!({"jsonrpc": "2.0", "id": set["id"], "error": {"code": -32602, "message": "Invalid value"}}))
        .await;
    assert!(
        matches!(client.next().await, FromAgent::Notice(text) if text.contains("Invalid value"))
    );
}
