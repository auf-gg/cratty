//! ACP messages: what Cratty sends and how it reads what an agent reports. No I/O here.

use serde_json::{Value, json};

use super::McpServer;

pub const PROTOCOL_VERSION: u64 = 1;
/// ACP's error code for "sign in first".
pub const AUTH_REQUIRED: i64 = -32000;
pub const METHOD_NOT_FOUND: i64 = -32601;

/// One step of the conversation as the window shows it.
#[derive(Clone, Debug, PartialEq)]
pub enum Update {
    AgentText(String),
    Thought(String),
    UserText(String),
    ToolCall(ToolCall),
    ToolCallUpdate(ToolCallUpdate),
    Plan(Vec<PlanEntry>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct ToolCall {
    pub id: String,
    pub title: String,
    pub kind: String,
    pub status: String,
    /// What the tool returned, as text.
    pub output: Option<String>,
    /// The arguments: a command or a path reads better than the title.
    pub input: Option<Value>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ToolCallUpdate {
    pub id: String,
    pub title: Option<String>,
    pub status: Option<String>,
    pub output: Option<String>,
    pub input: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanEntry {
    pub content: String,
    /// `pending`, `in_progress` or `completed`.
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermissionOption {
    pub id: String,
    pub name: String,
    /// `allow_once`, `allow_always`, `reject_once` or `reject_always`.
    pub kind: String,
}

impl PermissionOption {
    pub fn allows(&self) -> bool {
        self.kind.starts_with("allow")
    }
}

/// A way to sign in: the agent started with these extra arguments, in a terminal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoginMethod {
    pub name: String,
    pub description: Option<String>,
    pub args: Vec<String>,
}

/// What the agent can do beyond the baseline.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AgentCaps {
    /// `session/load`: a saved session comes back with its conversation.
    pub load: bool,
    /// `session/delete`.
    pub delete: bool,
}

/// The agent asks whether a tool call of its own may run.
#[derive(Clone, Debug, PartialEq)]
pub struct PermissionAsk {
    pub title: String,
    pub detail: Option<String>,
    pub options: Vec<PermissionOption>,
}

pub fn initialize() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        // No file system and no terminal: the agent works on the server through
        // Cratty's MCP tools, never on this computer through the client.
        // Sign-in runs the agent in a terminal: Cratty opens a local terminal tab for it.
        "clientCapabilities": {
            "fs": { "readTextFile": false, "writeTextFile": false },
            "terminal": false,
            "auth": { "terminal": true },
        },
        "clientInfo": {
            "name": "cratty",
            "title": "Cratty",
            "version": env!("CARGO_PKG_VERSION"),
        },
    })
}

pub fn agent_caps(initialize: &Value) -> AgentCaps {
    let caps = initialize.get("agentCapabilities");
    AgentCaps {
        load: caps
            .and_then(|caps| caps.get("loadSession"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        delete: caps
            .and_then(|caps| caps.get("sessionCapabilities"))
            .and_then(|caps| caps.get("delete"))
            .is_some_and(|delete| !delete.is_null()),
    }
}

/// The terminal sign-in methods the agent offers in its `initialize` answer.
pub fn login_methods(initialize: &Value) -> Vec<LoginMethod> {
    initialize
        .get("authMethods")
        .and_then(Value::as_array)
        .map(|methods| {
            methods
                .iter()
                .filter(|method| method.get("type").and_then(Value::as_str) == Some("terminal"))
                .filter_map(|method| {
                    Some(LoginMethod {
                        name: string(method, "name")?,
                        description: string(method, "description"),
                        args: method
                            .get("args")
                            .and_then(Value::as_array)
                            .map(|args| {
                                args.iter()
                                    .filter_map(Value::as_str)
                                    .map(str::to_owned)
                                    .collect()
                            })
                            .unwrap_or_default(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `session/load` takes the same as `session/new`, plus the session; the agent asks for
/// its options again on load.
pub fn load_session(session: &str, cwd: &str, mcp: &McpServer) -> Value {
    let mut params = new_session(cwd, mcp);
    params["sessionId"] = json!(session);
    params
}

pub fn delete_session(session: &str) -> Value {
    json!({ "sessionId": session })
}

pub fn new_session(cwd: &str, mcp: &McpServer) -> Value {
    let env: Vec<Value> = mcp
        .env
        .iter()
        .map(|(name, value)| json!({ "name": name, "value": value }))
        .collect();
    json!({
        "cwd": cwd,
        "mcpServers": [{
            "name": mcp.name,
            "command": mcp.command,
            "args": mcp.args,
            "env": env,
        }],
        // Claude Code (through claude-agent-acp): none of the built-in tools, which
        // would act on this computer; only the MCP servers given here; Cratty's
        // tools without a second question, since Cratty asks the user itself.
        // Other agents ignore it.
        "_meta": {
            "claudeCode": {
                "options": {
                    "tools": [],
                    "allowedTools": [format!("mcp__{}", mcp.name)],
                    "extraArgs": { "strict-mcp-config": null },
                }
            }
        }
    })
}

pub fn prompt(session: &str, text: &str) -> Value {
    json!({ "sessionId": session, "prompt": [{ "type": "text", "text": text }] })
}

pub fn cancel(session: &str) -> Value {
    json!({ "sessionId": session })
}

/// The answer to `session/request_permission`: an option, or `None` for a cancelled turn.
pub fn permission_outcome(option: Option<&str>) -> Value {
    match option {
        Some(option) => json!({ "outcome": { "outcome": "selected", "optionId": option } }),
        None => json!({ "outcome": { "outcome": "cancelled" } }),
    }
}

/// Reads `session/update`; `None` for updates the window does not show.
pub fn update(params: &Value) -> Option<Update> {
    let update = params.get("update")?;
    let text = || content_text(update.get("content")?);
    Some(match update.get("sessionUpdate")?.as_str()? {
        "agent_message_chunk" => Update::AgentText(text()?),
        "agent_thought_chunk" => Update::Thought(text()?),
        "user_message_chunk" => Update::UserText(text()?),
        "tool_call" => Update::ToolCall(ToolCall {
            id: string(update, "toolCallId")?,
            title: string(update, "title").unwrap_or_default(),
            kind: string(update, "kind").unwrap_or_else(|| "other".into()),
            status: string(update, "status").unwrap_or_else(|| "pending".into()),
            output: tool_output(update),
            input: present(update, "rawInput"),
        }),
        "tool_call_update" => Update::ToolCallUpdate(ToolCallUpdate {
            id: string(update, "toolCallId")?,
            title: string(update, "title"),
            status: string(update, "status"),
            output: tool_output(update),
            input: present(update, "rawInput"),
        }),
        "plan" => Update::Plan(
            update
                .get("entries")?
                .as_array()?
                .iter()
                .filter_map(|entry| {
                    Some(PlanEntry {
                        content: string(entry, "content")?,
                        status: string(entry, "status").unwrap_or_else(|| "pending".into()),
                    })
                })
                .collect(),
        ),
        _ => return None,
    })
}

pub fn permission_ask(params: &Value) -> PermissionAsk {
    let call = params.get("toolCall").cloned().unwrap_or(Value::Null);
    let options = params
        .get("options")
        .and_then(Value::as_array)
        .map(|options| {
            options
                .iter()
                .filter_map(|option| {
                    Some(PermissionOption {
                        id: string(option, "optionId")?,
                        name: string(option, "name").unwrap_or_default(),
                        kind: string(option, "kind").unwrap_or_default(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    PermissionAsk {
        title: string(&call, "title")
            .unwrap_or_else(|| string(&call, "toolCallId").unwrap_or_default()),
        detail: present(&call, "rawInput")
            .map(|input| input_summary(&input))
            .or_else(|| tool_output(&call)),
        options,
    }
}

/// A command or a path from tool arguments, else the arguments as JSON.
pub fn input_summary(input: &Value) -> String {
    for key in ["command", "path", "file_path", "url", "query", "pattern"] {
        if let Some(text) = input.get(key).and_then(Value::as_str) {
            return text.to_owned();
        }
    }
    input.to_string()
}

fn string(value: &Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(str::to_owned)
}

fn present(value: &Value, key: &str) -> Option<Value> {
    value.get(key).filter(|value| !value.is_null()).cloned()
}

/// Text of a content block: text as is, other kinds as a short note.
fn content_text(block: &Value) -> Option<String> {
    match block.get("type")?.as_str()? {
        "text" => string(block, "text"),
        "resource_link" => Some(format!("[{}]", string(block, "uri").unwrap_or_default())),
        "resource" => block
            .get("resource")
            .and_then(|resource| string(resource, "text").or_else(|| string(resource, "uri"))),
        "image" => Some("[image]".into()),
        _ => None,
    }
}

fn tool_output(update: &Value) -> Option<String> {
    let parts: Vec<String> = update
        .get("content")?
        .as_array()?
        .iter()
        .filter_map(|item| match item.get("type")?.as_str()? {
            "content" => content_text(item.get("content")?),
            "diff" => Some(format!(
                "{}\n--- before\n{}\n+++ after\n{}",
                string(item, "path").unwrap_or_default(),
                string(item, "oldText").unwrap_or_default(),
                string(item, "newText").unwrap_or_default()
            )),
            _ => None,
        })
        .collect();
    (!parts.is_empty()).then(|| parts.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update_of(value: Value) -> Option<Update> {
        update(&json!({ "sessionId": "s", "update": value }))
    }

    #[test]
    fn message_chunks_become_text() {
        assert_eq!(
            update_of(
                json!({"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "Hi"}})
            ),
            Some(Update::AgentText("Hi".into()))
        );
        assert_eq!(
            update_of(
                json!({"sessionUpdate": "agent_thought_chunk", "content": {"type": "text", "text": "hm"}})
            ),
            Some(Update::Thought("hm".into()))
        );
        assert_eq!(
            update_of(json!({"sessionUpdate": "usage_update", "used": 1, "size": 2})),
            None
        );
    }

    #[test]
    fn tool_calls_carry_their_input_and_output() {
        let Some(Update::ToolCall(call)) = update_of(json!({
            "sessionUpdate": "tool_call",
            "toolCallId": "c1",
            "title": "mcp__cratty__run_command",
            "kind": "execute",
            "rawInput": {"command": "df -h"},
        })) else {
            panic!("not a tool call");
        };
        assert_eq!(call.status, "pending");
        assert_eq!(input_summary(call.input.as_ref().unwrap()), "df -h");

        let Some(Update::ToolCallUpdate(done)) = update_of(json!({
            "sessionUpdate": "tool_call_update",
            "toolCallId": "c1",
            "status": "completed",
            "content": [{"type": "content", "content": {"type": "text", "text": "exit code: 0"}}],
        })) else {
            panic!("not an update");
        };
        assert_eq!(done.status.as_deref(), Some("completed"));
        assert_eq!(done.output.as_deref(), Some("exit code: 0"));
        assert_eq!(done.title, None);
    }

    #[test]
    fn plan_lists_its_entries() {
        assert_eq!(
            update_of(json!({"sessionUpdate": "plan", "entries": [
                {"content": "Check disk", "priority": "high", "status": "completed"},
                {"content": "Clean logs", "priority": "low", "status": "pending"},
            ]})),
            Some(Update::Plan(vec![
                PlanEntry {
                    content: "Check disk".into(),
                    status: "completed".into()
                },
                PlanEntry {
                    content: "Clean logs".into(),
                    status: "pending".into()
                },
            ]))
        );
    }

    #[test]
    fn session_asks_for_cratty_tools_only() {
        let mcp = McpServer {
            name: "cratty".into(),
            command: "/usr/bin/cratty".into(),
            args: vec!["--mcp-bridge".into()],
            env: vec![("CRATTY_MCP_TOKEN".into(), "t".into())],
        };
        let params = new_session("/tmp/w", &mcp);
        assert_eq!(
            params["mcpServers"][0]["env"][0],
            json!({"name": "CRATTY_MCP_TOKEN", "value": "t"})
        );
        let options = &params["_meta"]["claudeCode"]["options"];
        assert_eq!(options["tools"], json!([]));
        assert_eq!(options["allowedTools"], json!(["mcp__cratty"]));
        assert_eq!(initialize()["clientCapabilities"]["terminal"], false);
        assert_eq!(initialize()["clientCapabilities"]["auth"]["terminal"], true);

        let load = load_session("ses_1", "/tmp/w", &mcp);
        assert_eq!(load["sessionId"], "ses_1");
        assert_eq!(load["_meta"], params["_meta"]);
    }

    #[test]
    fn capabilities_and_sign_in_methods_are_read() {
        let answer = json!({
            "protocolVersion": 1,
            "agentCapabilities": {"loadSession": true, "sessionCapabilities": {"delete": {}, "close": {}}},
            "authMethods": [
                {"id": "claude-ai-login", "name": "Claude Subscription", "type": "terminal",
                 "args": ["--cli", "auth", "login", "--claudeai"], "description": "Use Claude subscription"},
                {"id": "agent", "name": "Agent login"},
            ],
        });
        assert_eq!(
            agent_caps(&answer),
            AgentCaps {
                load: true,
                delete: true
            }
        );
        assert_eq!(agent_caps(&json!({})), AgentCaps::default());
        assert_eq!(
            login_methods(&answer),
            vec![LoginMethod {
                name: "Claude Subscription".into(),
                description: Some("Use Claude subscription".into()),
                args: vec![
                    "--cli".into(),
                    "auth".into(),
                    "login".into(),
                    "--claudeai".into()
                ],
            }]
        );
    }

    #[test]
    fn permission_request_is_read_and_answered() {
        let ask = permission_ask(&json!({
            "sessionId": "s",
            "toolCall": {"toolCallId": "c2", "title": "Bash", "rawInput": {"command": "rm -rf /tmp/x"}},
            "options": [
                {"optionId": "once", "name": "Allow once", "kind": "allow_once"},
                {"optionId": "reject", "name": "Reject", "kind": "reject_once"},
            ],
        }));
        assert_eq!(ask.title, "Bash");
        assert_eq!(ask.detail.as_deref(), Some("rm -rf /tmp/x"));
        assert!(ask.options[0].allows() && !ask.options[1].allows());
        assert_eq!(
            permission_outcome(Some("once"))["outcome"]["optionId"],
            "once"
        );
        assert_eq!(permission_outcome(None)["outcome"]["outcome"], "cancelled");
    }
}
