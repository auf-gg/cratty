//! JSON-RPC and MCP messages: the part of the protocol that needs no I/O.

use serde_json::{Value, json};

use super::SessionInfo;

/// MCP versions this server speaks, newest first. A client asking for another one gets
/// the newest and decides itself whether it can go on.
const VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;

#[derive(Debug, PartialEq)]
pub enum Incoming {
    Request {
        id: Value,
        method: String,
        params: Value,
    },
    Notification {
        method: String,
        params: Value,
    },
    /// An answer of the client: this server sends no requests, so there is nothing to do.
    Response,
    /// Not a message: the error to send back.
    Invalid(Value),
}

pub fn parse(line: &[u8]) -> Incoming {
    let value: Value = match serde_json::from_slice(line) {
        Ok(value) => value,
        Err(error) => {
            return Incoming::Invalid(error_reply(Value::Null, PARSE_ERROR, &error.to_string()));
        }
    };
    let Some(object) = value.as_object() else {
        return Incoming::Invalid(error_reply(
            Value::Null,
            INVALID_REQUEST,
            "expected one JSON-RPC message object",
        ));
    };
    let id = object.get("id").cloned();
    let params = object.get("params").cloned().unwrap_or(Value::Null);
    match (object.get("method").and_then(Value::as_str), id) {
        (Some(method), None) => Incoming::Notification {
            method: method.to_owned(),
            params,
        },
        (Some(method), Some(id)) if id.is_string() || id.is_number() => Incoming::Request {
            id,
            method: method.to_owned(),
            params,
        },
        (Some(_), Some(_)) => Incoming::Invalid(error_reply(
            Value::Null,
            INVALID_REQUEST,
            "the id must be a string or a number",
        )),
        (None, _) if object.contains_key("result") || object.contains_key("error") => {
            Incoming::Response
        }
        (None, id) => Incoming::Invalid(error_reply(
            id.unwrap_or(Value::Null),
            INVALID_REQUEST,
            "no method",
        )),
    }
}

pub fn result_reply(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

pub fn error_reply(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

pub fn initialize(params: &Value, info: &SessionInfo) -> Value {
    let version = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .filter(|asked| VERSIONS.contains(asked))
        .unwrap_or(VERSIONS[0]);
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": {
            "name": super::SERVER_NAME,
            "title": "Cratty",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "instructions": instructions(info),
    })
}

/// Read by the model before it picks tools: where they act and what to expect.
pub fn instructions(info: &SessionInfo) -> String {
    format!(
        "These tools act on the SSH server {target} (tab \"{title}\" in Cratty, an SSH client the \
         user has open), through the connection of that tab. They do not touch the computer the \
         agent runs on. Commands run on the server with /bin/sh and without a terminal, so \
         interactive programs and password prompts do not work: use sudo -n and non-interactive \
         flags. Paths are on the server; relative paths and ~ start at the user's home folder. \
         The user approves every command and file change in Cratty and may deny it: then do not \
         retry the same thing, ask the user. read_terminal shows what the user sees in the \
         terminal of that tab.",
        target = info.target,
        title = info.title,
    )
}

pub fn tool_result(outcome: Result<String, String>) -> Value {
    let (text, is_error) = match outcome {
        Ok(text) => (text, false),
        Err(text) => (text, true),
    };
    json!({ "content": [{ "type": "text", "text": text }], "isError": is_error })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> SessionInfo {
        SessionInfo {
            title: "prod".into(),
            target: "root@prod-01".into(),
        }
    }

    #[test]
    fn messages_are_told_apart() {
        assert_eq!(
            parse(br#"{"jsonrpc":"2.0","id":7,"method":"tools/list"}"#),
            Incoming::Request {
                id: json!(7),
                method: "tools/list".into(),
                params: Value::Null,
            }
        );
        assert_eq!(
            parse(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
            Incoming::Notification {
                method: "notifications/initialized".into(),
                params: Value::Null,
            }
        );
        assert_eq!(
            parse(br#"{"jsonrpc":"2.0","id":"a","result":{}}"#),
            Incoming::Response
        );
        assert!(
            matches!(parse(b"{not json"), Incoming::Invalid(reply) if reply["error"]["code"] == PARSE_ERROR)
        );
        assert!(matches!(parse(b"[1,2]"), Incoming::Invalid(_)));
        assert!(matches!(
            parse(br#"{"id":null,"method":"ping"}"#),
            Incoming::Invalid(_)
        ));
    }

    #[test]
    fn initialize_keeps_a_known_version_and_names_the_server() {
        let reply = initialize(&json!({"protocolVersion": "2025-06-18"}), &info());
        assert_eq!(reply["protocolVersion"], "2025-06-18");
        assert_eq!(reply["serverInfo"]["name"], "cratty");
        assert!(reply["capabilities"]["tools"].is_object());
        assert!(
            reply["instructions"]
                .as_str()
                .unwrap()
                .contains("root@prod-01")
        );

        let reply = initialize(&json!({"protocolVersion": "1999-01-01"}), &info());
        assert_eq!(reply["protocolVersion"], VERSIONS[0]);
    }

    #[test]
    fn failures_are_tool_errors_for_the_model() {
        let reply = tool_result(Err("denied".into()));
        assert_eq!(reply["isError"], true);
        assert_eq!(reply["content"][0]["text"], "denied");
    }
}
