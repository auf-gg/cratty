//! Starting an agent process: its variables, and the ones it must not inherit. One test
//! in its own binary, since it changes this process's environment.
#![cfg(unix)]

use std::time::Duration;

use cratty::acp::{self, AgentCommand, AgentKind, FromAgent, McpServer, Setup};
use futures::StreamExt;

#[tokio::test]
async fn agent_gets_its_folder_and_loses_foreign_config() {
    // SAFETY: the only test in this binary, and no other thread reads the environment yet.
    unsafe { std::env::set_var("OPENCODE_CONFIG_CONTENT", r#"{"permissions": []}"#) };

    // Not an agent: it reports what it got on stderr and exits, which ends the session
    // with that text in the error.
    let command = AgentCommand {
        kind: AgentKind::OpenCode,
        program: "/bin/sh".into(),
        args: vec![
            "-c".into(),
            r#"echo "db=$OPENCODE_DB content=${OPENCODE_CONFIG_CONTENT:-none}" >&2"#.into(),
        ],
        path: std::env::var_os("PATH").unwrap_or_default(),
        env: vec![("OPENCODE_DB".into(), "/agents/opencode.db".into())],
    };
    let setup = Setup {
        cwd: std::env::temp_dir().to_string_lossy().into_owned(),
        mcp: McpServer {
            name: "cratty".into(),
            command: "/bin/false".into(),
            args: Vec::new(),
            env: Vec::new(),
        },
        login: "opencode auth login".into(),
        resume: None,
    };
    let mut handle = acp::spawn(command, setup).expect("spawn");
    let event = tokio::time::timeout(Duration::from_secs(10), handle.events.next())
        .await
        .expect("no event in time");
    let Some(FromAgent::Closed { error: Some(error) }) = event else {
        panic!("expected the session to close with an error, got {event:?}");
    };
    assert!(
        error.contains("db=/agents/opencode.db content=none"),
        "{error}"
    );
}
