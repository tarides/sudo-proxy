#![cfg(all(unix, feature = "mcp"))]

//! Reproduces what a registry crawler (Glama, the MCP Inspector) does when it
//! indexes the server: spawn `sudo-proxy-mcp`, run the MCP `initialize` →
//! `tools/list` handshake over stdio, and enumerate the tools. Glama's quality
//! score is computed from those tool definitions, so if this fails the server
//! is unscoreable. See docs/mcp.md ("Registry introspection").

use std::io::{BufRead, BufReader, Write};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

/// Wait for a JSON-RPC response with the given id, skipping notifications and
/// unrelated messages. Fails the test (rather than hanging CI) if the server
/// goes silent — a broken stdio handshake is exactly what we're guarding.
fn recv_response(rx: &Receiver<serde_json::Value>, want_id: i64) -> serde_json::Value {
    loop {
        let msg = rx
            .recv_timeout(Duration::from_secs(15))
            .expect("timed out waiting for MCP response — stdio handshake is broken");
        if msg.get("id").and_then(|v| v.as_i64()) == Some(want_id) {
            return msg;
        }
    }
}

fn send(stdin: &mut ChildStdin, line: &str) {
    stdin.write_all(line.as_bytes()).expect("write to mcp stdin");
    stdin.write_all(b"\n").expect("write newline to mcp stdin");
    stdin.flush().expect("flush mcp stdin");
}

#[test]
fn mcp_server_enumerates_its_tools() {
    let bin = env!("CARGO_BIN_EXE_sudo-proxy-mcp");
    let mut child = Command::new(bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sudo-proxy-mcp");

    // Drain stdout on a reader thread so blocking line reads enforce ordering
    // without any sleeps.
    let stdout = child.stdout.take().expect("mcp stdout");
    let (tx, rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) {
                if tx.send(value).is_err() {
                    break;
                }
            }
        }
    });

    let mut stdin = child.stdin.take().expect("mcp stdin");

    send(
        &mut stdin,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"introspection-test","version":"0"}}}"#,
    );
    let _ = recv_response(&rx, 1);

    send(
        &mut stdin,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    );
    send(
        &mut stdin,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
    );
    let list = recv_response(&rx, 2);

    let tools = list["result"]["tools"]
        .as_array()
        .expect("tools/list result.tools should be an array");

    let mut names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().expect("every tool needs a name"))
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        ["execute", "start_server", "update_host"],
        "unexpected MCP tool set — this is exactly what Glama enumerates to score the server",
    );

    // Glama scores tool-definition quality, which needs real descriptions.
    for tool in tools {
        let name = tool["name"].as_str().unwrap();
        let desc = tool["description"].as_str().unwrap_or("");
        assert!(
            desc.len() > 20,
            "tool `{name}` has a missing/trivial description ({desc:?}); Glama scores this",
        );
    }

    // Closing stdin ends the stdio transport; let the server exit cleanly.
    drop(stdin);
    let _ = child.wait();
    let _ = reader.join();
}
