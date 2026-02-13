use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    AnnotateAble, CallToolResult, Content, ListResourcesResult, PaginatedRequestParams,
    RawResource, ReadResourceRequestParams, ReadResourceResult, ResourceContents,
    ServerCapabilities, ServerInfo,
};
use rmcp::service::RequestContext;
use rmcp::{
    schemars, tool, tool_handler, tool_router, ErrorData as McpError, RoleServer, ServerHandler,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::hosts::HostsConfig;
use crate::protocol::{Request, Response, Status};
use crate::server::default_socket_path;

const DEFAULT_TIMEOUT_MS: u64 = 120_000;
const MAX_TIMEOUT_MS: u64 = 600_000;
/// Default remote socket path — uses /run/user/<uid>/sudo-proxy.sock.
/// The UID is resolved at connection time via `ssh host id -u`.

// ---------------------------------------------------------------------------
// Tool parameter schemas
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ExecuteParams {
    /// Command as argument array
    pub argv: Vec<String>,

    /// Target host (omit for localhost)
    #[serde(default)]
    pub host: Option<String>,

    /// Timeout in milliseconds (default: 120000, max: 600000)
    #[serde(default)]
    pub timeout: Option<u64>,

    /// What this command does (shown in TUI prompt)
    #[serde(default)]
    pub description: Option<String>,

    /// Privilege escalation (default: true)
    #[serde(default = "default_true")]
    pub privileged: bool,

    /// Environment variables
    #[serde(default)]
    pub env: Option<HashMap<String, String>>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct StartServerParams {
    /// Remote hostname (omit for localhost)
    #[serde(default)]
    pub host: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct UpdateHostParams {
    /// Hostname to update
    pub host: String,

    /// Human-readable description of the host (e.g. "CI server")
    #[serde(default)]
    pub description: Option<String>,

    /// Operating system info (e.g. "Ubuntu 24.04")
    #[serde(default)]
    pub os: Option<String>,
}

// ---------------------------------------------------------------------------
// McpProxy — the MCP server
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct McpProxy {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl McpProxy {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "Execute a command through sudo-proxy with human approval. The command runs on the target host (local by default). A human must approve privileged commands before they execute. Call start_server first if sudo-proxy is not already running."
    )]
    async fn execute(
        &self,
        Parameters(params): Parameters<ExecuteParams>,
    ) -> Result<CallToolResult, McpError> {
        let socket_path = socket_for_host(params.host.as_deref());
        let timeout_ms = params.timeout.unwrap_or(DEFAULT_TIMEOUT_MS).min(MAX_TIMEOUT_MS);

        if !socket_path.exists() {
            return Ok(error_result(format!(
                "sudo-proxy is not running (socket not found at {}). Call start_server first.",
                socket_path.display()
            )));
        }

        let host_name = params.host.clone().unwrap_or_else(|| "localhost".into());

        let req = Request {
            id: uuid::Uuid::new_v4().to_string(),
            host: params.host.unwrap_or_default(),
            session: "sudo-proxy-mcp".to_string(),
            time: now_iso8601(),
            argv: params.argv,
            env: params.env.unwrap_or_default(),
            reason: params.description.unwrap_or_default(),
            privileged: params.privileged,
        };

        let result = tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            send_request(&socket_path, &req),
        )
        .await;

        if let Ok(Ok(_)) = &result {
            touch_host(&host_name);
        }

        match result {
            Ok(Ok(resp)) => Ok(format_response(resp)),
            Ok(Err(e)) => Ok(error_result(e)),
            Err(_) => Ok(error_result("Request timed out.".to_string())),
        }
    }

    #[tool(
        description = "Start a sudo-proxy server. Local (no host): opens a terminal window with sudo-proxy's TUI for command approval. Remote (host given): opens a terminal window with SSH running sudo-proxy, with a socket tunnel so execute calls reach the remote host."
    )]
    async fn start_server(
        &self,
        Parameters(params): Parameters<StartServerParams>,
    ) -> Result<CallToolResult, McpError> {
        let result = match &params.host {
            None => start_local().await,
            Some(host) => start_remote(host).await,
        };

        if let Ok(ref r) = result {
            if r.is_error != Some(true) {
                let host_name = params.host.unwrap_or_else(|| "localhost".into());
                touch_host(&host_name);
            }
        }

        result
    }

    #[tool(
        description = "Update metadata for a known host. Use this to record a host's description or OS after learning it during a session."
    )]
    async fn update_host(
        &self,
        Parameters(params): Parameters<UpdateHostParams>,
    ) -> Result<CallToolResult, McpError> {
        let mut config = HostsConfig::load();
        let info = config
            .hosts
            .entry(params.host.clone())
            .or_insert_with(|| crate::hosts::HostInfo {
                description: String::new(),
                os: String::new(),
                last_connected: String::new(),
            });
        if let Some(desc) = params.description {
            info.description = desc;
        }
        if let Some(os) = params.os {
            info.os = os;
        }
        config.save();
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Updated host {}",
            params.host
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for McpProxy {
    fn get_info(&self) -> ServerInfo {
        let mut instructions = String::from(
            "Execute commands through sudo-proxy with human approval. \
             Call start_server first if sudo-proxy is not running, \
             then use execute to run commands.",
        );

        let config = HostsConfig::load();
        if !config.hosts.is_empty() {
            instructions.push_str("\n\nKnown hosts:");
            for (name, info) in &config.hosts {
                instructions.push_str(&format!("\n- {name}"));
                if !info.description.is_empty() {
                    instructions.push_str(&format!(": {}", info.description));
                }
                if !info.os.is_empty() {
                    instructions.push_str(&format!(" ({})", info.os));
                }
                if !info.last_connected.is_empty() {
                    instructions.push_str(&format!(" [last: {}]", info.last_connected));
                }
            }
        }

        let has_binary = find_sibling_binary("sudo-proxy").is_some()
            || which("sudo-proxy").is_some();
        if !has_binary {
            instructions.push_str(
                "\n\nThe sudo-proxy binary is not installed. \
                 See https://github.com/tarides/sudo-proxy#installation for setup instructions.",
            );
        }

        ServerInfo {
            instructions: Some(instructions.into()),
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
            ..Default::default()
        }
    }

    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListResourcesResult, McpError>> + Send + '_ {
        std::future::ready(Ok(ListResourcesResult {
            meta: None,
            next_cursor: None,
            resources: vec![RawResource {
                uri: "sudo-proxy://hosts".into(),
                name: "known-hosts".into(),
                title: None,
                description: Some(
                    "Known sudo-proxy hosts with system info and last connection time".into(),
                ),
                mime_type: Some("application/json".into()),
                size: None,
                icons: None,
                meta: None,
            }
            .no_annotation()],
        }))
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ReadResourceResult, McpError>> + Send + '_ {
        std::future::ready(if request.uri == "sudo-proxy://hosts" {
            let config = HostsConfig::load();
            let json =
                serde_json::to_string_pretty(&config).unwrap_or_else(|_| "{}".into());
            Ok(ReadResourceResult {
                contents: vec![ResourceContents::TextResourceContents {
                    uri: "sudo-proxy://hosts".into(),
                    mime_type: Some("application/json".into()),
                    text: json,
                    meta: None,
                }],
            })
        } else {
            Err(McpError::resource_not_found(
                format!("Unknown resource: {}", request.uri),
                None,
            ))
        })
    }
}

// ---------------------------------------------------------------------------
// start_server implementations
// ---------------------------------------------------------------------------

async fn start_local() -> Result<CallToolResult, McpError> {
    let socket_path = default_socket_path();

    // Check if already running
    if socket_path.exists() {
        if UnixStream::connect(&socket_path).await.is_ok() {
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "sudo-proxy is already running at {}",
                socket_path.display()
            ))]));
        }
        // Stale socket — sudo-proxy will clean it up on start
    }

    // Find the sudo-proxy binary next to our own executable, or in PATH
    let proxy_bin = find_sibling_binary("sudo-proxy").unwrap_or_else(|| "sudo-proxy".into());

    let terminal = find_terminal()
        .map_err(|e| McpError::internal_error(e, None))?;

    let proxy_cmd = format!("{}", proxy_bin.display());

    let mut cmd = std::process::Command::new(&terminal);
    match terminal.as_str() {
        "gnome-terminal" => {
            cmd.args(["--", "sh", "-c", &proxy_cmd]);
        }
        _ => {
            cmd.args(["-e", "sh", "-c", &proxy_cmd]);
        }
    }

    cmd.spawn()
        .map_err(|e| McpError::internal_error(format!("spawn terminal: {e}"), None))?;

    // Wait for socket to appear (up to 5s)
    for _ in 0..50 {
        if socket_path.exists() {
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "sudo-proxy started in terminal at {}",
                socket_path.display()
            ))]));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Ok(error_result(format!(
        "Terminal opened but socket not ready after 5s at {}",
        socket_path.display()
    )))
}

async fn start_remote(host: &str) -> Result<CallToolResult, McpError> {
    let local_sock = format!("/tmp/sudo-proxy-{host}.sock");

    // Check if tunnel already exists
    if Path::new(&local_sock).exists() {
        if UnixStream::connect(&local_sock).await.is_ok() {
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "SSH tunnel to {host} is already active at {local_sock}"
            ))]));
        }
        let _ = std::fs::remove_file(&local_sock);
    }

    // Resolve remote UID so we tunnel to the right XDG_RUNTIME_DIR
    let uid_output = std::process::Command::new("ssh")
        .args([host, "id", "-u"])
        .output()
        .map_err(|e| McpError::internal_error(format!("ssh id -u: {e}"), None))?;
    if !uid_output.status.success() {
        return Ok(error_result(format!(
            "Failed to get remote UID via ssh {host} id -u"
        )));
    }
    let remote_uid = String::from_utf8_lossy(&uid_output.stdout).trim().to_string();
    let remote_sock = format!("/run/user/{remote_uid}/sudo-proxy.sock");

    let tunnel = format!("{local_sock}:{remote_sock}");

    let terminal = find_terminal()
        .map_err(|e| McpError::internal_error(e, None))?;

    let ssh_cmd = format!("ssh -t -L {tunnel} {host} sudo-proxy");

    let mut cmd = std::process::Command::new(&terminal);
    match terminal.as_str() {
        "gnome-terminal" => {
            cmd.args(["--", "sh", "-c", &ssh_cmd]);
        }
        _ => {
            cmd.args(["-e", "sh", "-c", &ssh_cmd]);
        }
    }

    cmd.spawn()
        .map_err(|e| McpError::internal_error(format!("spawn terminal: {e}"), None))?;

    // Wait for tunnel socket (up to 30s)
    for _ in 0..300 {
        if Path::new(&local_sock).exists() {
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "SSH tunnel to {host} established at {local_sock}"
            ))]));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Ok(error_result(format!(
        "Terminal opened for SSH to {host} but tunnel socket not ready after 30s"
    )))
}

// ---------------------------------------------------------------------------
// Socket communication
// ---------------------------------------------------------------------------

async fn send_request(socket_path: &Path, req: &Request) -> Result<Response, String> {
    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|e| format!("connect to {}: {e}", socket_path.display()))?;

    let (read, mut write) = stream.into_split();

    let json = serde_json::to_string(req).map_err(|e| format!("serialize: {e}"))?;
    write
        .write_all(format!("{json}\n").as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;
    write.flush().await.map_err(|e| format!("flush: {e}"))?;

    let mut reader = BufReader::new(read);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .map_err(|e| format!("read: {e}"))?;

    if line.is_empty() {
        return Err("server closed connection without response".to_string());
    }

    serde_json::from_str(line.trim()).map_err(|e| format!("parse response: {e}"))
}

// ---------------------------------------------------------------------------
// Response formatting
// ---------------------------------------------------------------------------

fn format_response(resp: Response) -> CallToolResult {
    match resp.status {
        Status::Ok => {
            let exit_code = resp.exit_code.unwrap_or(0);
            let stdout = decode_b64(resp.stdout.as_deref());
            let stderr = decode_b64(resp.stderr.as_deref());

            let mut parts = Vec::new();
            if !stdout.is_empty() {
                parts.push(stdout);
            }
            if !stderr.is_empty() {
                parts.push(format!("[stderr]\n{stderr}"));
            }
            if parts.is_empty() || exit_code != 0 {
                parts.push(format!("[exit code: {exit_code}]"));
            }

            CallToolResult {
                content: parts.into_iter().map(Content::text).collect(),
                structured_content: None,
                is_error: Some(exit_code != 0),
                meta: None,
            }
        }
        Status::Denied => error_result("Request denied by user.".to_string()),
        Status::Timeout => {
            error_result("Request timed out waiting for user approval.".to_string())
        }
        Status::Error => {
            let msg = resp
                .message
                .unwrap_or_else(|| "unknown error".to_string());
            error_result(format!("Error: {msg}"))
        }
    }
}

fn error_result(msg: String) -> CallToolResult {
    CallToolResult {
        content: vec![Content::text(msg)],
        structured_content: None,
        is_error: Some(true),
        meta: None,
    }
}

fn decode_b64(s: Option<&str>) -> String {
    s.and_then(|v| B64.decode(v).ok())
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

fn socket_for_host(host: Option<&str>) -> PathBuf {
    match host {
        None => default_socket_path(),
        Some(h) => PathBuf::from(format!("/tmp/sudo-proxy-{h}.sock")),
    }
}

fn find_sibling_binary(name: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let candidate = dir.join(name);
    if candidate.is_file() {
        Some(candidate)
    } else {
        None
    }
}

fn find_terminal() -> Result<String, String> {
    for name in [
        "x-terminal-emulator",
        "gnome-terminal",
        "konsole",
        "xfce4-terminal",
        "xterm",
    ] {
        if which(name).is_some() {
            return Ok(name.to_string());
        }
    }
    Err("no terminal emulator found (tried x-terminal-emulator, gnome-terminal, konsole, xfce4-terminal, xterm)".to_string())
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::var("PATH").ok()?.split(':').find_map(|dir| {
        let path = PathBuf::from(dir).join(name);
        if path.is_file() {
            Some(path)
        } else {
            None
        }
    })
}

fn touch_host(host: &str) {
    let mut config = HostsConfig::load();
    config.touch(host);
    config.save();
}

fn now_iso8601() -> String {
    use std::time::SystemTime;
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let days = secs / 86400;
    let tod = secs % 86400;
    let (year, month, day) = days_to_ymd(days);

    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970;
    loop {
        let diy = if is_leap(year) { 366 } else { 365 };
        if days < diy {
            break;
        }
        days -= diy;
        year += 1;
    }
    let md: [u64; 12] = if is_leap(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 0;
    for (i, &m) in md.iter().enumerate() {
        if days < m {
            month = i as u64 + 1;
            break;
        }
        days -= m;
    }
    (year, month, days + 1)
}

fn is_leap(year: u64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}
