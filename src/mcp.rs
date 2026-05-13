use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
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
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::hosts::HostsConfig;
use crate::protocol::{self, Request, Response, Status};
use crate::server::default_socket_path;

const DEFAULT_TIMEOUT_MS: u64 = 120_000;
const MAX_TIMEOUT_MS: u64 = 600_000;

/// Whether SUDO_PROXY_MCP_VERBOSE is set. MCP stdio is JSON-RPC over
/// stdout, so the only safe trace sink is stderr. Cached once at first
/// use; an unset value disables tracing with no per-call cost.
fn mcp_verbose() -> bool {
    use std::sync::OnceLock;
    static V: OnceLock<bool> = OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("SUDO_PROXY_MCP_VERBOSE")
            .map(|v| !v.is_empty() && v != "0")
            .unwrap_or(false)
    })
}

/// stderr-only trace, gated on `SUDO_PROXY_MCP_VERBOSE`. Prefix all
/// messages with `[mcp]` so they're greppable in the user's terminal.
macro_rules! mcp_trace {
    ($($arg:tt)*) => {
        if $crate::mcp::mcp_verbose() {
            eprintln!("[mcp] {}", format!($($arg)*));
        }
    };
}

// ---------------------------------------------------------------------------
// Tool parameter schemas
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ExecuteParams {
    /// Command as argument array
    pub argv: Option<Vec<String>>,

    /// Pipeline of commands, each as an argument array. Use this for piped commands like [["ls", "/tmp"], ["wc", "-l"]].
    #[serde(default)]
    pub pipeline: Option<Vec<Vec<String>>>,

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

    /// Forward the local SSH agent to the command (unprivileged only).
    /// Requires the proxy session to have been started with `forward_agent: true`.
    /// Useful for `git clone` of private repos via SSH on a remote host.
    #[serde(default)]
    pub forward_agent: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct StartServerParams {
    /// Remote hostname (omit for localhost)
    #[serde(default)]
    pub host: Option<String>,

    /// Enable SSH agent forwarding on the tunnel so unprivileged commands
    /// that opt in (via execute's `forward_agent: true`) can authenticate
    /// to GitHub etc. with the user's local key. Ignored for local servers.
    #[serde(default)]
    pub forward_agent: bool,
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
        description = "Execute a command through sudo-proxy with human approval. The command runs on the target host (local by default). A human must approve privileged commands before they execute. Call start_server first if sudo-proxy is not already running. Supports pipelines: use `pipeline` for multi-stage commands (e.g. [[\"ls\", \"/tmp\"], [\"wc\", \"-l\"]]) or `argv` for a single command."
    )]
    async fn execute(
        &self,
        Parameters(params): Parameters<ExecuteParams>,
    ) -> Result<CallToolResult, McpError> {
        if let Some(ref h) = params.host {
            if let Err(e) = crate::server::validate_host(h) {
                return Ok(error_result(format!("invalid host: {e}")));
            }
        }
        let socket_path = socket_for_host(params.host.as_deref());
        let timeout_ms = params.timeout.unwrap_or(DEFAULT_TIMEOUT_MS).min(MAX_TIMEOUT_MS);

        if !socket_path.exists() {
            return Ok(error_result(format!(
                "sudo-proxy is not running (socket not found at {}). Call start_server first.",
                socket_path.display()
            )));
        }

        // Build pipeline from either `pipeline` or `argv` parameter
        let pipeline = match (params.pipeline, params.argv) {
            (Some(p), _) if !p.is_empty() => p,
            (_, Some(argv)) if !argv.is_empty() => vec![argv],
            _ => {
                return Ok(error_result(
                    "Either `argv` or `pipeline` must be provided.".to_string(),
                ));
            }
        };

        let host_name = params.host.clone().unwrap_or_else(|| "localhost".into());

        if params.forward_agent && params.privileged {
            return Ok(error_result(
                "forward_agent is only allowed with privileged: false".to_string(),
            ));
        }

        let req = Request {
            id: uuid::Uuid::new_v4().to_string(),
            host: params.host.unwrap_or_default(),
            session: "sudo-proxy-mcp".to_string(),
            time: now_iso8601(),
            pipeline,
            env: params.env.unwrap_or_default(),
            reason: params.description.unwrap_or_default(),
            privileged: params.privileged,
            forward_agent: params.forward_agent,
            version: protocol::VERSION.to_string(),
        };

        let total_timeout = Duration::from_millis(timeout_ms);
        let result = send_request(&socket_path, &req, total_timeout).await;

        match result {
            Ok(resp) => {
                touch_host(&host_name, &resp.version);
                Ok(format_response(resp))
            }
            Err(e) => Ok(error_result(e)),
        }
    }

    #[tool(
        description = "Start a sudo-proxy server. Local (no host): opens a terminal window with sudo-proxy's TUI for command approval. Remote (host given): opens a terminal window with SSH running sudo-proxy, with a socket tunnel so execute calls reach the remote host."
    )]
    async fn start_server(
        &self,
        Parameters(params): Parameters<StartServerParams>,
    ) -> Result<CallToolResult, McpError> {
        if let Some(ref h) = params.host {
            if let Err(e) = crate::server::validate_host(h) {
                return Ok(error_result(format!("invalid host: {e}")));
            }
        }
        let result = match &params.host {
            None => start_local().await,
            Some(host) => start_remote(host, params.forward_agent).await,
        };

        if let Ok(ref r) = result {
            if r.is_error != Some(true) {
                let host_name = params.host.unwrap_or_else(|| "localhost".into());
                touch_host(&host_name, "");
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
        if let Err(e) = crate::server::validate_host(&params.host) {
            return Ok(error_result(format!("invalid host: {e}")));
        }
        let mut config = HostsConfig::load();
        let info = config
            .hosts
            .entry(params.host.clone())
            .or_insert_with(|| crate::hosts::HostInfo {
                description: String::new(),
                os: String::new(),
                last_connected: String::new(),
                uid: String::new(),
                version: String::new(),
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

/// Render the MCP server's instructions block. Pure function over a
/// `HostsConfig` snapshot and a "is the sudo-proxy binary reachable?"
/// flag — the side-effectful pieces (config load, PATH lookup) live in
/// `get_info` so this layer stays testable.
///
/// The format is part of the MCP user-visible surface: it lands in every
/// Claude Code session's startup reminder. Changes here are observable
/// to the model and the operator.
pub fn build_instructions(config: &HostsConfig, have_proxy_binary: bool) -> String {
    let mut instructions = String::from(
        "Execute commands through sudo-proxy with human approval. \
         Call start_server first if sudo-proxy is not running, \
         then use execute to run commands.",
    );
    instructions.push_str(&format!(
        "\n\nThis sudo-proxy-mcp is version {}.",
        protocol::VERSION
    ));

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
            if !info.version.is_empty() {
                instructions.push_str(&format!(" [sudo-proxy {}]", info.version));
            }
            if !info.last_connected.is_empty() {
                instructions.push_str(&format!(" [last: {}]", info.last_connected));
            }
        }
    }

    if !have_proxy_binary {
        instructions.push_str(
            "\n\nThe sudo-proxy binary is not installed. \
             See https://github.com/tarides/sudo-proxy#installation for setup instructions.",
        );
    }

    instructions
}

#[tool_handler]
impl ServerHandler for McpProxy {
    fn get_info(&self) -> ServerInfo {
        let config = HostsConfig::load();
        let have_proxy_binary = find_sibling_binary("sudo-proxy").is_some()
            || which("sudo-proxy").is_some();
        let instructions = build_instructions(&config, have_proxy_binary);

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

/// Probe a socket for end-to-end readiness, not just file presence.
///
/// `local_sock.exists()` is true as soon as `sudo-proxy` (local) binds
/// the listener — or, for `start_remote`, as soon as `ssh -L` sets up
/// the local end of the forward. In the remote case the local socket
/// exists *before* the remote daemon has bound its socket: SSH will
/// accept a local connect, attempt to open a remote channel, find no
/// listener on the remote socket, and close the local end. The window
/// is sub-second on a warm SSH connection but easily widens to several
/// seconds (cold key auth, ControlMaster setup, slow remote startup).
///
/// We distinguish the two states by *connecting* and then doing a small
/// read with a tight timeout:
///   - read timeout (no bytes available) → daemon is listening, ready
///   - read EOF / error → tunnel was opened then closed: not ready
///
/// A real daemon will never spontaneously emit bytes before receiving a
/// request, so a 100 ms quiet window is a reliable positive signal.
async fn remote_socket_ready(local_sock: &Path) -> bool {
    let mut stream = match tokio::time::timeout(
        Duration::from_millis(500),
        UnixStream::connect(local_sock),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            mcp_trace!("readiness: connect({}) failed: {e}", local_sock.display());
            return false;
        }
        Err(_) => {
            mcp_trace!("readiness: connect({}) timed out", local_sock.display());
            return false;
        }
    };

    let mut buf = [0u8; 1];
    match tokio::time::timeout(Duration::from_millis(100), stream.read(&mut buf)).await {
        Err(_) => true, // read timeout — peer is silently waiting → ready
        Ok(Ok(0)) => {
            mcp_trace!("readiness: peer EOF on {} → not ready", local_sock.display());
            false
        }
        Ok(Ok(_)) => {
            // A daemon should never speak first. Treat unexpected data
            // as "something is listening but it isn't us" — fail closed.
            mcp_trace!("readiness: unexpected pre-request bytes on {}", local_sock.display());
            false
        }
        Ok(Err(e)) => {
            mcp_trace!("readiness: read({}) failed: {e}", local_sock.display());
            false
        }
    }
}

async fn start_local() -> Result<CallToolResult, McpError> {
    let socket_path = default_socket_path();
    mcp_trace!("start_local: socket={}", socket_path.display());

    // Check if already running
    if socket_path.exists() {
        if remote_socket_ready(&socket_path).await {
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

    let proxy_bin_str = proxy_bin.to_string_lossy().into_owned();

    let mut cmd = std::process::Command::new(&terminal);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Pass the proxy binary as a separate argv element so the terminal exec
    // path never goes through `sh -c`. This closes a command-injection
    // vector when user-controlled fields ever land in this code path.
    match terminal.as_str() {
        "gnome-terminal" => {
            cmd.args(["--", proxy_bin_str.as_str()]);
        }
        _ => {
            cmd.args(["-e", proxy_bin_str.as_str()]);
        }
    }

    cmd.spawn()
        .map_err(|e| McpError::internal_error(format!("spawn terminal: {e}"), None))?;

    // Wait for socket to be actively listening (not just file-present).
    // A stale socket file from a previous crashed daemon would otherwise
    // satisfy `exists()` immediately and let us return success before the
    // new daemon has bound. Up to 5 s total.
    let start = std::time::Instant::now();
    for tick in 0..50 {
        if socket_path.exists() && remote_socket_ready(&socket_path).await {
            mcp_trace!(
                "start_local: ready after {} ms ({} ticks)",
                start.elapsed().as_millis(),
                tick + 1
            );
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

async fn start_remote(host: &str, forward_agent: bool) -> Result<CallToolResult, McpError> {
    let local_sock = crate::server::remote_socket_path(host);
    mcp_trace!(
        "start_remote: host={host} local_sock={} forward_agent={forward_agent}",
        local_sock.display()
    );

    // Check if tunnel already exists and end-to-end ready (remote daemon
    // is bound, not just the SSH forward).
    if local_sock.exists() {
        if remote_socket_ready(&local_sock).await {
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "SSH tunnel to {host} is already active at {}",
                local_sock.display()
            ))]));
        }
        let _ = std::fs::remove_file(&local_sock);
    }

    // Find the sudo-proxy binary next to our own executable, or in PATH
    let proxy_bin = find_sibling_binary("sudo-proxy").unwrap_or_else(|| "sudo-proxy".into());

    let terminal = find_terminal()
        .map_err(|e| McpError::internal_error(e, None))?;

    let proxy_bin_str = proxy_bin.to_string_lossy().into_owned();

    let mut cmd = std::process::Command::new(&terminal);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Pass argv directly to the terminal — never through `sh -c`. The host
    // string is caller-controlled (via the MCP tool) and shell-interpolating
    // it would let a peer execute arbitrary commands inside the spawned
    // terminal without the TUI approval gate. validate_host has already
    // rejected anything outside [A-Za-z0-9._@:-], so this is defence in depth.
    let mut proxy_args: Vec<&str> = vec![proxy_bin_str.as_str(), "--host", host];
    if forward_agent {
        proxy_args.push("--forward-agent");
    }
    match terminal.as_str() {
        "gnome-terminal" => {
            let mut full = vec!["--"];
            full.extend(proxy_args.iter().copied());
            cmd.args(&full);
        }
        _ => {
            let mut full = vec!["-e"];
            full.extend(proxy_args.iter().copied());
            cmd.args(&full);
        }
    }

    cmd.spawn()
        .map_err(|e| McpError::internal_error(format!("spawn terminal: {e}"), None))?;

    // Wait for the tunnel to be end-to-end ready. The local socket file
    // appears as soon as ssh -L binds (well before the remote daemon
    // has bound its socket); just checking exists() lets the first
    // execute hit a tunnel whose remote end isn't there yet, get
    // immediate EOF, and triggers the user-visible "blank window,
    // Claude keeps retrying" failure. Probe instead.
    let start = std::time::Instant::now();
    for tick in 0..300 {
        if local_sock.exists() && remote_socket_ready(&local_sock).await {
            mcp_trace!(
                "start_remote: tunnel to {host} ready after {} ms ({} ticks)",
                start.elapsed().as_millis(),
                tick + 1
            );
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "SSH tunnel to {host} established at {}",
                local_sock.display()
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

/// Per-phase timeout for connect and write operations.
const PHASE_TIMEOUT: Duration = Duration::from_secs(5);

async fn send_request(
    socket_path: &Path,
    req: &Request,
    total_timeout: Duration,
) -> Result<Response, String> {
    // Bounded retry on transient EOF — the SSH `-L` forward accepts a
    // local connect before the remote daemon has bound the remote
    // socket, in which case the channel-open fails and we read 0 bytes.
    // Up to ~2 s of 200 ms retries closes that window without delaying
    // a genuinely-dead remote (the next attempt still surfaces the
    // existing error).
    const EOF_RETRY_BUDGET: Duration = Duration::from_secs(2);
    const EOF_RETRY_INTERVAL: Duration = Duration::from_millis(200);
    let retry_deadline = tokio::time::Instant::now() + EOF_RETRY_BUDGET;
    let mut eof_retries = 0u32;

    loop {
        match send_request_once(socket_path, req, total_timeout).await {
            Ok(resp) => {
                if eof_retries > 0 {
                    mcp_trace!(
                        "send_request: succeeded after {eof_retries} eof-retry"
                    );
                }
                return Ok(resp);
            }
            Err(SendError::TransientEof)
                if tokio::time::Instant::now() < retry_deadline =>
            {
                eof_retries += 1;
                mcp_trace!("send_request: eof-retry #{eof_retries} (transient EOF)");
                tokio::time::sleep(EOF_RETRY_INTERVAL).await;
                continue;
            }
            Err(SendError::TransientEof) => {
                return Err(format!(
                    "server closed connection without response (after {eof_retries} retries)"
                ));
            }
            Err(SendError::Hard(msg)) => return Err(msg),
        }
    }
}

enum SendError {
    /// Server closed the connection before sending a response. On an
    /// SSH-forwarded socket this typically means the remote daemon
    /// hadn't bound the remote socket yet; the next attempt may succeed.
    TransientEof,
    /// Anything else — propagate verbatim to the caller.
    Hard(String),
}

async fn send_request_once(
    socket_path: &Path,
    req: &Request,
    total_timeout: Duration,
) -> Result<Response, SendError> {
    let deadline = tokio::time::Instant::now() + total_timeout;

    // Phase 1: Connect (5s — if a Unix socket takes longer, the tunnel is dead)
    let stream = tokio::time::timeout(PHASE_TIMEOUT, UnixStream::connect(socket_path))
        .await
        .map_err(|_| {
            SendError::Hard(format!(
                "connect timed out after {}s — tunnel to {} may be dead, try restarting the server",
                PHASE_TIMEOUT.as_secs(),
                socket_path.display()
            ))
        })?
        .map_err(|e| SendError::Hard(format!("connect to {}: {e}", socket_path.display())))?;

    let (read, mut write) = stream.into_split();

    // Phase 2: Write (5s)
    let json = serde_json::to_string(req).map_err(|e| SendError::Hard(format!("serialize: {e}")))?;
    let write_result: Result<(), SendError> = tokio::time::timeout(PHASE_TIMEOUT, async {
        write
            .write_all(format!("{json}\n").as_bytes())
            .await
            .map_err(|e| {
                // A broken pipe on write is the SSH-channel-closed signal
                // surfacing on the write side instead of the read side.
                if e.kind() == std::io::ErrorKind::BrokenPipe {
                    SendError::TransientEof
                } else {
                    SendError::Hard(format!("write: {e}"))
                }
            })?;
        write
            .flush()
            .await
            .map_err(|e| SendError::Hard(format!("flush: {e}")))?;
        Ok(())
    })
    .await
    .map_err(|_| {
        SendError::Hard(format!(
            "write timed out after {}s — server at {} may be unresponsive",
            PHASE_TIMEOUT.as_secs(),
            socket_path.display()
        ))
    })?;
    write_result?;

    // Phase 3: Read (remaining time from user-specified timeout)
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    let remaining = remaining.max(Duration::from_secs(1)); // at least 1s

    let mut reader = BufReader::new(read);
    let mut line = String::new();
    tokio::time::timeout(remaining, reader.read_line(&mut line))
        .await
        .map_err(|_| {
            SendError::Hard(format!(
                "server did not respond within {}s — it may be busy with another command or waiting for user approval",
                total_timeout.as_secs()
            ))
        })?
        .map_err(|e| SendError::Hard(format!("read: {e}")))?;

    if line.is_empty() {
        return Err(SendError::TransientEof);
    }

    let trimmed = line.trim();
    serde_json::from_str::<Response>(trimmed).map_err(|e| {
        // Lenient peek: even if the response is structurally invalid, the
        // version field is usually a top-level string and can still be
        // extracted to make skew obvious in the diagnostic.
        let peer_ver = serde_json::from_str::<serde_json::Value>(trimmed)
            .ok()
            .as_ref()
            .and_then(|v| v.get("version"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        SendError::Hard(format!(
            "parse response from sudo-proxy {peer_ver} (client sudo-proxy-mcp {}): {e}",
            protocol::VERSION
        ))
    })
}

// ---------------------------------------------------------------------------
// Response formatting
// ---------------------------------------------------------------------------

fn format_response(resp: Response) -> CallToolResult {
    match resp.status {
        Status::Ok => {
            let exit_code = resp.exit_code();
            let stdout = decode_b64(resp.stdout.as_deref());
            let multi_stage = resp.stages.len() > 1;

            let mut parts = Vec::new();
            if !stdout.is_empty() {
                parts.push(stdout);
            }

            for (i, stage) in resp.stages.iter().enumerate() {
                let stderr = decode_b64(Some(&stage.stderr));
                if !stderr.is_empty() {
                    let label = if multi_stage {
                        format!("[stderr stage {i}]")
                    } else {
                        "[stderr]".to_string()
                    };
                    parts.push(format!("{label}\n{stderr}"));
                }
            }

            if parts.is_empty() || exit_code != 0 {
                if multi_stage {
                    let codes: Vec<String> =
                        resp.stages.iter().map(|s| s.exit_code.to_string()).collect();
                    parts.push(format!("[exit codes: {}]", codes.join(", ")));
                } else {
                    parts.push(format!("[exit code: {exit_code}]"));
                }
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
            let server_ver = if resp.version.is_empty() {
                "unknown".to_string()
            } else {
                resp.version
            };
            error_result(format!(
                "Error from sudo-proxy {server_ver} (client sudo-proxy-mcp {}): {msg}",
                protocol::VERSION
            ))
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
        Some(h) => crate::server::remote_socket_path(h),
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

fn touch_host(host: &str, version: &str) {
    let mut config = HostsConfig::load();
    config.touch(host);
    config.record_version(host, version);
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
