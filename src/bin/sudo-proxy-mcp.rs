use rmcp::{transport::stdio, ServiceExt};
use sudo_proxy::mcp::McpProxy;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(arg) = std::env::args().nth(1) {
        if matches!(arg.as_str(), "--version" | "-V") {
            sudo_proxy::cli::print_version("sudo-proxy-mcp");
        }
    }
    let service = McpProxy::new().serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
