use rmcp::{transport::stdio, ServiceExt};
use sudo_proxy::mcp::McpProxy;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(arg) = std::env::args().nth(1) {
        match arg.as_str() {
            "--version" | "-V" => {
                println!("sudo-proxy-mcp {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            _ => {}
        }
    }
    let service = McpProxy::new().serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
