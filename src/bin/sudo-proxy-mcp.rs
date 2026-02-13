use rmcp::{transport::stdio, ServiceExt};
use sudo_proxy::mcp::McpProxy;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = McpProxy::new().serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
