use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let app = wattswarm_servicenet_node::build_default_app().await?;
    let addr = std::env::var("SERVICENET_HTTP_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8042".to_owned())
        .parse::<SocketAddr>()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("servicenet node listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
