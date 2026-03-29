use std::net::SocketAddr;

use anyhow::Context;
use api_firewall::{app, config::AppConfig, storage, telemetry};
use tokio::net::TcpListener;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = AppConfig::load().context("failed to load application config")?;
    telemetry::init(&config.telemetry.log_level)?;

    storage::init_db(&config.storage.sqlite_path)
        .context("failed to initialize SQLite storage")?;

    let bind_addr: SocketAddr = config
        .server
        .bind_addr
        .parse()
        .with_context(|| format!("invalid bind address: {}", config.server.bind_addr))?;

    let app_state = app::build_state(config.clone())?;
    app::start_background_tasks(app_state.clone());

    let router = app::build_router(app_state);

    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind {}", bind_addr))?;

    info!(
        bind_addr = %bind_addr,
        upstream = %config.proxy.upstream_base_url,
        sqlite_path = %config.storage.sqlite_path,
        "api firewall starting"
    );

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("server exited with error")?;

    Ok(())
}