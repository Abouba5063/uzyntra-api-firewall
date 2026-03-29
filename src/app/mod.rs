use anyhow::Context;
use axum::{
    middleware,
    routing::{any, get, post},
    Router,
};
use reqwest::Client;
use tracing::info;

use crate::{
    config::AppConfig,
    control_plane, core,
    mitigation::TemporaryMitigationStore,
    proxy,
    rate_limit::RateLimiter,
    types::AppState,
};

pub fn build_state(config: AppConfig) -> anyhow::Result<AppState> {
    let proxy_client = Client::builder()
        .user_agent("api-firewall/0.1.0")
        .pool_idle_timeout(std::time::Duration::from_secs(
            config.proxy.pool_idle_timeout_secs,
        ))
        .connect_timeout(std::time::Duration::from_secs(
            config.proxy.connect_timeout_secs,
        ))
        .timeout(std::time::Duration::from_secs(
            config.proxy.request_timeout_secs,
        ))
        .build()
        .context("failed to build reqwest client")?;

    let state = AppState {
        config: std::sync::Arc::new(config.clone()),
        proxy_client,
        rate_limiter: std::sync::Arc::new(RateLimiter::new(
            config.security.rate_limit.requests_per_window,
            config.security.rate_limit.window_secs,
        )),
        mitigation_store: std::sync::Arc::new(TemporaryMitigationStore::default()),
        started_at: chrono::Utc::now(),
    };

    info!("application state initialized");
    Ok(state)
}

pub fn start_background_tasks(state: AppState) {
    tokio::spawn(async move {
        let interval_secs = 30u64;

        loop {
            tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
            let removed = state.mitigation_store.cleanup_expired();

            if removed > 0 {
                info!(removed = removed, "cleaned up expired temporary mitigations");
            }
        }
    });
}

pub fn build_router(state: AppState) -> Router {
    let public_router = Router::new()
        .route("/", get(control_plane::root))
        .route("/healthz", get(control_plane::healthz))
        .route("/readyz", get(control_plane::readyz))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            core::request_context_middleware,
        ));

    let admin_router = Router::new()
        .route("/v1/admin/config", get(control_plane::get_config))
        .route(
            "/v1/admin/recommendations/demo",
            get(control_plane::demo_recommendations),
        )
        .route(
            "/v1/admin/commands/demo",
            get(control_plane::demo_one_click_commands),
        )
        .route(
            "/v1/admin/mitigations/active",
            get(control_plane::list_active_blocks),
        )
        .route(
            "/v1/admin/reputations",
            get(control_plane::list_reputations),
        )
        .route(
            "/v1/admin/reputations/{ip}",
            get(control_plane::get_reputation),
        )
        .route(
            "/v1/admin/mitigations/unblock/{ip}",
            post(control_plane::unblock_ip),
        )
        .route(
            "/v1/admin/events/recent",
            get(control_plane::recent_events),
        )
        .route(
            "/v1/admin/events/search",
            get(control_plane::search_events),
        )
        .route(
            "/v1/admin/audits/recent",
            get(control_plane::recent_audits),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            core::admin_auth_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            core::request_context_middleware,
        ));

    let proxy_router = Router::new()
        .route("/proxy/{*path}", any(proxy::proxy_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            core::security_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            core::request_context_middleware,
        ));

    Router::new()
        .merge(public_router)
        .merge(admin_router)
        .merge(proxy_router)
        .with_state(state)
}