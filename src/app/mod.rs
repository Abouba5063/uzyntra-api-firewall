use anyhow::Context;
use tower_http::cors::{Any, CorsLayer};
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
    storage,
    types::{AppState, LivePolicyState},
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
        policy_state: std::sync::Arc::new(std::sync::RwLock::new(LivePolicyState::from_config(&config))),
        started_at: chrono::Utc::now(),
    };

    info!("application state initialized");
    Ok(state)
}

pub fn hydrate_state_from_storage(state: &AppState) -> anyhow::Result<()> {
    let mitigations = storage::load_active_mitigations(&state.config.storage.sqlite_path)?;
    let reputations = storage::load_reputations(&state.config.storage.sqlite_path)?;

    for mitigation in mitigations {
        if mitigation.expires_at > chrono::Utc::now() {
            state.mitigation_store.insert_block_hydrated(mitigation);
        }
    }

    for reputation in reputations {
        state.mitigation_store.insert_reputation_hydrated(reputation);
    }

    info!(
        active_blocks = state.mitigation_store.active_block_count(),
        reputation_entries = state.mitigation_store.list_reputations().len(),
        "hydrated in-memory state from SQLite"
    );

    Ok(())
}

pub fn start_background_tasks(state: AppState) {
    tokio::spawn(async move {
        let interval_secs = 30u64;

        loop {
            tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
            let expired = state.mitigation_store.cleanup_expired();

            if !expired.is_empty() {
                for ip in &expired {
                    if let Err(err) =
                        storage::delete_active_mitigation(&state.config.storage.sqlite_path, &ip.to_string())
                    {
                        tracing::error!(error = %err, source_ip = %ip, "failed to delete expired mitigation from SQLite");
                    }
                }

                info!(removed = expired.len(), "cleaned up expired temporary mitigations");
            }
        }
    });
}

pub fn build_public_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(control_plane::root))
        .route("/healthz", get(control_plane::public_healthz))
        .route("/readyz", get(control_plane::readyz))
        .route("/proxy/{*path}", any(proxy::proxy_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            core::security_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            core::request_context_middleware,
        ))
        .with_state(state)
}

pub fn build_admin_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin("http://localhost:3000".parse::<axum::http::HeaderValue>().unwrap())
        .allow_methods(Any)
        .allow_headers(Any);

    let live_router = if state.config.server.admin_public_health_enabled {
        Router::new().route("/livez", get(control_plane::admin_livez))
    } else {
        Router::new()
    };

    live_router
        .merge(
            Router::new()
                .route("/healthz", get(control_plane::admin_healthz))
                .route("/v1/admin/config", get(control_plane::get_config))
                .route("/v1/admin/policy/effective", get(control_plane::effective_policy))
                .route("/v1/admin/policy/rules/set", post(control_plane::set_global_rule_mode))
                .route("/v1/admin/policy/routes/upsert", post(control_plane::upsert_route_override))
                .route("/v1/admin/policy/routes/delete", post(control_plane::delete_route_override))
                .route("/v1/admin/policy/rate-limits/upsert", post(control_plane::upsert_route_rate_limit))
                .route("/v1/admin/policy/rate-limits/delete", post(control_plane::delete_route_rate_limit))
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
                    "/v1/admin/reputations/reset/{ip}",
                    post(control_plane::reset_reputation),
                )
                .route(
                    "/v1/admin/mitigations/unblock/{ip}",
                    post(control_plane::unblock_ip),
                )
                .route(
                    "/v1/admin/mitigations/block",
                    post(control_plane::manual_block_ip),
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
                .route(
                    "/v1/admin/metrics",
                    get(control_plane::metrics),
                )
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    core::admin_auth_middleware,
                ))
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    core::request_context_middleware,
                )),
        )
        .layer(cors)
        .with_state(state)
}