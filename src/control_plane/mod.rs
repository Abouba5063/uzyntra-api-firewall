use std::{collections::HashMap, net::IpAddr};

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use chrono::Utc;
use serde_json::{json, Value};

use crate::{
    config::{RoutePolicyOverride, RouteRateLimitOverride},
    mitigation, storage,
    types::{
        ok, err, AdminAudit, AppState, DeleteRouteOverrideRequest, DeleteRouteRateLimitRequest,
        EventSearchFilters, SetGlobalRuleModeRequest, UpsertRouteOverrideRequest,
        UpsertRouteRateLimitRequest,
    },
};

pub async fn root() -> Json<Value> {
    Json(json!({
        "service": "api_firewall",
        "status": "running",
        "message": "Rust API Firewall public plane is up"
    }))
}

pub async fn public_healthz() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "plane": "public"
    }))
}

pub async fn admin_healthz() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "plane": "admin",
        "auth_required": true
    }))
}

pub async fn admin_livez(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "plane": "admin",
        "public_health_enabled": state.config.server.admin_public_health_enabled
    }))
}

pub async fn readyz(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "status": "ready",
        "started_at": state.started_at,
        "upstream": state.config.proxy.upstream_base_url,
        "active_temp_blocks": state.mitigation_store.active_block_count(),
    }))
}

pub async fn get_config(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "server": state.config.server,
        "proxy": state.config.proxy,
        "security": state.config.security,
        "telemetry": state.config.telemetry,
        "storage": state.config.storage,
        "auth": {
            "enabled": state.config.auth.enabled,
            "header_name": state.config.auth.header_name,
            "protected_path_prefixes": state.config.auth.protected_path_prefixes,
            "api_keys_count": state.config.auth.api_keys.len(),
            "admin": {
                "enabled": state.config.auth.admin.enabled,
                "header_name": state.config.auth.admin.header_name
            }
        }
    }))
}

pub async fn effective_policy(State(state): State<AppState>) -> Json<Value> {
    let guard = state.policy_state.read().expect("policy_state poisoned");
    Json(json!(ok(json!({
        "global_rule_modes": guard.global_rule_modes,
        "route_overrides": guard.route_overrides,
        "route_rate_limits": guard.route_rate_limits
    }))))
}

pub async fn set_global_rule_mode(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SetGlobalRuleModeRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    {
        let mut guard = state.policy_state.write().expect("policy_state poisoned");
        guard.global_rule_modes.insert(body.rule_id.clone(), body.mode.clone());
    }

    audit(
        &state,
        actor,
        "set_global_rule_mode",
        body.rule_id.clone(),
        "updated",
        format!("mode={:?}", body.mode),
    );

    Json(json!(ok(json!({
        "rule_id": body.rule_id,
        "mode": body.mode
    }))))
}

pub async fn upsert_route_override(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UpsertRouteOverrideRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    {
        let mut guard = state.policy_state.write().expect("policy_state poisoned");
        if let Some(existing) = guard
            .route_overrides
            .iter_mut()
            .find(|r| r.path_prefix == body.path_prefix)
        {
            existing.rule_modes = body.rule_modes.clone();
        } else {
            guard.route_overrides.push(RoutePolicyOverride {
                path_prefix: body.path_prefix.clone(),
                rule_modes: body.rule_modes.clone(),
            });
        }
    }

    audit(
        &state,
        actor,
        "upsert_route_override",
        body.path_prefix.clone(),
        "updated",
        "route override upserted".to_string(),
    );

    Json(json!(ok(body)))
}

pub async fn delete_route_override(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DeleteRouteOverrideRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);
    let removed = {
        let mut guard = state.policy_state.write().expect("policy_state poisoned");
        let before = guard.route_overrides.len();
        guard.route_overrides.retain(|r| r.path_prefix != body.path_prefix);
        before != guard.route_overrides.len()
    };

    audit(
        &state,
        actor,
        "delete_route_override",
        body.path_prefix.clone(),
        if removed { "removed" } else { "not_found" },
        "route override delete attempted".to_string(),
    );

    Json(json!(ok(json!({
        "path_prefix": body.path_prefix,
        "removed": removed
    }))))
}

pub async fn upsert_route_rate_limit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UpsertRouteRateLimitRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    {
        let mut guard = state.policy_state.write().expect("policy_state poisoned");
        if let Some(existing) = guard
            .route_rate_limits
            .iter_mut()
            .find(|r| r.path_prefix == body.path_prefix)
        {
            existing.requests_per_window = body.requests_per_window;
            existing.window_secs = body.window_secs;
        } else {
            guard.route_rate_limits.push(RouteRateLimitOverride {
                path_prefix: body.path_prefix.clone(),
                requests_per_window: body.requests_per_window,
                window_secs: body.window_secs,
            });
        }
    }

    audit(
        &state,
        actor,
        "upsert_route_rate_limit",
        body.path_prefix.clone(),
        "updated",
        format!(
            "requests_per_window={}; window_secs={}",
            body.requests_per_window, body.window_secs
        ),
    );

    Json(json!(ok(body)))
}

pub async fn delete_route_rate_limit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DeleteRouteRateLimitRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);
    let removed = {
        let mut guard = state.policy_state.write().expect("policy_state poisoned");
        let before = guard.route_rate_limits.len();
        guard.route_rate_limits.retain(|r| r.path_prefix != body.path_prefix);
        before != guard.route_rate_limits.len()
    };

    audit(
        &state,
        actor,
        "delete_route_rate_limit",
        body.path_prefix.clone(),
        if removed { "removed" } else { "not_found" },
        "route rate limit delete attempted".to_string(),
    );

    Json(json!(ok(json!({
        "path_prefix": body.path_prefix,
        "removed": removed
    }))))
}

pub async fn demo_recommendations() -> Json<Value> {
    let recommendations = mitigation::demo_recommendations();
    let commands: Vec<_> = recommendations
        .iter()
        .filter_map(mitigation::recommendation_to_command)
        .collect();

    Json(json!(ok(json!({
        "recommendations": recommendations,
        "commands": commands
    }))))
}

pub async fn demo_one_click_commands() -> Json<Value> {
    let mut block_params = HashMap::new();
    block_params.insert("ttl_secs".to_string(), "900".to_string());
    block_params.insert("source_ip".to_string(), "127.0.0.1".to_string());

    let mut unblock_params = HashMap::new();
    unblock_params.insert("source_ip".to_string(), "127.0.0.1".to_string());

    let mut reset_rep_params = HashMap::new();
    reset_rep_params.insert("source_ip".to_string(), "127.0.0.1".to_string());

    Json(json!(ok(json!({
        "commands": [
            {
                "kind": "BlockIpTemporary",
                "title": "Temporarily block source IP",
                "rationale": "Use for repeated exploit probes.",
                "reversible": true,
                "parameters": block_params
            },
            {
                "kind": "UnblockIp",
                "title": "Remove temporary block",
                "rationale": "Use when analyst confirms the source should be restored.",
                "reversible": true,
                "parameters": unblock_params
            },
            {
                "kind": "ResetReputation",
                "title": "Reset source reputation",
                "rationale": "Use after analyst review clears the source.",
                "reversible": false,
                "parameters": reset_rep_params
            }
        ]
    }))))
}

pub async fn list_active_blocks(State(state): State<AppState>) -> Json<Value> {
    let blocks = state.mitigation_store.list_active_blocks();

    let items: Vec<_> = blocks
        .into_iter()
        .map(|b| {
            json!({
                "action_id": b.action_id,
                "source_ip": b.source_ip.to_string(),
                "action": b.action,
                "created_at": b.created_at,
                "expires_at": b.expires_at,
                "reason": b.reason
            })
        })
        .collect();

    Json(json!(ok(json!({
        "count": items.len(),
        "items": items
    }))))
}

pub async fn list_reputations(State(state): State<AppState>) -> Json<Value> {
    let items = state.mitigation_store.list_reputations();
    Json(json!(ok(json!({
        "count": items.len(),
        "items": items
    }))))
}

pub async fn get_reputation(
    State(state): State<AppState>,
    Path(ip): Path<String>,
) -> Json<Value> {
    match ip.parse::<IpAddr>() {
        Ok(parsed) => {
            let rep = state.mitigation_store.get_reputation(parsed);
            Json(json!(ok(json!({ "item": rep }))))
        }
        Err(_) => Json(json!(err::<Value>("invalid IP address"))),
    }
}

pub async fn unblock_ip(
    State(state): State<AppState>,
    Path(ip): Path<String>,
    headers: HeaderMap,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    match ip.parse::<IpAddr>() {
        Ok(parsed) => {
            let removed = state.mitigation_store.unblock_ip(parsed);

            if removed {
                if let Err(e) =
                    storage::delete_active_mitigation(&state.config.storage.sqlite_path, &parsed.to_string())
                {
                    tracing::error!(error = %e, "failed to delete active mitigation from SQLite");
                }
            }

            audit(
                &state,
                actor,
                "unblock_ip",
                parsed.to_string(),
                if removed { "removed" } else { "not_found" },
                "manual unblock via admin API".to_string(),
            );

            Json(json!(ok(json!({
                "source_ip": parsed.to_string(),
                "removed": removed
            }))))
        }
        Err(_) => Json(json!(err::<Value>("invalid IP address"))),
    }
}

pub async fn manual_block_ip(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::ManualBlockRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    let parsed_ip = match body.source_ip.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            return Json(json!(err::<Value>("invalid IP address")));
        }
    };

    let ttl_secs = body.ttl_secs.unwrap_or(state.config.security.temp_ban_secs);
    let reason = body
        .reason
        .unwrap_or_else(|| "manual block via admin API".to_string());

    match mitigation::apply_manual_block(&state, parsed_ip, ttl_secs, reason.clone()) {
        Ok(mit) => {
            audit(
                &state,
                actor,
                "manual_block_ip",
                parsed_ip.to_string(),
                "applied",
                format!("ttl_secs={ttl_secs}; reason={reason}"),
            );

            Json(json!(ok(json!({
                "action_id": mit.action_id,
                "source_ip": mit.source_ip.to_string(),
                "expires_at": mit.expires_at,
                "reason": mit.reason
            }))))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn reset_reputation(
    State(state): State<AppState>,
    Path(ip): Path<String>,
    headers: HeaderMap,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    let parsed = match ip.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            return Json(json!(err::<Value>("invalid IP address")));
        }
    };

    match mitigation::reset_reputation_for_ip(&state, parsed) {
        Ok(removed) => {
            audit(
                &state,
                actor,
                "reset_reputation",
                parsed.to_string(),
                if removed { "removed" } else { "not_found" },
                "manual reputation reset via admin API".to_string(),
            );

            Json(json!(ok(json!({
                "source_ip": parsed.to_string(),
                "removed": removed
            }))))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn recent_events(
    State(state): State<AppState>,
    Query(query): Query<EventSearchFilters>,
) -> Json<Value> {
    match storage::query_security_events(&state.config.storage.sqlite_path, &query) {
        Ok(items) => Json(json!(ok(json!({
            "count": items.len(),
            "limit": query.limit.unwrap_or(20),
            "offset": query.offset.unwrap_or(0),
            "items": items
        })))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn search_events(
    State(state): State<AppState>,
    Query(query): Query<EventSearchFilters>,
) -> Json<Value> {
    match storage::query_security_events(&state.config.storage.sqlite_path, &query) {
        Ok(items) => Json(json!(ok(json!({
            "count": items.len(),
            "limit": query.limit.unwrap_or(20),
            "offset": query.offset.unwrap_or(0),
            "items": items
        })))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn recent_audits(
    State(state): State<AppState>,
    Query(query): Query<crate::types::AuditSearchFilters>,
) -> Json<Value> {
    match storage::query_admin_audits(&state.config.storage.sqlite_path, &query) {
        Ok(items) => Json(json!(ok(json!({
            "count": items.len(),
            "limit": query.limit.unwrap_or(20),
            "offset": query.offset.unwrap_or(0),
            "items": items
        })))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn metrics(State(state): State<AppState>) -> Json<Value> {
    match storage::metrics_snapshot(&state.config.storage.sqlite_path) {
        Ok(metrics) => Json(json!(ok(json!({
            "public_bind_addr": state.config.server.public_bind_addr,
            "admin_bind_addr": state.config.server.admin_bind_addr,
            "active_temp_blocks": state.mitigation_store.active_block_count(),
            "reputation_entries": state.mitigation_store.list_reputations().len(),
            "persisted_active_mitigations": metrics.persisted_active_mitigations,
            "persisted_reputations": metrics.persisted_reputations,
            "total_events": metrics.total_events,
            "blocked_events": metrics.blocked_events,
            "total_audits": metrics.total_audits,
            "latest_rule_ids": metrics.latest_rule_ids
        })))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

fn actor_from_headers(headers: &HeaderMap) -> String {
    headers
        .get("x-admin-actor")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("admin")
        .to_string()
}

fn audit(
    state: &AppState,
    actor: String,
    action: &str,
    target: String,
    result: &str,
    details: String,
) {
    let audit = AdminAudit {
        timestamp: Utc::now(),
        actor,
        action: action.to_string(),
        target,
        result: result.to_string(),
        details,
    };

    if let Err(e) = storage::persist_admin_audit(&state.config.storage.sqlite_path, &audit) {
        tracing::error!(error = %e, "failed to persist admin audit");
    }
}