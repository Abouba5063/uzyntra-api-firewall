use std::{collections::HashMap, net::IpAddr};

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use chrono::Utc;
use serde_json::{json, Value};

use crate::{
    mitigation, storage,
    types::{AdminAudit, AppState, AuditSearchFilters, EventSearchFilters},
};

pub async fn root() -> Json<Value> {
    Json(json!({
        "service": "api_firewall",
        "status": "running",
        "message": "Rust API Firewall is up"
    }))
}

pub async fn healthz() -> Json<Value> {
    Json(json!({
        "status": "ok"
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

pub async fn demo_recommendations() -> Json<Value> {
    let recommendations = mitigation::demo_recommendations();
    let commands: Vec<_> = recommendations
        .iter()
        .filter_map(mitigation::recommendation_to_command)
        .collect();

    Json(json!({
        "recommendations": recommendations,
        "commands": commands
    }))
}

pub async fn demo_one_click_commands() -> Json<Value> {
    let mut block_params = HashMap::new();
    block_params.insert("ttl_secs".to_string(), "900".to_string());
    block_params.insert("source_ip".to_string(), "127.0.0.1".to_string());

    let mut unblock_params = HashMap::new();
    unblock_params.insert("source_ip".to_string(), "127.0.0.1".to_string());

    let commands = vec![
        json!({
            "kind": "BlockIpTemporary",
            "title": "Temporarily block source IP",
            "rationale": "Use for repeated exploit probes.",
            "reversible": true,
            "parameters": block_params
        }),
        json!({
            "kind": "UnblockIp",
            "title": "Remove temporary block",
            "rationale": "Use when analyst confirms the source should be restored.",
            "reversible": true,
            "parameters": unblock_params
        }),
    ];

    Json(json!({
        "commands": commands
    }))
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

    Json(json!({
        "count": items.len(),
        "items": items
    }))
}

pub async fn list_reputations(State(state): State<AppState>) -> Json<Value> {
    let items = state.mitigation_store.list_reputations();

    Json(json!({
        "count": items.len(),
        "items": items
    }))
}

pub async fn get_reputation(
    State(state): State<AppState>,
    Path(ip): Path<String>,
) -> Json<Value> {
    match ip.parse::<IpAddr>() {
        Ok(parsed) => {
            let rep = state.mitigation_store.get_reputation(parsed);
            Json(json!({ "item": rep }))
        }
        Err(_) => Json(json!({
            "error": "invalid IP address"
        })),
    }
}

pub async fn unblock_ip(
    State(state): State<AppState>,
    Path(ip): Path<String>,
    headers: HeaderMap,
) -> Json<Value> {
    let actor = headers
        .get("x-admin-actor")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("admin")
        .to_string();

    match ip.parse::<IpAddr>() {
        Ok(parsed) => {
            let removed = state.mitigation_store.unblock_ip(parsed);

            let audit = AdminAudit {
                timestamp: Utc::now(),
                actor,
                action: "unblock_ip".to_string(),
                target: parsed.to_string(),
                result: if removed { "removed" } else { "not_found" }.to_string(),
                details: "manual unblock via admin API".to_string(),
            };

            if let Err(err) = storage::persist_admin_audit(&state.config.storage.sqlite_path, &audit)
            {
                tracing::error!(error = %err, "failed to persist admin audit");
            }

            Json(json!({
                "source_ip": parsed.to_string(),
                "removed": removed
            }))
        }
        Err(_) => Json(json!({
            "error": "invalid IP address"
        })),
    }
}

pub async fn recent_events(
    State(state): State<AppState>,
    Query(query): Query<EventSearchFilters>,
) -> Json<Value> {
    match storage::query_security_events(&state.config.storage.sqlite_path, &query) {
        Ok(items) => Json(json!({
            "count": items.len(),
            "items": items
        })),
        Err(err) => Json(json!({
            "error": err.to_string()
        })),
    }
}

pub async fn search_events(
    State(state): State<AppState>,
    Query(query): Query<EventSearchFilters>,
) -> Json<Value> {
    match storage::query_security_events(&state.config.storage.sqlite_path, &query) {
        Ok(items) => Json(json!({
            "count": items.len(),
            "items": items
        })),
        Err(err) => Json(json!({
            "error": err.to_string()
        })),
    }
}

pub async fn recent_audits(
    State(state): State<AppState>,
    Query(query): Query<AuditSearchFilters>,
) -> Json<Value> {
    match storage::query_admin_audits(&state.config.storage.sqlite_path, &query) {
        Ok(items) => Json(json!({
            "count": items.len(),
            "items": items
        })),
        Err(err) => Json(json!({
            "error": err.to_string()
        })),
    }
}