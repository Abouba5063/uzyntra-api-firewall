use std::net::{IpAddr, SocketAddr};

use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    detection, mitigation, policy, rate_limit, telemetry,
    types::{
        AppState, AuthStatus, DecisionOutcome, RequestContext, SecurityDecision, SecurityEvent,
    },
};

pub async fn request_context_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let (mut parts, body) = request.into_parts();

    let connect_info = parts.extensions.get::<ConnectInfo<SocketAddr>>().cloned();

    let source_ip = determine_source_ip(
        &state,
        &parts.headers,
        connect_info.as_ref().map(|ci| ci.0),
    );

    let request_id = Uuid::new_v4().to_string();
    let query = parts.uri.query().map(ToOwned::to_owned);

    let (body_preview, body_bytes) = if state.config.security.inspect_body {
        match to_bytes(body, state.config.security.max_inspection_body_bytes).await {
            Ok(bytes) => {
                let preview = preview_body(&bytes, state.config.security.max_inspection_body_bytes);
                (preview, bytes.to_vec())
            }
            Err(_) => (None, Vec::new()),
        }
    } else {
        match to_bytes(body, state.config.proxy.max_body_bytes).await {
            Ok(bytes) => (None, bytes.to_vec()),
            Err(_) => (None, Vec::new()),
        }
    };

    let auth_status = evaluate_auth_status(&state, parts.uri.path(), &parts.headers);

    let context = RequestContext {
        request_id: request_id.clone(),
        timestamp: chrono::Utc::now(),
        source_ip,
        method: parts.method.to_string(),
        path: parts.uri.path().to_string(),
        query,
        body_preview,
        auth_status,
    };

    parts.extensions.insert(context);

    let request = Request::from_parts(parts, Body::from(body_bytes));

    let mut response = next.run(request).await;
    attach_request_id_header(
        &state.config.security.request_id_header,
        &request_id,
        &mut response,
    );
    response
}

pub async fn security_middleware(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let Some(context) = request.extensions().get::<RequestContext>().cloned() else {
        return build_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "missing request context",
            None,
        );
    };

    if let Some(active_block) = state.mitigation_store.get_active_block(&context.source_ip) {
        warn!(
            request_id = %context.request_id,
            source_ip = %context.source_ip,
            action_id = %active_block.action_id,
            "request rejected by active temporary mitigation"
        );

        return build_error_response(
            StatusCode::FORBIDDEN,
            "source temporarily blocked",
            Some(&context.request_id),
        );
    }

    if let Some(rate_limit_finding) = rate_limit::evaluate_request(&state, &context) {
        let decision = policy::evaluate_findings(&state, &context, vec![rate_limit_finding]);
        emit_event(&context, &decision);
        return mitigation::finalize_blocking_decision(&state, &context, decision);
    }

    let findings = detection::inspect_request(&state, &context, request.headers());
    let decision = policy::evaluate_findings(&state, &context, findings.clone());

    request.extensions_mut().insert(findings);
    request.extensions_mut().insert(decision.clone());

    emit_event(&context, &decision);

    if matches!(decision.outcome, DecisionOutcome::Reject { .. }) {
        return mitigation::finalize_blocking_decision(&state, &context, decision);
    }

    mitigation::apply_non_blocking_effects(&state, &context, &decision);

    let response = next.run(request).await;

    info!(
        request_id = %context.request_id,
        source_ip = %context.source_ip,
        method = %context.method,
        path = %context.path,
        status = %response.status(),
        "request allowed"
    );

    response
}

fn emit_event(context: &RequestContext, decision: &SecurityDecision) {
    if decision.findings.is_empty() {
        return;
    }

    let event = SecurityEvent {
        request_id: context.request_id.clone(),
        timestamp: context.timestamp,
        source_ip: context.source_ip.to_string(),
        method: context.method.clone(),
        path: context.path.clone(),
        findings: decision.findings.clone(),
        decision: decision.clone(),
    };

    telemetry::emit_security_event(&event);
}

fn evaluate_auth_status(state: &AppState, path: &str, headers: &HeaderMap) -> AuthStatus {
    if !state.config.auth.enabled {
        return AuthStatus::NotRequired;
    }

    let protected = state
        .config
        .auth
        .protected_path_prefixes
        .iter()
        .any(|prefix| path.starts_with(prefix));

    if !protected {
        return AuthStatus::NotRequired;
    }

    let Some(value) = headers.get(&state.config.auth.header_name) else {
        return AuthStatus::Missing;
    };

    let Ok(value_str) = value.to_str() else {
        return AuthStatus::Invalid;
    };

    if state.config.auth.api_keys.iter().any(|k| k == value_str) {
        AuthStatus::Satisfied
    } else {
        AuthStatus::Invalid
    }
}

fn determine_source_ip(
    state: &AppState,
    headers: &HeaderMap,
    peer_addr: Option<SocketAddr>,
) -> IpAddr {
    if state.config.server.trust_x_forwarded_for {
        if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = value.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }

    peer_addr
        .map(|addr| addr.ip())
        .unwrap_or_else(|| IpAddr::from([0, 0, 0, 0]))
}

fn attach_request_id_header(header_name: &str, request_id: &str, response: &mut Response) {
    if let (Ok(name), Ok(value)) = (
        axum::http::header::HeaderName::from_bytes(header_name.as_bytes()),
        HeaderValue::from_str(request_id),
    ) {
        response.headers_mut().insert(name, value);
    }
}

fn build_error_response(
    status: StatusCode,
    message: &str,
    request_id: Option<&str>,
) -> Response {
    let mut response = Response::new(Body::from(message.to_string()));
    *response.status_mut() = status;

    if let Some(req_id) = request_id {
        if let Ok(value) = HeaderValue::from_str(req_id) {
            response.headers_mut().insert("x-request-id", value);
        }
    }

    response
}

fn preview_body(bytes: &[u8], max: usize) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }

    let slice = if bytes.len() > max { &bytes[..max] } else { bytes };
    Some(String::from_utf8_lossy(slice).to_string())
}