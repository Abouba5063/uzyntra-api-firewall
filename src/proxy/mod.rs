use axum::{
    body::{to_bytes, Body},
    extract::{Path, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode},
};
use tracing::{error, info};

use crate::{
    policy, storage, telemetry,
    types::{
        AppState, AttackClass, Finding, FindingEvidence, RequestContext, SecurityEvent, Severity,
    },
};

pub async fn proxy_handler(
    State(state): State<AppState>,
    Path(path): Path<String>,
    request: Request<Body>,
) -> Response<Body> {
    let context = request.extensions().get::<RequestContext>().cloned();

    let method = request.method().clone();
    let query = request.uri().query().map(ToOwned::to_owned);
    let headers = request.headers().clone();

    let full_url = build_upstream_url(
        &state.config.proxy.upstream_base_url,
        &path,
        query.as_deref(),
    );

    let body_bytes = match to_bytes(request.into_body(), state.config.proxy.max_body_bytes).await {
        Ok(bytes) => bytes,
        Err(err) => {
            error!(error = %err, "failed to read request body for proxying");
            return response_with_status(StatusCode::BAD_REQUEST, "failed to read request body");
        }
    };

    let reqwest_method = match to_reqwest_method(&method) {
        Ok(m) => m,
        Err(err) => {
            error!(error = %err, method = %method, "unsupported method for reqwest");
            return response_with_status(StatusCode::METHOD_NOT_ALLOWED, "unsupported HTTP method");
        }
    };

    let mut builder = state.proxy_client.request(reqwest_method, &full_url);

    for (name, value) in &headers {
        if should_skip_request_header(name.as_str()) {
            continue;
        }

        if let Ok(value_str) = value.to_str() {
            builder = builder.header(name.as_str(), value_str);
        }
    }

    builder = builder.body(body_bytes);

    let upstream_response = match builder.send().await {
        Ok(resp) => resp,
        Err(err) => {
            error!(
                error = %err,
                upstream = %full_url,
                "upstream proxy request failed"
            );
            return response_with_status(StatusCode::BAD_GATEWAY, "upstream request failed");
        }
    };

    let status = upstream_response.status();
    let response_headers = upstream_response.headers().clone();

    let response_findings = inspect_response_headers(&response_headers, &state, context.as_ref());
    if !response_findings.is_empty() {
        if let Some(ctx) = &context {
            let decision = policy::evaluate_findings(&state, ctx, response_findings.clone());
            let event = SecurityEvent {
                request_id: ctx.request_id.clone(),
                timestamp: ctx.timestamp,
                source_ip: ctx.source_ip.to_string(),
                method: ctx.method.clone(),
                path: ctx.path.clone(),
                findings: response_findings,
                decision,
            };

            telemetry::emit_security_event(&event, &state.config.telemetry.security_event_log_path);

            if let Err(err) = storage::persist_security_event(&state.config.storage.sqlite_path, &event) {
                error!(error = %err, "failed to persist response-side security event to SQLite");
            }
        }
    }

    let response_body = match upstream_response.bytes().await {
        Ok(bytes) => bytes,
        Err(err) => {
            error!(error = %err, "failed to read upstream response body");
            return response_with_status(StatusCode::BAD_GATEWAY, "failed to read upstream response");
        }
    };

    let mut response = Response::new(Body::from(response_body));
    *response.status_mut() = status;

    for (name, value) in &response_headers {
        if should_skip_response_header(name.as_str()) {
            continue;
        }

        response.headers_mut().insert(name.clone(), value.clone());
    }

    if let Ok(header_name) = HeaderName::from_lowercase(b"x-firewall-proxied") {
        response
            .headers_mut()
            .insert(header_name, HeaderValue::from_static("true"));
    }

    info!(
        method = %method,
        upstream = %full_url,
        status = %status,
        "request proxied successfully"
    );

    response
}

fn inspect_response_headers(
    headers: &HeaderMap,
    state: &AppState,
    context: Option<&RequestContext>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let required = [
        ("x-content-type-options", "missing.x_content_type_options"),
        ("x-frame-options", "missing.x_frame_options"),
        ("content-security-policy", "missing.csp"),
    ];

    for (header, rule_id) in required {
        if !headers.contains_key(header) {
            let path = context.map(|c| c.path.as_str()).unwrap_or("/proxy");

            findings.push(Finding {
                rule_id: rule_id.to_string(),
                attack_class: AttackClass::MissingSecurityHeaders,
                severity: Severity::Low,
                confidence: 0.95,
                message: format!("upstream response missing security header '{}'", header),
                evidence: vec![FindingEvidence {
                    location: "response.headers".into(),
                    value_preview: header.to_string(),
                }],
                mode: crate::types::resolve_rule_mode(state, path, rule_id),
            });
        }
    }

    findings
}

fn build_upstream_url(base: &str, path: &str, query: Option<&str>) -> String {
    let base = base.trim_end_matches('/');
    let path = path.trim_start_matches('/');

    match query {
        Some(q) if !q.is_empty() => format!("{base}/{path}?{q}"),
        _ => format!("{base}/{path}"),
    }
}

fn to_reqwest_method(method: &Method) -> Result<reqwest::Method, String> {
    reqwest::Method::from_bytes(method.as_str().as_bytes())
        .map_err(|err| format!("invalid reqwest method conversion: {err}"))
}

fn should_skip_request_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "host" | "connection" | "content-length" | "transfer-encoding"
    )
}

fn should_skip_response_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection" | "transfer-encoding"
    )
}

fn response_with_status(status: StatusCode, message: &str) -> Response<Body> {
    let mut response = Response::new(Body::from(message.to_string()));
    *response.status_mut() = status;
    response
}