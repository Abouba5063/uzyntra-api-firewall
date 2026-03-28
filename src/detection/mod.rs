use axum::http::HeaderMap;
use urlencoding::decode;

use crate::types::{
    resolve_rule_mode, AppState, AttackClass, AuthStatus, Finding, FindingEvidence, RequestContext,
    Severity,
};

pub fn inspect_request(
    state: &AppState,
    context: &RequestContext,
    headers: &HeaderMap,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    inspect_auth(state, context, &mut findings);
    inspect_method(state, context, &mut findings);
    inspect_path_and_query(state, context, &mut findings);
    inspect_headers(state, context, headers, &mut findings);
    inspect_body(state, context, &mut findings);

    findings
}

fn inspect_auth(state: &AppState, context: &RequestContext, findings: &mut Vec<Finding>) {
    match context.auth_status {
        AuthStatus::Missing => findings.push(Finding {
            rule_id: "auth.missing_api_key".into(),
            attack_class: AttackClass::BrokenAuthentication,
            severity: Severity::High,
            confidence: 0.99,
            message: "missing API key for protected path".into(),
            evidence: vec![FindingEvidence {
                location: "request.headers".into(),
                value_preview: state.config.auth.header_name.clone(),
            }],
            mode: resolve_rule_mode(state, &context.path, "auth.missing_api_key"),
        }),
        AuthStatus::Invalid => findings.push(Finding {
            rule_id: "auth.invalid_api_key".into(),
            attack_class: AttackClass::BrokenAuthentication,
            severity: Severity::High,
            confidence: 0.99,
            message: "invalid API key for protected path".into(),
            evidence: vec![FindingEvidence {
                location: "request.headers".into(),
                value_preview: state.config.auth.header_name.clone(),
            }],
            mode: resolve_rule_mode(state, &context.path, "auth.invalid_api_key"),
        }),
        AuthStatus::NotRequired | AuthStatus::Satisfied => {}
    }
}

fn inspect_method(state: &AppState, context: &RequestContext, findings: &mut Vec<Finding>) {
    if state
        .config
        .security
        .blocked_methods
        .iter()
        .any(|m| m.eq_ignore_ascii_case(&context.method))
    {
        findings.push(Finding {
            rule_id: "method.disallowed".into(),
            attack_class: AttackClass::MethodAbuse,
            severity: Severity::High,
            confidence: 0.98,
            message: format!("disallowed HTTP method detected: {}", context.method),
            evidence: vec![FindingEvidence {
                location: "request.method".into(),
                value_preview: context.method.clone(),
            }],
            mode: resolve_rule_mode(state, &context.path, "method.disallowed"),
        });
    }
}

fn inspect_path_and_query(
    state: &AppState,
    context: &RequestContext,
    findings: &mut Vec<Finding>,
) {
    let mut candidates = vec![context.path.clone()];

    if state.config.security.inspect_query_string {
        if let Some(query) = &context.query {
            candidates.push(query.clone());
        }
    }

    let normalized = normalized_variants(candidates);
    let haystack = normalized.join(" | ");
    let lower = haystack.to_ascii_lowercase();

    if lower.contains("../")
        || lower.contains("..\\")
        || lower.contains("%2e%2e")
        || lower.contains("%252e%252e")
    {
        findings.push(Finding {
            rule_id: "path.traversal.basic".into(),
            attack_class: AttackClass::PathTraversal,
            severity: Severity::High,
            confidence: 0.95,
            message: "path traversal markers detected".into(),
            evidence: vec![FindingEvidence {
                location: "request.path_or_query".into(),
                value_preview: truncate(&haystack, 200),
            }],
            mode: resolve_rule_mode(state, &context.path, "path.traversal.basic"),
        });
    }

    if lower.contains("union select")
        || lower.contains("' or 1=1")
        || lower.contains("\" or 1=1")
        || lower.contains("sleep(")
        || lower.contains("benchmark(")
        || lower.contains("information_schema")
        || lower.contains("select%20")
        || lower.contains("union%20select")
    {
        findings.push(Finding {
            rule_id: "sqli.basic".into(),
            attack_class: AttackClass::SqlInjection,
            severity: Severity::Critical,
            confidence: 0.90,
            message: "SQL injection indicators detected".into(),
            evidence: vec![FindingEvidence {
                location: "request.path_or_query".into(),
                value_preview: truncate(&haystack, 200),
            }],
            mode: resolve_rule_mode(state, &context.path, "sqli.basic"),
        });
    }

    if lower.contains("<script")
        || lower.contains("javascript:")
        || lower.contains("onerror=")
        || lower.contains("onload=")
        || lower.contains("%3cscript")
        || lower.contains("%253cscript")
    {
        findings.push(Finding {
            rule_id: "xss.basic".into(),
            attack_class: AttackClass::Xss,
            severity: Severity::High,
            confidence: 0.88,
            message: "XSS indicators detected".into(),
            evidence: vec![FindingEvidence {
                location: "request.path_or_query".into(),
                value_preview: truncate(&haystack, 200),
            }],
            mode: resolve_rule_mode(state, &context.path, "xss.basic"),
        });
    }

    if lower.contains(";cat ")
        || lower.contains("|whoami")
        || lower.contains("&&whoami")
        || lower.contains("`whoami`")
        || lower.contains("$(whoami)")
        || lower.contains("/bin/sh")
        || lower.contains("cmd.exe")
    {
        findings.push(Finding {
            rule_id: "cmdi.basic".into(),
            attack_class: AttackClass::CommandInjection,
            severity: Severity::Critical,
            confidence: 0.87,
            message: "command injection indicators detected".into(),
            evidence: vec![FindingEvidence {
                location: "request.path_or_query".into(),
                value_preview: truncate(&haystack, 200),
            }],
            mode: resolve_rule_mode(state, &context.path, "cmdi.basic"),
        });
    }

    if lower.contains("http://127.0.0.1")
        || lower.contains("http://localhost")
        || lower.contains("http://169.254.169.254")
        || lower.contains("file://")
        || lower.contains("gopher://")
    {
        findings.push(Finding {
            rule_id: "ssrf.basic".into(),
            attack_class: AttackClass::Ssrf,
            severity: Severity::High,
            confidence: 0.80,
            message: "SSRF-like indicators detected".into(),
            evidence: vec![FindingEvidence {
                location: "request.path_or_query".into(),
                value_preview: truncate(&haystack, 200),
            }],
            mode: resolve_rule_mode(state, &context.path, "ssrf.basic"),
        });
    }

    let percent_count = lower.matches('%').count();
    if percent_count >= 8 || lower.contains("%25") {
        findings.push(Finding {
            rule_id: "evasion.encoding".into(),
            attack_class: AttackClass::PayloadEvasion,
            severity: Severity::Medium,
            confidence: 0.76,
            message: "encoded or evasive payload indicators detected".into(),
            evidence: vec![FindingEvidence {
                location: "request.path_or_query".into(),
                value_preview: truncate(&haystack, 200),
            }],
            mode: resolve_rule_mode(state, &context.path, "evasion.encoding"),
        });
    }
}

fn inspect_headers(
    state: &AppState,
    context: &RequestContext,
    headers: &HeaderMap,
    findings: &mut Vec<Finding>,
) {
    if !state.config.security.inspect_headers {
        return;
    }

    for (name, value) in headers {
        let value_str = match value.to_str() {
            Ok(v) => v,
            Err(_) => continue,
        };

        let lower = value_str.to_ascii_lowercase();

        if lower.contains('\r') || lower.contains('\n') {
            findings.push(Finding {
                rule_id: "header.crlf".into(),
                attack_class: AttackClass::HeaderInjection,
                severity: Severity::Critical,
                confidence: 0.97,
                message: format!("CRLF/header injection markers in header {}", name),
                evidence: vec![FindingEvidence {
                    location: format!("header.{}", name),
                    value_preview: truncate(value_str, 200),
                }],
                mode: resolve_rule_mode(state, &context.path, "header.crlf"),
            });
        }

        if lower.contains("chunked") && headers.contains_key("content-length") {
            findings.push(Finding {
                rule_id: "smuggling.cl_te".into(),
                attack_class: AttackClass::RequestSmuggling,
                severity: Severity::High,
                confidence: 0.72,
                message: "possible CL/TE ambiguity detected".into(),
                evidence: vec![FindingEvidence {
                    location: format!("header.{}", name),
                    value_preview: truncate(value_str, 200),
                }],
                mode: resolve_rule_mode(state, &context.path, "smuggling.cl_te"),
            });
        }
    }
}

fn inspect_body(state: &AppState, context: &RequestContext, findings: &mut Vec<Finding>) {
    if !state.config.security.inspect_body {
        return;
    }

    let Some(body) = &context.body_preview else {
        return;
    };

    let normalized = normalized_variants(vec![body.clone()]);
    let haystack = normalized.join(" | ");
    let lower = haystack.to_ascii_lowercase();

    if lower.contains("union select")
        || lower.contains("' or 1=1")
        || lower.contains("\" or 1=1")
        || lower.contains("information_schema")
    {
        findings.push(Finding {
            rule_id: "body.sqli.basic".into(),
            attack_class: AttackClass::SqlInjection,
            severity: Severity::Critical,
            confidence: 0.91,
            message: "SQL injection indicators detected in body".into(),
            evidence: vec![FindingEvidence {
                location: "request.body".into(),
                value_preview: truncate(&haystack, 200),
            }],
            mode: resolve_rule_mode(state, &context.path, "body.sqli.basic"),
        });
    }

    if lower.contains("<script")
        || lower.contains("javascript:")
        || lower.contains("onerror=")
        || lower.contains("onload=")
    {
        findings.push(Finding {
            rule_id: "body.xss.basic".into(),
            attack_class: AttackClass::Xss,
            severity: Severity::High,
            confidence: 0.89,
            message: "XSS indicators detected in body".into(),
            evidence: vec![FindingEvidence {
                location: "request.body".into(),
                value_preview: truncate(&haystack, 200),
            }],
            mode: resolve_rule_mode(state, &context.path, "body.xss.basic"),
        });
    }

    if lower.contains("cmd.exe")
        || lower.contains("/bin/sh")
        || lower.contains("&&")
        || lower.contains("|whoami")
    {
        findings.push(Finding {
            rule_id: "body.cmdi.basic".into(),
            attack_class: AttackClass::CommandInjection,
            severity: Severity::Critical,
            confidence: 0.85,
            message: "command injection indicators detected in body".into(),
            evidence: vec![FindingEvidence {
                location: "request.body".into(),
                value_preview: truncate(&haystack, 200),
            }],
            mode: resolve_rule_mode(state, &context.path, "body.cmdi.basic"),
        });
    }
}

fn normalized_variants(candidates: Vec<String>) -> Vec<String> {
    let mut normalized = Vec::new();

    for candidate in candidates {
        normalized.push(candidate.clone());

        if let Ok(decoded) = decode(&candidate) {
            normalized.push(decoded.to_string());

            if let Ok(double_decoded) = decode(decoded.as_ref()) {
                normalized.push(double_decoded.to_string());
            }
        }
    }

    normalized
}

fn truncate(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_string();
    }

    let mut end = max;
    while !value.is_char_boundary(end) && end > 0 {
        end -= 1;
    }

    format!("{}...", &value[..end])
}