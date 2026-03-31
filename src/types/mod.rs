use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, RwLock},
};

use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::{
    config::{AppConfig, RoutePolicyOverride, RouteRateLimitOverride, RuleMode},
    mitigation::TemporaryMitigationStore,
    rate_limit::RateLimiter,
};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub proxy_client: Client,
    pub rate_limiter: Arc<RateLimiter>,
    pub mitigation_store: Arc<TemporaryMitigationStore>,
    pub policy_state: Arc<RwLock<LivePolicyState>>,
    pub started_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivePolicyState {
    pub global_rule_modes: HashMap<String, RuleMode>,
    pub route_overrides: Vec<RoutePolicyOverride>,
    pub route_rate_limits: Vec<RouteRateLimitOverride>,
}

impl LivePolicyState {
    pub fn from_config(config: &AppConfig) -> Self {
        Self {
            global_rule_modes: config.security.rule_modes.clone(),
            route_overrides: config.security.route_overrides.clone(),
            route_rate_limits: config.security.route_rate_limits.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    pub request_id: String,
    pub timestamp: DateTime<Utc>,
    pub source_ip: IpAddr,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub body_preview: Option<String>,
    pub parsed_body_fields: Vec<ParsedBodyField>,
    pub auth_status: AuthStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedBodyField {
    pub key: String,
    pub value_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthStatus {
    NotRequired,
    Satisfied,
    Missing,
    Invalid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackClass {
    SqlInjection,
    Xss,
    CommandInjection,
    PathTraversal,
    HeaderInjection,
    RequestSmuggling,
    Ssrf,
    BrokenAuthentication,
    BruteForce,
    RateLimitExceeded,
    MethodAbuse,
    PayloadEvasion,
    MissingSecurityHeaders,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingEvidence {
    pub location: String,
    pub value_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub attack_class: AttackClass,
    pub severity: Severity,
    pub confidence: f32,
    pub message: String,
    pub evidence: Vec<FindingEvidence>,
    pub mode: RuleMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub action_key: String,
    pub title: String,
    pub rationale: String,
    pub risk: String,
    pub rollback_hint: String,
    pub parameters: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MitigationAction {
    BlockRequest,
    BlockSourceIpTemporary { ttl_secs: u64 },
    ThrottleSource { ttl_secs: u64 },
    MarkSourceSuspicious { ttl_secs: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DecisionOutcome {
    Allow,
    Reject { status_code: u16, message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityDecision {
    pub outcome: DecisionOutcome,
    pub actions: Vec<MitigationAction>,
    pub recommendations: Vec<Recommendation>,
    pub findings: Vec<Finding>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub request_id: String,
    pub timestamp: DateTime<Utc>,
    pub source_ip: String,
    pub method: String,
    pub path: String,
    pub findings: Vec<Finding>,
    pub decision: SecurityDecision,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceReputation {
    pub source_ip: String,
    pub suspicious_score: i32,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperatorActionKind {
    BlockIpTemporary,
    UnblockIp,
    TightenRouteRateLimit,
    SwitchRuleMode,
    ResetReputation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorActionCommand {
    pub kind: OperatorActionKind,
    pub title: String,
    pub rationale: String,
    pub reversible: bool,
    pub parameters: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminAudit {
    pub timestamp: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub result: String,
    pub details: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct EventSearchFilters {
    pub source_ip: Option<String>,
    pub rule_id: Option<String>,
    pub severity: Option<String>,
    pub method: Option<String>,
    pub path_contains: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuditSearchFilters {
    pub actor: Option<String>,
    pub action: Option<String>,
    pub target: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ManualBlockRequest {
    pub source_ip: String,
    pub ttl_secs: Option<u64>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SetGlobalRuleModeRequest {
    pub rule_id: String,
    pub mode: RuleMode,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpsertRouteOverrideRequest {
    pub path_prefix: String,
    pub rule_modes: HashMap<String, RuleMode>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeleteRouteOverrideRequest {
    pub path_prefix: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpsertRouteRateLimitRequest {
    pub path_prefix: String,
    pub requests_per_window: u64,
    pub window_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeleteRouteRateLimitRequest {
    pub path_prefix: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminResponse<T: Serialize> {
    pub ok: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

pub fn ok<T: Serialize>(data: T) -> AdminResponse<T> {
    AdminResponse {
        ok: true,
        data: Some(data),
        error: None,
    }
}

pub fn err<T: Serialize>(message: impl Into<String>) -> AdminResponse<T> {
    AdminResponse {
        ok: false,
        data: None,
        error: Some(message.into()),
    }
}

pub fn resolve_rule_mode(state: &AppState, path: &str, rule_id: &str) -> RuleMode {
    let guard = state.policy_state.read().expect("policy_state poisoned");

    for route_override in &guard.route_overrides {
        if path.starts_with(&route_override.path_prefix) {
            if let Some(mode) = route_override.rule_modes.get(rule_id) {
                return mode.clone();
            }
        }
    }

    guard
        .global_rule_modes
        .get(rule_id)
        .cloned()
        .unwrap_or(RuleMode::DetectOnly)
}

pub fn resolve_rate_limit_for_path(state: &AppState, path: &str) -> (String, u64, u64) {
    let guard = state.policy_state.read().expect("policy_state poisoned");

    for route in &guard.route_rate_limits {
        if path.starts_with(&route.path_prefix) {
            return (
                route.path_prefix.clone(),
                route.requests_per_window,
                route.window_secs,
            );
        }
    }

    (
        "default".to_string(),
        state.config.security.rate_limit.requests_per_window,
        state.config.security.rate_limit.window_secs,
    )
}