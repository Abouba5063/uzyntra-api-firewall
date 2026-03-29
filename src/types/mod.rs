use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
};

use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::{
    config::{AppConfig, RuleMode},
    mitigation::TemporaryMitigationStore,
    rate_limit::RateLimiter,
};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub proxy_client: Client,
    pub rate_limiter: Arc<RateLimiter>,
    pub mitigation_store: Arc<TemporaryMitigationStore>,
    pub started_at: DateTime<Utc>,
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
    pub auth_status: AuthStatus,
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
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuditSearchFilters {
    pub actor: Option<String>,
    pub action: Option<String>,
    pub target: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<usize>,
}

pub fn resolve_rule_mode(state: &AppState, path: &str, rule_id: &str) -> RuleMode {
    for route_override in &state.config.security.route_overrides {
        if path.starts_with(&route_override.path_prefix) {
            if let Some(mode) = route_override.rule_modes.get(rule_id) {
                return mode.clone();
            }
        }
    }

    state
        .config
        .security
        .rule_modes
        .get(rule_id)
        .cloned()
        .unwrap_or(RuleMode::DetectOnly)
}