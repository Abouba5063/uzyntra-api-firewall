use std::{
    collections::HashMap,
    net::IpAddr,
};

use axum::{
    body::Body,
    http::{HeaderValue, Response, StatusCode},
};
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use tracing::{info, warn};
use uuid::Uuid;

use crate::types::{
    AppState, DecisionOutcome, MitigationAction, OperatorActionCommand, OperatorActionKind,
    Recommendation, RequestContext, SecurityDecision, SourceReputation,
};

#[derive(Debug, Clone)]
pub struct ActiveMitigation {
    pub action_id: String,
    pub source_ip: IpAddr,
    pub action: MitigationAction,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct TemporaryMitigationStore {
    blocks: DashMap<IpAddr, ActiveMitigation>,
    reputation: DashMap<IpAddr, SourceReputationEntry>,
}

#[derive(Debug, Clone)]
struct SourceReputationEntry {
    suspicious_score: i32,
    last_seen_at: DateTime<Utc>,
}

impl TemporaryMitigationStore {
    pub fn get_active_block(&self, ip: &IpAddr) -> Option<ActiveMitigation> {
        let entry = self.blocks.get(ip)?;
        let mitigation = entry.value().clone();

        if mitigation.expires_at <= Utc::now() {
            drop(entry);
            self.blocks.remove(ip);
            return None;
        }

        Some(mitigation)
    }

    pub fn block_ip_for(&self, ip: IpAddr, seconds: u64, reason: String) -> ActiveMitigation {
        let mitigation = ActiveMitigation {
            action_id: Uuid::new_v4().to_string(),
            source_ip: ip,
            action: MitigationAction::BlockSourceIpTemporary { ttl_secs: seconds },
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(seconds as i64),
            reason,
        };

        self.blocks.insert(ip, mitigation.clone());
        mitigation
    }

    pub fn cleanup_expired(&self) -> usize {
        let now = Utc::now();
        let expired: Vec<IpAddr> = self
            .blocks
            .iter()
            .filter_map(|entry| {
                if entry.value().expires_at <= now {
                    Some(*entry.key())
                } else {
                    None
                }
            })
            .collect();

        let count = expired.len();

        for ip in expired {
            self.blocks.remove(&ip);
        }

        count
    }

    pub fn active_block_count(&self) -> usize {
        self.blocks.len()
    }

    pub fn list_active_blocks(&self) -> Vec<ActiveMitigation> {
        let now = Utc::now();
        self.blocks
            .iter()
            .filter_map(|entry| {
                let mitigation = entry.value().clone();
                if mitigation.expires_at > now {
                    Some(mitigation)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn unblock_ip(&self, ip: IpAddr) -> bool {
        self.blocks.remove(&ip).is_some()
    }

    pub fn add_suspicious_score(&self, ip: IpAddr, delta: i32) -> SourceReputation {
        let now = Utc::now();
        let score = match self.reputation.get_mut(&ip) {
            Some(mut entry) => {
                entry.suspicious_score += delta;
                entry.last_seen_at = now;
                entry.suspicious_score
            }
            None => {
                self.reputation.insert(
                    ip,
                    SourceReputationEntry {
                        suspicious_score: delta,
                        last_seen_at: now,
                    },
                );
                delta
            }
        };

        SourceReputation {
            source_ip: ip.to_string(),
            suspicious_score: score,
            last_seen_at: now,
        }
    }

    pub fn get_reputation(&self, ip: IpAddr) -> SourceReputation {
        if let Some(entry) = self.reputation.get(&ip) {
            return SourceReputation {
                source_ip: ip.to_string(),
                suspicious_score: entry.suspicious_score,
                last_seen_at: entry.last_seen_at,
            };
        }

        SourceReputation {
            source_ip: ip.to_string(),
            suspicious_score: 0,
            last_seen_at: Utc::now(),
        }
    }

    pub fn list_reputations(&self) -> Vec<SourceReputation> {
        self.reputation
            .iter()
            .map(|entry| SourceReputation {
                source_ip: entry.key().to_string(),
                suspicious_score: entry.value().suspicious_score,
                last_seen_at: entry.value().last_seen_at,
            })
            .collect()
    }
}

pub fn finalize_blocking_decision(
    state: &AppState,
    context: &RequestContext,
    decision: SecurityDecision,
) -> Response<Body> {
    let reputation_delta = calculate_reputation_delta(&decision);
    let reputation = if reputation_delta > 0 {
        Some(
            state
                .mitigation_store
                .add_suspicious_score(context.source_ip, reputation_delta),
        )
    } else {
        None
    };

    for action in &decision.actions {
        match action {
            MitigationAction::BlockSourceIpTemporary { ttl_secs } => {
                let mitigation = state.mitigation_store.block_ip_for(
                    context.source_ip,
                    *ttl_secs,
                    decision.summary.clone(),
                );

                warn!(
                    request_id = %context.request_id,
                    source_ip = %context.source_ip,
                    action_id = %mitigation.action_id,
                    ttl_secs = ttl_secs,
                    "temporary IP block applied"
                );
            }
            MitigationAction::MarkSourceSuspicious { .. }
            | MitigationAction::ThrottleSource { .. }
            | MitigationAction::BlockRequest => {}
        }
    }

    if let Some(reputation) = reputation {
        if reputation.suspicious_score >= state.config.security.suspicious_score_threshold {
            let mitigation = state.mitigation_store.block_ip_for(
                context.source_ip,
                state.config.security.temp_ban_secs,
                format!(
                    "source exceeded suspicious score threshold ({})",
                    reputation.suspicious_score
                ),
            );

            warn!(
                request_id = %context.request_id,
                source_ip = %context.source_ip,
                action_id = %mitigation.action_id,
                suspicious_score = reputation.suspicious_score,
                "automatic block applied due to suspicious score threshold"
            );
        }
    }

    let (status, body) = match &decision.outcome {
        DecisionOutcome::Reject {
            status_code,
            message,
        } => {
            let status = StatusCode::from_u16(*status_code).unwrap_or(StatusCode::FORBIDDEN);
            (status, message.clone())
        }
        DecisionOutcome::Allow => (StatusCode::OK, "allowed".to_string()),
    };

    info!(
        request_id = %context.request_id,
        source_ip = %context.source_ip,
        status_code = status.as_u16(),
        summary = %decision.summary,
        "blocking decision finalized"
    );

    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;

    if let Ok(value) = HeaderValue::from_str(&context.request_id) {
        response.headers_mut().insert("x-request-id", value);
    }

    response
}

pub fn apply_non_blocking_effects(state: &AppState, context: &RequestContext, decision: &SecurityDecision) {
    let delta = calculate_reputation_delta(decision);
    if delta > 0 {
        let reputation = state.mitigation_store.add_suspicious_score(context.source_ip, delta);

        if reputation.suspicious_score >= state.config.security.suspicious_score_threshold {
            let mitigation = state.mitigation_store.block_ip_for(
                context.source_ip,
                state.config.security.temp_ban_secs,
                format!(
                    "source exceeded suspicious score threshold ({})",
                    reputation.suspicious_score
                ),
            );

            warn!(
                request_id = %context.request_id,
                source_ip = %context.source_ip,
                action_id = %mitigation.action_id,
                suspicious_score = reputation.suspicious_score,
                "automatic block applied due to suspicious score threshold"
            );
        }
    }
}

fn calculate_reputation_delta(decision: &SecurityDecision) -> i32 {
    let mut score = 0;

    for finding in &decision.findings {
        score += match finding.severity {
            crate::types::Severity::Low => 1,
            crate::types::Severity::Medium => 2,
            crate::types::Severity::High => 4,
            crate::types::Severity::Critical => 6,
        };
    }

    score
}

pub fn demo_recommendations() -> Vec<Recommendation> {
    vec![
        Recommendation {
            action_key: "block_ip_15m".into(),
            title: "Temporarily block source IP".into(),
            rationale: "Use for repeated high-confidence exploit probes or brute-force bursts."
                .into(),
            risk: "May affect shared NAT users; keep TTL short.".into(),
            rollback_hint: "Remove from temporary denylist or wait for expiry.".into(),
            parameters: hashmap(vec![("ttl_secs".into(), "900".into())]),
        },
        Recommendation {
            action_key: "tighten_route_rate_limit".into(),
            title: "Tighten route-level rate limit".into(),
            rationale: "Useful for login abuse, scraping spikes, and repeated credential attempts."
                .into(),
            risk: "Can increase friction for legitimate users during traffic bursts.".into(),
            rollback_hint: "Restore previous route limit policy.".into(),
            parameters: hashmap(vec![
                ("route".into(), "/login".into()),
                ("window_secs".into(), "60".into()),
                ("requests".into(), "5".into()),
            ]),
        },
    ]
}

pub fn recommendation_to_command(rec: &Recommendation) -> Option<OperatorActionCommand> {
    match rec.action_key.as_str() {
        "block_ip_15m" => Some(OperatorActionCommand {
            kind: OperatorActionKind::BlockIpTemporary,
            title: rec.title.clone(),
            rationale: rec.rationale.clone(),
            reversible: true,
            parameters: rec.parameters.clone(),
        }),
        "tighten_route_rate_limit" => Some(OperatorActionCommand {
            kind: OperatorActionKind::TightenRouteRateLimit,
            title: rec.title.clone(),
            rationale: rec.rationale.clone(),
            reversible: true,
            parameters: rec.parameters.clone(),
        }),
        "disable_unused_methods" => Some(OperatorActionCommand {
            kind: OperatorActionKind::SwitchRuleMode,
            title: rec.title.clone(),
            rationale: rec.rationale.clone(),
            reversible: true,
            parameters: rec.parameters.clone(),
        }),
        _ => None,
    }
}

fn hashmap(entries: Vec<(String, String)>) -> HashMap<String, String> {
    entries.into_iter().collect()
}