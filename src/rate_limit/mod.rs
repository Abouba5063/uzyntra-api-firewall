use std::{
    net::IpAddr,
    time::{Duration, Instant},
};

use dashmap::DashMap;

use crate::types::{
    resolve_rule_mode, AppState, AttackClass, Finding, FindingEvidence, RequestContext, Severity,
};

#[derive(Debug, Clone)]
struct RateState {
    count: u64,
    window_start: Instant,
}

#[derive(Debug, Default)]
pub struct RateLimiter {
    limit: u64,
    window: Duration,
    entries: DashMap<IpAddr, RateState>,
}

impl RateLimiter {
    pub fn new(limit: u64, window_secs: u64) -> Self {
        Self {
            limit,
            window: Duration::from_secs(window_secs),
            entries: DashMap::new(),
        }
    }

    pub fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();

        match self.entries.get_mut(&ip) {
            Some(mut entry) => {
                if now.duration_since(entry.window_start) >= self.window {
                    entry.count = 1;
                    entry.window_start = now;
                    true
                } else {
                    entry.count += 1;
                    entry.count <= self.limit
                }
            }
            None => {
                self.entries.insert(
                    ip,
                    RateState {
                        count: 1,
                        window_start: now,
                    },
                );
                true
            }
        }
    }
}

pub fn evaluate_request(state: &AppState, context: &RequestContext) -> Option<Finding> {
    let allowed = state.rate_limiter.check(context.source_ip);

    if allowed {
        return None;
    }

    Some(Finding {
        rule_id: "rate_limit.exceeded".into(),
        attack_class: AttackClass::RateLimitExceeded,
        severity: Severity::High,
        confidence: 0.99,
        message: "rate limit exceeded".into(),
        evidence: vec![FindingEvidence {
            location: "source.ip".into(),
            value_preview: context.source_ip.to_string(),
        }],
        mode: resolve_rule_mode(state, &context.path, "rate_limit.exceeded"),
    })
}