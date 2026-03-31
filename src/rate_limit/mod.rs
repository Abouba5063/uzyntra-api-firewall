use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::types::{
    resolve_rate_limit_for_path, resolve_rule_mode, AppState, AttackClass, Finding,
    FindingEvidence, RequestContext, Severity,
};

#[derive(Debug, Clone)]
struct RateState {
    count: u64,
    window_start: Instant,
}

#[derive(Debug, Default)]
pub struct RateLimiter {
    entries: DashMap<String, RateState>,
}

impl RateLimiter {
    pub fn new(_limit: u64, _window_secs: u64) -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    pub fn check(&self, key: &str, limit: u64, window_secs: u64) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(window_secs);

        match self.entries.get_mut(key) {
            Some(mut entry) => {
                if now.duration_since(entry.window_start) >= window {
                    entry.count = 1;
                    entry.window_start = now;
                    true
                } else {
                    entry.count += 1;
                    entry.count <= limit
                }
            }
            None => {
                self.entries.insert(
                    key.to_string(),
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
    let (bucket, limit, window_secs) = resolve_rate_limit_for_path(state, &context.path);
    let key = format!("{}|{}", context.source_ip, bucket);

    let allowed = state.rate_limiter.check(&key, limit, window_secs);

    if allowed {
        return None;
    }

    Some(Finding {
        rule_id: "rate_limit.exceeded".into(),
        attack_class: AttackClass::RateLimitExceeded,
        severity: Severity::High,
        confidence: 0.99,
        message: format!(
            "rate limit exceeded for bucket '{}' ({} requests / {} seconds)",
            bucket, limit, window_secs
        ),
        evidence: vec![FindingEvidence {
            location: "source.ip".into(),
            value_preview: context.source_ip.to_string(),
        }],
        mode: resolve_rule_mode(state, &context.path, "rate_limit.exceeded"),
    })
}