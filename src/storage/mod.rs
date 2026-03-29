use std::{fs, path::Path};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{
    params, params_from_iter,
    types::Value as SqlValue,
    Connection,
};

use crate::{
    mitigation::ActiveMitigation,
    types::{AdminAudit, AuditSearchFilters, EventSearchFilters, SecurityEvent, Severity, SourceReputation},
};

pub fn init_db(sqlite_path: &str) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;

    let conn = Connection::open(sqlite_path)
        .with_context(|| format!("failed to open SQLite database at {}", sqlite_path))?;

    conn.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL
        );

        INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
        VALUES (1, 'initial_sqlite_persistence', CURRENT_TIMESTAMP);

        INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
        VALUES (2, 'phase_7_pagination_and_admin_actions', CURRENT_TIMESTAMP);

        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            rule_ids TEXT NOT NULL,
            highest_severity TEXT NOT NULL,
            outcome TEXT NOT NULL,
            event_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_security_events_timestamp
            ON security_events(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_security_events_source_ip
            ON security_events(source_ip);
        CREATE INDEX IF NOT EXISTS idx_security_events_request_id
            ON security_events(request_id);
        CREATE INDEX IF NOT EXISTS idx_security_events_rule_ids
            ON security_events(rule_ids);
        CREATE INDEX IF NOT EXISTS idx_security_events_highest_severity
            ON security_events(highest_severity);
        CREATE INDEX IF NOT EXISTS idx_security_events_method
            ON security_events(method);
        CREATE INDEX IF NOT EXISTS idx_security_events_path
            ON security_events(path);

        CREATE TABLE IF NOT EXISTS admin_audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            result TEXT NOT NULL,
            details TEXT NOT NULL,
            audit_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_admin_audits_timestamp
            ON admin_audits(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_admin_audits_actor
            ON admin_audits(actor);
        CREATE INDEX IF NOT EXISTS idx_admin_audits_action
            ON admin_audits(action);
        CREATE INDEX IF NOT EXISTS idx_admin_audits_target
            ON admin_audits(target);

        CREATE TABLE IF NOT EXISTS active_mitigations (
            source_ip TEXT PRIMARY KEY,
            action_id TEXT NOT NULL,
            action_type TEXT NOT NULL,
            ttl_secs INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            reason TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_active_mitigations_expires_at
            ON active_mitigations(expires_at);

        CREATE TABLE IF NOT EXISTS reputations (
            source_ip TEXT PRIMARY KEY,
            suspicious_score INTEGER NOT NULL,
            last_seen_at TEXT NOT NULL
        );
        "#,
    )?;

    Ok(())
}

pub fn persist_security_event(sqlite_path: &str, event: &SecurityEvent) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;

    let conn = Connection::open(sqlite_path)
        .with_context(|| format!("failed to open SQLite database at {}", sqlite_path))?;

    let json = serde_json::to_string(event)?;
    let rule_ids = event
        .findings
        .iter()
        .map(|f| f.rule_id.clone())
        .collect::<Vec<_>>()
        .join(",");

    let highest_severity = event
        .findings
        .iter()
        .map(|f| severity_rank(&f.severity))
        .max()
        .map(rank_to_severity_name)
        .unwrap_or("low")
        .to_string();

    let outcome = match &event.decision.outcome {
        crate::types::DecisionOutcome::Allow => "allow".to_string(),
        crate::types::DecisionOutcome::Reject { status_code, .. } => {
            format!("reject:{status_code}")
        }
    };

    conn.execute(
        r#"
        INSERT INTO security_events
        (request_id, timestamp, source_ip, method, path, rule_ids, highest_severity, outcome, event_json)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#,
        params![
            event.request_id,
            event.timestamp.to_rfc3339(),
            event.source_ip,
            event.method,
            event.path,
            rule_ids,
            highest_severity,
            outcome,
            json
        ],
    )?;

    Ok(())
}

pub fn persist_admin_audit(sqlite_path: &str, audit: &AdminAudit) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;

    let conn = Connection::open(sqlite_path)
        .with_context(|| format!("failed to open SQLite database at {}", sqlite_path))?;

    let json = serde_json::to_string(audit)?;

    conn.execute(
        r#"
        INSERT INTO admin_audits
        (timestamp, actor, action, target, result, details, audit_json)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
        params![
            audit.timestamp.to_rfc3339(),
            audit.actor,
            audit.action,
            audit.target,
            audit.result,
            audit.details,
            json
        ],
    )?;

    Ok(())
}

pub fn query_security_events(
    sqlite_path: &str,
    filters: &EventSearchFilters,
) -> Result<Vec<SecurityEvent>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(sqlite_path)
        .with_context(|| format!("failed to open SQLite database at {}", sqlite_path))?;

    let mut sql = String::from("SELECT event_json FROM security_events WHERE 1=1");
    let mut values: Vec<SqlValue> = Vec::new();

    if let Some(source_ip) = &filters.source_ip {
        sql.push_str(" AND source_ip = ?");
        values.push(SqlValue::Text(source_ip.clone()));
    }

    if let Some(rule_id) = &filters.rule_id {
        sql.push_str(" AND rule_ids LIKE ?");
        values.push(SqlValue::Text(format!("%{}%", rule_id)));
    }

    if let Some(severity) = &filters.severity {
        sql.push_str(" AND highest_severity = ?");
        values.push(SqlValue::Text(severity.to_ascii_lowercase()));
    }

    if let Some(method) = &filters.method {
        sql.push_str(" AND method = ?");
        values.push(SqlValue::Text(method.to_ascii_uppercase()));
    }

    if let Some(path_contains) = &filters.path_contains {
        sql.push_str(" AND path LIKE ?");
        values.push(SqlValue::Text(format!("%{}%", path_contains)));
    }

    if let Some(since) = &filters.since {
        sql.push_str(" AND timestamp >= ?");
        values.push(SqlValue::Text(normalize_rfc3339(since)?));
    }

    if let Some(until) = &filters.until {
        sql.push_str(" AND timestamp <= ?");
        values.push(SqlValue::Text(normalize_rfc3339(until)?));
    }

    sql.push_str(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");
    values.push(SqlValue::Integer(filters.limit.unwrap_or(20).clamp(1, 500) as i64));
    values.push(SqlValue::Integer(filters.offset.unwrap_or(0) as i64));

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(values.iter()), |row| row.get::<_, String>(0))?;

    let mut items = Vec::new();
    for row in rows {
        let json = row?;
        let event: SecurityEvent = serde_json::from_str(&json)?;
        items.push(event);
    }

    Ok(items)
}

pub fn query_admin_audits(
    sqlite_path: &str,
    filters: &AuditSearchFilters,
) -> Result<Vec<AdminAudit>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(sqlite_path)
        .with_context(|| format!("failed to open SQLite database at {}", sqlite_path))?;

    let mut sql = String::from("SELECT audit_json FROM admin_audits WHERE 1=1");
    let mut values: Vec<SqlValue> = Vec::new();

    if let Some(actor) = &filters.actor {
        sql.push_str(" AND actor = ?");
        values.push(SqlValue::Text(actor.clone()));
    }

    if let Some(action) = &filters.action {
        sql.push_str(" AND action = ?");
        values.push(SqlValue::Text(action.clone()));
    }

    if let Some(target) = &filters.target {
        sql.push_str(" AND target LIKE ?");
        values.push(SqlValue::Text(format!("%{}%", target)));
    }

    if let Some(since) = &filters.since {
        sql.push_str(" AND timestamp >= ?");
        values.push(SqlValue::Text(normalize_rfc3339(since)?));
    }

    if let Some(until) = &filters.until {
        sql.push_str(" AND timestamp <= ?");
        values.push(SqlValue::Text(normalize_rfc3339(until)?));
    }

    sql.push_str(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");
    values.push(SqlValue::Integer(filters.limit.unwrap_or(20).clamp(1, 500) as i64));
    values.push(SqlValue::Integer(filters.offset.unwrap_or(0) as i64));

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(values.iter()), |row| row.get::<_, String>(0))?;

    let mut items = Vec::new();
    for row in rows {
        let json = row?;
        let audit: AdminAudit = serde_json::from_str(&json)?;
        items.push(audit);
    }

    Ok(items)
}

pub fn upsert_active_mitigation(sqlite_path: &str, mitigation: &ActiveMitigation) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;

    let conn = Connection::open(sqlite_path)?;
    let (action_type, ttl_secs) = match mitigation.action {
        crate::types::MitigationAction::BlockSourceIpTemporary { ttl_secs } => {
            ("block_source_ip_temporary".to_string(), ttl_secs as i64)
        }
        crate::types::MitigationAction::ThrottleSource { ttl_secs } => {
            ("throttle_source".to_string(), ttl_secs as i64)
        }
        crate::types::MitigationAction::MarkSourceSuspicious { ttl_secs } => {
            ("mark_source_suspicious".to_string(), ttl_secs as i64)
        }
        crate::types::MitigationAction::BlockRequest => ("block_request".to_string(), 0),
    };

    conn.execute(
        r#"
        INSERT INTO active_mitigations
        (source_ip, action_id, action_type, ttl_secs, created_at, expires_at, reason)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT(source_ip) DO UPDATE SET
            action_id = excluded.action_id,
            action_type = excluded.action_type,
            ttl_secs = excluded.ttl_secs,
            created_at = excluded.created_at,
            expires_at = excluded.expires_at,
            reason = excluded.reason
        "#,
        params![
            mitigation.source_ip.to_string(),
            mitigation.action_id,
            action_type,
            ttl_secs,
            mitigation.created_at.to_rfc3339(),
            mitigation.expires_at.to_rfc3339(),
            mitigation.reason
        ],
    )?;

    Ok(())
}

pub fn delete_active_mitigation(sqlite_path: &str, source_ip: &str) -> Result<()> {
    let conn = Connection::open(sqlite_path)?;
    conn.execute(
        "DELETE FROM active_mitigations WHERE source_ip = ?1",
        params![source_ip],
    )?;
    Ok(())
}

pub fn load_active_mitigations(sqlite_path: &str) -> Result<Vec<ActiveMitigation>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(sqlite_path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT source_ip, action_id, action_type, ttl_secs, created_at, expires_at, reason
        FROM active_mitigations
        ORDER BY expires_at ASC
        "#,
    )?;

    let rows = stmt.query_map([], |row| {
        let source_ip: String = row.get(0)?;
        let action_id: String = row.get(1)?;
        let action_type: String = row.get(2)?;
        let ttl_secs: i64 = row.get(3)?;
        let created_at: String = row.get(4)?;
        let expires_at: String = row.get(5)?;
        let reason: String = row.get(6)?;

        let action = match action_type.as_str() {
            "block_source_ip_temporary" => {
                crate::types::MitigationAction::BlockSourceIpTemporary { ttl_secs: ttl_secs as u64 }
            }
            "throttle_source" => crate::types::MitigationAction::ThrottleSource { ttl_secs: ttl_secs as u64 },
            "mark_source_suspicious" => {
                crate::types::MitigationAction::MarkSourceSuspicious { ttl_secs: ttl_secs as u64 }
            }
            _ => crate::types::MitigationAction::BlockSourceIpTemporary { ttl_secs: ttl_secs as u64 },
        };

        Ok(ActiveMitigation {
            action_id,
            source_ip: source_ip.parse().map_err(|_| rusqlite::Error::InvalidQuery)?,
            action,
            created_at: parse_rfc3339_to_utc(&created_at).map_err(|_| rusqlite::Error::InvalidQuery)?,
            expires_at: parse_rfc3339_to_utc(&expires_at).map_err(|_| rusqlite::Error::InvalidQuery)?,
            reason,
        })
    })?;

    let mut items = Vec::new();
    for row in rows {
        items.push(row?);
    }

    Ok(items)
}

pub fn upsert_reputation(sqlite_path: &str, reputation: &SourceReputation) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;

    let conn = Connection::open(sqlite_path)?;
    conn.execute(
        r#"
        INSERT INTO reputations (source_ip, suspicious_score, last_seen_at)
        VALUES (?1, ?2, ?3)
        ON CONFLICT(source_ip) DO UPDATE SET
            suspicious_score = excluded.suspicious_score,
            last_seen_at = excluded.last_seen_at
        "#,
        params![
            reputation.source_ip,
            reputation.suspicious_score,
            reputation.last_seen_at.to_rfc3339()
        ],
    )?;
    Ok(())
}

pub fn load_reputations(sqlite_path: &str) -> Result<Vec<SourceReputation>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(sqlite_path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT source_ip, suspicious_score, last_seen_at
        FROM reputations
        ORDER BY last_seen_at DESC
        "#,
    )?;

    let rows = stmt.query_map([], |row| {
        let source_ip: String = row.get(0)?;
        let suspicious_score: i32 = row.get(1)?;
        let last_seen_at: String = row.get(2)?;

        Ok(SourceReputation {
            source_ip,
            suspicious_score,
            last_seen_at: parse_rfc3339_to_utc(&last_seen_at).map_err(|_| rusqlite::Error::InvalidQuery)?,
        })
    })?;

    let mut items = Vec::new();
    for row in rows {
        items.push(row?);
    }

    Ok(items)
}

pub fn delete_reputation(sqlite_path: &str, source_ip: &str) -> Result<()> {
    let conn = Connection::open(sqlite_path)?;
    conn.execute("DELETE FROM reputations WHERE source_ip = ?1", params![source_ip])?;
    Ok(())
}

pub fn metrics_snapshot(sqlite_path: &str) -> Result<StorageMetrics> {
    if !Path::new(sqlite_path).exists() {
        return Ok(StorageMetrics::default());
    }

    let conn = Connection::open(sqlite_path)?;

    let total_events: i64 = conn.query_row(
        "SELECT COUNT(*) FROM security_events",
        [],
        |row| row.get(0),
    )?;

    let blocked_events: i64 = conn.query_row(
        "SELECT COUNT(*) FROM security_events WHERE outcome LIKE 'reject:%'",
        [],
        |row| row.get(0),
    )?;

    let total_audits: i64 = conn.query_row(
        "SELECT COUNT(*) FROM admin_audits",
        [],
        |row| row.get(0),
    )?;

    let persisted_active_mitigations: i64 = conn.query_row(
        "SELECT COUNT(*) FROM active_mitigations",
        [],
        |row| row.get(0),
    )?;

    let persisted_reputations: i64 = conn.query_row(
        "SELECT COUNT(*) FROM reputations",
        [],
        |row| row.get(0),
    )?;

    let latest_rule_ids: Option<String> = conn
        .query_row(
            r#"
            SELECT rule_ids
            FROM security_events
            WHERE rule_ids <> ''
            ORDER BY timestamp DESC
            LIMIT 1
            "#,
            [],
            |row| row.get(0),
        )
        .ok();

    Ok(StorageMetrics {
        total_events,
        blocked_events,
        total_audits,
        latest_rule_ids: latest_rule_ids.unwrap_or_default(),
        persisted_active_mitigations,
        persisted_reputations,
    })
}

#[derive(Debug, Default)]
pub struct StorageMetrics {
    pub total_events: i64,
    pub blocked_events: i64,
    pub total_audits: i64,
    pub latest_rule_ids: String,
    pub persisted_active_mitigations: i64,
    pub persisted_reputations: i64,
}

fn ensure_parent_dir(path: &str) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

fn severity_rank(severity: &Severity) -> i32 {
    match severity {
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

fn rank_to_severity_name(rank: i32) -> &'static str {
    match rank {
        4 => "critical",
        3 => "high",
        2 => "medium",
        _ => "low",
    }
}

fn normalize_rfc3339(input: &str) -> Result<String> {
    Ok(parse_rfc3339_to_utc(input)?.to_rfc3339())
}

fn parse_rfc3339_to_utc(input: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(input)?.with_timezone(&Utc))
}