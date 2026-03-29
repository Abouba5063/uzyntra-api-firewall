use std::{fs, path::Path};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};

use crate::types::{AdminAudit, AuditSearchFilters, EventSearchFilters, SecurityEvent, Severity};

pub fn init_db(sqlite_path: &str) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;

    let conn = Connection::open(sqlite_path)
        .with_context(|| format!("failed to open SQLite database at {}", sqlite_path))?;

    conn.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;
        PRAGMA foreign_keys = ON;

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

    let fetch_limit = filters.limit.unwrap_or(20).clamp(1, 500).max(100);
    let mut stmt = conn.prepare(
        "SELECT event_json FROM security_events ORDER BY timestamp DESC LIMIT ?1"
    )?;

    let rows = stmt.query_map(params![fetch_limit as i64], |row| row.get::<_, String>(0))?;

    let mut items = Vec::new();
    for row in rows {
        let json = row?;
        let event: SecurityEvent = serde_json::from_str(&json)?;
        if matches_event(&event, filters)? {
            items.push(event);
        }
    }

    let final_limit = filters.limit.unwrap_or(20).clamp(1, 500);
    items.truncate(final_limit);

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

    let fetch_limit = filters.limit.unwrap_or(20).clamp(1, 500).max(100);
    let mut stmt = conn.prepare(
        "SELECT audit_json FROM admin_audits ORDER BY timestamp DESC LIMIT ?1"
    )?;

    let rows = stmt.query_map(params![fetch_limit as i64], |row| row.get::<_, String>(0))?;

    let mut items = Vec::new();
    for row in rows {
        let json = row?;
        let audit: AdminAudit = serde_json::from_str(&json)?;
        if matches_audit(&audit, filters)? {
            items.push(audit);
        }
    }

    let final_limit = filters.limit.unwrap_or(20).clamp(1, 500);
    items.truncate(final_limit);

    Ok(items)
}

fn matches_event(event: &SecurityEvent, filters: &EventSearchFilters) -> Result<bool> {
    if let Some(source_ip) = &filters.source_ip {
        if &event.source_ip != source_ip {
            return Ok(false);
        }
    }

    if let Some(method) = &filters.method {
        if !event.method.eq_ignore_ascii_case(method) {
            return Ok(false);
        }
    }

    if let Some(path_contains) = &filters.path_contains {
        if !event.path.contains(path_contains) {
            return Ok(false);
        }
    }

    if let Some(rule_id) = &filters.rule_id {
        if !event.findings.iter().any(|f| f.rule_id == *rule_id) {
            return Ok(false);
        }
    }

    if let Some(severity) = &filters.severity {
        let wanted = severity.to_ascii_lowercase();
        if !event
            .findings
            .iter()
            .any(|f| severity_to_name(&f.severity) == wanted)
        {
            return Ok(false);
        }
    }

    if let Some(since) = &filters.since {
        let since_dt = DateTime::parse_from_rfc3339(since)
            .with_context(|| format!("invalid since timestamp: {since}"))?
            .with_timezone(&Utc);

        if event.timestamp < since_dt {
            return Ok(false);
        }
    }

    if let Some(until) = &filters.until {
        let until_dt = DateTime::parse_from_rfc3339(until)
            .with_context(|| format!("invalid until timestamp: {until}"))?
            .with_timezone(&Utc);

        if event.timestamp > until_dt {
            return Ok(false);
        }
    }

    Ok(true)
}

fn matches_audit(audit: &AdminAudit, filters: &AuditSearchFilters) -> Result<bool> {
    if let Some(actor) = &filters.actor {
        if &audit.actor != actor {
            return Ok(false);
        }
    }

    if let Some(action) = &filters.action {
        if &audit.action != action {
            return Ok(false);
        }
    }

    if let Some(target) = &filters.target {
        if !audit.target.contains(target) {
            return Ok(false);
        }
    }

    if let Some(since) = &filters.since {
        let since_dt = DateTime::parse_from_rfc3339(since)
            .with_context(|| format!("invalid since timestamp: {since}"))?
            .with_timezone(&Utc);

        if audit.timestamp < since_dt {
            return Ok(false);
        }
    }

    if let Some(until) = &filters.until {
        let until_dt = DateTime::parse_from_rfc3339(until)
            .with_context(|| format!("invalid until timestamp: {until}"))?
            .with_timezone(&Utc);

        if audit.timestamp > until_dt {
            return Ok(false);
        }
    }

    Ok(true)
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

fn severity_to_name(severity: &Severity) -> String {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
    .to_string()
}