use anyhow::Result;
use tracing::{error, info};
use tracing_subscriber::{fmt, EnvFilter};

use crate::types::SecurityEvent;

pub fn init(log_level: &str) -> Result<()> {
    let filter = EnvFilter::try_new(log_level).or_else(|_| EnvFilter::try_new("info"))?;

    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .compact()
        .init();

    Ok(())
}

pub fn emit_security_event(event: &SecurityEvent) {
    match serde_json::to_string(event) {
        Ok(json) => info!(security_event = %json, "security event"),
        Err(err) => error!(error = %err, "failed to serialize security event"),
    }
}