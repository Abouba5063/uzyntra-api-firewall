use std::{collections::HashMap, env, fs, path::PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub proxy: ProxyConfig,
    pub security: SecurityConfig,
    pub telemetry: TelemetryConfig,
    pub auth: AuthConfig,
    pub storage: StorageConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub public_bind_addr: String,
    pub admin_bind_addr: String,
    pub trust_x_forwarded_for: bool,
    pub environment: String,
    pub admin_public_health_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub upstream_base_url: String,
    pub connect_timeout_secs: u64,
    pub request_timeout_secs: u64,
    pub pool_idle_timeout_secs: u64,
    pub max_body_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub blocked_methods: Vec<String>,
    pub request_id_header: String,
    pub inspect_headers: bool,
    pub inspect_query_string: bool,
    pub inspect_body: bool,
    pub max_inspection_body_bytes: usize,
    pub temp_ban_secs: u64,
    pub temp_suspicious_secs: u64,
    pub suspicious_score_threshold: i32,
    pub rate_limit: RateLimitConfig,
    pub rule_modes: HashMap<String, RuleMode>,
    pub route_overrides: Vec<RoutePolicyOverride>,
    pub route_rate_limits: Vec<RouteRateLimitOverride>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_window: u64,
    pub window_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    pub log_level: String,
    pub security_event_log_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub sqlite_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub enabled: bool,
    pub header_name: String,
    pub api_keys: Vec<String>,
    pub protected_path_prefixes: Vec<String>,
    pub admin: AdminAuthConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminAuthConfig {
    pub enabled: bool,
    pub header_name: String,
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleMode {
    DetectOnly,
    Recommend,
    Block,
}

impl Default for RuleMode {
    fn default() -> Self {
        Self::DetectOnly
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutePolicyOverride {
    pub path_prefix: String,
    pub rule_modes: HashMap<String, RuleMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteRateLimitOverride {
    pub path_prefix: String,
    pub requests_per_window: u64,
    pub window_secs: u64,
}

impl AppConfig {
    pub fn load() -> Result<Self> {
        let config_path = env::var("APP_CONFIG_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("config/development.yaml"));

        let raw = fs::read_to_string(&config_path)
            .with_context(|| format!("failed reading config file: {}", config_path.display()))?;

        let mut config: AppConfig = serde_yaml::from_str(&raw)
            .with_context(|| format!("failed parsing YAML config: {}", config_path.display()))?;

        if let Ok(public_bind_addr) = env::var("FIREWALL_PUBLIC_BIND_ADDR") {
            config.server.public_bind_addr = public_bind_addr;
        }

        if let Ok(admin_bind_addr) = env::var("FIREWALL_ADMIN_BIND_ADDR") {
            config.server.admin_bind_addr = admin_bind_addr;
        }

        if let Ok(upstream) = env::var("UPSTREAM_BASE_URL") {
            config.proxy.upstream_base_url = upstream;
        }

        if let Ok(log_level) = env::var("RUST_LOG") {
            config.telemetry.log_level = log_level;
        }

        Ok(config)
    }
}