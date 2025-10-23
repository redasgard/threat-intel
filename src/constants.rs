//! Constants for threat intelligence

// Risk scoring weights
pub const CRITICAL_WEIGHT: u32 = 10;
pub const HIGH_WEIGHT: u32 = 7;
pub const MEDIUM_WEIGHT: u32 = 4;
pub const LOW_WEIGHT: u32 = 1;

// Risk level thresholds
pub const HIGH_RISK_THRESHOLD: usize = 3;
pub const MEDIUM_RISK_THRESHOLD: usize = 5;

// Cache limits
pub const MAX_CACHE_SIZE: usize = 10000;
pub const MAX_VULNERABILITIES_PER_SOURCE: usize = 1000;
pub const MAX_IOCS_PER_SOURCE: usize = 1000;
pub const MAX_THREAT_ACTORS_PER_SOURCE: usize = 100;

// Sync intervals (in seconds)
pub const DEFAULT_SYNC_INTERVAL: u64 = 3600; // 1 hour
pub const REALTIME_SYNC_INTERVAL: u64 = 60; // 1 minute
pub const HOURLY_SYNC_INTERVAL: u64 = 3600; // 1 hour
pub const DAILY_SYNC_INTERVAL: u64 = 86400; // 24 hours
pub const WEEKLY_SYNC_INTERVAL: u64 = 604800; // 7 days

// HTTP request limits
pub const DEFAULT_TIMEOUT_SECONDS: u64 = 30;
pub const MAX_RETRIES: u32 = 3;
pub const RETRY_DELAY_MS: u64 = 1000;

// Confidence thresholds
pub const HIGH_CONFIDENCE_THRESHOLD: f32 = 0.8;
pub const MEDIUM_CONFIDENCE_THRESHOLD: f32 = 0.6;
pub const LOW_CONFIDENCE_THRESHOLD: f32 = 0.4;

// IOC type limits
pub const MAX_IOC_VALUE_LENGTH: usize = 1024;
pub const MAX_DOMAIN_LENGTH: usize = 253;
pub const MAX_EMAIL_LENGTH: usize = 320;

// Vulnerability limits
pub const MAX_VULNERABILITY_TITLE_LENGTH: usize = 500;
pub const MAX_VULNERABILITY_DESCRIPTION_LENGTH: usize = 10000;
pub const MAX_REFERENCES_PER_VULNERABILITY: usize = 100;

// Threat actor limits
pub const MAX_THREAT_ACTOR_NAME_LENGTH: usize = 200;
pub const MAX_THREAT_ACTOR_DESCRIPTION_LENGTH: usize = 5000;
pub const MAX_ALIASES_PER_THREAT_ACTOR: usize = 50;
