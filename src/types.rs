//! Type definitions for threat intelligence

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::constants::*;

/// Vulnerability information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub cve_id: Option<String>,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub cvss_score: Option<f32>,
    pub affected_products: Vec<AffectedProduct>,
    pub published_date: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    /// Get the numeric weight for risk scoring
    pub fn weight(&self) -> u32 {
        match self {
            Severity::Critical => CRITICAL_WEIGHT,
            Severity::High => HIGH_WEIGHT,
            Severity::Medium => MEDIUM_WEIGHT,
            Severity::Low => LOW_WEIGHT,
            Severity::Info => 0,
        }
    }

    /// Check if this severity is critical or high
    pub fn is_high_severity(&self) -> bool {
        matches!(self, Severity::Critical | Severity::High)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedProduct {
    pub vendor: String,
    pub product: String,
    pub version: String,
    pub platform: Option<String>,
}

/// Indicator of Compromise
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IOC {
    pub id: String,
    pub ioc_type: IOCType,
    pub value: String,
    pub description: Option<String>,
    pub confidence: f32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IOCType {
    IpAddress,
    Domain,
    Url,
    FileHash,
    Email,
    Other(String),
}

impl IOCType {
    /// Get the maximum allowed length for this IOC type
    pub fn max_length(&self) -> usize {
        match self {
            IOCType::Domain => MAX_DOMAIN_LENGTH,
            IOCType::Email => MAX_EMAIL_LENGTH,
            _ => MAX_IOC_VALUE_LENGTH,
        }
    }

    /// Validate the IOC value
    pub fn validate(&self, value: &str) -> bool {
        if value.len() > self.max_length() {
            return false;
        }

        match self {
            IOCType::IpAddress => self.validate_ip(value),
            IOCType::Domain => self.validate_domain(value),
            IOCType::Url => self.validate_url(value),
            IOCType::Email => self.validate_email(value),
            IOCType::FileHash => self.validate_hash(value),
            IOCType::Other(_) => true,
        }
    }

    fn validate_ip(&self, value: &str) -> bool {
        // Basic IP validation (IPv4 and IPv6)
        value.parse::<std::net::IpAddr>().is_ok()
    }

    fn validate_domain(&self, value: &str) -> bool {
        // Basic domain validation
        !value.is_empty() && !value.contains(' ') && value.len() <= MAX_DOMAIN_LENGTH
    }

    fn validate_url(&self, value: &str) -> bool {
        // Basic URL validation
        value.starts_with("http://") || value.starts_with("https://")
    }

    fn validate_email(&self, value: &str) -> bool {
        // Basic email validation
        value.contains('@') && value.len() <= MAX_EMAIL_LENGTH
    }

    fn validate_hash(&self, value: &str) -> bool {
        // Basic hash validation (hex string)
        value.len() == 32 || value.len() == 40 || value.len() == 64 // MD5, SHA1, SHA256
    }
}

/// Threat Actor information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActor {
    pub id: String,
    pub name: String,
    pub aliases: Vec<String>,
    pub description: String,
    pub tactics: Vec<String>,
    pub techniques: Vec<String>,
    pub first_seen: Option<DateTime<Utc>>,
    pub country: Option<String>,
    pub motivation: Option<String>,
}

/// Risk assessment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub level: RiskLevel,
    pub score: f32,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl RiskLevel {
    /// Get the priority order for this risk level
    pub fn priority(&self) -> u8 {
        match self {
            RiskLevel::Critical => 5,
            RiskLevel::High => 4,
            RiskLevel::Medium => 3,
            RiskLevel::Low => 2,
            RiskLevel::Info => 1,
        }
    }

    /// Check if this risk level requires immediate action
    pub fn requires_immediate_action(&self) -> bool {
        matches!(self, RiskLevel::Critical | RiskLevel::High)
    }
}

/// Statistics about the threat intelligence cache
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelStats {
    pub sources_count: usize,
    pub total_vulnerabilities: usize,
    pub total_iocs: usize,
    pub total_threat_actors: usize,
    pub last_sync: Option<DateTime<Utc>>,
}

/// Data returned from a threat intelligence source
#[derive(Debug, Clone, Default)]
pub struct ThreatData {
    pub vulnerabilities: Vec<Vulnerability>,
    pub iocs: Vec<IOC>,
    pub threat_actors: Vec<ThreatActor>,
    pub raw_data: Option<serde_json::Value>,
}

impl ThreatData {
    /// Create a new empty threat data instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a vulnerability to the data
    pub fn add_vulnerability(&mut self, vuln: Vulnerability) {
        self.vulnerabilities.push(vuln);
    }

    /// Add an IOC to the data
    pub fn add_ioc(&mut self, ioc: IOC) {
        self.iocs.push(ioc);
    }

    /// Add a threat actor to the data
    pub fn add_threat_actor(&mut self, actor: ThreatActor) {
        self.threat_actors.push(actor);
    }

    /// Get the total count of all data types
    pub fn total_count(&self) -> usize {
        self.vulnerabilities.len() + self.iocs.len() + self.threat_actors.len()
    }

    /// Check if the data is empty
    pub fn is_empty(&self) -> bool {
        self.vulnerabilities.is_empty() && self.iocs.is_empty() && self.threat_actors.is_empty()
    }
}
