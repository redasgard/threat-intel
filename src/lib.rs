//! # Valkra Threat Intelligence
//!
//! A comprehensive threat intelligence framework for Rust applications with multi-source
//! aggregation, CVE integration, and risk assessment.
//!
//! ## Features
//!
//! - **Multi-Source Aggregation**: Combine intelligence from MITRE ATT&CK, CVE databases, OSINT sources
//! - **HTTP Fetching**: Built-in support for authenticated API calls with retry logic
//! - **Multiple Auth Methods**: API Key, Bearer token, Basic auth support
//! - **Format Parsers**: JSON, XML (future), STIX (future) support
//! - **Configurable Updates**: Realtime, hourly, daily, weekly, or manual sync
//! - **Priority Management**: Source prioritization for conflict resolution
//! - **Capability-Based**: Query sources by capability (vulnerabilities, IOCs, tactics, etc.)
//! - **Risk Assessment**: Built-in risk scoring and assessment
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use threat_intel::{ThreatIntelConfig, ThreatIntelEngine};
//!
//! # async fn example() -> anyhow::Result<()> {
//! // Create config with default sources (MITRE ATT&CK, CVE, Abuse.ch)
//! let config = ThreatIntelConfig::default();
//!
//! // Create engine
//! let mut engine = ThreatIntelEngine::new(config);
//!
//! // Initialize (fetches from sources)
//! engine.initialize().await?;
//!
//! // Query for vulnerabilities
//! let vulns = engine.query_vulnerabilities("apache", "2.4").await?;
//! println!("Found {} vulnerabilities", vulns.len());
//! # Ok(())
//! # }
//! ```

pub mod config;
pub mod sources;
pub mod feeds;
pub mod error;

pub use config::*;
pub use sources::*;
pub use feeds::*;
pub use error::ThreatIntelError;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Optional tracing support
#[cfg(feature = "tracing")]
use tracing::{error, info, warn};

#[cfg(not(feature = "tracing"))]
macro_rules! info {
    ($($arg:tt)*) => {};
}

#[cfg(not(feature = "tracing"))]
macro_rules! warn {
    ($($arg:tt)*) => {
        eprintln!("WARN: {}", format!($($arg)*));
    };
}

/// Main threat intelligence engine
pub struct ThreatIntelEngine {
    config: ThreatIntelConfig,
    sources: HashMap<String, Box<dyn ThreatSource>>,
    last_sync: Option<DateTime<Utc>>,
    cache: ThreatCache,
}

impl ThreatIntelEngine {
    /// Create a new threat intelligence engine with the given configuration
    pub fn new(config: ThreatIntelConfig) -> Self {
        Self {
            config,
            sources: HashMap::new(),
            last_sync: None,
            cache: ThreatCache::new(),
        }
    }

    /// Initialize the engine by loading all enabled sources
    pub async fn initialize(&mut self) -> Result<()> {
        info!("Initializing threat intelligence engine...");

        for source_config in self.config.get_enabled_sources() {
            info!("Initializing source: {}", source_config.name);

            match self.create_source(source_config).await {
                Ok(source) => {
                    self.sources.insert(source_config.id.clone(), source);
                }
                Err(e) => {
                    warn!("Failed to initialize source {}: {}", source_config.name, e);
                    // Continue with other sources
                }
            }
        }

        info!(
            "Threat intelligence engine initialized with {} sources",
            self.sources.len()
        );

        // Perform initial sync
        self.sync().await?;

        Ok(())
    }

    /// Sync all sources to get latest intelligence
    pub async fn sync(&mut self) -> Result<()> {
        info!("Syncing threat intelligence sources...");

        for (id, source) in &mut self.sources {
            match source.fetch().await {
                Ok(data) => {
                    info!("Successfully synced source: {}", id);
                    self.cache.update(id, data);
                }
                Err(e) => {
                    warn!("Failed to sync source {}: {}", id, e);
                    // Continue with other sources
                }
            }
        }

        self.last_sync = Some(Utc::now());
        Ok(())
    }

    /// Query for vulnerabilities matching a product and version
    pub async fn query_vulnerabilities(
        &self,
        product: &str,
        version: &str,
    ) -> Result<Vec<Vulnerability>> {
        let sources = self
            .config
            .get_sources_by_capability(SourceCapability::Vulnerabilities);

        let mut results = Vec::new();

        for source_config in sources {
            if let Some(data) = self.cache.get(&source_config.id) {
                let vulns = data.vulnerabilities.iter()
                    .filter(|v| {
                        v.affected_products.iter().any(|p| {
                            p.product.to_lowercase().contains(&product.to_lowercase())
                                && p.version.contains(version)
                        })
                    })
                    .cloned()
                    .collect::<Vec<_>>();

                results.extend(vulns);
            }
        }

        Ok(results)
    }

    /// Query for IOCs (Indicators of Compromise)
    pub async fn query_iocs(&self, ioc_type: IOCType) -> Result<Vec<IOC>> {
        let sources = self
            .config
            .get_sources_by_capability(SourceCapability::Ioc);

        let mut results = Vec::new();

        for source_config in sources {
            if let Some(data) = self.cache.get(&source_config.id) {
                let iocs = data.iocs.iter()
                    .filter(|ioc| ioc.ioc_type == ioc_type)
                    .cloned()
                    .collect::<Vec<_>>();

                results.extend(iocs);
            }
        }

        Ok(results)
    }

    /// Get threat actors by name or alias
    pub async fn query_threat_actors(&self, query: &str) -> Result<Vec<ThreatActor>> {
        let sources = self
            .config
            .get_sources_by_capability(SourceCapability::ThreatActors);

        let mut results = Vec::new();
        let query_lower = query.to_lowercase();

        for source_config in sources {
            if let Some(data) = self.cache.get(&source_config.id) {
                let actors = data.threat_actors.iter()
                    .filter(|actor| {
                        actor.name.to_lowercase().contains(&query_lower)
                            || actor.aliases.iter().any(|a| a.to_lowercase().contains(&query_lower))
                    })
                    .cloned()
                    .collect::<Vec<_>>();

                results.extend(actors);
            }
        }

        Ok(results)
    }

    /// Assess risk for a given context
    pub fn assess_risk(&self, vulnerabilities: &[Vulnerability]) -> RiskAssessment {
        let critical_count = vulnerabilities.iter().filter(|v| v.severity == Severity::Critical).count();
        let high_count = vulnerabilities.iter().filter(|v| v.severity == Severity::High).count();
        let medium_count = vulnerabilities.iter().filter(|v| v.severity == Severity::Medium).count();
        let low_count = vulnerabilities.iter().filter(|v| v.severity == Severity::Low).count();

        let score = (critical_count * 10 + high_count * 7 + medium_count * 4 + low_count * 1) as f32;

        let level = if critical_count > 0 {
            RiskLevel::Critical
        } else if high_count >= 3 {
            RiskLevel::High
        } else if high_count > 0 || medium_count >= 5 {
            RiskLevel::Medium
        } else if medium_count > 0 || low_count > 0 {
            RiskLevel::Low
        } else {
            RiskLevel::Info
        };

        RiskAssessment {
            level,
            score,
            critical_count,
            high_count,
            medium_count,
            low_count,
            recommendations: generate_recommendations(&level, vulnerabilities),
        }
    }

    /// Get statistics about cached intelligence
    pub fn get_stats(&self) -> ThreatIntelStats {
        let mut total_vulnerabilities = 0;
        let mut total_iocs = 0;
        let mut total_threat_actors = 0;

        for data in self.cache.cache.values() {
            total_vulnerabilities += data.vulnerabilities.len();
            total_iocs += data.iocs.len();
            total_threat_actors += data.threat_actors.len();
        }

        ThreatIntelStats {
            sources_count: self.sources.len(),
            total_vulnerabilities,
            total_iocs,
            total_threat_actors,
            last_sync: self.last_sync,
        }
    }

    // Private helper to create source instances
    async fn create_source(&self, config: &SourceConfig) -> Result<Box<dyn ThreatSource>> {
        match config.source_type {
            SourceType::MitreAttack => {
                Ok(Box::new(sources::MitreAttackSource::new(config.clone())))
            }
            SourceType::Cve => {
                Ok(Box::new(sources::CVESource::new(config.clone())))
            }
            SourceType::Osint => {
                Ok(Box::new(sources::OSINTSource::new(config.clone())))
            }
            SourceType::Commercial | SourceType::Custom => {
                Ok(Box::new(sources::GenericSource::new(config.clone())))
            }
        }
    }
}

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

/// Statistics about the threat intelligence cache
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelStats {
    pub sources_count: usize,
    pub total_vulnerabilities: usize,
    pub total_iocs: usize,
    pub total_threat_actors: usize,
    pub last_sync: Option<DateTime<Utc>>,
}

// Internal cache for threat intelligence data
struct ThreatCache {
    cache: HashMap<String, ThreatData>,
}

impl ThreatCache {
    fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    fn update(&mut self, source_id: &str, data: ThreatData) {
        self.cache.insert(source_id.to_string(), data);
    }

    fn get(&self, source_id: &str) -> Option<&ThreatData> {
        self.cache.get(source_id)
    }
}

/// Data returned from a threat intelligence source
#[derive(Debug, Clone, Default)]
pub struct ThreatData {
    pub vulnerabilities: Vec<Vulnerability>,
    pub iocs: Vec<IOC>,
    pub threat_actors: Vec<ThreatActor>,
    pub raw_data: Option<serde_json::Value>,
}

// Helper function to generate recommendations
fn generate_recommendations(level: &RiskLevel, vulns: &[Vulnerability]) -> Vec<String> {
    let mut recommendations = Vec::new();

    match level {
        RiskLevel::Critical => {
            recommendations.push("URGENT: Critical vulnerabilities detected. Patch immediately.".to_string());
            recommendations.push("Consider taking affected systems offline until patched.".to_string());
        }
        RiskLevel::High => {
            recommendations.push("High-priority vulnerabilities found. Patch within 24-48 hours.".to_string());
            recommendations.push("Implement compensating controls if immediate patching isn't possible.".to_string());
        }
        RiskLevel::Medium => {
            recommendations.push("Medium-severity issues detected. Schedule patching within 1 week.".to_string());
        }
        RiskLevel::Low => {
            recommendations.push("Low-severity issues found. Include in next regular maintenance.".to_string());
        }
        RiskLevel::Info => {
            recommendations.push("No significant security issues detected.".to_string());
        }
    }

    // Add specific CVE recommendations if available
    for vuln in vulns.iter().take(3) {
        if let Some(cve) = &vuln.cve_id {
            recommendations.push(format!("Review and remediate: {} - {}", cve, vuln.title));
        }
    }

    recommendations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_assessment_critical() {
        let vulns = vec![
            Vulnerability {
                id: "V-001".to_string(),
                cve_id: Some("CVE-2024-0001".to_string()),
                title: "Critical RCE".to_string(),
                description: "Remote code execution".to_string(),
                severity: Severity::Critical,
                cvss_score: Some(9.8),
                affected_products: vec![],
                published_date: Utc::now(),
                last_modified: Utc::now(),
                references: vec![],
            },
        ];

        let config = ThreatIntelConfig::default();
        let engine = ThreatIntelEngine::new(config);
        let assessment = engine.assess_risk(&vulns);

        assert_eq!(assessment.level, RiskLevel::Critical);
        assert_eq!(assessment.critical_count, 1);
        assert!(assessment.score > 0.0);
        assert!(!assessment.recommendations.is_empty());
    }

    #[test]
    fn test_risk_assessment_low() {
        let vulns = vec![
            Vulnerability {
                id: "V-002".to_string(),
                cve_id: Some("CVE-2024-0002".to_string()),
                title: "Info disclosure".to_string(),
                description: "Minor information leak".to_string(),
                severity: Severity::Low,
                cvss_score: Some(3.1),
                affected_products: vec![],
                published_date: Utc::now(),
                last_modified: Utc::now(),
                references: vec![],
            },
        ];

        let config = ThreatIntelConfig::default();
        let engine = ThreatIntelEngine::new(config);
        let assessment = engine.assess_risk(&vulns);

        assert_eq!(assessment.level, RiskLevel::Low);
        assert_eq!(assessment.low_count, 1);
    }

    #[test]
    fn test_engine_creation() {
        let config = ThreatIntelConfig::default();
        let engine = ThreatIntelEngine::new(config);

        let stats = engine.get_stats();
        assert_eq!(stats.sources_count, 0); // Not initialized yet
        assert_eq!(stats.total_vulnerabilities, 0);
    }
}

