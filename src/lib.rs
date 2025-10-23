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

pub mod assessment;
pub mod config;
pub mod constants;
pub mod feeds;
pub mod sources;
pub mod types;

pub use assessment::*;
pub use config::*;
pub use constants::*;
pub use feeds::*;
pub use sources::*;
pub use types::*;

use anyhow::Result;
use chrono::{DateTime, Utc};
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
        assessment::assess_risk(vulnerabilities)
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