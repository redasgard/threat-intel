//! Threat intelligence source implementations

use crate::{config::SourceConfig, feeds::FeedFetcher, ThreatData};
use anyhow::Result;
use async_trait::async_trait;

/// Trait for threat intelligence sources
#[async_trait]
pub trait ThreatSource: Send + Sync {
    /// Fetch latest threat intelligence data from the source
    async fn fetch(&mut self) -> Result<ThreatData>;

    /// Get the source configuration
    fn config(&self) -> &SourceConfig;

    /// Get the source name
    fn name(&self) -> &str {
        &self.config().name
    }
}

/// MITRE ATT&CK source implementation
pub struct MitreAttackSource {
    config: SourceConfig,
    fetcher: FeedFetcher,
}

impl MitreAttackSource {
    pub fn new(config: SourceConfig) -> Self {
        let fetcher = FeedFetcher::new(config.clone());
        Self { config, fetcher }
    }
}

#[async_trait]
impl ThreatSource for MitreAttackSource {
    async fn fetch(&mut self) -> Result<ThreatData> {
        let json = self.fetcher.fetch_json_secure().await?;

        // Parse MITRE ATT&CK JSON format
        // For now, return raw data
        Ok(ThreatData {
            vulnerabilities: vec![],
            iocs: vec![],
            threat_actors: vec![], // Would parse from JSON
            raw_data: Some(json),
        })
    }

    fn config(&self) -> &SourceConfig {
        &self.config
    }
}

/// CVE Database source implementation
pub struct CVESource {
    config: SourceConfig,
    fetcher: FeedFetcher,
}

impl CVESource {
    pub fn new(config: SourceConfig) -> Self {
        let fetcher = FeedFetcher::new(config.clone());
        Self { config, fetcher }
    }
}

#[async_trait]
impl ThreatSource for CVESource {
    async fn fetch(&mut self) -> Result<ThreatData> {
        let json = self.fetcher.fetch_json_secure().await?;

        // Parse CVE JSON format
        Ok(ThreatData {
            vulnerabilities: vec![], // Would parse from JSON
            iocs: vec![],
            threat_actors: vec![],
            raw_data: Some(json),
        })
    }

    fn config(&self) -> &SourceConfig {
        &self.config
    }
}

/// OSINT source implementation (Abuse.ch, etc.)
pub struct OSINTSource {
    config: SourceConfig,
    fetcher: FeedFetcher,
}

impl OSINTSource {
    pub fn new(config: SourceConfig) -> Self {
        let fetcher = FeedFetcher::new(config.clone());
        Self { config, fetcher }
    }
}

#[async_trait]
impl ThreatSource for OSINTSource {
    async fn fetch(&mut self) -> Result<ThreatData> {
        let json = self.fetcher.fetch_json_secure().await?;

        // Parse OSINT JSON format
        Ok(ThreatData {
            vulnerabilities: vec![],
            iocs: vec![], // Would parse IOCs from JSON
            threat_actors: vec![],
            raw_data: Some(json),
        })
    }

    fn config(&self) -> &SourceConfig {
        &self.config
    }
}

/// Generic source for custom/commercial feeds
pub struct GenericSource {
    config: SourceConfig,
    fetcher: FeedFetcher,
}

impl GenericSource {
    pub fn new(config: SourceConfig) -> Self {
        let fetcher = FeedFetcher::new(config.clone());
        Self { config, fetcher }
    }
}

#[async_trait]
impl ThreatSource for GenericSource {
    async fn fetch(&mut self) -> Result<ThreatData> {
        let json = self.fetcher.fetch_json_secure().await?;

        Ok(ThreatData {
            vulnerabilities: vec![],
            iocs: vec![],
            threat_actors: vec![],
            raw_data: Some(json),
        })
    }

    fn config(&self) -> &SourceConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthType, SourceCapability, SourceType, UpdateFrequency};

    fn create_test_config() -> SourceConfig {
        SourceConfig {
            id: "test".to_string(),
            name: "Test Source".to_string(),
            source_type: SourceType::Custom,
            enabled: true,
            api_url: Some("https://example.com/api".to_string()),
            api_key: None,
            auth_type: AuthType::None,
            update_frequency: UpdateFrequency::Manual,
            priority: 5,
            capabilities: vec![SourceCapability::Vulnerabilities],
            timeout_secs: 30,
            retry_count: 1,
        }
    }

    #[test]
    fn test_source_creation() {
        let config = create_test_config();
        let source = GenericSource::new(config.clone());

        assert_eq!(source.name(), "Test Source");
        assert_eq!(source.config().id, "test");
    }

    #[test]
    fn test_mitre_attack_source_creation() {
        let config = create_test_config();
        let source = MitreAttackSource::new(config);

        assert_eq!(source.name(), "Test Source");
    }

    #[test]
    fn test_cve_source_creation() {
        let config = create_test_config();
        let source = CVESource::new(config);

        assert_eq!(source.name(), "Test Source");
    }

    #[test]
    fn test_osint_source_creation() {
        let config = create_test_config();
        let source = OSINTSource::new(config);

        assert_eq!(source.name(), "Test Source");
    }
}

