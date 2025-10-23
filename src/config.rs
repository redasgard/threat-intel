//! Configuration types for threat intelligence sources

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Threat intelligence configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelConfig {
    pub enabled: bool,
    pub sources: HashMap<String, SourceConfig>,
    pub sync_interval_hours: u32,
    pub cache_enabled: bool,
    pub cache_ttl_hours: u32,
}

/// Configuration for a single threat intelligence source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceConfig {
    pub id: String,
    pub name: String,
    pub source_type: SourceType,
    pub enabled: bool,
    pub api_url: Option<String>,
    pub api_key: Option<String>,
    pub auth_type: AuthType,
    pub update_frequency: UpdateFrequency,
    pub priority: u32,
    pub capabilities: Vec<SourceCapability>,
    pub timeout_secs: u64,
    pub retry_count: u32,
}

/// Type of threat intelligence source
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SourceType {
    MitreAttack,
    Cve,
    Osint,
    Commercial,
    Custom,
}

/// Authentication method for API access
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuthType {
    None,
    ApiKey,
    Bearer,
    Basic,
}

/// Update frequency for threat intelligence
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UpdateFrequency {
    Realtime,
    Hourly,
    Daily,
    Weekly,
    Manual,
}

/// Capability provided by a threat intelligence source
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SourceCapability {
    Vulnerabilities,
    Exploits,
    ThreatActors,
    Ioc,
    Advisories,
    Tactics,
    Techniques,
    Malware,
    Patches,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        let mut sources = HashMap::new();

        // MITRE ATT&CK
        sources.insert(
            "mitre_attack".to_string(),
            SourceConfig {
                id: "mitre_attack".to_string(),
                name: "MITRE ATT&CK".to_string(),
                source_type: SourceType::MitreAttack,
                enabled: true,
                api_url: Some(
                    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
                        .to_string(),
                ),
                api_key: None,
                auth_type: AuthType::None,
                update_frequency: UpdateFrequency::Daily,
                priority: 10,
                capabilities: vec![
                    SourceCapability::ThreatActors,
                    SourceCapability::Tactics,
                    SourceCapability::Techniques,
                ],
                timeout_secs: 30,
                retry_count: 3,
            },
        );

        // CVE Database (NIST NVD)
        sources.insert(
            "cve_database".to_string(),
            SourceConfig {
                id: "cve_database".to_string(),
                name: "CVE Database".to_string(),
                source_type: SourceType::Cve,
                enabled: true,
                api_url: Some("https://services.nvd.nist.gov/rest/json/cves/2.0".to_string()),
                api_key: None,
                auth_type: AuthType::None,
                update_frequency: UpdateFrequency::Realtime,
                priority: 9,
                capabilities: vec![
                    SourceCapability::Vulnerabilities,
                    SourceCapability::Exploits,
                    SourceCapability::Patches,
                ],
                timeout_secs: 60,
                retry_count: 3,
            },
        );

        // Abuse.ch (OSINT)
        sources.insert(
            "abuse_ch".to_string(),
            SourceConfig {
                id: "abuse_ch".to_string(),
                name: "Abuse.ch".to_string(),
                source_type: SourceType::Osint,
                enabled: true,
                api_url: Some("https://urlhaus-api.abuse.ch/v1/urls/recent/".to_string()),
                api_key: None,
                auth_type: AuthType::None,
                update_frequency: UpdateFrequency::Hourly,
                priority: 7,
                capabilities: vec![SourceCapability::Ioc, SourceCapability::Malware],
                timeout_secs: 30,
                retry_count: 2,
            },
        );

        Self {
            enabled: true,
            sources,
            sync_interval_hours: 24,
            cache_enabled: true,
            cache_ttl_hours: 6,
        }
    }
}

impl ThreatIntelConfig {
    /// Create a new empty configuration
    pub fn new() -> Self {
        Self {
            enabled: true,
            sources: HashMap::new(),
            sync_interval_hours: 24,
            cache_enabled: true,
            cache_ttl_hours: 6,
        }
    }

    /// Get enabled sources sorted by priority (highest first)
    pub fn get_enabled_sources(&self) -> Vec<&SourceConfig> {
        let mut sources: Vec<&SourceConfig> =
            self.sources.values().filter(|s| s.enabled).collect();

        sources.sort_by(|a, b| b.priority.cmp(&a.priority));
        sources
    }

    /// Get sources that provide a specific capability
    pub fn get_sources_by_capability(&self, capability: SourceCapability) -> Vec<&SourceConfig> {
        self.sources
            .values()
            .filter(|s| s.enabled && s.capabilities.contains(&capability))
            .collect()
    }

    /// Add or update a source
    pub fn add_source(&mut self, source: SourceConfig) {
        self.sources.insert(source.id.clone(), source);
    }

    /// Remove a source by ID
    pub fn remove_source(&mut self, id: &str) -> Option<SourceConfig> {
        self.sources.remove(id)
    }

    /// Enable or disable a source
    pub fn set_source_enabled(&mut self, id: &str, enabled: bool) -> bool {
        if let Some(source) = self.sources.get_mut(id) {
            source.enabled = enabled;
            true
        } else {
            false
        }
    }

    /// Get a source by ID
    pub fn get_source(&self, id: &str) -> Option<&SourceConfig> {
        self.sources.get(id)
    }

    /// Get a mutable source by ID
    pub fn get_source_mut(&mut self, id: &str) -> Option<&mut SourceConfig> {
        self.sources.get_mut(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ThreatIntelConfig::default();
        assert!(config.enabled);
        assert!(config.sources.len() >= 3);
        assert!(config.sources.contains_key("mitre_attack"));
        assert!(config.sources.contains_key("cve_database"));
        assert!(config.sources.contains_key("abuse_ch"));
    }

    #[test]
    fn test_get_enabled_sources() {
        let config = ThreatIntelConfig::default();
        let sources = config.get_enabled_sources();

        // Should have all 3 default sources
        assert_eq!(sources.len(), 3);

        // Should be sorted by priority (descending)
        for i in 0..sources.len() - 1 {
            assert!(sources[i].priority >= sources[i + 1].priority);
        }
    }

    #[test]
    fn test_get_sources_by_capability() {
        let config = ThreatIntelConfig::default();

        let vuln_sources = config.get_sources_by_capability(SourceCapability::Vulnerabilities);
        assert!(!vuln_sources.is_empty());

        for source in vuln_sources {
            assert!(source.capabilities.contains(&SourceCapability::Vulnerabilities));
        }

        let ioc_sources = config.get_sources_by_capability(SourceCapability::Ioc);
        assert!(!ioc_sources.is_empty());

        for source in ioc_sources {
            assert!(source.capabilities.contains(&SourceCapability::Ioc));
        }
    }

    #[test]
    fn test_add_remove_source() {
        let mut config = ThreatIntelConfig::new();

        let custom_source = SourceConfig {
            id: "custom".to_string(),
            name: "Custom Source".to_string(),
            source_type: SourceType::Custom,
            enabled: true,
            api_url: Some("https://example.com/api".to_string()),
            api_key: Some("test-key".to_string()),
            auth_type: AuthType::ApiKey,
            update_frequency: UpdateFrequency::Daily,
            priority: 5,
            capabilities: vec![SourceCapability::Ioc],
            timeout_secs: 30,
            retry_count: 3,
        };

        config.add_source(custom_source.clone());
        assert!(config.sources.contains_key("custom"));
        assert_eq!(config.sources.get("custom").unwrap().name, "Custom Source");

        let removed = config.remove_source("custom");
        assert!(removed.is_some());
        assert!(!config.sources.contains_key("custom"));
    }

    #[test]
    fn test_enable_disable_source() {
        let mut config = ThreatIntelConfig::default();

        let success = config.set_source_enabled("mitre_attack", false);
        assert!(success);
        assert!(!config.sources.get("mitre_attack").unwrap().enabled);

        let success = config.set_source_enabled("mitre_attack", true);
        assert!(success);
        assert!(config.sources.get("mitre_attack").unwrap().enabled);

        let failure = config.set_source_enabled("nonexistent", true);
        assert!(!failure);
    }

    #[test]
    fn test_get_source() {
        let config = ThreatIntelConfig::default();

        let source = config.get_source("mitre_attack");
        assert!(source.is_some());
        assert_eq!(source.unwrap().name, "MITRE ATT&CK");

        let missing = config.get_source("nonexistent");
        assert!(missing.is_none());
    }
}

