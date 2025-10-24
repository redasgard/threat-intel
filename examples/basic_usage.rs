//! Basic usage example for valkra-threat-intel

use threat_intel::{
    AuthType, RiskLevel, SourceCapability, SourceConfig, SourceType, ThreatIntelConfig,
    ThreatIntelEngine, UpdateFrequency,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== Red Asgard Threat Intelligence Example ===\n");

    // Example 1: Using default configuration
    println!("1. Default Configuration");
    println!("------------------------");

    let config = ThreatIntelConfig::default();
    println!("Default sources configured: {}", config.sources.len());

    for source in config.get_enabled_sources() {
        println!(
            "  - {} (Priority: {}, Type: {:?})",
            source.name, source.priority, source.source_type
        );
    }

    // Example 2: Create custom configuration
    println!("\n2. Custom Configuration");
    println!("-----------------------");

    let mut custom_config = ThreatIntelConfig::new();
    custom_config.sync_interval_hours = 6;
    custom_config.cache_ttl_hours = 2;

    // Add a custom source
    let custom_source = SourceConfig {
        id: "custom_feed".to_string(),
        name: "Custom Threat Feed".to_string(),
        source_type: SourceType::Custom,
        enabled: true,
        api_url: Some("https://api.example.com/threats".to_string()),
        api_key: Some("demo-key".to_string()),
        auth_type: AuthType::Bearer,
        update_frequency: UpdateFrequency::Hourly,
        priority: 8,
        capabilities: vec![SourceCapability::Vulnerabilities, SourceCapability::Ioc],
        timeout_secs: 30,
        retry_count: 3,
    };

    custom_config.add_source(custom_source);
    println!("Custom source added: custom_feed");

    // Example 3: Query by capability
    println!("\n3. Querying Sources by Capability");
    println!("----------------------------------");

    let config = ThreatIntelConfig::default();

    let vuln_sources = config.get_sources_by_capability(SourceCapability::Vulnerabilities);
    println!("Sources providing vulnerabilities: {}", vuln_sources.len());
    for source in vuln_sources {
        println!("  - {}", source.name);
    }

    let ioc_sources = config.get_sources_by_capability(SourceCapability::Ioc);
    println!("\nSources providing IOCs: {}", ioc_sources.len());
    for source in ioc_sources {
        println!("  - {}", source.name);
    }

    let tactic_sources = config.get_sources_by_capability(SourceCapability::Tactics);
    println!("\nSources providing tactics: {}", tactic_sources.len());
    for source in tactic_sources {
        println!("  - {}", source.name);
    }

    // Example 4: Create engine (note: initialize() would fetch from real sources)
    println!("\n4. Creating Threat Intelligence Engine");
    println!("---------------------------------------");

    let config = ThreatIntelConfig::default();
    let engine = ThreatIntelEngine::new(config);

    let stats = engine.get_stats();
    println!("Engine created:");
    println!("  Sources configured: {}", stats.sources_count);
    println!("  Vulnerabilities cached: {}", stats.total_vulnerabilities);
    println!("  IOCs cached: {}", stats.total_iocs);
    println!("  Threat actors cached: {}", stats.total_threat_actors);

    // Example 5: Risk Assessment (with mock data)
    println!("\n5. Risk Assessment");
    println!("------------------");

    use chrono::Utc;
    use threat_intel::{AffectedProduct, Severity, Vulnerability};

    let mock_vulnerabilities = vec![
        Vulnerability {
            id: "V-001".to_string(),
            cve_id: Some("CVE-2024-0001".to_string()),
            title: "Critical Remote Code Execution".to_string(),
            description: "Allows remote attackers to execute arbitrary code".to_string(),
            severity: Severity::Critical,
            cvss_score: Some(9.8),
            affected_products: vec![AffectedProduct {
                vendor: "Apache".to_string(),
                product: "Apache HTTP Server".to_string(),
                version: "2.4.49".to_string(),
                platform: Some("All".to_string()),
            }],
            published_date: Utc::now(),
            last_modified: Utc::now(),
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-0001".to_string()],
        },
        Vulnerability {
            id: "V-002".to_string(),
            cve_id: Some("CVE-2024-0002".to_string()),
            title: "High Severity SQL Injection".to_string(),
            description: "SQL injection in login form".to_string(),
            severity: Severity::High,
            cvss_score: Some(8.1),
            affected_products: vec![],
            published_date: Utc::now(),
            last_modified: Utc::now(),
            references: vec![],
        },
        Vulnerability {
            id: "V-003".to_string(),
            cve_id: Some("CVE-2024-0003".to_string()),
            title: "Medium Information Disclosure".to_string(),
            description: "Sensitive information in error messages".to_string(),
            severity: Severity::Medium,
            cvss_score: Some(5.3),
            affected_products: vec![],
            published_date: Utc::now(),
            last_modified: Utc::now(),
            references: vec![],
        },
    ];

    let assessment = engine.assess_risk(&mock_vulnerabilities);

    println!("Risk Assessment Results:");
    println!("  Level: {:?}", assessment.level);
    println!("  Score: {:.1}", assessment.score);
    println!("  Critical: {}", assessment.critical_count);
    println!("  High: {}", assessment.high_count);
    println!("  Medium: {}", assessment.medium_count);
    println!("  Low: {}", assessment.low_count);

    println!("\nRecommendations:");
    for (i, rec) in assessment.recommendations.iter().enumerate() {
        println!("  {}. {}", i + 1, rec);
    }

    // Example 6: Risk level interpretation
    println!("\n6. Risk Level Interpretation");
    println!("----------------------------");

    let levels = vec![
        (RiskLevel::Critical, "🔴", "Immediate action required - patch now!"),
        (RiskLevel::High, "🟠", "Address within 24-48 hours"),
        (RiskLevel::Medium, "🟡", "Schedule for next maintenance window"),
        (RiskLevel::Low, "🟢", "Include in regular updates"),
        (RiskLevel::Info, "ℹ️", "No significant security issues detected"),
    ];

    for (level, icon, description) in levels {
        println!("  {} {:?}: {}", icon, level, description);
    }

    // Example 7: Source management
    println!("\n7. Source Management");
    println!("--------------------");

    let mut config = ThreatIntelConfig::default();

    println!("Disabling MITRE ATT&CK...");
    let success = config.set_source_enabled("mitre_attack", false);
    println!("  Success: {}", success);

    println!("\nEnabled sources after change: {}", config.get_enabled_sources().len());

    println!("\nRe-enabling MITRE ATT&CK...");
    config.set_source_enabled("mitre_attack", true);
    println!("  Enabled sources: {}", config.get_enabled_sources().len());

    // Example 8: Authentication types
    println!("\n8. Authentication Methods");
    println!("-------------------------");

    println!("Supported authentication types:");
    println!("  - None: Public APIs");
    println!("  - API Key: X-API-Key header");
    println!("  - Bearer: Authorization: Bearer token");
    println!("  - Basic: Authorization: Basic credentials");

    println!("\n=== Example completed successfully ===");

    Ok(())
}

