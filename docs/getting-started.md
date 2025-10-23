# Getting Started

## Installation

Add Threat Intel to your `Cargo.toml`:

```toml
[dependencies]
threat-intel = "0.1"
tokio = { version = "1", features = ["full"] }  # Required for async

# Optional: with tracing support
threat-intel = { version = "0.1", features = ["tracing"] }
```

## First Steps

### 1. Create Configuration

Start with default sources (MITRE ATT&CK, CVE, Abuse.ch):

```rust
use threat_intel::ThreatIntelConfig;

fn main() {
    // Default configuration with 3 built-in sources
    let config = ThreatIntelConfig::default();
    
    println!("Configured sources:");
    for source in config.get_enabled_sources() {
        println!("  - {} ({})", source.name, source.source_type);
    }
}
```

### 2. Initialize Engine

Create and initialize the threat intelligence engine:

```rust
use threat_intel::{ThreatIntelConfig, ThreatIntelEngine};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = ThreatIntelConfig::default();
    let mut engine = ThreatIntelEngine::new(config);
    
    // Initialize (fetches from all sources)
    println!("Initializing threat intelligence...");
    engine.initialize().await?;
    
    println!("Initialization complete!");
    
    // Get statistics
    let stats = engine.get_stats();
    println!("Loaded {} sources", stats.sources_count);
    println!("Total vulnerabilities: {}", stats.total_vulnerabilities);
    println!("Total IOCs: {}", stats.total_iocs);
    
    Ok(())
}
```

### 3. Query Vulnerabilities

Search for vulnerabilities affecting specific software:

```rust
use threat_intel::{ThreatIntelConfig, ThreatIntelEngine};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = ThreatIntelConfig::default();
    let mut engine = ThreatIntelEngine::new(config);
    engine.initialize().await?;
    
    // Query Apache 2.4 vulnerabilities
    let vulns = engine.query_vulnerabilities("apache", "2.4").await?;
    
    println!("Found {} vulnerabilities for Apache 2.4:\n", vulns.len());
    
    for vuln in vulns.iter().take(5) {
        println!("CVE: {:?}", vuln.cve_id);
        println!("Severity: {:?}", vuln.severity);
        println!("CVSS: {:?}", vuln.cvss_score);
        println!("Title: {}", vuln.title);
        println!();
    }
    
    Ok(())
}
```

### 4. Assess Risk

Perform risk assessment on discovered vulnerabilities:

```rust
use threat_intel::{ThreatIntelConfig, ThreatIntelEngine};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = ThreatIntelConfig::default();
    let mut engine = ThreatIntelEngine::new(config);
    engine.initialize().await?;
    
    // Query vulnerabilities
    let vulns = engine.query_vulnerabilities("openssl", "1.0.1").await?;
    
    // Assess risk
    let assessment = engine.assess_risk(&vulns);
    
    println!("Risk Assessment:");
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
    
    Ok(())
}
```

### 5. Query IOCs

Search for Indicators of Compromise:

```rust
use threat_intel::{ThreatIntelConfig, ThreatIntelEngine, IOCType};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = ThreatIntelConfig::default();
    let mut engine = ThreatIntelEngine::new(config);
    engine.initialize().await?;
    
    // Query malicious IP addresses
    let malicious_ips = engine.query_iocs(IOCType::IpAddress).await?;
    
    println!("Found {} malicious IP addresses", malicious_ips.len());
    
    for ioc in malicious_ips.iter().take(10) {
        println!("IP: {}", ioc.value);
        println!("Confidence: {:.0}%", ioc.confidence * 100.0);
        println!("First seen: {}", ioc.first_seen);
        println!();
    }
    
    Ok(())
}
```

### 6. Query Threat Actors

Search for threat actor information:

```rust
use threat_intel::{ThreatIntelConfig, ThreatIntelEngine};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = ThreatIntelConfig::default();
    let mut engine = ThreatIntelEngine::new(config);
    engine.initialize().await?;
    
    // Search for APT groups
    let actors = engine.query_threat_actors("apt").await?;
    
    println!("Found {} threat actors:\n", actors.len());
    
    for actor in actors.iter().take(5) {
        println!("Name: {}", actor.name);
        println!("Aliases: {:?}", actor.aliases);
        println!("Country: {:?}", actor.country);
        println!("Tactics: {}", actor.tactics.join(", "));
        println!();
    }
    
    Ok(())
}
```

## Complete Example

Here's a complete example showing vulnerability scanning and risk assessment:

```rust
use threat_intel::{ThreatIntelConfig, ThreatIntelEngine, RiskLevel};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Setup
    println!("=== Threat Intelligence Scanner ===\n");
    
    let config = ThreatIntelConfig::default();
    let mut engine = ThreatIntelEngine::new(config);
    
    // 2. Initialize
    println!("Initializing threat intelligence sources...");
    engine.initialize().await?;
    
    let stats = engine.get_stats();
    println!("✓ Loaded {} sources\n", stats.sources_count);
    
    // 3. Scan multiple products
    let products = vec![
        ("apache", "2.4"),
        ("openssl", "1.1.1"),
        ("nginx", "1.18"),
    ];
    
    for (product, version) in products {
        println!("--- Scanning {} {} ---", product, version);
        
        // Query vulnerabilities
        let vulns = engine.query_vulnerabilities(product, version).await?;
        println!("Found {} vulnerabilities", vulns.len());
        
        // Assess risk
        let assessment = engine.assess_risk(&vulns);
        
        // Color-coded risk level
        let risk_icon = match assessment.level {
            RiskLevel::Critical => "🔴 CRITICAL",
            RiskLevel::High => "🟠 HIGH",
            RiskLevel::Medium => "🟡 MEDIUM",
            RiskLevel::Low => "🟢 LOW",
            RiskLevel::Info => "ℹ️  INFO",
        };
        
        println!("Risk Level: {}", risk_icon);
        println!("Risk Score: {:.1}", assessment.score);
        println!("Breakdown:");
        println!("  Critical: {}", assessment.critical_count);
        println!("  High: {}", assessment.high_count);
        println!("  Medium: {}", assessment.medium_count);
        println!("  Low: {}", assessment.low_count);
        
        if !assessment.recommendations.is_empty() {
            println!("\nTop Recommendations:");
            for rec in assessment.recommendations.iter().take(3) {
                println!("  • {}", rec);
            }
        }
        
        println!();
    }
    
    Ok(())
}
```

## Custom Sources

Add your own threat intelligence sources:

```rust
use threat_intel::{
    ThreatIntelConfig, SourceConfig, SourceType, AuthType,
    UpdateFrequency, SourceCapability
};

fn main() {
    let mut config = ThreatIntelConfig::default();
    
    // Add custom source
    let custom_source = SourceConfig {
        id: "my_threat_feed".to_string(),
        name: "My Threat Feed".to_string(),
        source_type: SourceType::Custom,
        enabled: true,
        api_url: Some("https://api.mycompany.com/threats".to_string()),
        api_key: Some(std::env::var("THREAT_API_KEY").unwrap()),
        auth_type: AuthType::Bearer,
        update_frequency: UpdateFrequency::Hourly,
        priority: 8,
        capabilities: vec![
            SourceCapability::Vulnerabilities,
            SourceCapability::Ioc,
        ],
        timeout_secs: 30,
        retry_count: 3,
    };
    
    config.add_source(custom_source);
    
    println!("Custom source configured!");
}
```

## Periodic Sync

Keep threat intelligence up to date:

```rust
use threat_intel::{ThreatIntelConfig, ThreatIntelEngine};
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = ThreatIntelConfig::default();
    let mut engine = ThreatIntelEngine::new(config);
    engine.initialize().await?;
    
    // Sync every 6 hours
    loop {
        println!("Syncing threat intelligence...");
        
        match engine.sync().await {
            Ok(_) => {
                let stats = engine.get_stats();
                println!("✓ Sync complete");
                println!("  Vulnerabilities: {}", stats.total_vulnerabilities);
                println!("  IOCs: {}", stats.total_iocs);
            }
            Err(e) => {
                eprintln!("✗ Sync failed: {}", e);
            }
        }
        
        sleep(Duration::from_secs(6 * 3600)).await;
    }
}
```

## Error Handling

All operations return `Result` for proper error handling:

```rust
use threat_intel::{ThreatIntelConfig, ThreatIntelEngine};

#[tokio::main]
async fn main() {
    let config = ThreatIntelConfig::default();
    let mut engine = ThreatIntelEngine::new(config);
    
    // Handle initialization errors
    match engine.initialize().await {
        Ok(_) => println!("Initialized successfully"),
        Err(e) => {
            eprintln!("Initialization failed: {}", e);
            return;
        }
    }
    
    // Handle query errors
    match engine.query_vulnerabilities("apache", "2.4").await {
        Ok(vulns) => println!("Found {} vulnerabilities", vulns.len()),
        Err(e) => eprintln!("Query failed: {}", e),
    }
}
```

## Configuration Options

### Adjust Sync Interval

```rust
let mut config = ThreatIntelConfig::default();
config.sync_interval_hours = 12;  // Sync every 12 hours
```

### Cache Settings

```rust
let mut config = ThreatIntelConfig::default();
config.cache_enabled = true;
config.cache_ttl_hours = 6;  // Cache expires after 6 hours
```

### Disable Sources

```rust
let mut config = ThreatIntelConfig::default();
config.set_source_enabled("mitre_attack", false);  // Disable MITRE
```

## Next Steps

- Read [Architecture](./architecture.md) for system design
- Check [Use Cases](./use-cases.md) for real-world applications
- Review [API Reference](./api-reference.md) for detailed documentation
- See [Configuration Guide](./configuration.md) for advanced options

## Troubleshooting

### Network Errors

If sources fail to fetch:
- Check internet connection
- Verify API keys are correct
- Check firewall/proxy settings
- Review source URLs

### Slow Initialization

If initialization is slow:
- Reduce number of sources
- Increase timeout values
- Check network latency
- Use cached data when possible

### Empty Results

If queries return no results:
- Ensure sources initialized successfully
- Check query parameters (spelling)
- Verify sources have relevant capabilities
- Try broader search terms

## Getting Help

- **Documentation**: See `/docs/` directory
- **Examples**: Check `examples/` directory
- **Issues**: https://github.com/redasgard/threat-intel/issues
- **Email**: hello@redasgard.com

