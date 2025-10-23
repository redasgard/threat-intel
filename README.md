# Valkra Threat Intelligence

[![Crates.io](https://img.shields.io/crates/v/threat-intel.svg)](https://crates.io/crates/threat-intel)
[![Documentation](https://docs.rs/threat-intel/badge.svg)](https://docs.rs/threat-intel)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A comprehensive threat intelligence framework for Rust applications with multi-source aggregation, CVE integration, and risk assessment.

## Features

- **Multi-Source Aggregation**: Combine intelligence from MITRE ATT&CK, CVE databases, OSINT sources
- **HTTP Fetching**: Built-in authenticated API calls with automatic retry logic
- **Multiple Auth Methods**: API Key, Bearer token, Basic auth support
- **Format Parsers**: JSON support (XML, STIX planned)
- **Configurable Updates**: Realtime, hourly, daily, weekly, or manual sync
- **Priority Management**: Source prioritization for conflict resolution
- **Capability-Based**: Query sources by capability (vulnerabilities, IOCs, tactics, etc.)
- **Risk Assessment**: Built-in risk scoring and assessment engine
- **Optional Tracing**: Built-in observability with `tracing` feature

## Installation

```toml
[dependencies]
threat-intel = "0.1"

# With tracing support
threat-intel = { version = "0.1", features = ["tracing"] }
```

## Quick Start

```rust
use threat_intel::{ThreatIntelConfig, ThreatIntelEngine};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create config with default sources (MITRE ATT&CK, CVE, Abuse.ch)
    let config = ThreatIntelConfig::default();
    
    // Create engine
    let mut engine = ThreatIntelEngine::new(config);
    
    // Initialize (fetches from all sources)
    engine.initialize().await?;
    
    // Query for vulnerabilities
    let vulns = engine.query_vulnerabilities("apache", "2.4").await?;
    println!("Found {} vulnerabilities for Apache 2.4", vulns.len());
    
    // Assess risk
    let assessment = engine.assess_risk(&vulns);
    println!("Risk Level: {:?}", assessment.level);
    println!("Risk Score: {}", assessment.score);
    
    for recommendation in assessment.recommendations {
        println!("  - {}", recommendation);
    }
    
    // Get stats
    let stats = engine.get_stats();
    println!("Sources: {}", stats.sources_count);
    println!("Total Vulnerabilities: {}", stats.total_vulnerabilities);
    
    Ok(())
}
```

## Default Sources

The library comes with three pre-configured sources:

### 1. MITRE ATT&CK
- **Type**: Tactics, Techniques, and Procedures (TTPs)
- **Capabilities**: Threat Actors, Tactics, Techniques
- **Update Frequency**: Daily
- **Priority**: 10 (highest)

### 2. CVE Database (NIST NVD)
- **Type**: Common Vulnerabilities and Exposures
- **Capabilities**: Vulnerabilities, Exploits, Patches
- **Update Frequency**: Realtime
- **Priority**: 9

### 3. Abuse.ch
- **Type**: OSINT threat intelligence
- **Capabilities**: Indicators of Compromise (IOCs), Malware
- **Update Frequency**: Hourly
- **Priority**: 7

## Custom Sources

Add your own threat intelligence sources:

```rust
use threat_intel::{
    ThreatIntelConfig, SourceConfig, SourceType, AuthType,
    UpdateFrequency, SourceCapability
};

let mut config = ThreatIntelConfig::default();

// Add custom source
let custom_source = SourceConfig {
    id: "my_source".to_string(),
    name: "My Threat Intel".to_string(),
    source_type: SourceType::Custom,
    enabled: true,
    api_url: Some("https://api.example.com/threats".to_string()),
    api_key: Some("your-api-key".to_string()),
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
```

## Authentication Methods

### API Key (Header)
```rust
auth_type: AuthType::ApiKey,
api_key: Some("your-api-key".to_string()),
// Sends: X-API-Key: your-api-key
```

### Bearer Token
```rust
auth_type: AuthType::Bearer,
api_key: Some("your-token".to_string()),
// Sends: Authorization: Bearer your-token
```

### Basic Auth
```rust
auth_type: AuthType::Basic,
api_key: Some("username:password".to_string()),
// Sends: Authorization: Basic base64(username:password)
```

### No Auth
```rust
auth_type: AuthType::None,
api_key: None,
```

## Querying Intelligence

### By Vulnerability
```rust
let vulns = engine.query_vulnerabilities("apache", "2.4").await?;

for vuln in vulns {
    println!("CVE: {:?}", vuln.cve_id);
    println!("Severity: {:?}", vuln.severity);
    println!("CVSS: {:?}", vuln.cvss_score);
}
```

### By IOC Type
```rust
use threat_intel::IOCType;

let malicious_ips = engine.query_iocs(IOCType::IpAddress).await?;
let malicious_domains = engine.query_iocs(IOCType::Domain).await?;
let file_hashes = engine.query_iocs(IOCType::FileHash).await?;
```

### By Threat Actor
```rust
let actors = engine.query_threat_actors("apt28").await?;

for actor in actors {
    println!("Name: {}", actor.name);
    println!("Aliases: {:?}", actor.aliases);
    println!("Tactics: {:?}", actor.tactics);
}
```

## Risk Assessment

```rust
let vulns = engine.query_vulnerabilities("openssl", "1.0.1").await?;
let assessment = engine.assess_risk(&vulns);

match assessment.level {
    RiskLevel::Critical => println!("🔴 CRITICAL: Immediate action required!"),
    RiskLevel::High => println!("🟠 HIGH: Address within 24-48 hours"),
    RiskLevel::Medium => println!("🟡 MEDIUM: Schedule patching"),
    RiskLevel::Low => println!("🟢 LOW: Include in maintenance"),
    RiskLevel::Info => println!("ℹ️ INFO: No significant issues"),
}

println!("Critical: {}", assessment.critical_count);
println!("High: {}", assessment.high_count);
println!("Medium: {}", assessment.medium_count);
println!("Low: {}", assessment.low_count);
println!("Score: {:.1}", assessment.score);
```

## Configuration Options

### Sync Interval
```rust
config.sync_interval_hours = 6; // Sync every 6 hours
```

### Cache Settings
```rust
config.cache_enabled = true;
config.cache_ttl_hours = 3; // Cache expires after 3 hours
```

### Source Management
```rust
// Disable a source
config.set_source_enabled("mitre_attack", false);

// Remove a source
config.remove_source("abuse_ch");

// Get sources by capability
let vuln_sources = config.get_sources_by_capability(
    SourceCapability::Vulnerabilities
);
```

## Manual Sync

```rust
// Force sync all sources
engine.sync().await?;

// Get last sync time
let stats = engine.get_stats();
if let Some(last_sync) = stats.last_sync {
    println!("Last synced: {}", last_sync);
}
```

## Use Cases

- **Vulnerability Management**: Track CVEs affecting your stack
- **SIEM Integration**: Enrich security events with threat intelligence
- **SOC Tools**: Real-time threat actor tracking and IOC lookups
- **Security Auditing**: Risk assessment for codebases and infrastructure
- **Incident Response**: Quick lookup of threats and indicators
- **Threat Hunting**: Proactive threat intelligence queries

## Architecture

```
┌─────────────────────────────────────┐
│     ThreatIntelEngine               │
│  (Aggregation & Query Interface)    │
└─────────────────────────────────────┘
              │
              ├─────────────┬─────────────┬─────────────┐
              ▼             ▼             ▼             ▼
       ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
       │  MITRE   │  │   CVE    │  │ Abuse.ch │  │  Custom  │
       │ ATT&CK   │  │ Database │  │  (OSINT) │  │  Source  │
       └──────────┘  └──────────┘  └──────────┘  └──────────┘
              │             │             │             │
              └─────────────┴─────────────┴─────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  FeedFetcher     │
                    │ (HTTP + Auth)    │
                    └──────────────────┘
```

## Performance

- **Lazy Loading**: Sources loaded on-demand
- **Caching**: Configurable TTL to reduce API calls
- **Async**: Non-blocking fetching from multiple sources
- **Retry Logic**: Exponential backoff for failed requests
- **Timeout**: Configurable per-source timeouts

## Error Handling

```rust
use threat_intel::ThreatIntelError;

match engine.initialize().await {
    Ok(_) => println!("Initialized successfully"),
    Err(e) => eprintln!("Initialization failed: {}", e),
}

// Individual source failures don't stop others
engine.sync().await?; // Continues even if one source fails
```

## Testing

```bash
# Run tests
cargo test

# Run with tracing
cargo test --features tracing

# Run specific test
cargo test test_risk_assessment

# Run ignored network tests (requires internet)
cargo test -- --ignored
```

## Roadmap

- [ ] XML and STIX format parsers
- [ ] Database backend support (PostgreSQL, SQLite)
- [ ] Webhook notifications for new threats
- [ ] ML-based threat correlation
- [ ] GraphQL API
- [ ] TLS certificate pinning
- [ ] Threat feed validation

## Origin

Extracted from [Valkra](https://github.com/asgardtech/valkra), a blockchain security auditing platform where it aggregates threat intelligence for smart contract vulnerability detection.

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Areas of interest:
- Additional threat intelligence sources
- Format parsers (XML, STIX, TAXII)
- Performance optimizations
- Documentation improvements

## Security

To report security vulnerabilities, email hello@redasgard.com.

**Do not** open public GitHub issues for security bugs.

## Contact

- **Email**: hello@redasgard.com
- **GitHub**: https://github.com/redasgard/threat-intel

