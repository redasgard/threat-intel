# Threat Intelligence Documentation

Comprehensive threat intelligence framework for Rust applications with multi-source aggregation, CVE integration, and risk assessment.

## Documentation Structure

- **[Architecture](./architecture.md)** - System design and data flow
- **[Getting Started](./getting-started.md)** - Quick start guide
- **[User Guide](./user-guide.md)** - Comprehensive usage patterns
- **[API Reference](./api-reference.md)** - Detailed API documentation
- **[Data Sources](./data-sources.md)** - Built-in and custom sources
- **[Configuration Guide](./configuration.md)** - Advanced configuration
- **[Integration Guide](./integration.md)** - Integration with other systems
- **[FAQ](./faq.md)** - Frequently asked questions

## Quick Links

- [Why Threat Intelligence?](./why-threat-intel.md)
- [Use Cases](./use-cases.md)
- [Risk Assessment](./risk-assessment.md)
- [Performance Tuning](./performance.md)

## Overview

Threat Intel aggregates intelligence from multiple sources (MITRE ATT&CK, CVE databases, OSINT) to provide real-time vulnerability and threat actor information for security applications.

### Key Features

- ✅ **Multi-Source Aggregation**: MITRE ATT&CK, CVE, OSINT feeds
- ✅ **HTTP Fetching**: Authenticated API calls with retry logic
- ✅ **Multiple Auth Methods**: API Key, Bearer, Basic auth
- ✅ **Format Parsers**: JSON support (XML, STIX planned)
- ✅ **Configurable Updates**: Realtime, hourly, daily, weekly
- ✅ **Priority Management**: Source prioritization for conflicts
- ✅ **Risk Assessment**: Built-in scoring and recommendations

### Quick Example

```rust
use threat_intel::{ThreatIntelConfig, ThreatIntelEngine};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create engine with default sources
    let config = ThreatIntelConfig::default();
    let mut engine = ThreatIntelEngine::new(config);
    
    // Initialize (fetches from sources)
    engine.initialize().await?;
    
    // Query vulnerabilities
    let vulns = engine.query_vulnerabilities("apache", "2.4").await?;
    println!("Found {} vulnerabilities", vulns.len());
    
    // Assess risk
    let assessment = engine.assess_risk(&vulns);
    println!("Risk Level: {:?}, Score: {}", assessment.level, assessment.score);
    
    Ok(())
}
```

## Default Sources

- **MITRE ATT&CK**: Tactics, techniques, threat actors
- **CVE Database (NIST NVD)**: Vulnerabilities and exploits
- **Abuse.ch**: OSINT threat intelligence and IOCs

## Support

- **GitHub**: https://github.com/redasgard/threat-intel
- **Email**: hello@redasgard.com
- **Security Issues**: security@redasgard.com

## License

MIT License - See [LICENSE](../LICENSE)

