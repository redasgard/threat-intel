# Data Sources

Available threat intelligence data sources and how to configure them.

## Built-in Sources

### MITRE ATT&CK

Official MITRE ATT&CK framework data.

```rust
use threat_intel::{MitreSource, Config};

let mitre_source = MitreSource::new()
    .with_custom_url("https://attack.mitre.org/api/v2/")
    .with_rate_limit(100);  // 100 requests per minute

let config = Config::new()
    .with_source(mitre_source);
```

**Data Types:**
- Tactics (TA0001-TA0043)
- Techniques (T1000-T2000+)
- Procedures
- Software
- Groups
- Campaigns

**Update Frequency:** Daily

### CVE Database

Common Vulnerabilities and Exposures database.

```rust
use threat_intel::{CveSource, Config};

let cve_source = CveSource::new()
    .with_api_key("your-nvd-api-key")
    .with_rate_limit(50);  // 50 requests per minute

let config = Config::new()
    .with_source(cve_source);
```

**Data Types:**
- CVE records
- CVSS scores
- CWE mappings
- References
- Affected products

**Update Frequency:** Real-time

### OSINT Feeds

Open source intelligence feeds.

```rust
use threat_intel::{OsintSource, Feed, Config};

let osint_source = OsintSource::new()
    .add_feed(Feed::new("https://feeds.example.com/threats.json")
        .with_auth("username", "password")
        .with_interval(Duration::from_secs(3600))
    )
    .add_feed(Feed::new("https://another-feed.com/feed.xml")
        .with_format(FeedFormat::Xml)
    );

let config = Config::new()
    .with_source(osint_source);
```

**Data Types:**
- Threat indicators
- Malware samples
- Attack campaigns
- IOCs (Indicators of Compromise)

**Update Frequency:** Variable (per feed)

## Custom Sources

### Creating Custom Sources

```rust
use threat_intel::{ThreatSource, ThreatData, Query, Error};

struct CustomSource {
    client: reqwest::Client,
    base_url: String,
}

impl ThreatSource for CustomSource {
    fn name(&self) -> &str {
        "custom-source"
    }
    
    async fn query(&self, query: &Query) -> Result<Vec<ThreatData>, Error> {
        // Implement your custom query logic
        let response = self.client
            .get(&format!("{}/threats", self.base_url))
            .query(&[("tactic", &query.tactics().join(","))])
            .send()
            .await?;
        
        let threats: Vec<ThreatData> = response.json().await?;
        Ok(threats)
    }
    
    async fn health_check(&self) -> Result<bool, Error> {
        let response = self.client
            .get(&format!("{}/health", self.base_url))
            .send()
            .await?;
        
        Ok(response.status().is_success())
    }
}
```

### Registering Custom Sources

```rust
use threat_intel::{ThreatIntelligence, Config};

let custom_source = Box::new(CustomSource::new(
    reqwest::Client::new(),
    "https://api.custom-threats.com".to_string(),
));

let config = Config::new()
    .with_source(custom_source);

let ti = ThreatIntelligence::new(config);
```

## Source Configuration

### Authentication

#### API Keys

```rust
use threat_intel::{Config, ApiKeyAuth};

let config = Config::new()
    .with_auth(ApiKeyAuth::new("your-api-key")
        .with_header("X-API-Key")
        .with_rotation_interval(Duration::from_secs(3600))
    );
```

#### OAuth 2.0

```rust
use threat_intel::{Config, OAuth2Auth};

let oauth = OAuth2Auth::new()
    .with_client_id("your-client-id")
    .with_client_secret("your-client-secret")
    .with_token_url("https://auth.example.com/oauth/token")
    .with_scope("threat-intel:read");

let config = Config::new()
    .with_auth(oauth);
```

#### Basic Authentication

```rust
use threat_intel::{Config, BasicAuth};

let basic_auth = BasicAuth::new("username", "password");
let config = Config::new()
    .with_auth(basic_auth);
```

### Rate Limiting

```rust
use threat_intel::{Config, RateLimit};

let config = Config::new()
    .with_global_rate_limit(RateLimit::new(100, Duration::from_secs(60)))
    .with_source_rate_limit("mitre", RateLimit::new(50, Duration::from_secs(60)))
    .with_source_rate_limit("cve", RateLimit::new(25, Duration::from_secs(60)));
```

### Caching

```rust
use threat_intel::{Config, CacheConfig};

let cache_config = CacheConfig::new()
    .with_ttl(Duration::from_secs(3600))
    .with_max_size(1000)
    .with_compression();

let config = Config::new()
    .with_cache_config(cache_config);
```

## Data Format Support

### JSON

```rust
use threat_intel::{JsonParser, Config};

let json_parser = JsonParser::new()
    .with_schema("threat-schema.json")
    .with_validation(true);

let config = Config::new()
    .with_parser("json", json_parser);
```

### XML

```rust
use threat_intel::{XmlParser, Config};

let xml_parser = XmlParser::new()
    .with_namespace("http://example.com/threats")
    .with_xpath("/threats/threat");

let config = Config::new()
    .with_parser("xml", xml_parser);
```

### CSV

```rust
use threat_intel::{CsvParser, Config};

let csv_parser = CsvParser::new()
    .with_headers(true)
    .with_delimiter(',')
    .with_encoding("utf-8");

let config = Config::new()
    .with_parser("csv", csv_parser);
```

### STIX/TAXII

```rust
use threat_intel::{StixParser, TaxiiClient, Config};

let taxii_client = TaxiiClient::new()
    .with_server("https://taxii.example.com")
    .with_collection("threats")
    .with_auth("api-key");

let stix_parser = StixParser::new()
    .with_taxii_client(taxii_client);

let config = Config::new()
    .with_parser("stix", stix_parser);
```

## Source Health Monitoring

### Health Checks

```rust
use threat_intel::{ThreatIntelligence, HealthMonitor};

let health_monitor = HealthMonitor::new()
    .with_check_interval(Duration::from_secs(300))
    .with_timeout(Duration::from_secs(10))
    .with_retry_attempts(3);

let ti = ThreatIntelligence::new_with_monitor(config, health_monitor);

// Check source health
let health_status = ti.check_source_health("mitre").await?;
if !health_status.is_healthy() {
    eprintln!("Source unhealthy: {}", health_status.error());
}
```

### Metrics

```rust
use threat_intel::{ThreatIntelligence, Metrics};

let metrics = Metrics::new()
    .with_request_count()
    .with_response_time()
    .with_error_rate()
    .with_data_freshness();

let ti = ThreatIntelligence::new_with_metrics(config, metrics);

// Get source metrics
let source_metrics = ti.get_source_metrics("mitre").await?;
println!("Requests: {}", source_metrics.request_count());
println!("Avg response time: {:?}", source_metrics.avg_response_time());
```

## Data Quality

### Validation

```rust
use threat_intel::{Config, DataValidator};

let validator = DataValidator::new()
    .with_required_fields(vec!["id", "title", "severity"])
    .with_field_validation("severity", |v| {
        matches!(v, "Critical" | "High" | "Medium" | "Low")
    })
    .with_data_freshness_check(Duration::from_secs(86400)); // 24 hours

let config = Config::new()
    .with_data_validator(validator);
```

### Deduplication

```rust
use threat_intel::{Config, DeduplicationConfig};

let dedup_config = DeduplicationConfig::new()
    .with_strategy(DeduplicationStrategy::ByHash)
    .with_priority_source("mitre")
    .with_merge_conflicts(true);

let config = Config::new()
    .with_deduplication_config(dedup_config);
```

### Data Enrichment

```rust
use threat_intel::{Config, EnrichmentConfig};

let enrichment_config = EnrichmentConfig::new()
    .with_geoip_enrichment()
    .with_domain_enrichment()
    .with_hash_enrichment()
    .with_custom_enricher(Box::new(CustomEnricher::new()));

let config = Config::new()
    .with_enrichment_config(enrichment_config);
```

## Source Priority and Fallback

### Priority Configuration

```rust
use threat_intel::{Config, SourcePriority};

let priority_config = SourcePriority::new()
    .with_primary_source("mitre")
    .with_fallback_sources(vec!["cve", "osint"])
    .with_failover_timeout(Duration::from_secs(5));

let config = Config::new()
    .with_source_priority(priority_config);
```

### Load Balancing

```rust
use threat_intel::{Config, LoadBalancer};

let load_balancer = LoadBalancer::new()
    .with_strategy(LoadBalanceStrategy::RoundRobin)
    .with_health_check(true)
    .with_weighted_sources(vec![
        ("mitre", 3),
        ("cve", 2),
        ("osint", 1),
    ]);

let config = Config::new()
    .with_load_balancer(load_balancer);
```

## Best Practices

### 1. Use Multiple Sources

```rust
let config = Config::new()
    .with_source(MitreSource::new())
    .with_source(CveSource::new())
    .with_source(OsintSource::new());
```

### 2. Configure Appropriate Rate Limits

```rust
let config = Config::new()
    .with_source_rate_limit("mitre", RateLimit::new(100, Duration::from_secs(60)))
    .with_source_rate_limit("cve", RateLimit::new(50, Duration::from_secs(60)));
```

### 3. Implement Caching

```rust
let config = Config::new()
    .with_cache_config(CacheConfig::new()
        .with_ttl(Duration::from_secs(3600))
        .with_compression()
    );
```

### 4. Monitor Source Health

```rust
let config = Config::new()
    .with_health_monitor(HealthMonitor::new()
        .with_check_interval(Duration::from_secs(300))
    );
```

## Troubleshooting

### Common Issues

**1. Authentication Failures**
```rust
// Check API keys
if api_key.is_empty() {
    eprintln!("API key not configured");
}

// Validate authentication
let auth_test = source.test_authentication().await?;
if !auth_test.success() {
    eprintln!("Authentication failed: {}", auth_test.error());
}
```

**2. Rate Limiting**
```rust
// Check rate limit status
let rate_limit_status = source.get_rate_limit_status().await?;
if rate_limit_status.remaining() == 0 {
    eprintln!("Rate limit exceeded, retry after: {:?}", rate_limit_status.reset_time());
}
```

**3. Data Format Issues**
```rust
// Validate data format
let validation_result = parser.validate_data(&raw_data).await?;
if !validation_result.is_valid() {
    eprintln!("Invalid data format: {}", validation_result.error());
}
```

## Next Steps

- Review [Configuration Guide](./configuration.md) for setup
- Check [Integration Guide](./integration.md) for system integration
- See [Performance Tuning](./performance.md) for optimization
