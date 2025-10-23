# Configuration Guide

Comprehensive guide for configuring Threat Intelligence.

## Basic Configuration

### Default Configuration

```rust
use threat_intel::{ThreatIntelligence, Config};

// Use default settings
let config = Config::default();
let ti = ThreatIntelligence::new(config);
```

### Custom Configuration

```rust
use threat_intel::{Config, Duration};

let config = Config::new()
    .with_cache_ttl(Duration::from_secs(3600))  // 1 hour cache
    .with_timeout(Duration::from_secs(30))     // 30 second timeout
    .with_retry_attempts(3)                    // 3 retry attempts
    .with_max_sources(10);                     // Max 10 sources

let ti = ThreatIntelligence::new(config);
```

## Data Source Configuration

### MITRE ATT&CK

```rust
use threat_intel::{Config, MitreSource};

let config = Config::new()
    .with_source(MitreSource::new()
        .with_custom_url("https://attack.mitre.org/api/v2/")
        .with_rate_limit(100)  // 100 requests per minute
    );
```

### CVE Database

```rust
use threat_intel::{Config, CveSource};

let config = Config::new()
    .with_source(CveSource::new()
        .with_api_key("your-nvd-api-key")
        .with_rate_limit(50)   // 50 requests per minute
    );
```

### OSINT Feeds

```rust
use threat_intel::{Config, OsintSource, Feed};

let config = Config::new()
    .with_source(OsintSource::new()
        .add_feed(Feed::new("https://feeds.example.com/threats.json")
            .with_auth("username", "password")
            .with_interval(Duration::from_secs(3600))
        )
        .add_feed(Feed::new("https://another-feed.com/feed.xml")
            .with_format(FeedFormat::Xml)
        )
    );
```

## API Keys and Authentication

### Environment Variables

```rust
use std::env;

let config = Config::new()
    .with_api_key("mitre", &env::var("MITRE_API_KEY")?)
    .with_api_key("cve", &env::var("CVE_API_KEY")?)
    .with_api_key("osint", &env::var("OSINT_API_KEY")?);
```

### Configuration File

```toml
# config.toml
[threat_intel]
cache_ttl = 3600
timeout = 30
max_sources = 10

[threat_intel.sources.mitre]
api_key = "your-mitre-key"
base_url = "https://attack.mitre.org/api/v2/"

[threat_intel.sources.cve]
api_key = "your-cve-key"
rate_limit = 50

[threat_intel.sources.osint]
feeds = [
    { url = "https://feed1.com", auth = "user:pass" },
    { url = "https://feed2.com", format = "xml" }
]
```

```rust
use threat_intel::Config;
use std::fs;

// Load from file
let config_str = fs::read_to_string("config.toml")?;
let config: Config = toml::from_str(&config_str)?;
```

## Cache Configuration

### Memory Cache

```rust
use threat_intel::{Config, CacheConfig};

let cache_config = CacheConfig::new()
    .with_ttl(Duration::from_secs(3600))      // 1 hour TTL
    .with_max_size(1000)                       // Max 1000 entries
    .with_compression()                        // Enable compression
    .with_eviction_policy(EvictionPolicy::LRU); // LRU eviction

let config = Config::new()
    .with_cache_config(cache_config);
```

### Redis Cache

```rust
use threat_intel::{Config, RedisCache};

let redis_cache = RedisCache::new()
    .with_url("redis://localhost:6379")
    .with_ttl(Duration::from_secs(3600))
    .with_compression();

let config = Config::new()
    .with_cache(redis_cache);
```

### File Cache

```rust
use threat_intel::{Config, FileCache};

let file_cache = FileCache::new()
    .with_directory("/tmp/threat-intel-cache")
    .with_ttl(Duration::from_secs(3600))
    .with_compression();

let config = Config::new()
    .with_cache(file_cache);
```

## Network Configuration

### HTTP Client Settings

```rust
use threat_intel::{Config, HttpClientConfig};

let http_config = HttpClientConfig::new()
    .with_timeout(Duration::from_secs(30))
    .with_connect_timeout(Duration::from_secs(10))
    .with_user_agent("ThreatIntel/1.0")
    .with_proxy("http://proxy.company.com:8080")
    .with_retry_policy(RetryPolicy::exponential_backoff(3));

let config = Config::new()
    .with_http_config(http_config);
```

### Rate Limiting

```rust
use threat_intel::{Config, RateLimit};

let config = Config::new()
    .with_global_rate_limit(RateLimit::new(100, Duration::from_secs(60)))  // 100 req/min
    .with_source_rate_limit("mitre", RateLimit::new(50, Duration::from_secs(60)))
    .with_source_rate_limit("cve", RateLimit::new(25, Duration::from_secs(60)));
```

### SSL/TLS Configuration

```rust
use threat_intel::{Config, SslConfig};

let ssl_config = SslConfig::new()
    .with_verify_certificates(true)
    .with_custom_ca_bundle("/path/to/ca-bundle.pem")
    .with_client_certificate("/path/to/client.pem", "/path/to/client.key");

let config = Config::new()
    .with_ssl_config(ssl_config);
```

## Filtering Configuration

### Data Filters

```rust
use threat_intel::{Config, Filter, FilterType};

let config = Config::new()
    .with_filter(Filter::new(FilterType::Severity)
        .with_values(vec!["High", "Critical"])
    )
    .with_filter(Filter::new(FilterType::Confidence)
        .with_minimum(Confidence::Medium)
    )
    .with_filter(Filter::new(FilterType::TimeRange)
        .with_start_date(chrono::Utc::now() - chrono::Duration::days(30))
    );
```

### Source Filters

```rust
use threat_intel::{Config, SourceFilter};

let config = Config::new()
    .with_source_filter(SourceFilter::new()
        .include_sources(vec!["mitre", "cve"])
        .exclude_sources(vec!["osint"])
        .with_priority("mitre", 1)
        .with_priority("cve", 2)
    );
```

## Performance Tuning

### Concurrent Requests

```rust
use threat_intel::{Config, ConcurrencyConfig};

let concurrency_config = ConcurrencyConfig::new()
    .with_max_concurrent_requests(10)
    .with_max_concurrent_sources(5)
    .with_request_queue_size(100);

let config = Config::new()
    .with_concurrency_config(concurrency_config);
```

### Memory Management

```rust
use threat_intel::{Config, MemoryConfig};

let memory_config = MemoryConfig::new()
    .with_max_memory_usage(1024 * 1024 * 1024)  // 1GB
    .with_compression_threshold(1024)            // Compress > 1KB
    .with_gc_interval(Duration::from_secs(300)); // GC every 5 minutes

let config = Config::new()
    .with_memory_config(memory_config);
```

### Batch Processing

```rust
use threat_intel::{Config, BatchConfig};

let batch_config = BatchConfig::new()
    .with_batch_size(100)
    .with_batch_timeout(Duration::from_secs(5))
    .with_max_batch_delay(Duration::from_secs(1));

let config = Config::new()
    .with_batch_config(batch_config);
```

## Logging Configuration

### Log Levels

```rust
use threat_intel::{Config, LogConfig, LogLevel};

let log_config = LogConfig::new()
    .with_level(LogLevel::Info)
    .with_structured_logging(true)
    .with_include_sensitive_data(false)
    .with_log_file("/var/log/threat-intel.log");

let config = Config::new()
    .with_log_config(log_config);
```

### Metrics

```rust
use threat_intel::{Config, MetricsConfig};

let metrics_config = MetricsConfig::new()
    .with_enabled(true)
    .with_export_interval(Duration::from_secs(60))
    .with_metrics_endpoint("http://metrics.company.com:9090");

let config = Config::new()
    .with_metrics_config(metrics_config);
```

## Security Configuration

### Authentication

```rust
use threat_intel::{Config, AuthConfig};

let auth_config = AuthConfig::new()
    .with_api_key_rotation(Duration::from_secs(3600))
    .with_secure_storage(true)
    .with_encryption_key("your-encryption-key");

let config = Config::new()
    .with_auth_config(auth_config);
```

### Data Privacy

```rust
use threat_intel::{Config, PrivacyConfig};

let privacy_config = PrivacyConfig::new()
    .with_anonymize_ips(true)
    .with_remove_pii(true)
    .with_data_retention(Duration::from_secs(86400 * 30)); // 30 days

let config = Config::new()
    .with_privacy_config(privacy_config);
```

## Environment-Specific Configuration

### Development

```rust
use threat_intel::{Config, Environment};

let config = Config::new()
    .with_environment(Environment::Development)
    .with_debug_logging(true)
    .with_mock_sources(true)
    .with_short_timeouts();
```

### Production

```rust
use threat_intel::{Config, Environment};

let config = Config::new()
    .with_environment(Environment::Production)
    .with_high_availability(true)
    .with_monitoring(true)
    .with_security_hardening(true);
```

### Testing

```rust
use threat_intel::{Config, Environment};

let config = Config::new()
    .with_environment(Environment::Testing)
    .with_mock_sources(true)
    .with_deterministic_results(true)
    .with_fast_timeouts();
```

## Configuration Validation

### Schema Validation

```rust
use threat_intel::{Config, ConfigValidator};

let validator = ConfigValidator::new()
    .with_required_fields(vec!["api_key", "timeout"])
    .with_value_ranges("timeout", 1..=300)
    .with_enum_values("log_level", vec!["debug", "info", "warn", "error"]);

let config = Config::new()
    .with_validator(validator);
```

### Runtime Validation

```rust
use threat_intel::{Config, RuntimeValidator};

let runtime_validator = RuntimeValidator::new()
    .with_connectivity_check(true)
    .with_api_key_validation(true)
    .with_source_health_check(true);

let config = Config::new()
    .with_runtime_validator(runtime_validator);
```

## Best Practices

### 1. Use Environment Variables

```rust
use std::env;

let config = Config::new()
    .with_api_key("mitre", &env::var("MITRE_API_KEY").unwrap_or_default())
    .with_timeout(Duration::from_secs(
        env::var("TIMEOUT_SECS")
            .unwrap_or_default()
            .parse()
            .unwrap_or(30)
    ));
```

### 2. Validate Configuration

```rust
fn validate_config(config: &Config) -> Result<(), String> {
    if config.timeout().as_secs() < 1 {
        return Err("Timeout must be at least 1 second".to_string());
    }
    
    if config.max_sources() == 0 {
        return Err("At least one source must be configured".to_string());
    }
    
    Ok(())
}
```

### 3. Use Configuration Profiles

```rust
use threat_intel::{Config, Profile};

let config = match env::var("ENVIRONMENT").unwrap_or_default().as_str() {
    "production" => Config::production(),
    "staging" => Config::staging(),
    "development" => Config::development(),
    _ => Config::default(),
};
```

## Troubleshooting

### Common Issues

**1. API Key Errors**
```rust
// Check API key configuration
if config.api_keys().is_empty() {
    eprintln!("No API keys configured");
}

// Validate API keys
for (source, key) in config.api_keys() {
    if key.is_empty() {
        eprintln!("Empty API key for source: {}", source);
    }
}
```

**2. Timeout Issues**
```rust
// Increase timeout for slow sources
let config = Config::new()
    .with_timeout(Duration::from_secs(60))  // Increase from default 30s
    .with_retry_attempts(5);                 // More retries
```

**3. Rate Limiting**
```rust
// Configure rate limits per source
let config = Config::new()
    .with_source_rate_limit("mitre", RateLimit::new(10, Duration::from_secs(60)))
    .with_source_rate_limit("cve", RateLimit::new(5, Duration::from_secs(60)));
```

## Next Steps

- Review [Data Sources](./data-sources.md) for available sources
- Check [Integration Guide](./integration.md) for system integration
- See [Performance Tuning](./performance.md) for optimization tips
