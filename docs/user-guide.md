# User Guide - Threat Intelligence

## Overview

This user guide provides comprehensive instructions for using the Threat Intelligence module. It covers everything from basic setup to advanced features, with practical examples and best practices.

## Getting Started

### Installation

```bash
# Add to Cargo.toml
[dependencies]
threat-intel = "0.1.0"
```

### Basic Setup

```rust
use threat_intel::{ThreatRegistry, Config};

// Create a new threat registry
let registry = ThreatRegistry::new()
    .with_config(Config::default())
    .build();

// Initialize the registry
registry.initialize().await?;
```

## Core Concepts

### 1. Threat Data Model

#### Threat Structure

```rust
use threat_intel::{Threat, ThreatType, ThreatSource, RiskLevel};

// Create a new threat
let threat = Threat {
    id: "threat-123".to_string(),
    name: "SQL Injection Attack".to_string(),
    description: "Attempted SQL injection on login endpoint".to_string(),
    threat_type: ThreatType::Attack,
    source: ThreatSource::MitreAttack,
    risk_level: RiskLevel::High,
    capabilities: vec!["sql_injection".to_string(), "data_exfiltration".to_string()],
    indicators: vec!["payload: ' OR 1=1--".to_string()],
    metadata: HashMap::new(),
    created_at: Utc::now(),
    updated_at: Utc::now(),
};
```

#### Threat Types

```rust
use threat_intel::ThreatType;

// Different threat types
let attack_threat = ThreatType::Attack;
let vulnerability_threat = ThreatType::Vulnerability;
let malware_threat = ThreatType::Malware;
let phishing_threat = ThreatType::Phishing;
let insider_threat = ThreatType::InsiderThreat;
```

### 2. Threat Sources

#### MITRE ATT&CK Integration

```rust
use threat_intel::{ThreatRegistry, MitreAttackSource};

// Configure MITRE ATT&CK source
let mitre_source = MitreAttackSource::new()
    .with_enterprise_techniques(true)
    .with_mobile_techniques(true)
    .with_ics_techniques(true)
    .with_cloud_techniques(true);

let registry = ThreatRegistry::new()
    .with_source(mitre_source)
    .build();
```

#### CVE Database Integration

```rust
use threat_intel::{ThreatRegistry, CveSource};

// Configure CVE source
let cve_source = CveSource::new()
    .with_cvss_scoring(true)
    .with_epss_scoring(true)
    .with_kev_list(true)
    .with_update_interval(Duration::from_secs(86400)); // 24 hours

let registry = ThreatRegistry::new()
    .with_source(cve_source)
    .build();
```

#### OSINT Feed Integration

```rust
use threat_intel::{ThreatRegistry, OsintSource};

// Configure OSINT source
let osint_source = OsintSource::new()
    .with_feed_url("https://osint-feed.example.com/threats".to_string())
    .with_auth_token("your-api-token".to_string())
    .with_update_interval(Duration::from_secs(3600)) // 1 hour
    .with_priority(Priority::Medium);

let registry = ThreatRegistry::new()
    .with_source(osint_source)
    .build();
```

## Basic Operations

### 1. Adding Threats

#### Manual Threat Addition

```rust
use threat_intel::{ThreatRegistry, Threat, ThreatType, RiskLevel};

// Create threat registry
let registry = ThreatRegistry::new().build();

// Add a new threat
let threat = Threat {
    id: "custom-threat-001".to_string(),
    name: "Custom Malware".to_string(),
    description: "Custom malware detected in network".to_string(),
    threat_type: ThreatType::Malware,
    source: ThreatSource::UserReport,
    risk_level: RiskLevel::High,
    capabilities: vec!["file_encryption".to_string(), "network_communication".to_string()],
    indicators: vec!["hash: abc123def456".to_string()],
    metadata: HashMap::new(),
    created_at: Utc::now(),
    updated_at: Utc::now(),
};

registry.add_threat(threat).await?;
```

#### Bulk Threat Addition

```rust
use threat_intel::{ThreatRegistry, ThreatBatch};

// Create threat batch
let threat_batch = ThreatBatch::new()
    .with_threats(vec![threat1, threat2, threat3])
    .with_batch_size(100)
    .with_parallel_processing(true);

// Add threats in batch
registry.add_threats_batch(threat_batch).await?;
```

### 2. Querying Threats

#### Basic Queries

```rust
use threat_intel::{ThreatRegistry, ThreatQuery};

// Create threat registry
let registry = ThreatRegistry::new().build();

// Get all threats
let all_threats = registry.get_all_threats().await?;

// Get threat by ID
let threat = registry.get_threat_by_id("threat-123").await?;

// Get threats by type
let malware_threats = registry.get_threats_by_type(ThreatType::Malware).await?;

// Get threats by risk level
let high_risk_threats = registry.get_threats_by_risk_level(RiskLevel::High).await?;
```

#### Advanced Queries

```rust
use threat_intel::{ThreatRegistry, ThreatQuery, QueryBuilder};

// Create advanced query
let query = QueryBuilder::new()
    .with_threat_type(ThreatType::Attack)
    .with_risk_level(RiskLevel::High)
    .with_capabilities(vec!["sql_injection".to_string()])
    .with_time_range(TimeRange::Last24Hours)
    .with_source(ThreatSource::MitreAttack)
    .build();

// Execute query
let threats = registry.query_threats(query).await?;
```

#### Capability-based Queries

```rust
use threat_intel::{ThreatRegistry, CapabilityQuery};

// Query by capability
let capability_query = CapabilityQuery::new()
    .with_capability("privilege_escalation")
    .with_environment("linux")
    .with_technology("kubernetes");

let threats = registry.query_by_capability(capability_query).await?;
```

### 3. Threat Updates

#### Updating Threat Information

```rust
use threat_intel::{ThreatRegistry, ThreatUpdate};

// Create threat update
let threat_update = ThreatUpdate::new("threat-123")
    .with_risk_level(RiskLevel::Critical)
    .with_description("Updated threat description")
    .with_indicators(vec!["new_indicator".to_string()])
    .with_metadata("key", "value");

// Apply update
registry.update_threat(threat_update).await?;
```

#### Bulk Updates

```rust
use threat_intel::{ThreatRegistry, ThreatBatchUpdate};

// Create batch update
let batch_update = ThreatBatchUpdate::new()
    .with_threat_ids(vec!["threat-1", "threat-2", "threat-3"])
    .with_risk_level(RiskLevel::Medium)
    .with_metadata("updated_by", "system");

// Apply batch update
registry.update_threats_batch(batch_update).await?;
```

## Advanced Features

### 1. Risk Assessment

#### Automated Risk Scoring

```rust
use threat_intel::{ThreatRegistry, RiskAssessment};

// Configure risk assessment
let risk_assessment = RiskAssessment::new()
    .with_cvss_scoring(true)
    .with_mitre_impact(true)
    .with_recency_scoring(true)
    .with_source_reliability(true)
    .with_environmental_context(true);

let registry = ThreatRegistry::new()
    .with_risk_assessment(risk_assessment)
    .build();

// Calculate risk score for threat
let risk_score = registry.calculate_risk_score("threat-123").await?;
println!("Risk Score: {}", risk_score);
```

#### Risk-based Filtering

```rust
use threat_intel::{ThreatRegistry, RiskFilter};

// Create risk filter
let risk_filter = RiskFilter::new()
    .with_min_risk_score(6.0)
    .with_max_risk_score(10.0)
    .with_risk_levels(vec![RiskLevel::High, RiskLevel::Critical]);

// Filter threats by risk
let high_risk_threats = registry.filter_by_risk(risk_filter).await?;
```

### 2. Threat Intelligence Sharing

#### Export Threats

```rust
use threat_intel::{ThreatRegistry, ThreatExport};

// Configure threat export
let threat_export = ThreatExport::new()
    .with_format(ExportFormat::Json)
    .with_compression(true)
    .with_encryption(true)
    .with_include_metadata(true);

let registry = ThreatRegistry::new()
    .with_export_config(threat_export)
    .build();

// Export threats
let export_data = registry.export_threats().await?;
```

#### Import Threats

```rust
use threat_intel::{ThreatRegistry, ThreatImport};

// Configure threat import
let threat_import = ThreatImport::new()
    .with_format(ImportFormat::Json)
    .with_validation(true)
    .with_duplicate_handling(DuplicateHandling::Skip)
    .with_batch_size(1000);

let registry = ThreatRegistry::new()
    .with_import_config(threat_import)
    .build();

// Import threats
let import_result = registry.import_threats(import_data).await?;
```

### 3. Real-time Monitoring

#### Threat Monitoring

```rust
use threat_intel::{ThreatRegistry, ThreatMonitoring};

// Configure threat monitoring
let threat_monitoring = ThreatMonitoring::new()
    .with_monitoring_interval(Duration::from_secs(60))
    .with_alert_threshold(5.0)
    .with_alert_channels(vec![AlertChannel::Email, AlertChannel::Slack])
    .with_auto_response(true);

let registry = ThreatRegistry::new()
    .with_monitoring(threat_monitoring)
    .build();

// Start monitoring
registry.start_monitoring().await?;
```

#### Event Handling

```rust
use threat_intel::{ThreatRegistry, EventHandler};

// Create event handler
let event_handler = EventHandler::new()
    .on_threat_created(|threat| {
        println!("New threat created: {}", threat.name);
        Ok(())
    })
    .on_threat_updated(|threat| {
        println!("Threat updated: {}", threat.name);
        Ok(())
    })
    .on_risk_level_changed(|threat, old_level, new_level| {
        println!("Risk level changed for {}: {} -> {}", threat.name, old_level, new_level);
        Ok(())
    });

let registry = ThreatRegistry::new()
    .with_event_handler(event_handler)
    .build();
```

## Integration Examples

### 1. SIEM Integration

#### Splunk Integration

```rust
use threat_intel::{ThreatRegistry, SplunkConnector};

// Configure Splunk connector
let splunk_connector = SplunkConnector::new()
    .with_host("https://splunk.company.com".to_string())
    .with_token("your-splunk-token".to_string())
    .with_index("threat_intel".to_string())
    .with_auto_export(true);

let registry = ThreatRegistry::new()
    .with_connector(splunk_connector)
    .build();
```

#### Elastic SIEM Integration

```rust
use threat_intel::{ThreatRegistry, ElasticConnector};

// Configure Elastic connector
let elastic_connector = ElasticConnector::new()
    .with_host("https://elastic.company.com".to_string())
    .with_username("elastic".to_string())
    .with_password("password".to_string())
    .with_index("threat-intel-*".to_string());

let registry = ThreatRegistry::new()
    .with_connector(elastic_connector)
    .build();
```

### 2. API Integration

#### REST API Server

```rust
use threat_intel::{ThreatRegistry, ApiServer};
use warp::Filter;

// Create API server
let registry = ThreatRegistry::new().build();
let api_server = ApiServer::new(registry);

// Define API routes
let routes = warp::path("api")
    .and(warp::path("threats"))
    .and(warp::get())
    .and(api_server.get_threats_handler())
    .or(warp::path("api")
        .and(warp::path("threats"))
        .and(warp::post())
        .and(api_server.create_threat_handler()));

// Start server
warp::serve(routes).run(([0, 0, 0, 0], 8080)).await;
```

#### GraphQL API

```rust
use threat_intel::{ThreatRegistry, GraphQLServer};
use juniper::{EmptyMutation, EmptySubscription, RootNode};

// Define GraphQL schema
type Schema = RootNode<'static, Query, EmptyMutation, EmptySubscription>;

struct Query;

#[juniper::object]
impl Query {
    async fn threats(&self) -> Vec<Threat> {
        registry.get_all_threats().await.unwrap_or_default()
    }
    
    async fn threat_by_id(&self, id: String) -> Option<Threat> {
        registry.get_threat_by_id(&id).await.ok()
    }
}

// Create GraphQL server
let registry = ThreatRegistry::new().build();
let schema = Schema::new(Query, EmptyMutation, EmptySubscription);
let server = GraphQLServer::new(registry, schema);
```

### 3. Database Integration

#### PostgreSQL Integration

```rust
use threat_intel::{ThreatRegistry, PostgresConnector};
use sqlx::PgPool;

// Configure PostgreSQL connection
let pool = PgPool::connect("postgresql://user:pass@localhost/threat_intel").await?;

let postgres_connector = PostgresConnector::new(pool);
let registry = ThreatRegistry::new()
    .with_connector(postgres_connector)
    .build();

// Sync threat data to PostgreSQL
registry.sync_to_database().await?;
```

#### MongoDB Integration

```rust
use threat_intel::{ThreatRegistry, MongoConnector};
use mongodb::Client;

// Configure MongoDB connection
let client = Client::with_uri_str("mongodb://localhost:27017").await?;
let db = client.database("threat_intel");

let mongo_connector = MongoConnector::new(db);
let registry = ThreatRegistry::new()
    .with_connector(mongo_connector)
    .build();
```

## Configuration

### 1. Basic Configuration

```rust
use threat_intel::{ThreatRegistry, Config};

// Create configuration
let config = Config::new()
    .with_max_threats(1000000)
    .with_cache_size(10000)
    .with_update_interval(Duration::from_secs(3600))
    .with_risk_assessment(true)
    .with_monitoring(true);

let registry = ThreatRegistry::new()
    .with_config(config)
    .build();
```

### 2. Advanced Configuration

```rust
use threat_intel::{ThreatRegistry, AdvancedConfig};

// Create advanced configuration
let advanced_config = AdvancedConfig::new()
    .with_performance_config(PerformanceConfig {
        max_memory_usage: 2 * 1024 * 1024 * 1024, // 2GB
        gc_threshold: 0.8,
        batch_size: 1000,
        parallel_processing: true,
    })
    .with_security_config(SecurityConfig {
        encryption: true,
        authentication: true,
        authorization: true,
        audit_logging: true,
    })
    .with_monitoring_config(MonitoringConfig {
        metrics_enabled: true,
        health_checks: true,
        alerting: true,
        logging: true,
    });

let registry = ThreatRegistry::new()
    .with_advanced_config(advanced_config)
    .build();
```

## Best Practices

### 1. Threat Management

1. **Regular Updates**: Keep threat data updated with latest intelligence
2. **Data Quality**: Ensure high-quality threat data with proper validation
3. **Classification**: Use consistent threat classification and tagging
4. **Documentation**: Document threat assessment decisions and rationale
5. **Review Process**: Implement regular threat review and validation processes

### 2. Performance Optimization

1. **Caching**: Use caching for frequently accessed threat data
2. **Indexing**: Implement proper indexing for fast queries
3. **Batch Operations**: Use batch operations for bulk data processing
4. **Resource Management**: Monitor and manage resource usage
5. **Scalability**: Design for horizontal scaling when needed

### 3. Security Considerations

1. **Access Control**: Implement proper access control and authentication
2. **Data Encryption**: Encrypt sensitive threat data in transit and at rest
3. **Audit Logging**: Implement comprehensive audit logging
4. **Data Retention**: Implement proper data retention policies
5. **Compliance**: Ensure compliance with relevant regulations and standards

### 4. Integration Best Practices

1. **API Design**: Design clean, consistent APIs for integration
2. **Error Handling**: Implement robust error handling and retry logic
3. **Rate Limiting**: Implement rate limiting to prevent abuse
4. **Monitoring**: Monitor integration health and performance
5. **Documentation**: Provide comprehensive integration documentation

## Troubleshooting

### Common Issues

1. **Performance Issues**: Check memory usage, query performance, and resource utilization
2. **Data Quality Issues**: Validate threat data quality and completeness
3. **Integration Issues**: Check network connectivity, authentication, and API compatibility
4. **Configuration Issues**: Verify configuration settings and parameters

### Debugging

```rust
use threat_intel::{ThreatRegistry, DebugConfig};

// Enable debug logging
let debug_config = DebugConfig {
    log_level: LogLevel::Debug,
    log_requests: true,
    log_responses: true,
    log_errors: true,
};

let registry = ThreatRegistry::new()
    .with_debug_config(debug_config)
    .build();
```

### Getting Help

1. **Documentation**: Check the comprehensive documentation
2. **Community**: Join the community discussions and forums
3. **Support**: Contact support for enterprise deployments
4. **Issues**: Report issues on the GitHub repository
