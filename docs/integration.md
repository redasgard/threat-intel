# Integration Guide - Threat Intelligence

## Overview

This guide covers integrating the Threat Intelligence module with various systems, platforms, and tools. The module is designed to be flexible and work with existing security infrastructure.

## Integration Patterns

### 1. SIEM Integration

#### Splunk Integration

```rust
use threat_intel::{ThreatRegistry, SplunkConnector};

// Configure Splunk connector
let splunk_config = SplunkConfig {
    host: "https://splunk.company.com".to_string(),
    token: "your-splunk-token".to_string(),
    index: "threat_intel".to_string(),
};

let connector = SplunkConnector::new(splunk_config);
let registry = ThreatRegistry::new()
    .with_connector(connector)
    .build();

// Send threat data to Splunk
registry.export_to_splunk().await?;
```

#### Elastic SIEM Integration

```rust
use threat_intel::{ThreatRegistry, ElasticConnector};

let elastic_config = ElasticConfig {
    host: "https://elastic.company.com".to_string(),
    username: "elastic".to_string(),
    password: "password".to_string(),
    index: "threat-intel-*".to_string(),
};

let connector = ElasticConnector::new(elastic_config);
let registry = ThreatRegistry::new()
    .with_connector(connector)
    .build();
```

#### IBM QRadar Integration

```rust
use threat_intel::{ThreatRegistry, QRadarConnector};

let qradar_config = QRadarConfig {
    host: "https://qradar.company.com".to_string(),
    token: "qradar-token".to_string(),
    reference_set: "threat_intel".to_string(),
};

let connector = QRadarConnector::new(qradar_config);
let registry = ThreatRegistry::new()
    .with_connector(connector)
    .build();
```

### 2. Security Orchestration Integration

#### SOAR Platform Integration

```rust
use threat_intel::{ThreatRegistry, SoarConnector};

// Configure SOAR connector
let soar_config = SoarConfig {
    platform: SoarPlatform::Phantom,
    endpoint: "https://phantom.company.com".to_string(),
    credentials: SoarCredentials::ApiKey("api-key".to_string()),
};

let connector = SoarConnector::new(soar_config);
let registry = ThreatRegistry::new()
    .with_connector(connector)
    .build();

// Trigger SOAR playbooks based on threat data
registry.on_high_risk_threat(|threat| {
    soar_connector.trigger_playbook("incident_response", threat).await
}).await?;
```

### 3. API Integration

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

#### GraphQL Integration

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

### 4. Database Integration

#### PostgreSQL Integration

```rust
use threat_intel::{ThreatRegistry, PostgresConnector};
use sqlx::PgPool;

// Configure PostgreSQL connection
let pool = PgPool::connect("postgresql://user:pass@localhost/threat_intel").await?;

let connector = PostgresConnector::new(pool);
let registry = ThreatRegistry::new()
    .with_connector(connector)
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

let connector = MongoConnector::new(db);
let registry = ThreatRegistry::new()
    .with_connector(connector)
    .build();
```

### 5. Message Queue Integration

#### Apache Kafka Integration

```rust
use threat_intel::{ThreatRegistry, KafkaConnector};
use kafka::producer::Producer;

// Configure Kafka producer
let producer = Producer::from_hosts(vec!["localhost:9092".to_string()])
    .create()
    .unwrap();

let connector = KafkaConnector::new(producer, "threat-intel".to_string());
let registry = ThreatRegistry::new()
    .with_connector(connector)
    .build();

// Publish threat updates to Kafka
registry.on_threat_update(|threat| {
    kafka_connector.publish_threat(threat).await
}).await?;
```

#### RabbitMQ Integration

```rust
use threat_intel::{ThreatRegistry, RabbitMQConnector};
use lapin::{Connection, ConnectionProperties};

// Configure RabbitMQ connection
let connection = Connection::connect(
    "amqp://guest:guest@localhost:5672",
    ConnectionProperties::default(),
).await?;

let channel = connection.create_channel().await?;
let connector = RabbitMQConnector::new(channel, "threat.intel".to_string());
let registry = ThreatRegistry::new()
    .with_connector(connector)
    .build();
```

## Webhook Integration

### Outbound Webhooks

```rust
use threat_intel::{ThreatRegistry, WebhookConfig};

// Configure webhook
let webhook_config = WebhookConfig {
    url: "https://your-system.com/webhook".to_string(),
    secret: "webhook-secret".to_string(),
    events: vec![
        "threat.created".to_string(),
        "threat.updated".to_string(),
        "threat.deleted".to_string(),
    ],
};

let registry = ThreatRegistry::new()
    .with_webhook(webhook_config)
    .build();
```

### Inbound Webhooks

```rust
use threat_intel::{ThreatRegistry, WebhookHandler};
use warp::Filter;

// Create webhook handler
let registry = ThreatRegistry::new().build();
let webhook_handler = WebhookHandler::new(registry);

// Define webhook endpoint
let webhook_route = warp::path("webhook")
    .and(warp::post())
    .and(warp::body::json())
    .and(webhook_handler.handle_webhook());

warp::serve(webhook_route).run(([0, 0, 0, 0], 8080)).await;
```

## Cloud Platform Integration

### AWS Integration

```rust
use threat_intel::{ThreatRegistry, AwsConnector};
use aws_sdk_s3::Client as S3Client;

// Configure AWS S3 connector
let s3_client = S3Client::new(&aws_config);
let connector = AwsConnector::new(s3_client, "threat-intel-bucket".to_string());
let registry = ThreatRegistry::new()
    .with_connector(connector)
    .build();

// Export to S3
registry.export_to_s3("threat-data.json").await?;
```

### Azure Integration

```rust
use threat_intel::{ThreatRegistry, AzureConnector};
use azure_storage_blobs::prelude::*;

// Configure Azure Blob Storage connector
let client = ClientBuilder::new("account", "key").build();
let connector = AzureConnector::new(client, "threat-intel".to_string());
let registry = ThreatRegistry::new()
    .with_connector(connector)
    .build();
```

### Google Cloud Integration

```rust
use threat_intel::{ThreatRegistry, GcpConnector};
use google_cloud_storage::Client as GcsClient;

// Configure Google Cloud Storage connector
let gcs_client = GcsClient::new().await?;
let connector = GcpConnector::new(gcs_client, "threat-intel-bucket".to_string());
let registry = ThreatRegistry::new()
    .with_connector(connector)
    .build();
```

## Monitoring and Alerting Integration

### Prometheus Integration

```rust
use threat_intel::{ThreatRegistry, PrometheusExporter};
use prometheus::{Counter, Histogram, Registry as PromRegistry};

// Configure Prometheus metrics
let prom_registry = PromRegistry::new();
let threat_counter = Counter::new("threats_total", "Total number of threats").unwrap();
let processing_time = Histogram::new("threat_processing_seconds", "Threat processing time").unwrap();

let exporter = PrometheusExporter::new(prom_registry, threat_counter, processing_time);
let registry = ThreatRegistry::new()
    .with_exporter(exporter)
    .build();
```

### Grafana Integration

```rust
use threat_intel::{ThreatRegistry, GrafanaConnector};

// Configure Grafana connector
let grafana_config = GrafanaConfig {
    url: "https://grafana.company.com".to_string(),
    api_key: "grafana-api-key".to_string(),
    dashboard_id: "threat-intel-dashboard".to_string(),
};

let connector = GrafanaConnector::new(grafana_config);
let registry = ThreatRegistry::new()
    .with_connector(connector)
    .build();
```

## Custom Integration

### Building Custom Connectors

```rust
use threat_intel::{ThreatRegistry, Connector, ThreatData};
use async_trait::async_trait;

// Define custom connector
struct MyCustomConnector {
    endpoint: String,
    api_key: String,
}

#[async_trait]
impl Connector for MyCustomConnector {
    async fn send_threat(&self, threat: &ThreatData) -> Result<(), Box<dyn std::error::Error>> {
        // Implement custom sending logic
        let client = reqwest::Client::new();
        let response = client
            .post(&self.endpoint)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(threat)
            .send()
            .await?;
        
        if response.status().is_success() {
            Ok(())
        } else {
            Err("Failed to send threat".into())
        }
    }
}

// Use custom connector
let custom_connector = MyCustomConnector {
    endpoint: "https://my-system.com/api/threats".to_string(),
    api_key: "my-api-key".to_string(),
};

let registry = ThreatRegistry::new()
    .with_connector(custom_connector)
    .build();
```

## Configuration Management

### Environment-based Configuration

```rust
use threat_intel::{ThreatRegistry, Config};

// Load configuration from environment
let config = Config::from_env()?;

let registry = ThreatRegistry::new()
    .with_config(config)
    .build();
```

### Configuration Files

```yaml
# config.yaml
threat_intel:
  sources:
    - name: "mitre_attack"
      url: "https://attack.mitre.org/api"
      update_interval: "1h"
      priority: "high"
    
    - name: "cve_database"
      url: "https://cve.mitre.org/api"
      update_interval: "24h"
      priority: "medium"
  
  connectors:
    - type: "splunk"
      host: "https://splunk.company.com"
      token: "${SPLUNK_TOKEN}"
    
    - type: "elastic"
      host: "https://elastic.company.com"
      username: "${ELASTIC_USERNAME}"
      password: "${ELASTIC_PASSWORD}"
  
  webhooks:
    - url: "https://your-system.com/webhook"
      secret: "${WEBHOOK_SECRET}"
      events: ["threat.created", "threat.updated"]
```

## Testing Integration

### Integration Testing

```rust
use threat_intel::{ThreatRegistry, MockConnector};
use tokio_test;

#[tokio::test]
async fn test_splunk_integration() {
    // Create mock Splunk connector
    let mock_connector = MockConnector::new();
    let registry = ThreatRegistry::new()
        .with_connector(mock_connector)
        .build();
    
    // Test threat export
    let threats = registry.get_all_threats().await.unwrap();
    registry.export_to_splunk().await.unwrap();
    
    // Verify connector was called
    assert!(mock_connector.was_called());
}
```

### Load Testing

```rust
use threat_intel::{ThreatRegistry, LoadTestConfig};

// Configure load testing
let load_test_config = LoadTestConfig {
    concurrent_requests: 100,
    duration: Duration::from_secs(300),
    ramp_up_time: Duration::from_secs(60),
};

let registry = ThreatRegistry::new()
    .with_load_test_config(load_test_config)
    .build();

// Run load test
registry.run_load_test().await?;
```

## Security Considerations

### Authentication and Authorization

```rust
use threat_intel::{ThreatRegistry, AuthConfig};

// Configure authentication
let auth_config = AuthConfig {
    jwt_secret: "your-jwt-secret".to_string(),
    token_expiry: Duration::from_secs(3600),
    roles: vec![
        "admin".to_string(),
        "analyst".to_string(),
        "viewer".to_string(),
    ],
};

let registry = ThreatRegistry::new()
    .with_auth_config(auth_config)
    .build();
```

### Data Encryption

```rust
use threat_intel::{ThreatRegistry, EncryptionConfig};

// Configure encryption
let encryption_config = EncryptionConfig {
    algorithm: EncryptionAlgorithm::Aes256Gcm,
    key: "your-encryption-key".to_string(),
    iv: "your-initialization-vector".to_string(),
};

let registry = ThreatRegistry::new()
    .with_encryption_config(encryption_config)
    .build();
```

## Troubleshooting

### Common Integration Issues

1. **Authentication Failures**
   - Verify API credentials
   - Check token expiration
   - Ensure proper permissions

2. **Network Connectivity**
   - Test network connectivity
   - Check firewall rules
   - Verify DNS resolution

3. **Data Format Issues**
   - Validate JSON schema
   - Check field mappings
   - Verify data types

4. **Performance Issues**
   - Monitor resource usage
   - Check rate limits
   - Optimize queries

### Debugging Tools

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

## Best Practices

### Integration Best Practices

1. **Error Handling**: Implement robust error handling and retry logic
2. **Rate Limiting**: Respect API rate limits and implement backoff
3. **Monitoring**: Monitor integration health and performance
4. **Security**: Use secure authentication and encryption
5. **Testing**: Implement comprehensive integration tests
6. **Documentation**: Document integration patterns and configurations

### Performance Optimization

1. **Batch Operations**: Use batch operations when possible
2. **Caching**: Implement caching for frequently accessed data
3. **Async Processing**: Use async processing for non-blocking operations
4. **Resource Management**: Monitor and manage resource usage
5. **Connection Pooling**: Use connection pooling for database connections
