# API Reference

Complete API documentation for Threat Intelligence.

## Core Types

### ThreatIntelligence

Main threat intelligence client.

```rust
pub struct ThreatIntelligence {
    config: Config,
    sources: Vec<Box<dyn ThreatSource>>,
    cache: Cache,
}
```

#### Methods

##### `new()`

```rust
pub fn new(config: Config) -> Self
```

Create a new threat intelligence client.

**Parameters:**
- `config` - Configuration for the client

**Returns:** New `ThreatIntelligence` instance

**Example:**
```rust
let config = Config::default();
let ti = ThreatIntelligence::new(config);
```

##### `add_source()`

```rust
pub fn add_source(&mut self, source: Box<dyn ThreatSource>) -> &mut Self
```

Add a threat intelligence source.

**Parameters:**
- `source` - Threat source to add

**Returns:** `&mut Self` for chaining

**Example:**
```rust
let mut ti = ThreatIntelligence::new(config);
ti.add_source(Box::new(MitreSource::new()));
```

##### `query()`

```rust
pub async fn query(&self, query: Query) -> Result<Vec<ThreatData>, Error>
```

Query threat intelligence data.

**Parameters:**
- `query` - Query to execute

**Returns:** `Result<Vec<ThreatData>, Error>` - Threat data results

**Example:**
```rust
let query = Query::new()
    .with_tactic("TA0001")
    .with_technique("T1055")
    .with_confidence(Confidence::High);

let threats = ti.query(query).await?;
```

##### `assess_risk()`

```rust
pub async fn assess_risk(&self, context: &RiskContext) -> Result<RiskAssessment, Error>
```

Assess risk for a given context.

**Parameters:**
- `context` - Risk assessment context

**Returns:** `Result<RiskAssessment, Error>` - Risk assessment

**Example:**
```rust
let context = RiskContext::new()
    .with_asset("web-server")
    .with_environment("production");

let risk = ti.assess_risk(&context).await?;
```

---

## Query Types

### Query

Threat intelligence query builder.

```rust
pub struct Query {
    tactics: Vec<String>,
    techniques: Vec<String>,
    confidence: Option<Confidence>,
    time_range: Option<TimeRange>,
    sources: Vec<String>,
}
```

#### Builder Methods

##### `new()`

```rust
pub fn new() -> Self
```

Create a new query.

##### `with_tactic()`

```rust
pub fn with_tactic(mut self, tactic: &str) -> Self
```

Add a MITRE ATT&CK tactic.

**Example:**
```rust
let query = Query::new()
    .with_tactic("TA0001")  // Initial Access
    .with_tactic("TA0002"); // Execution
```

##### `with_technique()`

```rust
pub fn with_technique(mut self, technique: &str) -> Self
```

Add a MITRE ATT&CK technique.

**Example:**
```rust
let query = Query::new()
    .with_technique("T1055")  // Process Injection
    .with_technique("T1059"); // Command and Scripting Interpreter
```

##### `with_confidence()`

```rust
pub fn with_confidence(mut self, confidence: Confidence) -> Self
```

Set minimum confidence level.

**Example:**
```rust
let query = Query::new()
    .with_confidence(Confidence::High);
```

##### `with_time_range()`

```rust
pub fn with_time_range(mut self, range: TimeRange) -> Self
```

Set time range for data.

**Example:**
```rust
let query = Query::new()
    .with_time_range(TimeRange::last_30_days());
```

---

## Data Types

### ThreatData

Individual threat intelligence record.

```rust
pub struct ThreatData {
    pub id: String,
    pub title: String,
    pub description: String,
    pub threat_type: ThreatType,
    pub severity: Severity,
    pub confidence: Confidence,
    pub source: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub tags: Vec<String>,
    pub indicators: Vec<Indicator>,
    pub references: Vec<Reference>,
}
```

#### Fields

- `id` - Unique identifier
- `title` - Threat title
- `description` - Detailed description
- `threat_type` - Type of threat
- `severity` - Severity level
- `confidence` - Confidence level
- `source` - Data source
- `created_at` - Creation timestamp
- `updated_at` - Last update timestamp
- `tags` - Associated tags
- `indicators` - Threat indicators
- `references` - External references

### ThreatType

Enumeration of threat types.

```rust
pub enum ThreatType {
    Malware,
    Vulnerability,
    AttackPattern,
    Campaign,
    IntrusionSet,
    Tool,
    Infrastructure,
    DataSource,
}
```

### Severity

Threat severity levels.

```rust
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}
```

### Confidence

Confidence levels for threat data.

```rust
pub enum Confidence {
    VeryHigh,
    High,
    Medium,
    Low,
    VeryLow,
}
```

### Indicator

Threat indicator data.

```rust
pub struct Indicator {
    pub indicator_type: IndicatorType,
    pub value: String,
    pub description: String,
    pub confidence: Confidence,
}
```

#### IndicatorType

```rust
pub enum IndicatorType {
    Hash,
    IpAddress,
    Domain,
    Url,
    Email,
    File,
    Registry,
    Mutex,
    Service,
    Driver,
    UserAgent,
    Certificate,
    Bitcoin,
    EmailAddress,
    EmailSubject,
    FileName,
    FilePath,
    MacAddress,
    Other,
}
```

---

## Risk Assessment

### RiskContext

Context for risk assessment.

```rust
pub struct RiskContext {
    pub asset: String,
    pub environment: String,
    pub business_impact: BusinessImpact,
    pub technical_controls: Vec<String>,
    pub organizational_controls: Vec<String>,
}
```

### RiskAssessment

Result of risk assessment.

```rust
pub struct RiskAssessment {
    pub overall_risk: RiskLevel,
    pub risk_factors: Vec<RiskFactor>,
    pub recommendations: Vec<Recommendation>,
    pub mitigation_strategies: Vec<MitigationStrategy>,
}
```

### RiskLevel

Risk level enumeration.

```rust
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Minimal,
}
```

---

## Configuration

### Config

Threat intelligence configuration.

```rust
pub struct Config {
    pub cache_ttl: Duration,
    pub max_sources: usize,
    pub timeout: Duration,
    pub retry_attempts: u32,
    pub api_keys: HashMap<String, String>,
    pub filters: Vec<Filter>,
}
```

#### Builder Methods

##### `new()`

```rust
pub fn new() -> Self
```

Create default configuration.

##### `with_cache_ttl()`

```rust
pub fn with_cache_ttl(mut self, ttl: Duration) -> Self
```

Set cache time-to-live.

##### `with_timeout()`

```rust
pub fn with_timeout(mut self, timeout: Duration) -> Self
```

Set request timeout.

##### `with_api_key()`

```rust
pub fn with_api_key(mut self, source: &str, key: &str) -> Self
```

Add API key for source.

**Example:**
```rust
let config = Config::new()
    .with_cache_ttl(Duration::from_secs(3600))
    .with_timeout(Duration::from_secs(30))
    .with_api_key("mitre", "your-api-key");
```

---

## Data Sources

### ThreatSource

Trait for threat intelligence sources.

```rust
pub trait ThreatSource: Send + Sync {
    fn name(&self) -> &str;
    async fn query(&self, query: &Query) -> Result<Vec<ThreatData>, Error>;
    async fn health_check(&self) -> Result<bool, Error>;
}
```

### Built-in Sources

#### MitreSource

MITRE ATT&CK framework source.

```rust
pub struct MitreSource {
    client: reqwest::Client,
    base_url: String,
}
```

**Methods:**
- `new()` - Create new MITRE source
- `with_custom_url()` - Use custom API URL

#### CveSource

CVE database source.

```rust
pub struct CveSource {
    client: reqwest::Client,
    api_key: Option<String>,
}
```

**Methods:**
- `new()` - Create new CVE source
- `with_api_key()` - Add API key for rate limits

#### OsintSource

Open source intelligence source.

```rust
pub struct OsintSource {
    feeds: Vec<Feed>,
    client: reqwest::Client,
}
```

**Methods:**
- `new()` - Create new OSINT source
- `add_feed()` - Add intelligence feed

---

## Error Handling

### Error

Threat intelligence errors.

```rust
pub enum Error {
    NetworkError(reqwest::Error),
    ParseError(serde_json::Error),
    SourceError(String),
    CacheError(String),
    ConfigurationError(String),
    TimeoutError,
    RateLimitError,
    AuthenticationError,
}
```

### Error Handling Example

```rust
use threat_intel::{ThreatIntelligence, Error};

async fn handle_query() -> Result<(), Box<dyn std::error::Error>> {
    let ti = ThreatIntelligence::new(Config::default());
    
    match ti.query(query).await {
        Ok(threats) => {
            println!("Found {} threats", threats.len());
        }
        Err(Error::NetworkError(e)) => {
            eprintln!("Network error: {}", e);
        }
        Err(Error::RateLimitError) => {
            eprintln!("Rate limit exceeded, retrying later");
        }
        Err(e) => {
            eprintln!("Unexpected error: {}", e);
        }
    }
    
    Ok(())
}
```

---

## Async Operations

### Concurrent Queries

```rust
use futures::future::join_all;

async fn query_multiple_sources(ti: &ThreatIntelligence, queries: Vec<Query>) -> Result<Vec<Vec<ThreatData>>, Error> {
    let futures: Vec<_> = queries.into_iter()
        .map(|query| ti.query(query))
        .collect();
    
    let results = join_all(futures).await;
    
    let mut all_results = Vec::new();
    for result in results {
        all_results.push(result?);
    }
    
    Ok(all_results)
}
```

### Streaming Results

```rust
use futures::stream::StreamExt;

async fn stream_threats(ti: &ThreatIntelligence, query: Query) -> Result<(), Error> {
    let mut stream = ti.stream_query(query).await?;
    
    while let Some(threat) = stream.next().await {
        match threat {
            Ok(data) => println!("Received threat: {}", data.title),
            Err(e) => eprintln!("Stream error: {}", e),
        }
    }
    
    Ok(())
}
```

---

## Performance

### Caching

```rust
use threat_intel::{ThreatIntelligence, CacheConfig};

let cache_config = CacheConfig::new()
    .with_ttl(Duration::from_secs(3600))
    .with_max_size(1000)
    .with_compression();

let config = Config::new()
    .with_cache_config(cache_config);

let ti = ThreatIntelligence::new(config);
```

### Batch Operations

```rust
async fn batch_assessment(ti: &ThreatIntelligence, contexts: Vec<RiskContext>) -> Result<Vec<RiskAssessment>, Error> {
    let futures: Vec<_> = contexts.into_iter()
        .map(|context| ti.assess_risk(&context))
        .collect();
    
    let results = join_all(futures).await;
    
    let mut assessments = Vec::new();
    for result in results {
        assessments.push(result?);
    }
    
    Ok(assessments)
}
```

---

## Thread Safety

All types implement `Send + Sync`:

```rust
// Safe to use across threads
let ti = Arc::new(ThreatIntelligence::new(config));

// Use in async context
tokio::spawn(async move {
    let threats = ti.query(query).await?;
    // Process threats...
});
```

---

## Version Compatibility

Current version: `0.1.0`

**Breaking changes:** Will use semantic versioning (0.x.0 for breaking changes)

**Stability:** API is in development, expect changes in v0.x releases
