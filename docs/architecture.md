# Architecture

## System Overview

Threat Intel implements a **multi-source aggregation system** that fetches, parses, and correlates threat intelligence from diverse sources into a unified query interface.

```
┌─────────────────────────────────────────────────────────────┐
│                   ThreatIntelEngine                          │
│              (Aggregation & Query Interface)                 │
├─────────────────────────────────────────────────────────────┤
│  - initialize()                                              │
│  - sync()                                                    │
│  - query_vulnerabilities()                                   │
│  - query_iocs()                                              │
│  - query_threat_actors()                                     │
│  - assess_risk()                                             │
└───────────────────┬──────────────────────────────────────────┘
                    │
       ┌────────────┴────────────┬────────────┬────────────┐
       │                         │            │            │
       ▼                         ▼            ▼            ▼
┌──────────────┐        ┌──────────────┐  ┌───────┐  ┌───────┐
│   MITRE      │        │     CVE      │  │Abuse  │  │Custom │
│   ATT&CK     │        │   Database   │  │ .ch   │  │Source │
│              │        │   (NIST NVD) │  │       │  │       │
│ Priority: 10 │        │ Priority: 9  │  │ Pri:7 │  │ Pri:8 │
└──────┬───────┘        └──────┬───────┘  └───┬───┘  └───┬───┘
       │                       │              │          │
       │        ┌──────────────┴──────────────┴──────────┘
       │        │
       ▼        ▼
┌─────────────────────────────────────────────────────────────┐
│                     FeedFetcher                              │
│                 (HTTP Client + Auth)                         │
├─────────────────────────────────────────────────────────────┤
│  - Authenticated HTTP requests                               │
│  - Retry logic with exponential backoff                      │
│  - Multiple auth methods (API Key, Bearer, Basic)            │
│  - Timeout management                                        │
└─────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│                      ThreatCache                             │
│               (In-Memory Data Store)                         │
├─────────────────────────────────────────────────────────────┤
│  HashMap<SourceID, ThreatData>                               │
│    - Vulnerabilities                                         │
│    - IOCs (Indicators of Compromise)                         │
│    - Threat Actors                                           │
│    - Raw data (JSON)                                         │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. ThreatIntelEngine

Central orchestrator for all threat intelligence operations.

**Responsibilities:**
- Source initialization and management
- Periodic synchronization
- Query aggregation across sources
- Risk assessment
- Statistics and monitoring

**State:**
```rust
pub struct ThreatIntelEngine {
    config: ThreatIntelConfig,
    sources: HashMap<String, Box<dyn ThreatSource>>,
    last_sync: Option<DateTime<Utc>>,
    cache: ThreatCache,
}
```

**Location:** `src/lib.rs`

### 2. ThreatSource Trait

Abstract interface for all threat intelligence sources.

**Interface:**
```rust
pub trait ThreatSource: Send + Sync {
    async fn fetch(&mut self) -> Result<ThreatData>;
    fn config(&self) -> &SourceConfig;
}
```

**Implementations:**
- `MitreAttackSource` - MITRE ATT&CK framework data
- `CVESource` - CVE/NVD vulnerability database
- `OSINTSource` - Open-source intelligence feeds
- `GenericSource` - Custom HTTP endpoints

**Location:** `src/sources/`

### 3. FeedFetcher

HTTP client with authentication and retry logic.

**Features:**
- Multiple auth methods (API Key, Bearer, Basic)
- Exponential backoff retry (3 attempts)
- Configurable timeouts (default 30s)
- TLS/SSL support
- Header customization

**Authentication Flow:**
```
Request
  │
  ├─ AuthType::None
  │    └─> Plain HTTP request
  │
  ├─ AuthType::ApiKey
  │    └─> Header: X-API-Key: {key}
  │
  ├─ AuthType::Bearer
  │    └─> Header: Authorization: Bearer {token}
  │
  └─ AuthType::Basic
       └─> Header: Authorization: Basic base64({user}:{pass})
```

**Location:** `src/feeds/`

### 4. ThreatCache

In-memory storage for aggregated threat intelligence.

**Structure:**
```rust
struct ThreatCache {
    cache: HashMap<String, ThreatData>,
}

pub struct ThreatData {
    pub vulnerabilities: Vec<Vulnerability>,
    pub iocs: Vec<IOC>,
    pub threat_actors: Vec<ThreatActor>,
    pub raw_data: Option<serde_json::Value>,
}
```

**Operations:**
- `update(source_id, data)` - Store source data
- `get(source_id)` - Retrieve source data
- Automatic conflict resolution by source priority

**Location:** `src/lib.rs`

## Data Models

### Vulnerability

```rust
pub struct Vulnerability {
    pub id: String,                          // Internal ID
    pub cve_id: Option<String>,              // CVE-2024-XXXX
    pub title: String,                       // Short description
    pub description: String,                 // Detailed description
    pub severity: Severity,                  // Critical/High/Medium/Low/Info
    pub cvss_score: Option<f32>,            // 0.0 - 10.0
    pub affected_products: Vec<AffectedProduct>,
    pub published_date: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    pub references: Vec<String>,            // URLs
}
```

### IOC (Indicator of Compromise)

```rust
pub struct IOC {
    pub id: String,
    pub ioc_type: IOCType,                   // IP, Domain, Hash, etc.
    pub value: String,                       // The actual IOC
    pub description: Option<String>,
    pub confidence: f32,                     // 0.0 - 1.0
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub tags: Vec<String>,
}
```

### Threat Actor

```rust
pub struct ThreatActor {
    pub id: String,
    pub name: String,                        // APT28, Lazarus Group, etc.
    pub aliases: Vec<String>,                // Alternative names
    pub description: String,
    pub tactics: Vec<String>,                // MITRE tactics
    pub techniques: Vec<String>,             // MITRE techniques
    pub first_seen: Option<DateTime<Utc>>,
    pub country: Option<String>,
    pub motivation: Option<String>,
}
```

## Query Flow

### Vulnerability Query

```
User Query: "apache", "2.4"
  │
  ▼
┌─────────────────────────────────────────────┐
│ 1. Get sources with Vulnerabilities capability│
└───────────────────┬─────────────────────────┘
                    ▼
┌─────────────────────────────────────────────┐
│ 2. For each source:                          │
│    - Fetch cached data                       │
│    - Filter vulnerabilities by:              │
│      * product name contains "apache"        │
│      * version matches "2.4"                 │
└───────────────────┬─────────────────────────┘
                    ▼
┌─────────────────────────────────────────────┐
│ 3. Aggregate results from all sources       │
└───────────────────┬─────────────────────────┘
                    ▼
┌─────────────────────────────────────────────┐
│ 4. De-duplicate by CVE ID                   │
│    (priority source wins conflicts)          │
└───────────────────┬─────────────────────────┘
                    ▼
Results: Vec<Vulnerability>
```

### IOC Query

```
User Query: IOCType::IpAddress
  │
  ▼
┌─────────────────────────────────────────────┐
│ 1. Get sources with IOC capability          │
└───────────────────┬─────────────────────────┘
                    ▼
┌─────────────────────────────────────────────┐
│ 2. For each source:                          │
│    - Fetch cached data                       │
│    - Filter IOCs by type                     │
└───────────────────┬─────────────────────────┘
                    ▼
┌─────────────────────────────────────────────┐
│ 3. Aggregate and de-duplicate                │
│    (by IOC value)                            │
└───────────────────┬─────────────────────────┘
                    ▼
Results: Vec<IOC>
```

## Sync Mechanism

### Initialization

```
engine.initialize()
  │
  ├─ For each enabled source in config:
  │   │
  │   ├─ Create source instance
  │   │   (MitreAttackSource, CVESource, etc.)
  │   │
  │   ├─ Store in sources HashMap
  │   │
  │   └─ Continue on error (resilient)
  │
  └─ Perform initial sync()
```

### Periodic Sync

```
engine.sync()
  │
  └─ For each source:
      │
      ├─ Call source.fetch()
      │   │
      │   ├─ FeedFetcher makes HTTP request
      │   │   with authentication
      │   │
      │   ├─ Parse response (JSON)
      │   │
      │   ├─ Transform to ThreatData
      │   │
      │   └─ Return or retry on failure
      │
      ├─ Update cache with new data
      │   cache.update(source_id, data)
      │
      └─ Continue on error (other sources still update)
```

**Update Frequencies:**
- `Realtime`: On every query (not recommended)
- `Hourly`: Every hour
- `Daily`: Once per day
- `Weekly`: Once per week
- `Manual`: Only when explicitly synced

## Risk Assessment Engine

### Algorithm

```
Input: Vec<Vulnerability>
  │
  ├─ Count by severity:
  │   - critical_count
  │   - high_count
  │   - medium_count
  │   - low_count
  │
  ├─ Calculate score:
  │   score = (critical × 10) + (high × 7) + (medium × 4) + (low × 1)
  │
  ├─ Determine risk level:
  │   - Critical: if any critical vulnerabilities
  │   - High: if high >= 3
  │   - Medium: if high > 0 or medium >= 5
  │   - Low: if medium > 0 or low > 0
  │   - Info: otherwise
  │
  └─ Generate recommendations:
      - Based on risk level
      - Specific CVEs (top 3)
      - Prioritized actions

Output: RiskAssessment
```

### RiskAssessment Structure

```rust
pub struct RiskAssessment {
    pub level: RiskLevel,                // Critical/High/Medium/Low/Info
    pub score: f32,                      // Calculated risk score
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub recommendations: Vec<String>,    // Actionable advice
}
```

## Source Capabilities

Sources declare their capabilities to enable targeted queries:

```rust
pub enum SourceCapability {
    Vulnerabilities,    // CVE, exploit info
    Ioc,               // IPs, domains, hashes
    ThreatActors,      // APT groups, actors
    Tactics,           // MITRE tactics
    Techniques,        // MITRE techniques
    Malware,           // Malware families
    Exploits,          // Exploit code
    Patches,           // Security patches
}
```

**Query Optimization:**
Only sources with relevant capabilities are queried for each request.

## Configuration Architecture

```rust
pub struct ThreatIntelConfig {
    pub sources: Vec<SourceConfig>,
    pub sync_interval_hours: u64,
    pub cache_enabled: bool,
    pub cache_ttl_hours: u64,
}

pub struct SourceConfig {
    pub id: String,                      // Unique identifier
    pub name: String,                    // Display name
    pub source_type: SourceType,         // MitreAttack, Cve, Osint, etc.
    pub enabled: bool,
    pub api_url: Option<String>,
    pub api_key: Option<String>,
    pub auth_type: AuthType,
    pub update_frequency: UpdateFrequency,
    pub priority: u8,                    // 1-10, higher wins conflicts
    pub capabilities: Vec<SourceCapability>,
    pub timeout_secs: u64,
    pub retry_count: u32,
}
```

## Error Handling

### Resilient Design

- Source failures don't stop initialization
- Sync errors are logged but other sources continue
- Queries aggregate from available sources
- Cache provides last-known-good data

### Error Types

```rust
pub enum ThreatIntelError {
    SourceInitFailed(String),
    FetchFailed(String),
    ParseError(String),
    NetworkError(String),
    AuthenticationFailed,
    RateLimitExceeded,
    InvalidConfiguration(String),
}
```

## Performance Characteristics

### Memory Usage
- Cache size: ~1-10MB per source (depends on data volume)
- No disk I/O (pure in-memory)
- Configurable TTL for cache eviction

### Network Usage
- Initial fetch: 100KB - 10MB per source
- Updates: Incremental when supported
- Configurable update frequency

### Query Performance
- Latency: < 1ms for cached queries
- Throughput: 10,000+ queries/sec
- Concurrent queries: Lock-free reads (RwLock)

## Security Considerations

### Data Integrity
- TLS/SSL for all HTTP connections
- Signature verification (future feature)
- Source priority for conflict resolution

### Authentication
- API keys stored in memory only
- Support for environment variables
- No plaintext key logging

### Rate Limiting
- Respectful of source rate limits
- Exponential backoff on errors
- Configurable retry strategies

## Future Enhancements

### v0.2
- Database backend (PostgreSQL, SQLite)
- XML and STIX format parsers
- Webhook notifications

### v0.3
- ML-based threat correlation
- GraphQL query API
- Distributed caching (Redis)

### v0.4
- Threat feed validation
- TAXII protocol support
- Advanced analytics

