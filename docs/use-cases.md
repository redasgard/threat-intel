# Use Cases

Real-world applications and scenarios for Threat Intel.

## 1. SIEM Integration

### Scenario: Security Information and Event Management

Enrich security events with threat intelligence for better detection and response.

**Implementation:**

```rust
use threat_intel::{ThreatIntelConfig, ThreatIntelEngine, IOCType};

struct SIEMIntegration {
    threat_intel: ThreatIntelEngine,
}

impl SIEMIntegration {
    async fn new() -> anyhow::Result<Self> {
        let config = ThreatIntelConfig::default();
        let mut engine = ThreatIntelEngine::new(config);
        engine.initialize().await?;
        
        Ok(Self { threat_intel: engine })
    }
    
    async fn enrich_event(&self, ip_address: &str) -> anyhow::Result<EventEnrichment> {
        // Query for IP in IOC database
        let iocs = self.threat_intel.query_iocs(IOCType::IpAddress).await?;
        
        let is_malicious = iocs.iter().any(|ioc| ioc.value == ip_address);
        
        if is_malicious {
            let ioc = iocs.iter().find(|i| i.value == ip_address).unwrap();
            Ok(EventEnrichment {
                is_threat: true,
                confidence: ioc.confidence,
                threat_type: "Malicious IP".to_string(),
                first_seen: ioc.first_seen,
                tags: ioc.tags.clone(),
            })
        } else {
            Ok(EventEnrichment::benign())
        }
    }
}

struct EventEnrichment {
    is_threat: bool,
    confidence: f32,
    threat_type: String,
    first_seen: chrono::DateTime<chrono::Utc>,
    tags: Vec<String>,
}

impl EventEnrichment {
    fn benign() -> Self {
        Self {
            is_threat: false,
            confidence: 0.0,
            threat_type: String::new(),
            first_seen: chrono::Utc::now(),
            tags: vec![],
        }
    }
}
```

**Benefits:**
- Real-time threat detection
- Reduced false positives
- Better incident prioritization
- Context for security analysts

## 2. Vulnerability Management

### Scenario: Track Software Vulnerabilities

Monitor infrastructure for known vulnerabilities.

**Implementation:**

```rust
use threat_intel::{ThreatIntelEngine, RiskLevel};

struct VulnerabilityScanner {
    threat_intel: ThreatIntelEngine,
}

impl VulnerabilityScanner {
    async fn scan_infrastructure(&self) -> anyhow::Result<ScanReport> {
        let mut report = ScanReport::new();
        
        // Scan different components
        let components = vec![
            ("apache", "2.4.41"),
            ("openssl", "1.1.1"),
            ("nginx", "1.18.0"),
        ];
        
        for (product, version) in components {
            let vulns = self.threat_intel
                .query_vulnerabilities(product, version)
                .await?;
            
            if !vulns.is_empty() {
                let assessment = self.threat_intel.assess_risk(&vulns);
                report.add_component(product, version, assessment, vulns);
            }
        }
        
        Ok(report)
    }
}

struct ScanReport {
    components: Vec<ComponentRisk>,
}

impl ScanReport {
    fn new() -> Self {
        Self { components: vec![] }
    }
    
    fn add_component(
        &mut self,
        product: &str,
        version: &str,
        assessment: threat_intel::RiskAssessment,
        vulns: Vec<threat_intel::Vulnerability>,
    ) {
        self.components.push(ComponentRisk {
            product: product.to_string(),
            version: version.to_string(),
            risk_level: assessment.level,
            vuln_count: vulns.len(),
            recommendations: assessment.recommendations,
        });
    }
}

struct ComponentRisk {
    product: String,
    version: String,
    risk_level: RiskLevel,
    vuln_count: usize,
    recommendations: Vec<String>,
}
```

**Benefits:**
- Automated vulnerability discovery
- Risk-based prioritization
- Actionable recommendations
- Continuous monitoring

## 3. SOC Operations

### Scenario: Security Operations Center Workflow

Daily threat intelligence briefings for SOC analysts.

**Implementation:**

```rust
use threat_intel::{ThreatIntelEngine};

struct SOCDashboard {
    threat_intel: ThreatIntelEngine,
}

impl SOCDashboard {
    async fn daily_briefing(&self) -> anyhow::Result<ThreatBriefing> {
        let stats = self.threat_intel.get_stats();
        
        // Get critical vulnerabilities
        let critical_threats = self.get_critical_threats().await?;
        
        // Get active threat actors
        let active_actors = self.threat_intel
            .query_threat_actors("apt")
            .await?;
        
        Ok(ThreatBriefing {
            date: chrono::Utc::now(),
            total_vulnerabilities: stats.total_vulnerabilities,
            total_iocs: stats.total_iocs,
            critical_threats,
            active_threat_actors: active_actors.len(),
            recommendations: self.generate_recommendations(),
        })
    }
    
    async fn get_critical_threats(&self) -> anyhow::Result<Vec<String>> {
        // Query recent critical vulnerabilities
        let vulns = self.threat_intel
            .query_vulnerabilities("*", "*")
            .await?;
        
        Ok(vulns.iter()
            .filter(|v| matches!(v.severity, threat_intel::Severity::Critical))
            .take(10)
            .filter_map(|v| v.cve_id.clone())
            .collect())
    }
    
    fn generate_recommendations(&self) -> Vec<String> {
        vec![
            "Review critical vulnerabilities in production systems".to_string(),
            "Update threat actor TTPs in detection rules".to_string(),
            "Validate IOC blocklists are current".to_string(),
        ]
    }
}

struct ThreatBriefing {
    date: chrono::DateTime<chrono::Utc>,
    total_vulnerabilities: usize,
    total_iocs: usize,
    critical_threats: Vec<String>,
    active_threat_actors: usize,
    recommendations: Vec<String>,
}
```

**Benefits:**
- Situational awareness
- Trend analysis
- Proactive threat hunting
- Resource allocation

## 4. Incident Response

### Scenario: Rapid Threat Correlation

Quickly correlate incidents with known threats during response.

**Implementation:**

```rust
use threat_intel::{ThreatIntelEngine, IOCType};

struct IncidentResponse {
    threat_intel: ThreatIntelEngine,
}

impl IncidentResponse {
    async fn investigate_incident(&self, incident: &Incident) -> anyhow::Result<Investigation> {
        let mut investigation = Investigation::new(incident.id.clone());
        
        // Check if IP is known malicious
        if let Some(ip) = &incident.source_ip {
            let iocs = self.threat_intel.query_iocs(IOCType::IpAddress).await?;
            if let Some(ioc) = iocs.iter().find(|i| i.value == *ip) {
                investigation.add_finding(format!(
                    "Source IP {} is known malicious (confidence: {:.0}%)",
                    ip, ioc.confidence * 100.0
                ));
            }
        }
        
        // Check if domain is suspicious
        if let Some(domain) = &incident.domain {
            let iocs = self.threat_intel.query_iocs(IOCType::Domain).await?;
            if iocs.iter().any(|i| i.value == *domain) {
                investigation.add_finding(format!(
                    "Domain {} appears in threat feeds",
                    domain
                ));
            }
        }
        
        // Check for related threat actors
        if let Some(technique) = &incident.mitre_technique {
            let actors = self.threat_intel.query_threat_actors(technique).await?;
            if !actors.is_empty() {
                investigation.add_finding(format!(
                    "Technique {} associated with {} threat actors",
                    technique, actors.len()
                ));
                for actor in actors.iter().take(3) {
                    investigation.add_actor(actor.name.clone());
                }
            }
        }
        
        Ok(investigation)
    }
}

struct Incident {
    id: String,
    source_ip: Option<String>,
    domain: Option<String>,
    mitre_technique: Option<String>,
}

struct Investigation {
    incident_id: String,
    findings: Vec<String>,
    related_actors: Vec<String>,
}

impl Investigation {
    fn new(incident_id: String) -> Self {
        Self {
            incident_id,
            findings: vec![],
            related_actors: vec![],
        }
    }
    
    fn add_finding(&mut self, finding: String) {
        self.findings.push(finding);
    }
    
    fn add_actor(&mut self, actor: String) {
        self.related_actors.push(actor);
    }
}
```

**Benefits:**
- Faster incident analysis
- Attribution insights
- Guided remediation
- Historical context

## 5. Threat Hunting

### Scenario: Proactive Threat Discovery

Hunt for threats based on latest intelligence.

**Implementation:**

```rust
use threat_intel::{ThreatIntelEngine, IOCType};

struct ThreatHunter {
    threat_intel: ThreatIntelEngine,
}

impl ThreatHunter {
    async fn hunt_campaign(&self, campaign_name: &str) -> anyhow::Result<HuntResults> {
        let mut results = HuntResults::new(campaign_name);
        
        // Get threat actors associated with campaign
        let actors = self.threat_intel
            .query_threat_actors(campaign_name)
            .await?;
        
        // Get their known IOCs
        for actor in &actors {
            let iocs = self.get_actor_iocs(&actor.name).await?;
            results.add_iocs(iocs);
            results.add_tactics(actor.tactics.clone());
            results.add_techniques(actor.techniques.clone());
        }
        
        Ok(results)
    }
    
    async fn get_actor_iocs(&self, actor_name: &str) -> anyhow::Result<Vec<String>> {
        // Query IOCs associated with this actor
        let ip_iocs = self.threat_intel.query_iocs(IOCType::IpAddress).await?;
        let domain_iocs = self.threat_intel.query_iocs(IOCType::Domain).await?;
        
        let mut iocs = Vec::new();
        
        // Filter IOCs with actor in tags
        for ioc in ip_iocs.iter().chain(domain_iocs.iter()) {
            if ioc.tags.iter().any(|tag| tag.contains(actor_name)) {
                iocs.push(ioc.value.clone());
            }
        }
        
        Ok(iocs)
    }
}

struct HuntResults {
    campaign: String,
    iocs: Vec<String>,
    tactics: Vec<String>,
    techniques: Vec<String>,
}

impl HuntResults {
    fn new(campaign: &str) -> Self {
        Self {
            campaign: campaign.to_string(),
            iocs: vec![],
            tactics: vec![],
            techniques: vec![],
        }
    }
    
    fn add_iocs(&mut self, iocs: Vec<String>) {
        self.iocs.extend(iocs);
    }
    
    fn add_tactics(&mut self, tactics: Vec<String>) {
        self.tactics.extend(tactics);
    }
    
    fn add_techniques(&mut self, techniques: Vec<String>) {
        self.techniques.extend(techniques);
    }
}
```

**Benefits:**
- Proactive defense
- Intelligence-driven hunting
- Early threat detection
- Reduced dwell time

## 6. Compliance Reporting

### Scenario: Generate Security Compliance Reports

Automated reporting for security compliance.

**Implementation:**

```rust
use threat_intel::{ThreatIntelEngine, Severity};

struct ComplianceReporter {
    threat_intel: ThreatIntelEngine,
}

impl ComplianceReporter {
    async fn generate_report(&self) -> anyhow::Result<ComplianceReport> {
        let stats = self.threat_intel.get_stats();
        
        // Get all vulnerabilities for compliance check
        let critical_vulns = self.count_by_severity(Severity::Critical).await?;
        let high_vulns = self.count_by_severity(Severity::High).await?;
        
        let compliance_status = if critical_vulns == 0 && high_vulns < 5 {
            "COMPLIANT"
        } else {
            "NON-COMPLIANT"
        };
        
        Ok(ComplianceReport {
            report_date: chrono::Utc::now(),
            status: compliance_status.to_string(),
            total_vulnerabilities: stats.total_vulnerabilities,
            critical_count: critical_vulns,
            high_count: high_vulns,
            threat_sources: stats.sources_count,
            last_update: stats.last_sync,
        })
    }
    
    async fn count_by_severity(&self, severity: Severity) -> anyhow::Result<usize> {
        let vulns = self.threat_intel.query_vulnerabilities("*", "*").await?;
        Ok(vulns.iter().filter(|v| v.severity == severity).count())
    }
}

struct ComplianceReport {
    report_date: chrono::DateTime<chrono::Utc>,
    status: String,
    total_vulnerabilities: usize,
    critical_count: usize,
    high_count: usize,
    threat_sources: usize,
    last_update: Option<chrono::DateTime<chrono::Utc>>,
}
```

**Benefits:**
- Automated compliance
- Audit trail
- Risk documentation
- Regulatory requirements

## Summary

Threat Intel is ideal for:

✅ **SIEM Integration** - Enrich security events
✅ **Vulnerability Management** - Track and prioritize vulns
✅ **SOC Operations** - Daily briefings and awareness
✅ **Incident Response** - Rapid correlation and attribution
✅ **Threat Hunting** - Proactive threat discovery
✅ **Compliance** - Automated security reporting

## Next Steps

- Review [Architecture](./architecture.md) for system design
- Check [Getting Started](./getting-started.md) for quick start
- See [API Reference](./api-reference.md) for detailed docs
- Read [Configuration Guide](./configuration.md) for advanced setup

