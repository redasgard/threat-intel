//! Risk assessment functionality for threat intelligence

use serde::{Deserialize, Serialize};
use crate::types::*;
use crate::constants::*;

/// Assess risk for a given set of vulnerabilities
pub fn assess_risk(vulnerabilities: &[Vulnerability]) -> RiskAssessment {
    let critical_count = vulnerabilities.iter().filter(|v| v.severity == Severity::Critical).count();
    let high_count = vulnerabilities.iter().filter(|v| v.severity == Severity::High).count();
    let medium_count = vulnerabilities.iter().filter(|v| v.severity == Severity::Medium).count();
    let low_count = vulnerabilities.iter().filter(|v| v.severity == Severity::Low).count();

    let score = calculate_risk_score(critical_count, high_count, medium_count, low_count);
    let level = determine_risk_level(critical_count, high_count, medium_count, low_count);

    RiskAssessment {
        level,
        score,
        critical_count,
        high_count,
        medium_count,
        low_count,
        recommendations: generate_recommendations(&level, vulnerabilities),
    }
}

/// Calculate the risk score based on vulnerability counts
fn calculate_risk_score(critical: usize, high: usize, medium: usize, low: usize) -> f32 {
    (critical * CRITICAL_WEIGHT as usize + 
     high * HIGH_WEIGHT as usize + 
     medium * MEDIUM_WEIGHT as usize + 
     low * LOW_WEIGHT as usize) as f32
}

/// Determine the risk level based on vulnerability counts
fn determine_risk_level(critical: usize, high: usize, medium: usize, low: usize) -> RiskLevel {
    if critical > 0 {
        RiskLevel::Critical
    } else if high >= HIGH_RISK_THRESHOLD {
        RiskLevel::High
    } else if high > 0 || medium >= MEDIUM_RISK_THRESHOLD {
        RiskLevel::Medium
    } else if medium > 0 || low > 0 {
        RiskLevel::Low
    } else {
        RiskLevel::Info
    }
}

/// Generate recommendations based on risk level and vulnerabilities
fn generate_recommendations(level: &RiskLevel, vulns: &[Vulnerability]) -> Vec<String> {
    let mut recommendations = Vec::new();

    match level {
        RiskLevel::Critical => {
            recommendations.push("URGENT: Critical vulnerabilities detected. Patch immediately.".to_string());
            recommendations.push("Consider taking affected systems offline until patched.".to_string());
            recommendations.push("Implement emergency response procedures.".to_string());
        }
        RiskLevel::High => {
            recommendations.push("High-priority vulnerabilities found. Patch within 24-48 hours.".to_string());
            recommendations.push("Implement compensating controls if immediate patching isn't possible.".to_string());
            recommendations.push("Increase monitoring of affected systems.".to_string());
        }
        RiskLevel::Medium => {
            recommendations.push("Medium-severity issues detected. Schedule patching within 1 week.".to_string());
            recommendations.push("Review and prioritize based on business impact.".to_string());
        }
        RiskLevel::Low => {
            recommendations.push("Low-severity issues found. Include in next regular maintenance.".to_string());
            recommendations.push("Consider addressing during routine updates.".to_string());
        }
        RiskLevel::Info => {
            recommendations.push("No significant security issues detected.".to_string());
            recommendations.push("Continue regular security monitoring.".to_string());
        }
    }

    // Add specific CVE recommendations if available
    for vuln in vulns.iter().take(3) {
        if let Some(cve) = &vuln.cve_id {
            recommendations.push(format!("Review and remediate: {} - {}", cve, vuln.title));
        }
    }

    // Add general security recommendations
    add_general_recommendations(&mut recommendations, level);

    recommendations
}

/// Add general security recommendations based on risk level
fn add_general_recommendations(recommendations: &mut Vec<String>, level: &RiskLevel) {
    match level {
        RiskLevel::Critical | RiskLevel::High => {
            recommendations.push("Conduct immediate security assessment.".to_string());
            recommendations.push("Review and update incident response procedures.".to_string());
            recommendations.push("Consider engaging external security experts.".to_string());
        }
        RiskLevel::Medium => {
            recommendations.push("Schedule security review meeting.".to_string());
            recommendations.push("Update vulnerability management procedures.".to_string());
        }
        RiskLevel::Low => {
            recommendations.push("Continue regular security assessments.".to_string());
            recommendations.push("Maintain current security controls.".to_string());
        }
        RiskLevel::Info => {
            recommendations.push("Maintain current security posture.".to_string());
            recommendations.push("Continue proactive security monitoring.".to_string());
        }
    }
}

/// Assess the overall security posture based on multiple factors
pub fn assess_security_posture(
    vulnerabilities: &[Vulnerability],
    iocs: &[IOC],
    threat_actors: &[ThreatActor],
) -> SecurityPostureAssessment {
    let vuln_assessment = assess_risk(vulnerabilities);
    let ioc_risk = assess_ioc_risk(iocs);
    let actor_risk = assess_threat_actor_risk(threat_actors);

    let overall_level = determine_overall_risk_level(
        &vuln_assessment.level,
        &ioc_risk,
        &actor_risk,
    );

    let overall_score = calculate_overall_score(
        vuln_assessment.score,
        ioc_risk.score,
        actor_risk.score,
    );

    SecurityPostureAssessment {
        overall_level,
        overall_score,
        vulnerability_assessment: vuln_assessment,
        ioc_risk,
        threat_actor_risk: actor_risk,
        recommendations: generate_comprehensive_recommendations(
            &overall_level,
            vulnerabilities,
            iocs,
            threat_actors,
        ),
    }
}

/// Assess risk based on IOCs
fn assess_ioc_risk(iocs: &[IOC]) -> IOCRiskAssessment {
    let high_confidence_count = iocs.iter().filter(|ioc| ioc.confidence >= HIGH_CONFIDENCE_THRESHOLD).count();
    let medium_confidence_count = iocs.iter().filter(|ioc| ioc.confidence >= MEDIUM_CONFIDENCE_THRESHOLD && ioc.confidence < HIGH_CONFIDENCE_THRESHOLD).count();
    let low_confidence_count = iocs.iter().filter(|ioc| ioc.confidence < MEDIUM_CONFIDENCE_THRESHOLD).count();

    let score = (high_confidence_count * 10 + medium_confidence_count * 5 + low_confidence_count * 1) as f32;
    
    let level = if high_confidence_count >= 5 {
        RiskLevel::High
    } else if high_confidence_count >= 2 || medium_confidence_count >= 10 {
        RiskLevel::Medium
    } else if high_confidence_count > 0 || medium_confidence_count > 0 {
        RiskLevel::Low
    } else {
        RiskLevel::Info
    };

    IOCRiskAssessment {
        level,
        score,
        high_confidence_count,
        medium_confidence_count,
        low_confidence_count,
        total_iocs: iocs.len(),
    }
}

/// Assess risk based on threat actors
fn assess_threat_actor_risk(actors: &[ThreatActor]) -> ThreatActorRiskAssessment {
    let active_actors = actors.len();
    let sophisticated_actors = actors.iter().filter(|actor| actor.tactics.len() >= 5).count();

    let score = (active_actors * 5 + sophisticated_actors * 10) as f32;
    
    let level = if sophisticated_actors >= 3 {
        RiskLevel::High
    } else if sophisticated_actors >= 1 || active_actors >= 10 {
        RiskLevel::Medium
    } else if active_actors > 0 {
        RiskLevel::Low
    } else {
        RiskLevel::Info
    };

    ThreatActorRiskAssessment {
        level,
        score,
        total_actors: active_actors,
        sophisticated_actors,
    }
}

/// Determine overall risk level
fn determine_overall_risk_level(
    vuln_level: &RiskLevel,
    ioc_risk: &IOCRiskAssessment,
    actor_risk: &ThreatActorRiskAssessment,
) -> RiskLevel {
    let levels = [vuln_level, &ioc_risk.level, &actor_risk.level];
    let max_priority = levels.iter().map(|l| l.priority()).max().unwrap_or(1);
    
    match max_priority {
        5 => RiskLevel::Critical,
        4 => RiskLevel::High,
        3 => RiskLevel::Medium,
        2 => RiskLevel::Low,
        _ => RiskLevel::Info,
    }
}

/// Calculate overall security score
fn calculate_overall_score(vuln_score: f32, ioc_score: f32, actor_score: f32) -> f32 {
    vuln_score * 0.5 + ioc_score * 0.3 + actor_score * 0.2
}

/// Generate comprehensive recommendations
fn generate_comprehensive_recommendations(
    overall_level: &RiskLevel,
    vulnerabilities: &[Vulnerability],
    iocs: &[IOC],
    threat_actors: &[ThreatActor],
) -> Vec<String> {
    let mut recommendations = Vec::new();

    // Overall recommendations
    match overall_level {
        RiskLevel::Critical => {
            recommendations.push("CRITICAL: Immediate security response required.".to_string());
            recommendations.push("Activate incident response team.".to_string());
            recommendations.push("Consider system isolation and forensic analysis.".to_string());
        }
        RiskLevel::High => {
            recommendations.push("HIGH: Urgent security actions needed.".to_string());
            recommendations.push("Implement enhanced monitoring and controls.".to_string());
            recommendations.push("Schedule emergency security review.".to_string());
        }
        RiskLevel::Medium => {
            recommendations.push("MEDIUM: Security improvements recommended.".to_string());
            recommendations.push("Update security policies and procedures.".to_string());
            recommendations.push("Enhance security awareness training.".to_string());
        }
        RiskLevel::Low => {
            recommendations.push("LOW: Maintain current security posture.".to_string());
            recommendations.push("Continue regular security assessments.".to_string());
        }
        RiskLevel::Info => {
            recommendations.push("INFO: No immediate security concerns.".to_string());
            recommendations.push("Continue proactive security monitoring.".to_string());
        }
    }

    // Specific recommendations based on data
    if !vulnerabilities.is_empty() {
        recommendations.push(format!("Address {} vulnerabilities identified.", vulnerabilities.len()));
    }

    if !iocs.is_empty() {
        recommendations.push(format!("Monitor {} indicators of compromise.", iocs.len()));
    }

    if !threat_actors.is_empty() {
        recommendations.push(format!("Be aware of {} threat actors targeting your organization.", threat_actors.len()));
    }

    recommendations
}

/// IOC Risk Assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IOCRiskAssessment {
    pub level: RiskLevel,
    pub score: f32,
    pub high_confidence_count: usize,
    pub medium_confidence_count: usize,
    pub low_confidence_count: usize,
    pub total_iocs: usize,
}

/// Threat Actor Risk Assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActorRiskAssessment {
    pub level: RiskLevel,
    pub score: f32,
    pub total_actors: usize,
    pub sophisticated_actors: usize,
}

/// Comprehensive Security Posture Assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPostureAssessment {
    pub overall_level: RiskLevel,
    pub overall_score: f32,
    pub vulnerability_assessment: RiskAssessment,
    pub ioc_risk: IOCRiskAssessment,
    pub threat_actor_risk: ThreatActorRiskAssessment,
    pub recommendations: Vec<String>,
}
