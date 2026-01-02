# HCRS risk engine - Updated comprehensive version
from datetime import datetime
from typing import List, Dict
from .models import (
    FileRiskScore, RepositoryRiskScore, SecurityViolation, 
    Severity, ViolationType
)
from .config_loader import load_hcrs_config, get_risk_weight

def compute_file_risk_score(file_path: str, language: str, violations: List[SecurityViolation]) -> FileRiskScore:
    """Compute risk score for a single file"""
    config = load_hcrs_config()
    
    total_score = 0.0
    severity_breakdown = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0,
        'INFO': 0
    }
    
    for violation in violations:
        # Get weight for this violation type
        weight = get_risk_weight(violation.violation_type.value, config)
        
        # Calculate weighted score with confidence
        violation_score = weight * violation.confidence
        total_score += violation_score
        
        # Update severity breakdown
        severity_breakdown[violation.severity.value] += 1
    
    return FileRiskScore(
        file_path=file_path,
        language=language,
        total_score=total_score,
        violations=violations,
        severity_breakdown=severity_breakdown,
        lines_analyzed=len(violations)  # Approximate
    )

def compute_repository_risk_score(repo_path: str, file_scores: List[FileRiskScore]) -> RepositoryRiskScore:
    """Compute aggregate risk score for entire repository"""
    total_score = sum(fs.total_score for fs in file_scores)
    
    # Aggregate statistics
    total_violations = sum(len(fs.violations) for fs in file_scores)
    severity_counts = {
        'CRITICAL': sum(fs.severity_breakdown.get('CRITICAL', 0) for fs in file_scores),
        'HIGH': sum(fs.severity_breakdown.get('HIGH', 0) for fs in file_scores),
        'MEDIUM': sum(fs.severity_breakdown.get('MEDIUM', 0) for fs in file_scores),
        'LOW': sum(fs.severity_breakdown.get('LOW', 0) for fs in file_scores),
    }
    
    # Violation type breakdown
    violation_type_counts = {}
    for fs in file_scores:
        for violation in fs.violations:
            vtype = violation.violation_type.value
            violation_type_counts[vtype] = violation_type_counts.get(vtype, 0) + 1
    
    # High-risk files (top 10)
    high_risk_files = sorted(
        file_scores,
        key=lambda x: x.total_score,
        reverse=True
    )[:10]
    
    # Generate recommendation
    recommendation = generate_recommendation(severity_counts, total_score)
    
    summary = {
        'total_files_analyzed': len(file_scores),
        'total_violations': total_violations,
        'severity_counts': severity_counts,
        'violation_type_counts': violation_type_counts,
        'dependency_vulnerability_count': 0,  # Will be updated after OSV scan
        'high_risk_files': [
            {
                'file': fs.file_path,
                'score': fs.total_score,
                'critical_count': fs.severity_breakdown.get('CRITICAL', 0),
                'high_count': fs.severity_breakdown.get('HIGH', 0)
            }
            for fs in high_risk_files if fs.total_score > 0
        ]
    }
    
    repo_score = RepositoryRiskScore(
        repo_path=repo_path,
        timestamp=datetime.now(),
        total_score=total_score,
        file_scores=file_scores,
        summary=summary,
        recommendation=recommendation
    )
    
    return repo_score

def generate_recommendation(severity_counts: Dict[str, int], total_score: float) -> str:
    """Generate actionable recommendation based on risk analysis"""
    critical = severity_counts.get('CRITICAL', 0)
    high = severity_counts.get('HIGH', 0)
    medium = severity_counts.get('MEDIUM', 0)
    
    recommendations = []
    
    if critical > 0:
        recommendations.append(
            f"🚨 CRITICAL: {critical} critical security issue(s) detected. "
            "These must be fixed immediately before deployment. "
            "Review hardcoded secrets, command injection risks, and unsafe deserialization."
        )
    
    if high > 0:
        recommendations.append(
            f"⚠️  HIGH: {high} high-severity issue(s) found. "
            "Address these before merging to production. "
            "Focus on SQL injection, weak cryptography, and sensitive data exposure."
        )
    
    if medium > 0:
        recommendations.append(
            f"📋 MEDIUM: {medium} medium-severity issue(s) detected. "
            "Plan to fix these in upcoming sprints."
        )
    
    if total_score > 500:
        recommendations.append(
            "⛔ BLOCK: Total risk score exceeds acceptable threshold. "
            "This code should not be deployed until critical issues are resolved."
        )
    elif total_score > 200:
        recommendations.append(
            "⚠️  WARN: Risk score is elevated. Requires security review before deployment."
        )
    else:
        if not recommendations:
            recommendations.append("✅ ALLOW: No significant security issues detected.")
    
    return " ".join(recommendations)

def compute_risk(lineage, drift_report, osv_results):
    """
    Legacy function for backward compatibility.
    Computes composite risk from lineage, drift, and dependencies.
    """
    score = 0
    breakdown = {}

    # Handle None values defensively
    breakdown["dependencies"] = len(osv_results) * 10 if osv_results else 0
    breakdown["secret_lineage"] = len(lineage.secrets) * 5 if lineage and hasattr(lineage, 'secrets') else 0
    breakdown["secret_drift"] = len(drift_report.drifted_secrets) * 15 if drift_report and hasattr(drift_report, 'drifted_secrets') else 0

    score = sum(breakdown.values())

    if score > 80:
        decision = "BLOCK"
    elif score > 50:
        decision = "WARN"
    else:
        decision = "ALLOW"

    return {
        "total": score,
        "breakdown": breakdown,
        "recommendation": decision
    }
