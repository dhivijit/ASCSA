# Export functions for test compatibility (must be after class definition)
generate_json_report = HCRSReporter.generate_json_report
generate_text_report = HCRSReporter.generate_text_report

# Export functions for test compatibility (must be after class definition)
generate_json_report = HCRSReporter.generate_json_report
generate_text_report = HCRSReporter.generate_text_report
# HCRS report generator
import json
from typing import TextIO
from datetime import datetime
from .models import RepositoryRiskScore, FileRiskScore, SecurityViolation

class HCRSReporter:
    """Generate reports for HCRS analysis results"""
    
    @staticmethod
    def generate_json_report(repo_score: RepositoryRiskScore) -> str:
        """Generate JSON report"""
        report = {
            'repo_path': repo_score.repo_path,
            'timestamp': repo_score.timestamp.isoformat(),
            'total_score': repo_score.total_score,
            'recommendation': repo_score.recommendation,
            'summary': {
                'total_files': repo_score.summary['total_files_analyzed'],
                'total_violations': repo_score.summary['total_violations'],
                'severity_counts': repo_score.summary['severity_counts'],
                'violation_types': repo_score.summary['violation_type_counts'],
                'dependency_vulnerabilities': repo_score.summary.get('dependency_vulnerability_count', 0)
            },
            'high_risk_files': repo_score.summary.get('high_risk_files', []),
            'dependency_vulnerabilities': repo_score.dependency_vulnerabilities,
            'files': []
        }
        
        for file_score in repo_score.file_scores:
            if file_score.violations:  # Only include files with violations
                file_data = {
                    'path': file_score.file_path,
                    'language': file_score.language,
                    'score': file_score.total_score,
                    'severity_breakdown': file_score.severity_breakdown,
                    'violations': [
                        {
                            'type': v.violation_type.value,
                            'severity': v.severity.value,
                            'line': v.location.line_start,
                            'column': v.location.column_start,
                            'message': v.message,
                            'description': v.description,
                            'cwe': v.cwe_id,
                            'recommendation': v.recommendation,
                            'confidence': v.confidence,
                            'snippet': v.location.snippet
                        }
                        for v in file_score.violations
                    ]
                }
                report['files'].append(file_data)
        
        return json.dumps(report, indent=2)
    
    @staticmethod
    def generate_text_report(repo_score: RepositoryRiskScore) -> str:
        """Generate human-readable text report"""
        lines = []
        lines.append("=" * 80)
        lines.append("HCRS - Hybrid Code Risk Scoring Report")
        lines.append("=" * 80)
        lines.append(f"Repository: {repo_score.repo_path}")
        lines.append(f"Scan Time: {repo_score.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Total Risk Score: {repo_score.total_score:.2f}")
        lines.append("")
        
        # Summary
        lines.append("SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Files Analyzed: {repo_score.summary['total_files_analyzed']}")
        lines.append(f"Total Violations: {repo_score.summary['total_violations']}")
        lines.append("")
        lines.append("Severity Breakdown:")
        severity_counts = repo_score.summary['severity_counts']
        lines.append(f"  🚨 Critical: {severity_counts.get('CRITICAL', 0)}")
        lines.append(f"  ⚠️  High:     {severity_counts.get('HIGH', 0)}")
        lines.append(f"  📋 Medium:   {severity_counts.get('MEDIUM', 0)}")
        lines.append(f"  ℹ️  Low:      {severity_counts.get('LOW', 0)}")
        lines.append("")
        
        # Dependency vulnerabilities
        dep_vuln_count = repo_score.summary.get('dependency_vulnerability_count', 0)
        if dep_vuln_count > 0:
            lines.append(f"Dependency Vulnerabilities: {dep_vuln_count}")
            lines.append("")
        
        # Violation types
        if repo_score.summary.get('violation_type_counts'):
            lines.append("Violation Types:")
            for vtype, count in sorted(
                repo_score.summary['violation_type_counts'].items(),
                key=lambda x: x[1],
                reverse=True
            ):
                lines.append(f"  - {vtype}: {count}")
            lines.append("")
        
        # Recommendation
        lines.append("RECOMMENDATION")
        lines.append("-" * 80)
        lines.append(repo_score.recommendation)
        lines.append("")
        
        # High-risk files
        high_risk = repo_score.summary.get('high_risk_files', [])
        if high_risk:
            lines.append("HIGH-RISK FILES (Top 10)")
            lines.append("-" * 80)
            for i, file_info in enumerate(high_risk[:10], 1):
                lines.append(f"{i}. {file_info['file']}")
                lines.append(f"   Score: {file_info['score']:.2f}")
                lines.append(f"   Critical: {file_info['critical_count']}, High: {file_info['high_count']}")
                lines.append("")
        
        # Dependency vulnerabilities details
        if repo_score.dependency_vulnerabilities:
            lines.append("DEPENDENCY VULNERABILITIES")
            lines.append("-" * 80)
            for vuln in repo_score.dependency_vulnerabilities[:20]:  # Show first 20
                lines.append(f"📦 {vuln.get('package_name')} ({vuln.get('ecosystem')}) v{vuln.get('version')}")
                lines.append(f"   ID: {vuln.get('id')}")
                if vuln.get('summary'):
                    lines.append(f"   Summary: {vuln.get('summary')}")
                if vuln.get('fixed'):
                    lines.append(f"   Fixed in: {', '.join(vuln.get('fixed', []))}")
                lines.append("")
            
            if len(repo_score.dependency_vulnerabilities) > 20:
                remaining = len(repo_score.dependency_vulnerabilities) - 20
                lines.append(f"... and {remaining} more (see JSON report for full list)")
                lines.append("")
        
        # Detailed violations
        lines.append("DETAILED VIOLATIONS")
        lines.append("=" * 80)
        
        for file_score in sorted(repo_score.file_scores, key=lambda x: x.total_score, reverse=True):
            if not file_score.violations:
                continue
            
            lines.append("")
            lines.append(f"File: {file_score.file_path}")
            lines.append(f"Language: {file_score.language}")
            lines.append(f"Risk Score: {file_score.total_score:.2f}")
            lines.append("-" * 80)
            
            for violation in file_score.violations:
                severity_emoji = {
                    'CRITICAL': '🚨',
                    'HIGH': '⚠️',
                    'MEDIUM': '📋',
                    'LOW': 'ℹ️',
                    'INFO': 'ℹ️'
                }.get(violation.severity.value, '')
                
                lines.append(f"{severity_emoji} [{violation.severity.value}] Line {violation.location.line_start}")
                lines.append(f"  Type: {violation.violation_type.value}")
                lines.append(f"  Message: {violation.message}")
                if violation.cwe_id:
                    lines.append(f"  CWE: {violation.cwe_id}")
                if violation.description:
                    lines.append(f"  Description: {violation.description}")
                if violation.location.snippet:
                    lines.append(f"  Code: {violation.location.snippet}")
                if violation.recommendation:
                    lines.append(f"  Fix: {violation.recommendation}")
                lines.append(f"  Confidence: {violation.confidence:.0%}")
                lines.append("")
        
        lines.append("=" * 80)
        lines.append("End of Report")
        lines.append("=" * 80)
        
        return "\\n".join(lines)
    
    @staticmethod
    def save_report(repo_score: RepositoryRiskScore, output_path: str, format: str = 'json'):
        """Save report to file"""
        if format == 'json':
            content = HCRSReporter.generate_json_report(repo_score)
        elif format == 'text':
            content = HCRSReporter.generate_text_report(repo_score)
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"Report saved to: {output_path}")
