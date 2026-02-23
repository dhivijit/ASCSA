"""
HCRS Reporter — Report generation for Hybrid Code Risk Scoring.

Generates text and JSON reports from HCRS scan results. Reports include
scan coverage metadata, violation details, dependency vulnerability
information, and risk recommendations. Designed to provide meaningful
context for LLM remediation workflows even when no violations are found.
"""
import json
from typing import TextIO
from datetime import datetime
from .models import RepositoryRiskScore, FileRiskScore, SecurityViolation


class HCRSReporter:
    """Generate reports for HCRS analysis results."""

    @staticmethod
    def generate_json_report(repo_score: RepositoryRiskScore) -> str:
        """Generate JSON report with full scan context.

        Includes all scanned files (not just those with violations) and
        scan coverage metadata for LLM consumption.
        """
        scan_coverage = repo_score.summary.get('scan_coverage', {})

        report = {
            'repo_path': repo_score.repo_path,
            'timestamp': repo_score.timestamp.isoformat(),
            'total_score': repo_score.total_score,
            'recommendation': repo_score.recommendation,
            'scan_coverage': scan_coverage,
            'summary': {
                'total_files_analyzed': repo_score.summary.get('total_files_analyzed', len(repo_score.file_scores)),
                'total_violations': repo_score.summary.get('total_violations', 0),
                'severity_counts': repo_score.summary.get('severity_counts', {}),
                'violation_types': repo_score.summary.get('violation_type_counts', {}),
                'dependency_vulnerabilities': repo_score.summary.get('dependency_vulnerability_count', 0),
                'status': 'clean' if repo_score.summary.get('total_violations', 0) == 0 else 'violations_found',
                'description': (
                    'No security violations detected in analyzed files.'
                    if repo_score.summary.get('total_violations', 0) == 0
                    else f"{repo_score.summary.get('total_violations', 0)} violation(s) detected."
                )
            },
            'high_risk_files': repo_score.summary.get('high_risk_files', []),
            'dependency_vulnerabilities': repo_score.dependency_vulnerabilities,
            'files_with_violations': [],
            'all_files_analyzed': []
        }

        for file_score in repo_score.file_scores:
            file_entry = {
                'path': file_score.file_path,
                'language': file_score.language,
                'score': file_score.total_score,
                'lines_analyzed': file_score.lines_analyzed,
                'violation_count': len(file_score.violations),
            }
            report['all_files_analyzed'].append(file_entry)

            if file_score.violations:
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
                report['files_with_violations'].append(file_data)

        return json.dumps(report, indent=2)

    @staticmethod
    def generate_text_report(repo_score: RepositoryRiskScore) -> str:
        """Generate human-readable text report."""
        lines = []
        lines.append("=" * 80)
        lines.append("HCRS - Hybrid Code Risk Scoring Report")
        lines.append("=" * 80)
        lines.append(f"Repository: {repo_score.repo_path}")
        lines.append(f"Scan Time: {repo_score.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Total Risk Score: {repo_score.total_score:.2f}")
        lines.append("")

        # Scan Coverage
        scan_coverage = repo_score.summary.get('scan_coverage', {})
        if scan_coverage:
            lines.append("SCAN COVERAGE")
            lines.append("-" * 80)
            lines.append(f"Files discovered: {scan_coverage.get('total_files_discovered', 'N/A')}")
            lines.append(f"Files analyzed: {scan_coverage.get('total_files_analyzed', 'N/A')}")
            lines.append(f"Files skipped: {scan_coverage.get('files_skipped', 'N/A')}")
            files_by_lang = scan_coverage.get('files_by_language', {})
            if files_by_lang:
                lines.append("Files by language:")
                for lang, count in sorted(files_by_lang.items(), key=lambda x: -x[1]):
                    lines.append(f"  {lang}: {count}")
            rules = scan_coverage.get('rules_loaded', {})
            if rules:
                total_rules = sum(rules.values())
                lines.append(f"Security rules loaded: {total_rules}")
                for lang, count in rules.items():
                    lines.append(f"  {lang}: {count}")
            dep_files = scan_coverage.get('dependency_files_checked', 0)
            lines.append(f"Dependency manifest files checked: {dep_files}")
            lines.append("")

        # Summary
        lines.append("SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Files Analyzed: {repo_score.summary.get('total_files_analyzed', len(repo_score.file_scores))}")
        lines.append(f"Total Violations: {repo_score.summary.get('total_violations', 0)}")
        lines.append("")

        total_violations = repo_score.summary.get('total_violations', 0)
        if total_violations == 0:
            lines.append("RESULT: No security violations detected in analyzed source files.")
            lines.append("")

        lines.append("Severity Breakdown:")
        severity_counts = repo_score.summary.get('severity_counts', {})
        lines.append(f"  Critical: {severity_counts.get('CRITICAL', 0)}")
        lines.append(f"  High:     {severity_counts.get('HIGH', 0)}")
        lines.append(f"  Medium:   {severity_counts.get('MEDIUM', 0)}")
        lines.append(f"  Low:      {severity_counts.get('LOW', 0)}")
        lines.append("")

        # Dependency vulnerabilities
        dep_vuln_count = repo_score.summary.get('dependency_vulnerability_count', 0)
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
            for vuln in repo_score.dependency_vulnerabilities[:20]:
                lines.append(f"  {vuln.get('package_name')} ({vuln.get('ecosystem')}) v{vuln.get('version')}")
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
        violated_files = [fs for fs in repo_score.file_scores if fs.violations]
        if violated_files:
            lines.append("DETAILED VIOLATIONS")
            lines.append("=" * 80)

            for file_score in sorted(violated_files, key=lambda x: x.total_score, reverse=True):
                lines.append("")
                lines.append(f"File: {file_score.file_path}")
                lines.append(f"Language: {file_score.language}")
                lines.append(f"Risk Score: {file_score.total_score:.2f}")
                lines.append("-" * 80)

                for violation in file_score.violations:
                    severity_emoji = {
                        'CRITICAL': '[!]',
                        'HIGH': '[H]',
                        'MEDIUM': '[M]',
                        'LOW': '[L]',
                        'INFO': '[I]'
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

        return "\n".join(lines)

    @staticmethod
    def save_report(repo_score: RepositoryRiskScore, output_path: str, format: str = 'json'):
        """Save report to file."""
        if format == 'json':
            content = HCRSReporter.generate_json_report(repo_score)
        elif format == 'text':
            content = HCRSReporter.generate_text_report(repo_score)
        else:
            raise ValueError(f"Unsupported format: {format}")

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)

        print(f"Report saved to: {output_path}")


# Backward-compatible module-level aliases
generate_json_report = HCRSReporter.generate_json_report
generate_text_report = HCRSReporter.generate_text_report
