"""
CSCE Reporter — Report generation for cross-engine security correlations.

Generates text and JSON reports that include input summaries (what each
engine contributed) so the output is meaningful even when no correlations
are found.
"""
import json
from typing import Optional
from pathlib import Path
from datetime import datetime

from .models import CorrelationReport, Correlation, CorrelationSeverity


class CSCEReporter:
    """Generates human-readable and structured reports for CSCE correlations."""

    @staticmethod
    def generate_text_report(report: CorrelationReport) -> str:
        """Generate a formatted text report."""
        lines = []
        lines.append("=" * 80)
        lines.append("CSCE - Code-Secret Correlation Report")
        lines.append("=" * 80)
        lines.append(f"Generated: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        # Input Summary — always shown so LLMs know what was available
        isum = report.input_summary
        lines.append("ENGINE INPUT SUMMARY")
        lines.append("-" * 80)
        lines.append(f"  HCRS violations received: {isum.get('hcrs_violations', 0)}")
        lines.append(f"  SDDA drift detections received: {isum.get('sdda_drifts', 0)}")
        lines.append(f"  SLGA secrets received: {isum.get('slga_secrets', 0)}")
        raw_spatial = isum.get('raw_spatial_pairs', 0)
        grouped_spatial = isum.get('grouped_spatial_findings', 0)
        if raw_spatial > 0 and raw_spatial != grouped_spatial:
            lines.append(
                f"  Spatial correlations: {raw_spatial} raw line-pairs "
                f"\u2192 {grouped_spatial} grouped findings "
                f"(deduplicated by file + violation-type; "
                f"{raw_spatial - grouped_spatial} redundant pairs removed)"
            )
        lines.append("")

        # Summary
        lines.append("CORRELATION SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Total Correlations: {report.total_correlations}")
        if report.total_correlations > 0:
            lines.append(f"High Confidence: {report.high_confidence_count} ({report.avg_confidence:.1%} avg)")
        lines.append("")
        lines.append("Severity Breakdown:")
        lines.append(f"  Critical: {report.critical_count}")
        lines.append(f"  High:     {report.high_count}")
        lines.append(f"  Medium:   {report.medium_count}")
        lines.append(f"  Low:      {report.low_count}")
        lines.append("")

        if report.total_correlations == 0:
            lines.append("RESULT: No cross-engine correlations found.")
            if isum.get('hcrs_violations', 0) == 0 and isum.get('slga_secrets', 0) == 0:
                lines.append("This is expected — no violations or secrets were detected by the individual engines.")
            lines.append("")

        # Overall assessment
        if report.critical_count > 0:
            lines.append("OVERALL ASSESSMENT")
            lines.append("-" * 80)
            lines.append(f"CRITICAL: {report.critical_count} critical correlation(s) detected!")
            lines.append("These represent high-confidence security risks requiring immediate action.")
            lines.append("")

        # Top priorities
        if report.top_priorities:
            lines.append("TOP PRIORITIES")
            lines.append("-" * 80)
            for i, corr in enumerate(report.top_priorities[:5], 1):
                lines.append(f"{i}. [{corr.severity.value}] {corr.description}")
                lines.append(f"   Type: {corr.correlation_type.value.upper()}")
                lines.append(f"   Confidence: {corr.confidence:.1%}")
                lines.append(f"   Recommendation: {corr.recommendation}")
                lines.append("")

        # Detailed correlations
        if report.correlations:
            lines.append("DETAILED FINDINGS")
            lines.append("=" * 80)

            for corr in report.correlations:
                lines.append("")
                lines.append(f"Correlation ID: {corr.correlation_id}")
                lines.append(f"Type: {corr.correlation_type.value.upper()}")
                lines.append(f"Severity: {corr.severity.value}")
                lines.append(f"Confidence: {corr.confidence:.1%}")
                lines.append("")
                lines.append(f"Description: {corr.description}")
                lines.append("")

                if corr.evidence:
                    lines.append("Evidence:")
                    for key, value in corr.evidence.items():
                        lines.append(f"  - {key}: {value}")
                    lines.append("")

                if corr.hcrs_violation_ids:
                    lines.append(f"HCRS Violations: {', '.join(corr.hcrs_violation_ids)}")
                if corr.sdda_drift_ids:
                    lines.append(f"SDDA Drifts: {', '.join(corr.sdda_drift_ids)}")
                if corr.slga_secret_ids:
                    lines.append(f"SLGA Secrets: {', '.join(corr.slga_secret_ids)}")

                lines.append("")
                lines.append(f"Recommendation: {corr.recommendation}")
                lines.append("-" * 80)

        lines.append("")
        lines.append("=" * 80)
        lines.append("End of CSCE Report")
        lines.append("=" * 80)

        return "\n".join(lines)

    @staticmethod
    def generate_json_report(report: CorrelationReport) -> str:
        """Generate JSON report."""
        return json.dumps(report.to_dict(), indent=2)

    @staticmethod
    def save_report(report: CorrelationReport, output_path: str, format: str = 'text'):
        """Save report to file."""
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        if format == 'json':
            content = CSCEReporter.generate_json_report(report)
        else:
            content = CSCEReporter.generate_text_report(report)

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(content)

    @staticmethod
    def generate_summary(report: CorrelationReport) -> str:
        """Generate a brief summary suitable for CI/CD output."""
        if report.critical_count > 0:
            return f"CRITICAL: {report.critical_count} critical correlation(s) found! Immediate action required."
        elif report.high_count > 0:
            return f"WARNING: {report.high_count} high-severity correlation(s) detected. Review recommended."
        elif report.total_correlations > 0:
            return f"OK: {report.total_correlations} correlation(s) found. No critical issues."
        else:
            return "OK: No significant correlations detected."
