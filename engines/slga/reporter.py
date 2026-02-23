"""
SLGA Reporter — Report generation for Secret Lineage Graph Analysis.

Generates text and JSON reports from SLGA scan results, including:
  - Scan coverage statistics (files scanned, directories walked, file types)
  - Secrets found in current files and git commit history
  - Propagation analysis from Neo4j graph (when available)
  - Risk scoring based on secret propagation scope

Reports are designed to be consumed by LLMs for remediation workflows,
so they include rich context even when no secrets are found.
"""

import hashlib
import json
from typing import List, Dict, Optional
from datetime import datetime
from .database import SLGADatabase
from .models import Secret


def _anonymize_value(value: str) -> str:
    """Create a stable, anonymized hash of a secret value.

    Uses SHA-256 instead of Python's built-in hash() to ensure
    consistent hashing across runs and Python versions.
    """
    return hashlib.sha256(value.encode('utf-8', errors='replace')).hexdigest()[:16]


class SLGAReporter:
    """Reporter for SLGA scan data.

    Generates text and JSON reports from secrets and scan statistics.
    Can also generate reports from the SQLite database when no live
    secrets list is provided.
    """

    def __init__(self, db_path: str = "slga.db"):
        self.db = SLGADatabase(db_path)

    def generate_summary_report(self) -> Dict:
        """Generate summary report of all stored data."""
        stats = self.db.get_statistics()
        recent_scans = self.db.get_scan_history(limit=5)

        return {
            'generated_at': datetime.now().isoformat(),
            'statistics': stats,
            'recent_scans': recent_scans
        }

    def generate_secret_report(self, secret_value: str = None) -> Dict:
        """Generate detailed report for a specific secret or all secrets."""
        if secret_value:
            lineage = self.db.get_secret_lineage(secret_value)
            if not lineage:
                return {'error': f'Secret not found: {secret_value}'}

            return {
                'generated_at': datetime.now().isoformat(),
                'secret_lineage': lineage
            }
        else:
            secrets = self.db.get_all_secrets()
            return {
                'generated_at': datetime.now().isoformat(),
                'total_secrets': len(secrets),
                'secrets': secrets
            }

    def generate_propagation_report(self, secret_value: str) -> Dict:
        """Generate propagation analysis report for a secret."""
        lineage = self.db.get_secret_lineage(secret_value)

        if not lineage:
            return {'error': f'Secret not found: {secret_value}'}

        propagation_scope = {
            'files_affected': len(lineage['files']),
            'commits_involved': len(lineage['commits']),
            'stages_using': len(lineage['stages']),
            'logs_containing': len(lineage['logs']),
            'artifacts_containing': len(lineage['artifacts'])
        }

        risk_score = 0
        risk_factors = []

        if propagation_scope['files_affected'] > 5:
            risk_score += 30
            risk_factors.append(f"High file spread ({propagation_scope['files_affected']} files)")
        elif propagation_scope['files_affected'] > 2:
            risk_score += 15
            risk_factors.append(f"Moderate file spread ({propagation_scope['files_affected']} files)")

        if propagation_scope['commits_involved'] > 10:
            risk_score += 20
            risk_factors.append(f"High commit history ({propagation_scope['commits_involved']} commits)")
        elif propagation_scope['commits_involved'] > 5:
            risk_score += 10
            risk_factors.append(f"Moderate commit history ({propagation_scope['commits_involved']} commits)")

        if propagation_scope['stages_using'] > 0:
            risk_score += 25
            risk_factors.append(f"Used in CI/CD stages ({propagation_scope['stages_using']} stages)")

        if propagation_scope['logs_containing'] > 0:
            risk_score += 15
            risk_factors.append(f"Appears in logs ({propagation_scope['logs_containing']} logs)")

        if propagation_scope['artifacts_containing'] > 0:
            risk_score += 10
            risk_factors.append(f"Appears in artifacts ({propagation_scope['artifacts_containing']} artifacts)")

        if risk_score >= 70:
            severity = "CRITICAL"
        elif risk_score >= 50:
            severity = "HIGH"
        elif risk_score >= 30:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            'generated_at': datetime.now().isoformat(),
            'secret_value': secret_value,
            'propagation_scope': propagation_scope,
            'risk_score': risk_score,
            'severity': severity,
            'risk_factors': risk_factors,
            'lineage_details': lineage
        }

    def generate_text_report(self, secrets: List[Secret] = None,
                             scan_stats: Optional[Dict] = None) -> str:
        """Generate a human-readable text report.

        Args:
            secrets: List of Secret objects from the current scan.
                     If None, generates a report from the database.
            scan_stats: Coverage statistics from detect_secrets()
                        (files_scanned, directories_walked, etc.).

        Returns:
            Multi-line text report string.
        """
        if secrets is not None:
            lines = []
            lines.append("=" * 80)
            lines.append("SECRET LINEAGE GRAPH ANALYSIS (SLGA) REPORT")
            lines.append("=" * 80)
            lines.append(f"Generated: {datetime.now().isoformat()}")
            lines.append("")

            # --- Scan Coverage Section ---
            if scan_stats:
                lines.append("SCAN COVERAGE:")
                lines.append(f"  Files scanned: {scan_stats.get('files_scanned', 'N/A')}")
                lines.append(f"  Directories walked: {scan_stats.get('directories_walked', 'N/A')}")
                lines.append(f"  Directories skipped: {scan_stats.get('directories_skipped', 'N/A')}")
                lines.append(f"  Files skipped (errors): {scan_stats.get('files_skipped_errors', 'N/A')}")
                lines.append(f"  False positives filtered: {scan_stats.get('false_positives_filtered', 'N/A')}")
                commits_scanned = scan_stats.get('commits_scanned', 'N/A')
                lines.append(f"  Commits scanned: {commits_scanned}")

                files_by_type = scan_stats.get('files_by_type', {})
                if files_by_type:
                    lines.append("  Files by type:")
                    for ext, count in sorted(files_by_type.items(), key=lambda x: -x[1]):
                        lines.append(f"    {ext}: {count}")
                lines.append("")

            lines.append(f"Total Secrets Found: {len(secrets)}")

            file_secrets = [s for s in secrets if s.files]
            commit_secrets = [s for s in secrets if s.secret_type == "commit_history"]

            lines.append(f"  - From current files: {len(file_secrets)}")
            lines.append(f"  - From commit history: {len(commit_secrets)}")
            lines.append("")

            if len(secrets) == 0:
                lines.append("RESULT: No hardcoded secrets detected in scanned files or commit history.")
                lines.append("The repository appears clean from a secret-leakage perspective.")
                lines.append("")

            # --- Code Structure Analysis Section ---
            if scan_stats and scan_stats.get('code_analysis'):
                ca = scan_stats['code_analysis']
                lines.append("CODE STRUCTURE ANALYSIS:")
                lines.append(f"  Files parsed: {ca.get('files_parsed', 0)}")
                lines.append(f"  Languages: {', '.join(ca.get('languages', []))}")
                lines.append(f"  Functions: {ca.get('total_functions', 0)}")
                lines.append(f"  Classes: {ca.get('total_classes', 0)}")
                lines.append(f"  Variables: {ca.get('total_variables', 0)}")
                lines.append(f"  Imports: {ca.get('total_imports', 0)}")
                lines.append(f"  Call graph edges: {ca.get('total_call_edges', 0)}")
                lines.append("")

            # --- Git Context Section ---
            if scan_stats and scan_stats.get('git_context'):
                gc = scan_stats['git_context']
                lines.append("GIT CONTRIBUTORS:")
                lines.append(f"  Total commits analyzed: {gc.get('total_commits', 0)}")
                lines.append(f"  Contributors: {gc.get('total_contributors', 0)}")
                lines.append(f"  Files with git context: {gc.get('total_files_analyzed', 0)}")
                contribs = gc.get('contributors', [])
                if contribs:
                    lines.append("  Top contributors:")
                    for c in sorted(contribs, key=lambda x: -x.get('commits', 0))[:5]:
                        lines.append(f"    {c['name']} ({c.get('email', '')}): {c.get('commits', 0)} commit(s)")
                hotspots = gc.get('hotspots', [])
                if hotspots:
                    lines.append(f"\n  FILE HOTSPOTS ({len(hotspots)}):")
                    lines.append("  (Files with high change frequency and multiple contributors)")
                    for hp in hotspots[:10]:
                        lines.append(f"    - {hp}")
                lines.append("")

            if commit_secrets:
                lines.append("\n" + "=" * 80)
                lines.append("SECRETS FOUND IN GIT COMMIT HISTORY")
                lines.append("=" * 80)
                lines.append("These secrets were found in git commit diffs (may have been removed from current files)")
                lines.append("")

                for idx, secret in enumerate(commit_secrets, 1):
                    lines.append(f"\n{idx}. Commit-Based Secret:")
                    lines.append(f"   Value: {secret.value[:40]}...")
                    lines.append(f"   Type: {secret.secret_type}")
                    lines.append(f"   Entropy: {secret.entropy:.2f}")
                    lines.append(f"   Found in {len(secret.commits)} commit(s):")
                    for commit_hash in secret.commits[:5]:
                        lines.append(f"     - Commit: {commit_hash[:8]}")
                    if len(secret.commits) > 5:
                        lines.append(f"     ... and {len(secret.commits) - 5} more commits")

            if file_secrets:
                lines.append("\n" + "=" * 80)
                lines.append("SECRETS IN CURRENT FILES")
                lines.append("=" * 80)
                lines.append("")

                for idx, secret in enumerate(file_secrets, 1):
                    lines.append(f"\n{idx}. File-Based Secret:")
                    lines.append(f"   Value: {secret.value[:40]}...")
                    lines.append(f"   Type: {secret.secret_type}")
                    lines.append(f"   Entropy: {secret.entropy:.2f}")
                    lines.append(f"   Files: {len(secret.files)}")

                    if secret.files:
                        lines.append(f"   File Locations:")
                        for file_path, line_num in zip(secret.files[:5], secret.lines[:5]):
                            lines.append(f"     - {file_path}:{line_num}")
                        if len(secret.files) > 5:
                            lines.append(f"     ... and {len(secret.files) - 5} more")

                    if secret.commits:
                        lines.append(f"   Commit History: {len(secret.commits)} commit(s)")
                        for commit_hash in secret.commits[:3]:
                            lines.append(f"     - {commit_hash[:8]}")
                        if len(secret.commits) > 3:
                            lines.append(f"     ... and {len(secret.commits) - 3} more")

            lines.append("\n" + "=" * 80)
            return "\n".join(lines)
        else:
            stats = self.db.get_statistics()
            all_secrets = self.db.get_all_secrets()

            lines = []
            lines.append("=" * 80)
            lines.append("SECRET LINEAGE GRAPH ANALYSIS (SLGA) DATABASE REPORT")
            lines.append("=" * 80)
            lines.append(f"Generated: {datetime.now().isoformat()}")
            lines.append("")
            lines.append("DATABASE STATISTICS:")
            for key, value in stats.items():
                lines.append(f"  {key}: {value}")
            lines.append("")

            if all_secrets:
                lines.append(f"\nRECENT SECRETS (Last {min(10, len(all_secrets))}):")
                for idx, secret in enumerate(all_secrets[:10], 1):
                    lines.append(f"\n{idx}. Secret:")
                    lines.append(f"   Type: {secret['secret_type']}")
                    lines.append(f"   Entropy: {secret['entropy']:.2f}")
                    lines.append(f"   First Seen: {secret['first_seen']}")
                    lines.append(f"   Last Seen: {secret['last_seen']}")

            lines.append("\n" + "=" * 80)
            return "\n".join(lines)

    def generate_json_report(self, secrets: List[Secret] = None,
                             scan_stats: Optional[Dict] = None) -> str:
        """Generate JSON report.

        Args:
            secrets: List of Secret objects from the current scan.
                     If None, generates a report from the database.
            scan_stats: Coverage statistics from detect_secrets().

        Returns:
            JSON string with full report data.
        """
        if secrets is not None:
            file_secrets = [s for s in secrets if s.files]
            commit_secrets = [s for s in secrets if s.secret_type == "commit_history"]

            report = {
                'generated_at': datetime.now().isoformat(),
                'scan_coverage': scan_stats or {},
                'total_secrets': len(secrets),
                'secrets_from_files': len(file_secrets),
                'secrets_from_commits': len(commit_secrets),
                'code_analysis': (scan_stats or {}).get('code_analysis'),
                'git_context': (scan_stats or {}).get('git_context'),
                'summary': {
                    'total_files_with_secrets': len(set(f for s in secrets for f in s.files)),
                    'total_commits_analyzed': len(set(c for s in secrets for c in s.commits)),
                    'status': 'clean' if len(secrets) == 0 else 'secrets_found',
                    'description': (
                        'No hardcoded secrets detected in scanned files or commit history.'
                        if len(secrets) == 0
                        else f'{len(secrets)} secret(s) detected across files and commits.'
                    )
                },
                'commit_based_secrets': [
                    {
                        'value_preview': s.value[:40] + '...' if len(s.value) > 40 else s.value,
                        'value_hash': _anonymize_value(s.value),
                        'type': s.secret_type,
                        'entropy': round(s.entropy, 2),
                        'commits': s.commits[:10],
                        'total_commits': len(s.commits)
                    }
                    for s in commit_secrets
                ],
                'file_based_secrets': [
                    {
                        'value_hash': _anonymize_value(s.value),
                        'type': s.secret_type,
                        'entropy': round(s.entropy, 2),
                        'files_count': len(s.files),
                        'commits_count': len(s.commits),
                        'files': [
                            {'path': f, 'line': l}
                            for f, l in zip(s.files[:10], s.lines[:10])
                        ],
                        'commits': s.commits[:5] if s.commits else []
                    }
                    for s in file_secrets
                ]
            }
        else:
            stats = self.db.get_statistics()
            all_secrets = self.db.get_all_secrets()

            report = {
                'generated_at': datetime.now().isoformat(),
                'statistics': stats,
                'total_secrets': len(all_secrets),
                'secrets': all_secrets[:50]
            }

        return json.dumps(report, indent=2, default=str)

    def close(self):
        """Close database connection."""
        self.db.close()
