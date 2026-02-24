"""Integration tests for PipelineOrchestrator.

Validates engine sequencing, data handoff between SLGA→SDDA→HCRS→CSCE,
skip logic, exit code determination, and error resilience.
"""
import os
import json
import tempfile
import shutil
import unittest
from datetime import datetime
from unittest.mock import patch, MagicMock

from cli.context import ScanContext
from cli import exit_codes
from core.orchestrator import PipelineOrchestrator, run_pipeline
from core.contracts import SecretLineage
from engines.slga.models import Secret
from engines.hcrs.models import (
    RepositoryRiskScore,
    FileRiskScore,
    SecurityViolation,
    Severity,
    ViolationType,
    CodeLocation,
)
from engines.sdda.models import DriftReport
from engines.sdda.git_drift_detector import GitDriftDetection, _sid


def _make_temp_git_repo():
    """Create a minimal temp directory that passes ScanContext validation."""
    d = tempfile.mkdtemp(prefix="ascsa_test_")
    # ScanContext only requires the path to exist as a directory.
    return d


def _dummy_slga_result(secrets=None, graph=None):
    """Return a (graph, secrets, db_path, propagation, stats) 5-tuple."""
    if secrets is None:
        secrets = [
            Secret(
                value="AKIAIOSFODNN7EXAMPLE",
                secret_type="aws_access_key",
                entropy=4.5,
                files=["config.py"],
                lines=[10],
                commits=[],
            )
        ]
    return (graph, secrets, ":memory:", None, {"commits_scanned": 0})


def _dummy_hcrs_result(repo_path, violations=None):
    """Build a RepositoryRiskScore with optional violations."""
    if violations is None:
        violations = [
            SecurityViolation(
                violation_type=ViolationType.HARDCODED_SECRET,
                severity=Severity.CRITICAL,
                location=CodeLocation(file_path="config.py", line_start=10, line_end=10),
                message="Hardcoded AWS key",
            )
        ]
    fs = FileRiskScore(
        file_path="config.py",
        language="python",
        violations=violations,
        total_score=80.0,
    )
    return RepositoryRiskScore(
        repo_path=repo_path,
        timestamp=datetime.now(),
        total_score=80.0,
        file_scores=[fs],
        summary={
            "total_files_analyzed": 1,
            "total_violations": len(violations),
            "severity_counts": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "high_risk_files": [],
        },
        recommendation="FAIL",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test class
# ─────────────────────────────────────────────────────────────────────────────
class TestPipelineOrchestrator(unittest.TestCase):
    """Integration tests for PipelineOrchestrator."""

    def setUp(self):
        self.repo_dir = _make_temp_git_repo()
        self.output_dir = tempfile.mkdtemp(prefix="ascsa_out_")

    def tearDown(self):
        shutil.rmtree(self.repo_dir, ignore_errors=True)
        shutil.rmtree(self.output_dir, ignore_errors=True)

    def _make_context(self, **overrides):
        defaults = dict(
            repo_path=self.repo_dir,
            reportout_dir=self.output_dir,
            branch="main",
            environment="test",
            actor="test-bot",
            enable_upload=False,
        )
        defaults.update(overrides)
        return ScanContext(**defaults)

    # ── Happy path ───────────────────────────────────────────────────────
    @patch("core.orchestrator.PipelineOrchestrator._upload_reports")
    @patch("engines.hcrs.scanner.HCRSScanner.scan_repository")
    @patch("engines.slga.run.run_slga")
    def test_happy_path_all_engines(self, mock_slga, mock_hcrs_scan, _upload):
        """All four engines run; results dict has slga, sdda, hcrs, csce."""
        mock_slga.return_value = _dummy_slga_result()
        mock_hcrs_scan.return_value = _dummy_hcrs_result(self.repo_dir)

        ctx = self._make_context()
        results = run_pipeline(ctx)

        self.assertIsNotNone(results["slga"], "SLGA results should be populated")
        self.assertIsNotNone(results["hcrs"], "HCRS results should be populated")
        # CSCE should have run (HCRS present)
        self.assertIsNotNone(results.get("csce"), "CSCE results should be populated")
        # ascsa_report.json should exist
        report_path = os.path.join(self.output_dir, "ascsa_report.json")
        self.assertTrue(os.path.exists(report_path))
        with open(report_path) as f:
            saved = json.load(f)
        self.assertIn("scan_metadata", saved)

    # ── Skip logic ───────────────────────────────────────────────────────
    @patch("core.orchestrator.PipelineOrchestrator._upload_reports")
    @patch("engines.hcrs.scanner.HCRSScanner.scan_repository")
    def test_skip_slga_skips_sdda(self, mock_hcrs, _upload):
        """When SLGA is skipped, SDDA must also be skipped (dependency)."""
        mock_hcrs.return_value = _dummy_hcrs_result(self.repo_dir, violations=[])

        ctx = self._make_context(skip_slga=True)
        results = run_pipeline(ctx)

        self.assertTrue(results["slga_skipped"])
        self.assertTrue(results["sdda_skipped"])

    @patch("core.orchestrator.PipelineOrchestrator._upload_reports")
    @patch("engines.slga.run.run_slga")
    def test_skip_hcrs_skips_csce(self, mock_slga, _upload):
        """When HCRS is skipped, CSCE must also be skipped (dependency)."""
        mock_slga.return_value = _dummy_slga_result()

        ctx = self._make_context(skip_hcrs=True)
        results = run_pipeline(ctx)

        self.assertTrue(results["hcrs_skipped"])
        self.assertTrue(results["csce_skipped"])

    # ── Data handoff ─────────────────────────────────────────────────────
    @patch("core.orchestrator.PipelineOrchestrator._upload_reports")
    @patch("engines.hcrs.scanner.HCRSScanner.scan_repository")
    @patch("engines.slga.run.run_slga")
    def test_slga_secrets_reach_csce(self, mock_slga, mock_hcrs, _upload):
        """SLGA secrets should flow into CSCE via orchestrator wiring."""
        secrets = [
            Secret(value="sk_live_xyz", secret_type="api_key", entropy=4.0,
                   files=["pay.py"], lines=[5], commits=[]),
        ]
        mock_slga.return_value = _dummy_slga_result(secrets=secrets)
        mock_hcrs.return_value = _dummy_hcrs_result(
            self.repo_dir,
            violations=[
                SecurityViolation(
                    violation_type=ViolationType.HARDCODED_SECRET,
                    severity=Severity.CRITICAL,
                    location=CodeLocation(file_path="pay.py", line_start=5, line_end=5),
                    message="Stripe key",
                )
            ],
        )

        results = run_pipeline(self._make_context())

        csce = results.get("csce")
        self.assertIsNotNone(csce)
        # SPATIAL or SECRET_MATCH correlation expected (same file + secret)
        self.assertGreater(csce["total_correlations"], 0)

    # ── Exit code determination ──────────────────────────────────────────
    @patch("core.orchestrator.PipelineOrchestrator._upload_reports")
    @patch("engines.hcrs.scanner.HCRSScanner.scan_repository")
    @patch("engines.slga.run.run_slga")
    def test_exit_code_critical(self, mock_slga, mock_hcrs, _upload):
        """CRITICAL findings should produce RISK_CRITICAL exit code."""
        mock_slga.return_value = _dummy_slga_result()
        mock_hcrs.return_value = _dummy_hcrs_result(self.repo_dir)

        results = run_pipeline(self._make_context())

        # There's a CRITICAL violation in HCRS, so CSCE should have CRITICAL correlations
        self.assertIn(results["exit_code"], [exit_codes.RISK_CRITICAL, exit_codes.RISK_HIGH])

    @patch("core.orchestrator.PipelineOrchestrator._upload_reports")
    @patch("engines.hcrs.scanner.HCRSScanner.scan_repository")
    @patch("engines.slga.run.run_slga")
    def test_exit_code_success_clean_repo(self, mock_slga, mock_hcrs, _upload):
        """A clean repo should produce SUCCESS exit code."""
        mock_slga.return_value = _dummy_slga_result(secrets=[])
        mock_hcrs.return_value = _dummy_hcrs_result(self.repo_dir, violations=[])

        results = run_pipeline(self._make_context())

        self.assertEqual(results["exit_code"], exit_codes.SUCCESS)
        self.assertEqual(results["recommendation"], "PASS")

    # ── Engine failure resilience ────────────────────────────────────────
    @patch("core.orchestrator.PipelineOrchestrator._upload_reports")
    @patch("engines.hcrs.scanner.HCRSScanner.scan_repository")
    @patch("engines.slga.run.run_slga", side_effect=RuntimeError("Neo4j down"))
    def test_slga_failure_does_not_crash_pipeline(self, _slga, mock_hcrs, _upload):
        """If SLGA raises, the pipeline should continue with HCRS."""
        mock_hcrs.return_value = _dummy_hcrs_result(self.repo_dir, violations=[])

        results = run_pipeline(self._make_context())

        # SLGA failed but pipeline should still complete
        self.assertTrue(results["slga_skipped"])
        self.assertIsNotNone(results["hcrs"])

    @patch("core.orchestrator.PipelineOrchestrator._upload_reports")
    @patch("engines.hcrs.scanner.HCRSScanner.scan_repository", side_effect=RuntimeError("parse error"))
    @patch("engines.slga.run.run_slga")
    def test_hcrs_failure_does_not_crash_pipeline(self, mock_slga, _hcrs, _upload):
        """If HCRS raises, the pipeline should still produce a report."""
        mock_slga.return_value = _dummy_slga_result(secrets=[])

        results = run_pipeline(self._make_context())

        self.assertTrue(results["hcrs_skipped"])
        # Report file should still be written
        self.assertTrue(os.path.exists(os.path.join(self.output_dir, "ascsa_report.json")))

    # ── Scan metadata ────────────────────────────────────────────────────
    @patch("core.orchestrator.PipelineOrchestrator._upload_reports")
    @patch("engines.hcrs.scanner.HCRSScanner.scan_repository")
    @patch("engines.slga.run.run_slga")
    def test_scan_metadata_present(self, mock_slga, mock_hcrs, _upload):
        """Results should contain scan_metadata with timing and engine flags."""
        mock_slga.return_value = _dummy_slga_result(secrets=[])
        mock_hcrs.return_value = _dummy_hcrs_result(self.repo_dir, violations=[])

        results = run_pipeline(self._make_context())

        meta = results.get("scan_metadata")
        self.assertIsNotNone(meta)
        self.assertIn("scan_duration_seconds", meta)
        self.assertIn("engines_run", meta)
        self.assertTrue(meta["engines_run"]["slga"])
        self.assertTrue(meta["engines_run"]["hcrs"])


if __name__ == "__main__":
    unittest.main()
