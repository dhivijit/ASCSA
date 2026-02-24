"""Tests for SDDA git-diff mode (Mode 2).

Validates diff_snapshots() and run_sdda_git_diff() which are the
production code paths used by the orchestrator.
"""
import unittest
from datetime import datetime

from engines.slga.models import Secret
from engines.sdda.git_drift_detector import (
    GitDriftDetection,
    diff_snapshots,
    _sid,
)
from engines.sdda.run import run_sdda_git_diff
from engines.sdda.models import DriftReport


def _secret(value, files=None, secret_type="api_key"):
    return Secret(
        value=value,
        secret_type=secret_type,
        entropy=4.5,
        files=files or ["app.py"],
        lines=[1],
        commits=[],
    )


class TestSid(unittest.TestCase):
    """Verify _sid() produces stable, distinct hashes."""

    def test_deterministic(self):
        self.assertEqual(_sid("abc"), _sid("abc"))

    def test_distinct(self):
        self.assertNotEqual(_sid("abc"), _sid("xyz"))

    def test_prefix(self):
        self.assertTrue(_sid("abc").startswith("secret_"))


class TestDiffSnapshots(unittest.TestCase):
    """Unit tests for diff_snapshots()."""

    def _run(self, current, previous):
        return diff_snapshots(current, previous, "run1", datetime.now())

    # ── ADDED ────────────────────────────────────────────────────────────
    def test_added_secret(self):
        """New secret in HEAD that was absent at HEAD~1 → ADDED / CRITICAL."""
        current = [_secret("new_api_key_12345")]
        previous = []

        detections = self._run(current, previous)

        self.assertEqual(len(detections), 1)
        d = detections[0]
        self.assertEqual(d.drift_type, "ADDED")
        self.assertEqual(d.severity, "CRITICAL")
        self.assertTrue(d.is_drifted)
        self.assertEqual(d.secret_id, _sid("new_api_key_12345"))

    # ── REMOVED ──────────────────────────────────────────────────────────
    def test_removed_secret(self):
        """Secret at HEAD~1 gone at HEAD → REMOVED / LOW."""
        current = []
        previous = [_secret("old_secret_value")]

        detections = self._run(current, previous)

        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].drift_type, "REMOVED")
        self.assertEqual(detections[0].severity, "LOW")

    # ── MOVED ────────────────────────────────────────────────────────────
    def test_moved_secret(self):
        """Same value exists at both but in different files → MOVED / MEDIUM."""
        current = [_secret("shared_key", files=["new_location.py"])]
        previous = [_secret("shared_key", files=["old_location.py"])]

        detections = self._run(current, previous)

        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].drift_type, "MOVED")
        self.assertEqual(detections[0].severity, "MEDIUM")

    # ── No drift ─────────────────────────────────────────────────────────
    def test_no_drift(self):
        """Identical snapshots → no detections."""
        both = [_secret("stable_key", files=["config.py"])]
        detections = self._run(both, both)
        self.assertEqual(len(detections), 0)

    # ── Multiple events ──────────────────────────────────────────────────
    def test_multiple_changes(self):
        """Mixed ADDED + REMOVED + MOVED in one diff."""
        current = [
            _secret("added_key"),
            _secret("moved_key", files=["b.py"]),
        ]
        previous = [
            _secret("removed_key"),
            _secret("moved_key", files=["a.py"]),
        ]

        detections = self._run(current, previous)

        types = {d.drift_type for d in detections}
        self.assertIn("ADDED", types)
        self.assertIn("REMOVED", types)
        self.assertIn("MOVED", types)

    # ── commit_history secrets excluded ──────────────────────────────────
    def test_commit_history_excluded(self):
        """Secrets with secret_type='commit_history' should be ignored."""
        current = [_secret("key_in_commit", secret_type="commit_history")]
        previous = []

        detections = self._run(current, previous)
        self.assertEqual(len(detections), 0)


class TestRunSddaGitDiff(unittest.TestCase):
    """End-to-end test for run_sdda_git_diff()."""

    def test_returns_drift_report(self):
        current = [_secret("new_secret")]
        previous = []

        report = run_sdda_git_diff(current, previous, "run_42", datetime.now())

        self.assertIsInstance(report, DriftReport)
        self.assertEqual(report.total_secrets_analyzed, 1)
        self.assertEqual(len(report.drifted_secrets), 1)
        self.assertEqual(report.summary["CRITICAL"], 1)
        self.assertIn("DRIFT_DETECTED", report.baseline_status)

    def test_clean_diff_returns_ok(self):
        both = [_secret("stable")]
        report = run_sdda_git_diff(both, both, "run_43", datetime.now())

        self.assertEqual(len(report.drifted_secrets), 0)
        self.assertIn("OK", report.baseline_status)

    def test_empty_inputs(self):
        report = run_sdda_git_diff([], [], "run_44", datetime.now())
        self.assertEqual(report.total_secrets_analyzed, 0)
        self.assertEqual(len(report.drifted_secrets), 0)


if __name__ == "__main__":
    unittest.main()
