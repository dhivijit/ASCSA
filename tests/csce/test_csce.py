# Test CSCE - Basic unit tests
import unittest
from datetime import datetime
from unittest.mock import MagicMock

from engines.hcrs.models import SecurityViolation, Severity, ViolationType, CodeLocation
from engines.slga.models import Secret
from engines.sdda.models import DriftDetection
from engines.sdda.git_drift_detector import GitDriftDetection, _sid
from engines.csce import run_csce
from engines.csce.models import CorrelationType, CorrelationSeverity

class TestCSCE(unittest.TestCase):
    
    def test_spatial_correlation(self):
        """Test spatial correlation (same file)"""
        violations = [
            SecurityViolation(
                violation_type=ViolationType.SENSITIVE_LOGGING,
                severity=Severity.HIGH,
                location=CodeLocation(
                    file_path="test.py",
                    line_start=10,
                    line_end=10
                ),
                message="Test violation"
            )
        ]
        
        secrets = [
            Secret(
                value="test_secret",
                secret_type="api_key",
                entropy=4.0,
                files=["test.py"],
                lines=[10]
            )
        ]
        
        report = run_csce(violations, slga_secrets=secrets)
        
        self.assertGreater(report.total_correlations, 0)
        # Should find spatial correlation
        spatial = [c for c in report.correlations if c.correlation_type == CorrelationType.SPATIAL]
        self.assertGreater(len(spatial), 0)
    
    def test_secret_match_correlation(self):
        """Test secret match correlation"""
        violations = [
            SecurityViolation(
                violation_type=ViolationType.HARDCODED_SECRET,
                severity=Severity.CRITICAL,
                location=CodeLocation(
                    file_path="config.py",
                    line_start=42,
                    line_end=42
                ),
                message="Hardcoded secret"
            )
        ]
        
        secrets = [
            Secret(
                value="api_key_123",
                secret_type="api_key",
                entropy=4.5,
                files=["config.py"],
                lines=[42]
            )
        ]
        
        report = run_csce(violations, slga_secrets=secrets)
        
        # Should find SECRET_MATCH correlation
        secret_matches = [c for c in report.correlations if c.correlation_type == CorrelationType.SECRET_MATCH]
        self.assertGreater(len(secret_matches), 0)
        
        # Should be CRITICAL severity
        self.assertEqual(secret_matches[0].severity, CorrelationSeverity.CRITICAL)
        
        # Should have high confidence
        self.assertGreaterEqual(secret_matches[0].confidence, 0.9)
    
    def test_behavioral_correlation(self):
        """Test behavioral correlation (drift + code risk) with git-diff mode data"""
        secret_value = "deploy_key_abc123"

        violations = [
            SecurityViolation(
                violation_type=ViolationType.COMMAND_INJECTION,
                severity=Severity.CRITICAL,
                location=CodeLocation(
                    file_path="deploy.py",
                    line_start=100,
                    line_end=100
                ),
                message="Command injection"
            )
        ]
        
        secrets = [
            Secret(
                value=secret_value,
                secret_type="api_key",
                entropy=4.2,
                files=["deploy.py"],
                lines=[100]
            )
        ]
        
        # Use _sid() to produce the same hash the git-diff detector would
        drifts = [
            GitDriftDetection(
                secret_id=_sid(secret_value),
                run_id="test_run",
                timestamp=datetime.now(),
                drift_type="ADDED",
                severity="HIGH",
                is_drifted=True,
                total_drift_score=5.0,
                anomaly_details={"type": "ADDED", "files": ["deploy.py"]},
                recommendation="Review access"
            )
        ]
        
        report = run_csce(violations, sdda_drifts=drifts, slga_secrets=secrets)
        
        # Should find BEHAVIORAL correlation
        behavioral = [c for c in report.correlations if c.correlation_type == CorrelationType.BEHAVIORAL]
        self.assertGreater(len(behavioral), 0)
        
        # Should be high/critical severity
        self.assertIn(behavioral[0].severity.value, ['HIGH', 'CRITICAL'])

    def test_behavioral_correlation_mode1(self):
        """Test behavioral correlation with baseline-mode DriftDetection (direct value match)"""
        violations = [
            SecurityViolation(
                violation_type=ViolationType.COMMAND_INJECTION,
                severity=Severity.HIGH,
                location=CodeLocation(file_path="app.py", line_start=10, line_end=10),
                message="injection"
            )
        ]
        secrets = [
            Secret(value="my_api_key", secret_type="api_key", entropy=4.0, files=["app.py"], lines=[10])
        ]
        drifts = [
            DriftDetection(
                secret_id="my_api_key",
                run_id="run1",
                timestamp=datetime.now(),
                severity="HIGH",
                is_drifted=True,
                total_drift_score=4.0,
                anomaly_details=["New actor detected"],
                recommendation="Review"
            )
        ]
        report = run_csce(violations, sdda_drifts=drifts, slga_secrets=secrets)
        behavioral = [c for c in report.correlations if c.correlation_type == CorrelationType.BEHAVIORAL]
        self.assertGreater(len(behavioral), 0)

    def test_propagation_correlation(self):
        """Test propagation correlation with a mock Neo4j graph"""
        violations = [
            SecurityViolation(
                violation_type=ViolationType.SENSITIVE_LOGGING,
                severity=Severity.HIGH,
                location=CodeLocation(file_path="app.py", line_start=20, line_end=20),
                message="Logging secret"
            )
        ]
        secrets = [
            Secret(value="prop_secret", secret_type="api_key", entropy=4.5, files=["app.py"], lines=[20])
        ]

        # Mock graph returning the real analyze_secret_propagation format
        mock_graph = MagicMock()
        mock_graph.analyze_secret_propagation.return_value = {
            'secret_value': 'prop_secret',
            'propagation_scope': {
                'files': 3,
                'commits': 5,
                'stages': 2,
                'logs': 1,
                'artifacts': 0,
            },
            'file_paths': ['app.py', 'lib.py', 'util.py'],
            'stage_names': ['build', 'deploy'],
            'log_paths': ['ci.log'],
            'artifact_paths': [],
            'risk_score': 55,
            'severity': 'HIGH',
            'risk_factors': ['Moderate file spread: 3 files', 'EXPOSED in logs: 1 log file(s)'],
        }

        report = run_csce(violations, slga_secrets=secrets, neo4j_graph=mock_graph)

        propagation = [c for c in report.correlations if c.correlation_type == CorrelationType.PROPAGATION]
        self.assertGreater(len(propagation), 0)
        self.assertEqual(propagation[0].severity, CorrelationSeverity.HIGH)
        self.assertGreaterEqual(propagation[0].confidence, 0.9)
    
    def test_no_correlations(self):
        """Test when there are no correlations"""
        violations = [
            SecurityViolation(
                violation_type=ViolationType.WEAK_CRYPTO,
                severity=Severity.MEDIUM,
                location=CodeLocation(
                    file_path="crypto.py",
                    line_start=50,
                    line_end=50
                ),
                message="Weak crypto"
            )
        ]
        
        secrets = [
            Secret(
                value="different_secret",
                secret_type="password",
                entropy=4.0,
                files=["different_file.py"],
                lines=[20]
            )
        ]
        
        report = run_csce(violations, slga_secrets=secrets)
        
        # Should find no correlations (different files, no match)
        self.assertEqual(report.total_correlations, 0)
    
    def test_report_statistics(self):
        """Test report statistics calculation"""
        violations = [
            SecurityViolation(
                violation_type=ViolationType.HARDCODED_SECRET,
                severity=Severity.CRITICAL,
                location=CodeLocation(file_path="test.py", line_start=1, line_end=1),
                message="Test"
            )
        ]
        
        secrets = [
            Secret(value="secret", secret_type="key", entropy=4.0, files=["test.py"], lines=[1])
        ]
        
        report = run_csce(violations, slga_secrets=secrets)
        
        # Check statistics
        self.assertGreaterEqual(report.avg_confidence, 0.0)
        self.assertLessEqual(report.avg_confidence, 1.0)
        self.assertIsInstance(report.top_priorities, list)
    
    def test_severity_amplification(self):
        """Test that severity is amplified when multiple high signals combine"""
        secret_value = "key_for_amplification_test"

        violations = [
            SecurityViolation(
                violation_type=ViolationType.COMMAND_INJECTION,
                severity=Severity.CRITICAL,
                location=CodeLocation(file_path="app.py", line_start=10, line_end=10),
                message="Critical violation"
            )
        ]
        
        secrets = [
            Secret(value=secret_value, secret_type="api_key", entropy=4.5, files=["app.py"], lines=[10])
        ]
        
        drifts = [
            GitDriftDetection(
                secret_id=_sid(secret_value),
                run_id="test_run",
                timestamp=datetime.now(),
                drift_type="ADDED",
                severity="CRITICAL",
                is_drifted=True,
                total_drift_score=100.0,
                anomaly_details={"type": "ADDED", "files": ["app.py"], "note": "Secret used in PRODUCTION for first time"},
                recommendation="Immediate action"
            )
        ]
        
        report = run_csce(violations, sdda_drifts=drifts, slga_secrets=secrets)
        
        # Should have at least one CRITICAL correlation
        critical_count = sum(1 for c in report.correlations if c.severity == CorrelationSeverity.CRITICAL)
        self.assertGreater(critical_count, 0)

if __name__ == '__main__':
    unittest.main()
