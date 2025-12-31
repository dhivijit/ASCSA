# Tests for branch comparison feature
import pytest
from datetime import datetime, timedelta
from engines.sdda.models import SecretUsage, Baseline
from engines.sdda.comparators import compare_branches
from engines.sdda.database import SDDADatabase
from engines.sdda.baseline_manager import BaselineManager
from engines.sdda.drift_detector import DriftDetector
import tempfile
import os


class TestBranchComparison:
    """Test branch drift detection"""
    
    def test_compare_branches_expected_branch(self):
        """Should not flag drift for known branches"""
        baseline = Baseline(
            secret_id="test_secret",
            window_days=30,
            normal_branches={'main', 'develop', 'feature/auth'},
            branch_mean=1.5,
            branch_std=0.5
        )
        
        drift = compare_branches('main', baseline, threshold=3.0)
        
        assert drift.feature_name == "branch"
        assert not drift.is_anomaly
        assert "Expected branch" in drift.details
    
    def test_compare_branches_new_branch(self):
        """Should flag drift for new branches"""
        baseline = Baseline(
            secret_id="test_secret",
            window_days=30,
            normal_branches={'main', 'develop'},
            branch_mean=1.0,
            branch_std=0.3
        )
        
        drift = compare_branches('feature/new-feature', baseline, threshold=3.0)
        
        assert drift.is_anomaly
        assert "New branch detected" in drift.details
        assert drift.z_score > 3.0
    
    def test_compare_branches_suspicious_pattern(self):
        """Should flag suspicious branch names with higher severity"""
        baseline = Baseline(
            secret_id="test_secret",
            window_days=30,
            normal_branches={'main', 'develop'},
            branch_mean=1.0,
            branch_std=0.3
        )
        
        # Test suspicious branch names
        suspicious_branches = ['temp-access', 'test-bypass', 'hack-attempt', 'bypass-security']
        
        for branch in suspicious_branches:
            drift = compare_branches(branch, baseline, threshold=3.0)
            
            assert drift.is_anomaly
            assert "SUSPICIOUS" in drift.details
            assert drift.z_score >= 4.5  # Higher than threshold + 1.5


class TestBranchBaselineCreation:
    """Test that baselines correctly track branch statistics"""
    
    def setup_method(self):
        """Create temp database for each test"""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_branch.db")
        # Disable encryption for tests
        os.environ['SDDA_ENCRYPTION_ENABLED'] = 'false'
        os.environ['SDDA_AUDIT_ENABLED'] = 'false'
        self.db = SDDADatabase(self.db_path)
        self.config = {
            'baseline_window_days': 7,
            'min_samples': 3,
            'zscore_threshold': 3.0
        }
        self.baseline_manager = BaselineManager(self.db, self.config)
    
    def teardown_method(self):
        """Cleanup"""
        self.db.close()
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_baseline_captures_branch_patterns(self):
        """Baseline should capture branch usage patterns"""
        # Add usage data from multiple branches
        for i in range(10):
            usage = SecretUsage(
                secret_id="SECRET_1",
                run_id=f"run_{i}",
                timestamp=datetime.now() - timedelta(days=i % 5),
                stages={'build'},
                access_count=1,
                actor="ci-bot",
                environment="dev",
                branch='main' if i < 7 else 'develop'  # 70% main, 30% develop
            )
            self.db.store_secret_usage(usage)
        
        baseline = self.baseline_manager.create_baseline("SECRET_1")
        
        assert baseline is not None
        assert 'main' in baseline.normal_branches
        assert 'develop' in baseline.normal_branches
        assert baseline.branch_mean > 0
        assert baseline.branch_std >= 0
    
    def test_baseline_with_single_branch(self):
        """Baseline should handle single branch usage"""
        # Add usage data from only one branch
        for i in range(5):
            usage = SecretUsage(
                secret_id="SECRET_2",
                run_id=f"run_{i}",
                timestamp=datetime.now() - timedelta(days=i),
                stages={'build'},
                access_count=1,
                actor="ci-bot",
                environment="dev",
                branch='main'
            )
            self.db.store_secret_usage(usage)
        
        baseline = self.baseline_manager.create_baseline("SECRET_2")
        
        assert baseline is not None
        assert baseline.normal_branches == {'main'}
        assert baseline.branch_std == 0.0  # No variance


class TestBranchDriftDetection:
    """Test end-to-end branch drift detection"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_drift.db")
        os.environ['SDDA_ENCRYPTION_ENABLED'] = 'false'
        os.environ['SDDA_AUDIT_ENABLED'] = 'false'
        self.db = SDDADatabase(self.db_path)
        self.config = {
            'baseline_window_days': 7,
            'min_samples': 3,
            'zscore_threshold': 3.0
        }
        self.baseline_manager = BaselineManager(self.db, self.config)
        self.detector = DriftDetector(self.baseline_manager, self.config)
    
    def teardown_method(self):
        """Cleanup"""
        self.db.close()
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_detect_branch_drift_new_branch(self):
        """Should detect drift when secret accessed from new branch"""
        # Establish baseline with main/develop branches
        for i in range(5):
            usage = SecretUsage(
                secret_id="API_KEY",
                run_id=f"run_{i}",
                timestamp=datetime.now() - timedelta(days=5-i),
                stages={'deploy'},
                access_count=1,
                actor="ci-bot",
                environment="staging",
                branch='main' if i % 2 == 0 else 'develop'
            )
            self.db.store_secret_usage(usage)
        
        # Now access from new branch
        new_usage = SecretUsage(
            secret_id="API_KEY",
            run_id="run_new",
            timestamp=datetime.now(),
            stages={'deploy'},
            access_count=1,
            actor="ci-bot",
            environment="staging",
            branch='feature/suspicious'
        )
        
        detection = self.detector.detect_drift(new_usage)
        
        assert detection is not None
        assert detection.is_drifted
        assert detection.branch_drift is not None
        assert detection.branch_drift.is_anomaly
        assert 'branch' in detection.recommendation.lower()
    
    def test_no_drift_expected_branch(self):
        """Should not detect drift for expected branches"""
        # Establish baseline
        for i in range(5):
            usage = SecretUsage(
                secret_id="DB_PASS",
                run_id=f"run_{i}",
                timestamp=datetime.now() - timedelta(days=5-i),
                stages={'build'},
                access_count=1,
                actor="ci-bot",
                environment="dev",
                branch='main'
            )
            self.db.store_secret_usage(usage)
        
        # Access from same branch
        normal_usage = SecretUsage(
            secret_id="DB_PASS",
            run_id="run_new",
            timestamp=datetime.now(),
            stages={'build'},
            access_count=1,
            actor="ci-bot",
            environment="dev",
            branch='main'
        )
        
        detection = self.detector.detect_drift(normal_usage)
        
        # Should return None or no branch drift
        if detection:
            assert not detection.branch_drift.is_anomaly
    
    def test_suspicious_branch_triggers_alert(self):
        """Should detect and flag suspicious branch patterns"""
        # Establish baseline
        for i in range(5):
            usage = SecretUsage(
                secret_id="PROD_KEY",
                run_id=f"run_{i}",
                timestamp=datetime.now() - timedelta(days=5-i),
                stages={'deploy'},
                access_count=1,
                actor="deploy-bot",
                environment="production",
                branch='release/v1.0'
            )
            self.db.store_secret_usage(usage)
        
        # Access from suspicious branch
        suspicious_usage = SecretUsage(
            secret_id="PROD_KEY",
            run_id="run_suspicious",
            timestamp=datetime.now(),
            stages={'deploy'},
            access_count=1,
            actor="unknown",
            environment="production",
            branch='temp-bypass'
        )
        
        detection = self.detector.detect_drift(suspicious_usage)
        
        assert detection is not None
        assert detection.is_drifted
        assert detection.branch_drift.is_anomaly
        assert "SUSPICIOUS" in detection.branch_drift.details
        assert detection.severity in ["HIGH", "CRITICAL"]


class TestBranchEdgeCases:
    """Test edge cases for branch comparison"""
    
    def test_empty_branch_name(self):
        """Should handle empty branch names gracefully"""
        baseline = Baseline(
            secret_id="test",
            window_days=30,
            normal_branches={'main'},
            branch_mean=1.0,
            branch_std=0.0
        )
        
        drift = compare_branches('', baseline, threshold=3.0)
        
        # Empty branch should be considered new
        assert drift.is_anomaly
    
    def test_very_long_branch_name(self):
        """Should handle long branch names"""
        baseline = Baseline(
            secret_id="test",
            window_days=30,
            normal_branches={'main'},
            branch_mean=1.0,
            branch_std=0.0
        )
        
        long_branch = 'feature/' + 'x' * 200
        drift = compare_branches(long_branch, baseline, threshold=3.0)
        
        assert drift.is_anomaly
    
    def test_branch_with_special_characters(self):
        """Should handle branches with special characters"""
        baseline = Baseline(
            secret_id="test",
            window_days=30,
            normal_branches={'feature/JIRA-123', 'hotfix/2.1.0'},
            branch_mean=1.0,
            branch_std=0.0
        )
        
        # Should not flag known branches with special chars
        drift = compare_branches('feature/JIRA-123', baseline, threshold=3.0)
        assert not drift.is_anomaly
        
        # Should flag unknown branches
        drift = compare_branches('feature/JIRA-999', baseline, threshold=3.0)
        assert drift.is_anomaly


if __name__ == "__main__":
    pytest.main([__file__, '-v'])
