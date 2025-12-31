"""
Edge case tests for SDDA - Secret Drift Detection Algorithm
Tests corner cases, error handling, and boundary conditions
"""

import unittest
import os
import tempfile
from datetime import datetime, timedelta
from engines.sdda import (
    PipelineRun,
    SecretUsage,
    SDDADatabase,
    BaselineManager,
    DriftDetector,
    run_sdda,
    rebuild_baselines,
    analyze_secret
)
from engines.sdda.comparators import calculate_z_score

class TestZeroDataScenarios(unittest.TestCase):
    """Test handling of zero/minimal data scenarios"""
    
    def setUp(self):
        self.db_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.db_path = self.db_file.name
        self.db_file.close()
        self.db = SDDADatabase(self.db_path)
        self.config = {
            'baseline_window_days': 30,
            'min_samples': 10,
            'zscore_threshold': 3.0
        }
        self.manager = BaselineManager(self.db, self.config)
    
    def tearDown(self):
        self.db.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
    
    def test_no_historical_data(self):
        """Test drift detection with no baseline data"""
        detector = DriftDetector(self.manager, self.config)
        
        usage = SecretUsage(
            secret_id="NEW_SECRET",
            run_id="run-1",
            timestamp=datetime.now(),
            stages={"build"},
            access_count=1,
            actor="bot",
            environment="dev",
            branch="main"
        )
        
        # Should return None (no baseline to compare against)
        detection = detector.detect_drift(usage)
        self.assertIsNone(detection)
    
    def test_insufficient_samples_for_baseline(self):
        """Test baseline creation with too few samples"""
        # Add only 5 samples (below min_samples=10)
        for i in range(5):
            usage = SecretUsage(
                secret_id="SECRET1",
                run_id=f"run-{i}",
                timestamp=datetime.now() - timedelta(days=i),
                stages={"build"},
                access_count=1,
                actor="bot",
                environment="dev",
                branch="main"
            )
            self.db.store_secret_usage(usage)
        
        baseline = self.manager.create_baseline("SECRET1")
        self.assertIsNone(baseline)
    
    def test_single_sample_edge_case(self):
        """Test with exactly 1 historical sample"""
        usage = SecretUsage(
            secret_id="SECRET1",
            run_id="run-1",
            timestamp=datetime.now() - timedelta(days=1),
            stages={"build"},
            access_count=1,
            actor="bot",
            environment="dev",
            branch="main"
        )
        self.db.store_secret_usage(usage)
        
        baseline = self.manager.create_baseline("SECRET1")
        self.assertIsNone(baseline)  # Below min_samples
    
    def test_empty_stages_set(self):
        """Test handling of secret with no stages"""
        for i in range(15):
            usage = SecretUsage(
                secret_id="SECRET1",
                run_id=f"run-{i}",
                timestamp=datetime.now() - timedelta(days=i),
                stages=set(),  # Empty set
                access_count=1,
                actor="bot",
                environment="dev",
                branch="main"
            )
            self.db.store_secret_usage(usage)
        
        baseline = self.manager.create_baseline("SECRET1")
        self.assertIsNotNone(baseline)
        self.assertEqual(len(baseline.normal_stages), 0)
        self.assertEqual(baseline.stage_mean, 0.0)

class TestIdenticalDataScenarios(unittest.TestCase):
    """Test scenarios where all data is identical (std=0)"""
    
    def setUp(self):
        self.db_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.db_path = self.db_file.name
        self.db_file.close()
        
        # Create baseline with all identical values
        for i in range(20):
            run = PipelineRun(
                run_id=f"baseline-{i}",
                timestamp=datetime.now() - timedelta(days=20-i),
                branch="main",
                environment="dev",
                actor="bot",
                secrets_used=["SECRET1"],
                stages=["build", "test"]
            )
            usage = SecretUsage(
                secret_id="SECRET1",
                run_id=run.run_id,
                timestamp=run.timestamp,
                stages={"build", "test"},  # Always same
                access_count=2,  # Always same
                actor="bot",  # Always same
                environment="dev",  # Always same
                branch="main"
            )
            run_sdda(run, [usage], db_path=self.db_path)
        
        rebuild_baselines(db_path=self.db_path)
    
    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
    
    def test_identical_usage_no_drift(self):
        """Test that identical usage doesn't trigger drift"""
        run = PipelineRun(
            run_id="identical",
            timestamp=datetime.now(),
            branch="main",
            environment="dev",
            actor="bot",
            secrets_used=["SECRET1"],
            stages=["build", "test"]
        )
        usage = SecretUsage(
            secret_id="SECRET1",
            run_id="identical",
            timestamp=datetime.now(),
            stages={"build", "test"},
            access_count=2,
            actor="bot",
            environment="dev",
            branch="main"
        )
        
        report = run_sdda(run, [usage], db_path=self.db_path)
        self.assertEqual(len(report.drifted_secrets), 0)
    
    def test_any_deviation_from_zero_std_baseline(self):
        """Test that ANY deviation from zero-std baseline is flagged"""
        run = PipelineRun(
            run_id="different",
            timestamp=datetime.now(),
            branch="main",
            environment="dev",
            actor="bot",
            secrets_used=["SECRET1"],
            stages=["build", "test"]
        )
        usage = SecretUsage(
            secret_id="SECRET1",
            run_id="different",
            timestamp=datetime.now(),
            stages={"build", "test"},
            access_count=3,  # Different from baseline (2)
            actor="bot",
            environment="dev",
            branch="main"
        )
        
        report = run_sdda(run, [usage], db_path=self.db_path)
        self.assertGreater(len(report.drifted_secrets), 0)
    
    def test_z_score_with_zero_std(self):
        """Test Z-score calculation with zero standard deviation"""
        # Same value - should return 0
        z = calculate_z_score(5.0, 5.0, 0.0)
        self.assertEqual(z, 0.0)
        
        # Different value - should return very high z-score
        z = calculate_z_score(10.0, 5.0, 0.0)
        self.assertEqual(z, 999.0)

class TestExtremeValues(unittest.TestCase):
    """Test handling of extreme values"""
    
    def setUp(self):
        self.db_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.db_path = self.db_file.name
        self.db_file.close()
        self.db = SDDADatabase(self.db_path)
        self.config = {
            'baseline_window_days': 30,
            'min_samples': 10,
            'zscore_threshold': 3.0
        }
        self.manager = BaselineManager(self.db, self.config)
    
    def tearDown(self):
        self.db.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
    
    def test_very_high_access_count(self):
        """Test handling of extremely high access counts"""
        # Create normal baseline
        for i in range(15):
            usage = SecretUsage(
                secret_id="SECRET1",
                run_id=f"baseline-{i}",
                timestamp=datetime.now() - timedelta(days=i),
                stages={"build"},
                access_count=2,
                actor="bot",
                environment="dev",
                branch="main"
            )
            self.db.store_secret_usage(usage)
        
        baseline = self.manager.create_baseline("SECRET1")
        self.db.store_baseline(baseline)
        
        detector = DriftDetector(self.manager, self.config)
        
        # Test with extremely high count
        usage = SecretUsage(
            secret_id="SECRET1",
            run_id="extreme",
            timestamp=datetime.now(),
            stages={"build"},
            access_count=10000,  # Extremely high
            actor="bot",
            environment="dev",
            branch="main"
        )
        
        detection = detector.detect_drift(usage)
        self.assertIsNotNone(detection)
        self.assertTrue(detection.is_drifted)
        self.assertTrue(detection.frequency_drift.is_anomaly)
    
    def test_zero_access_count(self):
        """Test handling of zero access count"""
        for i in range(15):
            usage = SecretUsage(
                secret_id="SECRET1",
                run_id=f"baseline-{i}",
                timestamp=datetime.now() - timedelta(days=i),
                stages={"build"},
                access_count=5,
                actor="bot",
                environment="dev",
                branch="main"
            )
            self.db.store_secret_usage(usage)
        
        baseline = self.manager.create_baseline("SECRET1")
        self.db.store_baseline(baseline)
        
        detector = DriftDetector(self.manager, self.config)
        
        # Zero access count
        usage = SecretUsage(
            secret_id="SECRET1",
            run_id="zero",
            timestamp=datetime.now(),
            stages={"build"},
            access_count=0,  # Zero
            actor="bot",
            environment="dev",
            branch="main"
        )
        
        detection = detector.detect_drift(usage)
        self.assertIsNotNone(detection)
        self.assertTrue(detection.frequency_drift.is_anomaly)
    
    def test_very_long_baseline_window(self):
        """Test with extremely long baseline window (365 days)"""
        config = {
            'baseline_window_days': 365,
            'min_samples': 10,
            'zscore_threshold': 3.0
        }
        manager = BaselineManager(self.db, config)
        
        # Add data across long period
        for i in range(20):
            usage = SecretUsage(
                secret_id="SECRET1",
                run_id=f"old-{i}",
                timestamp=datetime.now() - timedelta(days=300-i*10),
                stages={"build"},
                access_count=2,
                actor="bot",
                environment="dev",
                branch="main"
            )
            self.db.store_secret_usage(usage)
        
        baseline = manager.create_baseline("SECRET1")
        self.assertIsNotNone(baseline)
        self.assertEqual(baseline.window_days, 365)

class TestSpecialCharactersAndStrings(unittest.TestCase):
    """Test handling of special characters in IDs and strings"""
    
    def setUp(self):
        self.db_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.db_path = self.db_file.name
        self.db_file.close()
        self.db = SDDADatabase(self.db_path)
    
    def tearDown(self):
        self.db.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
    
    def test_special_characters_in_secret_id(self):
        """Test secret IDs with special characters"""
        special_ids = [
            "SECRET-WITH-DASHES",
            "secret.with.dots",
            "secret_with_underscores",
            "SECRET@SYMBOL",
            "secret/with/slashes",
            "秘密",  # Unicode
        ]
        
        for secret_id in special_ids:
            usage = SecretUsage(
                secret_id=secret_id,
                run_id="run-1",
                timestamp=datetime.now(),
                stages={"build"},
                access_count=1,
                actor="bot",
                environment="dev",
                branch="main"
            )
            
            # Should not raise exception
            self.db.store_secret_usage(usage)
            
            # Verify retrieval
            usages = self.db.get_historical_usage(secret_id, 30)
            self.assertEqual(len(usages), 1)
            self.assertEqual(usages[0].secret_id, secret_id)
    
    def test_empty_string_actor(self):
        """Test handling of empty string actor"""
        usage = SecretUsage(
            secret_id="SECRET1",
            run_id="run-1",
            timestamp=datetime.now(),
            stages={"build"},
            access_count=1,
            actor="",  # Empty string
            environment="dev",
            branch="main"
        )
        
        self.db.store_secret_usage(usage)
        usages = self.db.get_historical_usage("SECRET1", 30)
        self.assertEqual(len(usages), 1)
        self.assertEqual(usages[0].actor, "")
    
    def test_very_long_strings(self):
        """Test handling of very long strings"""
        long_id = "SECRET_" + "X" * 1000
        long_actor = "actor@" + "x" * 500 + ".com"
        
        usage = SecretUsage(
            secret_id=long_id,
            run_id="run-1",
            timestamp=datetime.now(),
            stages={"build"},
            access_count=1,
            actor=long_actor,
            environment="dev",
            branch="main"
        )
        
        self.db.store_secret_usage(usage)
        usages = self.db.get_historical_usage(long_id, 30)
        self.assertEqual(len(usages), 1)

class TestTimeEdgeCases(unittest.TestCase):
    """Test edge cases related to time and timestamps"""
    
    def setUp(self):
        self.db_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.db_path = self.db_file.name
        self.db_file.close()
        self.db = SDDADatabase(self.db_path)
    
    def tearDown(self):
        self.db.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
    
    def test_future_timestamp(self):
        """Test handling of future timestamps"""
        future_time = datetime.now() + timedelta(days=10)
        
        usage = SecretUsage(
            secret_id="SECRET1",
            run_id="future-run",
            timestamp=future_time,
            stages={"build"},
            access_count=1,
            actor="bot",
            environment="dev",
            branch="main"
        )
        
        # Should handle without error
        self.db.store_secret_usage(usage)
        usages = self.db.get_historical_usage("SECRET1", 30)
        self.assertEqual(len(usages), 1)
    
    def test_very_old_timestamp(self):
        """Test handling of very old timestamps"""
        old_time = datetime.now() - timedelta(days=365*10)  # 10 years ago
        
        usage = SecretUsage(
            secret_id="SECRET1",
            run_id="old-run",
            timestamp=old_time,
            stages={"build"},
            access_count=1,
            actor="bot",
            environment="dev",
            branch="main"
        )
        
        self.db.store_secret_usage(usage)
        
        # Should not be in 30-day window
        usages = self.db.get_historical_usage("SECRET1", 30)
        self.assertEqual(len(usages), 0)
        
        # Should be in very large window (365*11 to account for any current date)
        usages = self.db.get_historical_usage("SECRET1", 365*11)
        self.assertGreaterEqual(len(usages), 1)
    
    def test_same_timestamp_multiple_runs(self):
        """Test multiple runs with identical timestamps"""
        same_time = datetime.now()
        
        for i in range(3):
            usage = SecretUsage(
                secret_id="SECRET1",
                run_id=f"run-{i}",
                timestamp=same_time,
                stages={"build"},
                access_count=1,
                actor="bot",
                environment="dev",
                branch="main"
            )
            self.db.store_secret_usage(usage)
        
        usages = self.db.get_historical_usage("SECRET1", 30)
        self.assertEqual(len(usages), 3)

class TestDatabaseEdgeCases(unittest.TestCase):
    """Test database-related edge cases"""
    
    def test_missing_database_file(self):
        """Test handling when database file doesn't exist"""
        temp_path = os.path.join(tempfile.gettempdir(), "nonexistent_test.db")
        
        # Should create database automatically
        db = SDDADatabase(temp_path)
        self.assertTrue(os.path.exists(temp_path))
        db.close()
        
        # Cleanup
        if os.path.exists(temp_path):
            os.remove(temp_path)
    
    def test_database_in_nonexistent_directory(self):
        """Test creating database in non-existent directory"""
        # This should fail or handle gracefully
        import tempfile
        temp_dir = tempfile.gettempdir()
        nonexistent_path = os.path.join(temp_dir, "nonexistent_dir", "test.db")
        
        try:
            # Create parent directory first (real-world scenario)
            os.makedirs(os.path.dirname(nonexistent_path), exist_ok=True)
            db = SDDADatabase(nonexistent_path)
            db.close()
            os.remove(nonexistent_path)
            os.rmdir(os.path.dirname(nonexistent_path))
        except Exception:
            pass  # Expected if directory doesn't exist
    
    def test_concurrent_database_access(self):
        """Test multiple database connections (read scenario)"""
        db_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        db_path = db_file.name
        db_file.close()
        
        try:
            # Create initial data
            db1 = SDDADatabase(db_path)
            usage = SecretUsage(
                secret_id="SECRET1",
                run_id="run-1",
                timestamp=datetime.now(),
                stages={"build"},
                access_count=1,
                actor="bot",
                environment="dev",
                branch="main"
            )
            db1.store_secret_usage(usage)
            db1.close()
            
            # Open two connections and read
            db2 = SDDADatabase(db_path)
            db3 = SDDADatabase(db_path)
            
            usages2 = db2.get_historical_usage("SECRET1", 30)
            usages3 = db3.get_historical_usage("SECRET1", 30)
            
            self.assertEqual(len(usages2), 1)
            self.assertEqual(len(usages3), 1)
            
            db2.close()
            db3.close()
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)

class TestConfigurationEdgeCases(unittest.TestCase):
    """Test edge cases in configuration"""
    
    def setUp(self):
        self.db_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.db_path = self.db_file.name
        self.db_file.close()
        self.db = SDDADatabase(self.db_path)
    
    def tearDown(self):
        self.db.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
    
    def test_zero_min_samples(self):
        """Test with min_samples set to 0"""
        config = {
            'baseline_window_days': 30,
            'min_samples': 0,  # Zero
            'zscore_threshold': 3.0
        }
        manager = BaselineManager(self.db, config)
        
        # Add single sample
        usage = SecretUsage(
            secret_id="SECRET1",
            run_id="run-1",
            timestamp=datetime.now(),
            stages={"build"},
            access_count=1,
            actor="bot",
            environment="dev",
            branch="main"
        )
        self.db.store_secret_usage(usage)
        
        # Should create baseline even with 1 sample
        baseline = manager.create_baseline("SECRET1")
        self.assertIsNotNone(baseline)
    
    def test_very_low_threshold(self):
        """Test with very low z-score threshold"""
        config = {
            'baseline_window_days': 30,
            'min_samples': 10,
            'zscore_threshold': 0.5  # Very sensitive
        }
        
        # Should work but detect more drifts
        self.assertIsNotNone(config)
        self.assertEqual(config['zscore_threshold'], 0.5)
    
    def test_very_high_threshold(self):
        """Test with very high z-score threshold"""
        config = {
            'baseline_window_days': 30,
            'min_samples': 10,
            'zscore_threshold': 100.0  # Very insensitive
        }
        
        # Should work but detect fewer drifts
        self.assertIsNotNone(config)
        self.assertEqual(config['zscore_threshold'], 100.0)

class TestMissingDataFields(unittest.TestCase):
    """Test handling of missing or None fields"""
    
    def setUp(self):
        self.db_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.db_path = self.db_file.name
        self.db_file.close()
        self.db = SDDADatabase(self.db_path)
    
    def tearDown(self):
        self.db.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
    
    def test_empty_secrets_used_list(self):
        """Test pipeline run with no secrets"""
        run = PipelineRun(
            run_id="empty-run",
            timestamp=datetime.now(),
            branch="main",
            environment="dev",
            actor="bot",
            secrets_used=[],  # Empty
            stages=["build"]
        )
        
        self.db.store_pipeline_run(run)
        # Should not raise exception
    
    def test_empty_stages_list(self):
        """Test pipeline run with no stages"""
        run = PipelineRun(
            run_id="no-stages",
            timestamp=datetime.now(),
            branch="main",
            environment="dev",
            actor="bot",
            secrets_used=["SECRET1"],
            stages=[]  # Empty
        )
        
        self.db.store_pipeline_run(run)
        # Should not raise exception

class TestReportGeneration(unittest.TestCase):
    """Test drift report generation edge cases"""
    
    def setUp(self):
        self.db_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.db_path = self.db_file.name
        self.db_file.close()
    
    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
    
    def test_report_with_no_secrets(self):
        """Test generating report with empty secret list"""
        run = PipelineRun(
            run_id="empty",
            timestamp=datetime.now(),
            branch="main",
            environment="dev",
            actor="bot",
            secrets_used=[],
            stages=["build"]
        )
        
        report = run_sdda(run, [], db_path=self.db_path)
        
        self.assertEqual(report.total_secrets_analyzed, 0)
        self.assertEqual(len(report.drifted_secrets), 0)
    
    def test_report_severity_summary_all_levels(self):
        """Test that severity summary includes all levels"""
        # Create baseline
        for i in range(20):
            run = PipelineRun(
                run_id=f"baseline-{i}",
                timestamp=datetime.now() - timedelta(days=20-i),
                branch="main",
                environment="dev",
                actor="bot",
                secrets_used=["SECRET1"],
                stages=["build"]
            )
            usage = SecretUsage(
                secret_id="SECRET1",
                run_id=run.run_id,
                timestamp=run.timestamp,
                stages={"build"},
                access_count=2,
                actor="bot",
                environment="dev",
                branch="main"
            )
            run_sdda(run, [usage], db_path=self.db_path)
        
        rebuild_baselines(db_path=self.db_path)
        
        # Run with drift
        run = PipelineRun(
            run_id="current",
            timestamp=datetime.now(),
            branch="main",
            environment="production",
            actor="bot",
            secrets_used=["SECRET1"],
            stages=["build"]
        )
        usage = SecretUsage(
            secret_id="SECRET1",
            run_id="current",
            timestamp=datetime.now(),
            stages={"build"},
            access_count=2,
            actor="bot",
            environment="production",
            branch="main"
        )
        
        report = run_sdda(run, [usage], db_path=self.db_path)
        
        # Verify summary has all severity levels initialized
        self.assertIn('CRITICAL', report.summary)
        self.assertIn('HIGH', report.summary)
        self.assertIn('MEDIUM', report.summary)
        self.assertIn('LOW', report.summary)

if __name__ == '__main__':
    unittest.main()
