"""
Unit tests for SDDA - Secret Drift Detection Algorithm
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

class TestSDDAModels(unittest.TestCase):
    """Test SDDA data models"""
    
    def test_pipeline_run_creation(self):
        run = PipelineRun(
            run_id="test-001",
            timestamp=datetime.now(),
            branch="main",
            environment="dev",
            actor="bot",
            secrets_used=["SECRET1"],
            stages=["build"]
        )
        self.assertEqual(run.run_id, "test-001")
        self.assertEqual(run.environment, "dev")
    
    def test_secret_usage_creation(self):
        usage = SecretUsage(
            secret_id="SECRET1",
            run_id="test-001",
            timestamp=datetime.now(),
            stages={"build", "test"},
            access_count=2,
            actor="bot",
            environment="dev",
            branch="main"
        )
        self.assertEqual(usage.secret_id, "SECRET1")
        self.assertEqual(len(usage.stages), 2)

class TestSDDADatabase(unittest.TestCase):
    """Test database operations"""
    
    def setUp(self):
        self.db_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.db_path = self.db_file.name
        self.db_file.close()
        self.db = SDDADatabase(self.db_path)
    
    def tearDown(self):
        self.db.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
    
    def test_store_and_retrieve_pipeline_run(self):
        run = PipelineRun(
            run_id="test-001",
            timestamp=datetime.now(),
            branch="main",
            environment="dev",
            actor="bot",
            secrets_used=["SECRET1"],
            stages=["build"]
        )
        self.db.store_pipeline_run(run)
        # Verify it was stored (manual query)
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT * FROM pipeline_runs WHERE run_id = ?", ("test-001",))
        row = cursor.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row['run_id'], "test-001")
    
    def test_store_and_retrieve_secret_usage(self):
        usage = SecretUsage(
            secret_id="SECRET1",
            run_id="test-001",
            timestamp=datetime.now(),
            stages={"build"},
            access_count=1,
            actor="bot",
            environment="dev",
            branch="main"
        )
        self.db.store_secret_usage(usage)
        
        usages = self.db.get_historical_usage("SECRET1", 30)
        self.assertEqual(len(usages), 1)
        self.assertEqual(usages[0].secret_id, "SECRET1")
    
    def test_get_historical_usage_with_window(self):
        # Add usage from 40 days ago
        old_usage = SecretUsage(
            secret_id="SECRET1",
            run_id="old-001",
            timestamp=datetime.now() - timedelta(days=40),
            stages={"build"},
            access_count=1,
            actor="bot",
            environment="dev",
            branch="main"
        )
        self.db.store_secret_usage(old_usage)
        
        # Add usage from 10 days ago
        recent_usage = SecretUsage(
            secret_id="SECRET1",
            run_id="recent-001",
            timestamp=datetime.now() - timedelta(days=10),
            stages={"build"},
            access_count=1,
            actor="bot",
            environment="dev",
            branch="main"
        )
        self.db.store_secret_usage(recent_usage)
        
        # Query with 30-day window
        usages = self.db.get_historical_usage("SECRET1", 30)
        self.assertEqual(len(usages), 1)  # Should only get recent one
        self.assertEqual(usages[0].run_id, "recent-001")

class TestBaselineManager(unittest.TestCase):
    """Test baseline management"""
    
    def setUp(self):
        self.db_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.db_path = self.db_file.name
        self.db_file.close()
        self.db = SDDADatabase(self.db_path)
        self.config = {
            'baseline_window_days': 30,
            'min_samples': 5
        }
        self.manager = BaselineManager(self.db, self.config)
    
    def tearDown(self):
        self.db.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
    
    def test_create_baseline_insufficient_data(self):
        # Add only 2 samples (below min_samples=5)
        for i in range(2):
            usage = SecretUsage(
                secret_id="SECRET1",
                run_id=f"run-{i}",
                timestamp=datetime.now() - timedelta(days=i),
                stages={"build"},
                access_count=2,
                actor="bot",
                environment="dev",
                branch="main"
            )
            self.db.store_secret_usage(usage)
        
        baseline = self.manager.create_baseline("SECRET1")
        self.assertIsNone(baseline)
    
    def test_create_baseline_sufficient_data(self):
        # Add 10 samples
        for i in range(10):
            usage = SecretUsage(
                secret_id="SECRET1",
                run_id=f"run-{i}",
                timestamp=datetime.now() - timedelta(days=i),
                stages={"build", "test"},
                access_count=2,
                actor="bot",
                environment="dev",
                branch="main"
            )
            self.db.store_secret_usage(usage)
        
        baseline = self.manager.create_baseline("SECRET1")
        self.assertIsNotNone(baseline)
        self.assertEqual(baseline.secret_id, "SECRET1")
        self.assertEqual(baseline.sample_count, 10)
        self.assertIn("build", baseline.normal_stages)
        self.assertIn("test", baseline.normal_stages)
    
    def test_behavioral_features_extraction(self):
        usages = [
            SecretUsage(
                secret_id="SECRET1",
                run_id="run-1",
                timestamp=datetime.now(),
                stages={"build"},
                access_count=2,
                actor="bot",
                environment="dev",
                branch="main"
            ),
            SecretUsage(
                secret_id="SECRET1",
                run_id="run-2",
                timestamp=datetime.now() - timedelta(days=1),
                stages={"build", "test"},
                access_count=3,
                actor="bot",
                environment="staging",
                branch="main"
            )
        ]
        
        features = self.manager.compute_behavioral_features(usages)
        self.assertEqual(features.secret_id, "SECRET1")
        self.assertIn("build", features.stages_used)
        self.assertIn("test", features.stages_used)
        self.assertIn("bot", features.actors)
        self.assertEqual(features.total_runs, 2)

class TestDriftDetector(unittest.TestCase):
    """Test drift detection"""
    
    def setUp(self):
        self.db_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.db_path = self.db_file.name
        self.db_file.close()
        self.db = SDDADatabase(self.db_path)
        self.config = {
            'baseline_window_days': 30,
            'min_samples': 5,
            'zscore_threshold': 3.0
        }
        self.manager = BaselineManager(self.db, self.config)
        self.detector = DriftDetector(self.manager, self.config)
        
        # Create baseline data
        for i in range(20):
            usage = SecretUsage(
                secret_id="SECRET1",
                run_id=f"baseline-run-{i}",
                timestamp=datetime.now() - timedelta(days=20-i),
                stages={"build", "test"},
                access_count=2,
                actor="bot",
                environment="dev",
                branch="main"
            )
            self.db.store_secret_usage(usage)
        
        # Create baseline
        baseline = self.manager.create_baseline("SECRET1")
        self.db.store_baseline(baseline)
    
    def tearDown(self):
        self.db.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
    
    def test_no_drift_normal_usage(self):
        # Normal usage matching baseline
        usage = SecretUsage(
            secret_id="SECRET1",
            run_id="current-run",
            timestamp=datetime.now(),
            stages={"build", "test"},
            access_count=2,
            actor="bot",
            environment="dev",
            branch="main"
        )
        
        detection = self.detector.detect_drift(usage)
        # Should return None or have is_drifted=False
        if detection:
            self.assertFalse(detection.is_drifted)
    
    def test_stage_drift_new_stage(self):
        # Usage with new stage
        usage = SecretUsage(
            secret_id="SECRET1",
            run_id="drift-run",
            timestamp=datetime.now(),
            stages={"build", "test", "deploy"},  # deploy is new
            access_count=2,
            actor="bot",
            environment="dev",
            branch="main"
        )
        
        detection = self.detector.detect_drift(usage)
        self.assertIsNotNone(detection)
        self.assertTrue(detection.is_drifted)
        self.assertTrue(detection.stage_drift.is_anomaly)
    
    def test_frequency_drift_spike(self):
        # Usage with unusual frequency
        usage = SecretUsage(
            secret_id="SECRET1",
            run_id="drift-run",
            timestamp=datetime.now(),
            stages={"build", "test"},
            access_count=20,  # Much higher than baseline (2)
            actor="bot",
            environment="dev",
            branch="main"
        )
        
        detection = self.detector.detect_drift(usage)
        self.assertIsNotNone(detection)
        self.assertTrue(detection.is_drifted)
        self.assertTrue(detection.frequency_drift.is_anomaly)
    
    def test_actor_drift_new_actor(self):
        # Usage by new actor
        usage = SecretUsage(
            secret_id="SECRET1",
            run_id="drift-run",
            timestamp=datetime.now(),
            stages={"build", "test"},
            access_count=2,
            actor="new-user@example.com",  # New actor
            environment="dev",
            branch="main"
        )
        
        detection = self.detector.detect_drift(usage)
        self.assertIsNotNone(detection)
        self.assertTrue(detection.is_drifted)
        self.assertTrue(detection.actor_drift.is_anomaly)
    
    def test_environment_drift_production(self):
        # Usage in production (new environment)
        usage = SecretUsage(
            secret_id="SECRET1",
            run_id="drift-run",
            timestamp=datetime.now(),
            stages={"build", "test"},
            access_count=2,
            actor="bot",
            environment="production",  # New environment
            branch="main"
        )
        
        detection = self.detector.detect_drift(usage)
        self.assertIsNotNone(detection)
        self.assertTrue(detection.is_drifted)
        self.assertTrue(detection.environment_drift.is_anomaly)
        self.assertEqual(detection.severity, "CRITICAL")  # Production should be critical

class TestSDDAIntegration(unittest.TestCase):
    """Integration tests for complete SDDA workflow"""
    
    def setUp(self):
        self.db_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.db_path = self.db_file.name
        self.db_file.close()
    
    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
    
    def test_full_workflow(self):
        # Generate baseline data
        for i in range(25):
            run = PipelineRun(
                run_id=f"baseline-{i}",
                timestamp=datetime.now() - timedelta(days=25-i),
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
                stages={"build", "test"},
                access_count=2,
                actor="bot",
                environment="dev",
                branch="main"
            )
            run_sdda(run, [usage], db_path=self.db_path)
        
        # Rebuild baselines
        count = rebuild_baselines(db_path=self.db_path)
        self.assertGreater(count, 0)
        
        # Test normal run (no drift)
        normal_run = PipelineRun(
            run_id="normal",
            timestamp=datetime.now(),
            branch="main",
            environment="dev",
            actor="bot",
            secrets_used=["SECRET1"],
            stages=["build", "test"]
        )
        normal_usage = SecretUsage(
            secret_id="SECRET1",
            run_id="normal",
            timestamp=datetime.now(),
            stages={"build", "test"},
            access_count=2,
            actor="bot",
            environment="dev",
            branch="main"
        )
        report = run_sdda(normal_run, [normal_usage], db_path=self.db_path)
        self.assertEqual(len(report.drifted_secrets), 0)
        
        # Test drift run
        drift_run = PipelineRun(
            run_id="drift",
            timestamp=datetime.now(),
            branch="main",
            environment="production",
            actor="bot",
            secrets_used=["SECRET1"],
            stages=["build", "test", "deploy"]
        )
        drift_usage = SecretUsage(
            secret_id="SECRET1",
            run_id="drift",
            timestamp=datetime.now(),
            stages={"build", "test", "deploy"},
            access_count=2,
            actor="bot",
            environment="production",
            branch="main"
        )
        report = run_sdda(drift_run, [drift_usage], db_path=self.db_path)
        self.assertGreater(len(report.drifted_secrets), 0)
        
        # Analyze secret
        analysis = analyze_secret("SECRET1", db_path=self.db_path)
        self.assertEqual(analysis['secret_id'], "SECRET1")
        self.assertGreater(analysis['total_runs'], 20)

if __name__ == '__main__':
    unittest.main()
