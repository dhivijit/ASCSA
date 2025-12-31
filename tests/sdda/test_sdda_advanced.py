"""
Advanced integration tests for SDDA - Secret Drift Detection Algorithm
Tests complex scenarios, multi-secret workflows, and real-world use cases
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

class TestAdvancedMultiSecretScenarios(unittest.TestCase):
    """Test scenarios with multiple secrets"""
    
    def setUp(self):
        self.db_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.db_path = self.db_file.name
        self.db_file.close()
        
        # Generate diverse baseline data for multiple secrets
        self._generate_baseline_data()
    
    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
    
    def _generate_baseline_data(self):
        """Generate baseline data for 3 different secrets with different patterns"""
        base_date = datetime.now() - timedelta(days=30)
        
        for i in range(30):
            run_date = base_date + timedelta(days=i)
            
            run = PipelineRun(
                run_id=f"baseline-{i}",
                timestamp=run_date,
                branch="main",
                environment="staging",
                actor="ci-bot",
                secrets_used=["DB_PASSWORD", "API_KEY", "SSH_KEY"],
                stages=["build", "test", "deploy"]
            )
            
            # DB_PASSWORD - stable usage
            db_usage = SecretUsage(
                secret_id="DB_PASSWORD",
                run_id=run.run_id,
                timestamp=run.timestamp,
                stages={"build", "test"},
                access_count=2,
                actor="ci-bot",
                environment="staging",
                branch="main"
            )
            
            # API_KEY - variable usage
            api_usage = SecretUsage(
                secret_id="API_KEY",
                run_id=run.run_id,
                timestamp=run.timestamp,
                stages={"test", "deploy"},
                access_count=i % 5 + 1,  # 1-5 varying
                actor="ci-bot",
                environment="staging",
                branch="main"
            )
            
            # SSH_KEY - occasional usage
            if i % 3 == 0:  # Only every 3rd run
                ssh_usage = SecretUsage(
                    secret_id="SSH_KEY",
                    run_id=run.run_id,
                    timestamp=run.timestamp,
                    stages={"deploy"},
                    access_count=1,
                    actor="ci-bot",
                    environment="staging",
                    branch="main"
                )
                run_sdda(run, [db_usage, api_usage, ssh_usage], db_path=self.db_path)
            else:
                run_sdda(run, [db_usage, api_usage], db_path=self.db_path)
        
        # Build baselines
        rebuild_baselines(db_path=self.db_path)
    
    def test_multiple_secrets_simultaneous_drift(self):
        """Test detecting drift in multiple secrets simultaneously"""
        run = PipelineRun(
            run_id="multi-drift",
            timestamp=datetime.now(),
            branch="main",
            environment="production",  # NEW env for all
            actor="ci-bot",
            secrets_used=["DB_PASSWORD", "API_KEY"],
            stages=["build", "test", "deploy"]
        )
        
        db_usage = SecretUsage(
            secret_id="DB_PASSWORD",
            run_id="multi-drift",
            timestamp=datetime.now(),
            stages={"build", "test", "deploy"},  # NEW stage
            access_count=2,
            actor="ci-bot",
            environment="production",
            branch="main"
        )
        
        api_usage = SecretUsage(
            secret_id="API_KEY",
            run_id="multi-drift",
            timestamp=datetime.now(),
            stages={"test", "deploy"},
            access_count=20,  # SPIKE
            actor="ci-bot",
            environment="production",
            branch="main"
        )
        
        report = run_sdda(run, [db_usage, api_usage], db_path=self.db_path)
        
        # Should detect drift in both secrets
        self.assertGreater(len(report.drifted_secrets), 0)
        
        # Check both secrets flagged
        drifted_ids = {d.secret_id for d in report.drifted_secrets}
        self.assertIn("DB_PASSWORD", drifted_ids)
        self.assertIn("API_KEY", drifted_ids)
        
        # Production should trigger CRITICAL for at least one
        severities = [d.severity for d in report.drifted_secrets]
        self.assertIn("CRITICAL", severities)
    
    def test_selective_drift_one_secret_normal_one_drifted(self):
        """Test when one secret drifts but another is normal"""
        run = PipelineRun(
            run_id="selective-drift",
            timestamp=datetime.now(),
            branch="main",
            environment="staging",
            actor="ci-bot",
            secrets_used=["DB_PASSWORD", "API_KEY"],
            stages=["build", "test"]
        )
        
        # DB_PASSWORD - normal
        db_usage = SecretUsage(
            secret_id="DB_PASSWORD",
            run_id="selective-drift",
            timestamp=datetime.now(),
            stages={"build", "test"},
            access_count=2,
            actor="ci-bot",
            environment="staging",
            branch="main"
        )
        
        # API_KEY - drifted (new actor)
        api_usage = SecretUsage(
            secret_id="API_KEY",
            run_id="selective-drift",
            timestamp=datetime.now(),
            stages={"test"},
            access_count=3,
            actor="malicious-actor@evil.com",  # NEW
            environment="staging",
            branch="main"
        )
        
        report = run_sdda(run, [db_usage, api_usage], db_path=self.db_path)
        
        # Should detect drift only in API_KEY
        self.assertEqual(len(report.drifted_secrets), 1)
        self.assertEqual(report.drifted_secrets[0].secret_id, "API_KEY")
        self.assertTrue(report.drifted_secrets[0].actor_drift.is_anomaly)

class TestBaselineEvolution(unittest.TestCase):
    """Test baseline evolution and adaptation over time"""
    
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
    
    def test_baseline_adapts_to_legitimate_changes(self):
        """Test that baseline evolves when behavior legitimately changes"""
        # Create initial baseline with 2-stage pattern
        for i in range(15):
            usage = SecretUsage(
                secret_id="SECRET1",
                run_id=f"phase1-{i}",
                timestamp=datetime.now() - timedelta(days=30-i),
                stages={"build", "test"},
                access_count=2,
                actor="bot",
                environment="dev",
                branch="main"
            )
            self.db.store_secret_usage(usage)
        
        baseline1 = self.manager.create_baseline("SECRET1")
        self.assertEqual(len(baseline1.normal_stages), 2)
        
        # Add new usage pattern with 3 stages (legitimate evolution)
        for i in range(15):
            usage = SecretUsage(
                secret_id="SECRET1",
                run_id=f"phase2-{i}",
                timestamp=datetime.now() - timedelta(days=15-i),
                stages={"build", "test", "deploy"},
                access_count=3,
                actor="bot",
                environment="dev",
                branch="main"
            )
            self.db.store_secret_usage(usage)
        
        # Rebuild baseline - should now include deploy stage
        baseline2 = self.manager.update_baseline("SECRET1")
        self.assertEqual(len(baseline2.normal_stages), 3)
        self.assertIn("deploy", baseline2.normal_stages)
    
    def test_baseline_staleness_triggers_update(self):
        """Test that stale baselines are automatically refreshed"""
        # Create baseline with data in current window (last 30 days)
        for i in range(15):
            usage = SecretUsage(
                secret_id="SECRET1",
                run_id=f"old-{i}",
                timestamp=datetime.now() - timedelta(days=25-i),  # Within 30-day window
                stages={"build"},
                access_count=1,
                actor="bot",
                environment="dev",
                branch="main"
            )
            self.db.store_secret_usage(usage)
        
        baseline_old = self.manager.create_baseline("SECRET1")
        self.assertIsNotNone(baseline_old, "Baseline should be created with sufficient data in window")
        self.db.store_baseline(baseline_old)
        
        # Manually set baseline to be very old
        baseline_old.updated_at = datetime.now() - timedelta(days=20)
        self.db.store_baseline(baseline_old)
        
        # Add recent usage
        for i in range(15):
            usage = SecretUsage(
                secret_id="SECRET1",
                run_id=f"recent-{i}",
                timestamp=datetime.now() - timedelta(days=10-i),
                stages={"build", "test"},
                access_count=2,
                actor="bot",
                environment="dev",
                branch="main"
            )
            self.db.store_secret_usage(usage)
        
        # Get or create should trigger update due to staleness
        baseline_new = self.manager.get_or_create_baseline("SECRET1")
        self.assertGreater(baseline_new.updated_at, baseline_old.updated_at)

class TestDriftCorrelation(unittest.TestCase):
    """Test complex drift correlation scenarios"""
    
    def setUp(self):
        self.db_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.db_path = self.db_file.name
        self.db_file.close()
        
        # Create baseline
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
        
        rebuild_baselines(db_path=self.db_path)
    
    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
    
    def test_multi_feature_drift_increases_severity(self):
        """Test that multiple features drifting increases severity"""
        # Single feature drift
        run1 = PipelineRun(
            run_id="single-drift",
            timestamp=datetime.now(),
            branch="main",
            environment="dev",
            actor="new-bot",  # Only actor changed
            secrets_used=["SECRET1"],
            stages=["build", "test"]
        )
        usage1 = SecretUsage(
            secret_id="SECRET1",
            run_id="single-drift",
            timestamp=datetime.now(),
            stages={"build", "test"},
            access_count=2,
            actor="new-bot",
            environment="dev",
            branch="main"
        )
        report1 = run_sdda(run1, [usage1], db_path=self.db_path)
        
        # Multi-feature drift
        run2 = PipelineRun(
            run_id="multi-drift",
            timestamp=datetime.now(),
            branch="feature",
            environment="production",  # Changed
            actor="new-bot",  # Changed
            secrets_used=["SECRET1"],
            stages=["build", "test", "deploy"]  # Changed
        )
        usage2 = SecretUsage(
            secret_id="SECRET1",
            run_id="multi-drift",
            timestamp=datetime.now(),
            stages={"build", "test", "deploy"},
            access_count=10,  # Changed
            actor="new-bot",
            environment="production",
            branch="feature"
        )
        report2 = run_sdda(run2, [usage2], db_path=self.db_path)
        
        # Multi-feature drift should have higher severity
        if report1.drifted_secrets and report2.drifted_secrets:
            severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            severity1 = severity_order.get(report1.drifted_secrets[0].severity, 0)
            severity2 = severity_order.get(report2.drifted_secrets[0].severity, 0)
            self.assertGreater(severity2, severity1)

class TestPerformanceAndScalability(unittest.TestCase):
    """Test performance with large datasets"""
    
    def setUp(self):
        self.db_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.db_path = self.db_file.name
        self.db_file.close()
    
    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
    
    def test_large_baseline_dataset(self):
        """Test baseline creation with large historical dataset (100+ runs)"""
        import time
        
        # Generate 100 runs
        for i in range(100):
            run = PipelineRun(
                run_id=f"large-{i}",
                timestamp=datetime.now() - timedelta(days=90-i*0.9),
                branch="main",
                environment="dev" if i % 2 == 0 else "staging",
                actor="bot",
                secrets_used=["SECRET1"],
                stages=["build", "test"]
            )
            usage = SecretUsage(
                secret_id="SECRET1",
                run_id=run.run_id,
                timestamp=run.timestamp,
                stages={"build", "test"},
                access_count=2 + (i % 3),  # 2-4
                actor="bot",
                environment=run.environment,
                branch="main"
            )
            run_sdda(run, [usage], db_path=self.db_path)
        
        # Measure baseline rebuild time
        start = time.time()
        count = rebuild_baselines(db_path=self.db_path)
        elapsed = time.time() - start
        
        self.assertEqual(count, 1)
        self.assertLess(elapsed, 2.0)  # Should complete in under 2 seconds
    
    def test_many_secrets_single_run(self):
        """Test handling many secrets in a single pipeline run"""
        # Create baselines for 20 secrets
        for i in range(20):
            for j in range(15):
                usage = SecretUsage(
                    secret_id=f"SECRET_{i}",
                    run_id=f"baseline-{i}-{j}",
                    timestamp=datetime.now() - timedelta(days=20-j),
                    stages={"build", "test"},
                    access_count=2,
                    actor="bot",
                    environment="dev",
                    branch="main"
                )
                db = SDDADatabase(self.db_path)
                db.store_secret_usage(usage)
                db.close()
        
        rebuild_baselines(db_path=self.db_path)
        
        # Create run with all 20 secrets
        run = PipelineRun(
            run_id="many-secrets",
            timestamp=datetime.now(),
            branch="main",
            environment="dev",
            actor="bot",
            secrets_used=[f"SECRET_{i}" for i in range(20)],
            stages=["build", "test"]
        )
        
        usages = [
            SecretUsage(
                secret_id=f"SECRET_{i}",
                run_id="many-secrets",
                timestamp=datetime.now(),
                stages={"build", "test"},
                access_count=2,
                actor="bot",
                environment="dev",
                branch="main"
            )
            for i in range(20)
        ]
        
        report = run_sdda(run, usages, db_path=self.db_path)
        self.assertEqual(report.total_secrets_analyzed, 20)

class TestRecommendationQuality(unittest.TestCase):
    """Test quality and relevance of recommendations"""
    
    def setUp(self):
        self.db_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.db_path = self.db_file.name
        self.db_file.close()
        
        # Create baseline
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
                stages={"build", "test"},
                access_count=2,
                actor="bot",
                environment="dev",
                branch="main"
            )
            run_sdda(run, [usage], db_path=self.db_path)
        
        rebuild_baselines(db_path=self.db_path)
    
    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
    
    def test_production_recommendation_urgency(self):
        """Test that production drift gets urgent recommendations"""
        run = PipelineRun(
            run_id="prod-drift",
            timestamp=datetime.now(),
            branch="main",
            environment="production",
            actor="bot",
            secrets_used=["SECRET1"],
            stages=["build", "test"]
        )
        usage = SecretUsage(
            secret_id="SECRET1",
            run_id="prod-drift",
            timestamp=datetime.now(),
            stages={"build", "test"},
            access_count=2,
            actor="bot",
            environment="production",
            branch="main"
        )
        
        report = run_sdda(run, [usage], db_path=self.db_path)
        
        if report.drifted_secrets:
            recommendation = report.drifted_secrets[0].recommendation
            # Should mention critical actions
            self.assertTrue(
                any(keyword in recommendation.lower() for keyword in 
                    ['critical', 'immediately', 'rotate', 'verify'])
            )
    
    def test_frequency_spike_recommendation_specificity(self):
        """Test that frequency spike gets specific troubleshooting advice"""
        run = PipelineRun(
            run_id="freq-spike",
            timestamp=datetime.now(),
            branch="main",
            environment="dev",
            actor="bot",
            secrets_used=["SECRET1"],
            stages=["build", "test"]
        )
        usage = SecretUsage(
            secret_id="SECRET1",
            run_id="freq-spike",
            timestamp=datetime.now(),
            stages={"build", "test"},
            access_count=50,  # Huge spike
            actor="bot",
            environment="dev",
            branch="main"
        )
        
        report = run_sdda(run, [usage], db_path=self.db_path)
        
        if report.drifted_secrets:
            recommendation = report.drifted_secrets[0].recommendation
            # Should mention possible causes
            self.assertTrue(
                any(keyword in recommendation.lower() for keyword in 
                    ['retry', 'loop', 'spike', 'frequency', 'investigate'])
            )

class TestAnalysisUtilities(unittest.TestCase):
    """Test utility functions for secret analysis"""
    
    def setUp(self):
        self.db_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.db_path = self.db_file.name
        self.db_file.close()
        
        # Create test data
        for i in range(30):
            run = PipelineRun(
                run_id=f"run-{i}",
                timestamp=datetime.now() - timedelta(days=30-i),
                branch="main" if i % 3 != 0 else "develop",
                environment="dev" if i % 2 == 0 else "staging",
                actor="bot-a" if i < 20 else "bot-b",
                secrets_used=["SECRET1"],
                stages=["build", "test"]
            )
            usage = SecretUsage(
                secret_id="SECRET1",
                run_id=run.run_id,
                timestamp=run.timestamp,
                stages={"build", "test"} if i % 4 != 0 else {"build", "test", "deploy"},
                access_count=2 + (i % 3),
                actor=run.actor,
                environment=run.environment,
                branch=run.branch
            )
            run_sdda(run, [usage], db_path=self.db_path)
        
        rebuild_baselines(db_path=self.db_path)
    
    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
    
    def test_analyze_secret_completeness(self):
        """Test that analyze_secret returns complete information"""
        analysis = analyze_secret("SECRET1", db_path=self.db_path)
        
        # Check required fields
        self.assertIn('secret_id', analysis)
        self.assertIn('total_runs', analysis)
        self.assertIn('time_window_days', analysis)
        self.assertIn('behavioral_features', analysis)
        self.assertIn('baseline', analysis)
        
        # Check behavioral features
        features = analysis['behavioral_features']
        self.assertIn('stages', features)
        self.assertIn('actors', features)
        self.assertIn('environments', features)
        self.assertIn('total_accesses', features)
        self.assertIn('avg_accesses_per_run', features)
        
        # Verify data - should get all 30 runs
        self.assertEqual(analysis['total_runs'], 30, 
                        f"Expected 30 runs but got {analysis['total_runs']}. Check time window calculation.")
        self.assertGreater(len(features['actors']), 0)
        self.assertGreater(len(features['environments']), 0)
    
    def test_analyze_nonexistent_secret(self):
        """Test analyzing a secret that doesn't exist"""
        analysis = analyze_secret("NONEXISTENT", db_path=self.db_path)
        
        self.assertEqual(analysis['total_runs'], 0)
        self.assertIsNone(analysis['baseline'])

if __name__ == '__main__':
    unittest.main()
