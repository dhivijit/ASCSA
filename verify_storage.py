#!/usr/bin/env python3
"""
Quick verification script for storage implementation.
Tests basic functionality of SLGA and SDDA storage.
"""

import os
import sys
import tempfile
from datetime import datetime

def test_slga_storage():
    """Test SLGA storage functionality"""
    print("=" * 60)
    print("Testing SLGA Storage")
    print("=" * 60)
    
    try:
        from engines.slga.database import SLGADatabase
        from engines.slga.reporter import SLGAReporter
        from engines.slga.models import Secret, Commit
        
        # Create temporary database
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        print(f"✓ Database path: {db_path}")
        
        # Initialize database
        db = SLGADatabase(db_path)
        print("✓ Database initialized")
        
        # Create test secret
        secret = Secret(
            value="test_secret_12345",
            secret_type="api_key",
            entropy=4.5,
            files=["test.py", "config.yaml"],
            lines=[10, 20]
        )
        
        # Store secret
        secret_id = db.store_secret(secret)
        print(f"✓ Secret stored with ID: {secret_id}")
        
        # Store files and link to secret
        for file_path, line in zip(secret.files, secret.lines):
            file_id = db.store_file(file_path)
            db.link_secret_to_file(secret_id, file_id, line)
        print("✓ Files stored and linked")
        
        # Store commit
        commit = Commit(
            hash="abc123",
            message="Test commit",
            author="tester",
            date="2025-01-02",
            files=["test.py"]
        )
        commit_id = db.store_commit(commit)
        print(f"✓ Commit stored with ID: {commit_id}")
        
        # Store scan history
        db.store_scan_history(
            scan_id="test_scan_001",
            repo_path="/test/repo",
            total_secrets=1,
            total_files=2,
            total_commits=1
        )
        print("✓ Scan history stored")
        
        # Query lineage
        lineage = db.get_secret_lineage(secret.value)
        print(f"✓ Lineage retrieved: {len(lineage['files'])} files")
        
        # Get statistics
        stats = db.get_statistics()
        print(f"✓ Statistics: {stats['total_secrets']} secrets, {stats['total_files']} files")
        
        db.close()
        
        # Test reporter
        reporter = SLGAReporter(db_path)
        summary = reporter.generate_summary_report()
        print(f"✓ Summary report generated")
        
        text_report = reporter.generate_text_report([secret])
        print(f"✓ Text report generated ({len(text_report)} chars)")
        
        json_report = reporter.generate_json_report([secret])
        print(f"✓ JSON report generated ({len(json_report)} chars)")
        
        reporter.close()
        
        # Cleanup
        os.unlink(db_path)
        
        print("\n✅ SLGA Storage: ALL TESTS PASSED\n")
        return True
        
    except Exception as e:
        print(f"\n❌ SLGA Storage Test Failed: {e}\n")
        import traceback
        traceback.print_exc()
        return False


def test_sdda_storage():
    """Test SDDA storage functionality"""
    print("=" * 60)
    print("Testing SDDA Storage")
    print("=" * 60)
    
    try:
        from engines.sdda.database import SDDADatabase
        from engines.sdda.models import PipelineRun, SecretUsage, DriftReport, DriftDetection
        
        # Create temporary database
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        print(f"✓ Database path: {db_path}")
        
        # Initialize database (disable encryption for testing)
        db = SDDADatabase(db_path, encryption_key=None)
        print("✓ Database initialized")
        
        # Create test pipeline run
        pipeline_run = PipelineRun(
            run_id="test_run_001",
            timestamp=datetime.now(),
            branch="main",
            environment="test",
            actor="tester",
            secrets_used=["secret_1", "secret_2"],
            stages=["build", "test"]
        )
        
        db.store_pipeline_run(pipeline_run)
        print("✓ Pipeline run stored")
        
        # Create test secret usage
        usage = SecretUsage(
            secret_id="secret_abc123",
            run_id="test_run_001",
            timestamp=datetime.now(),
            stages={"build", "test"},
            access_count=5,
            actor="tester",
            environment="test",
            branch="main"
        )
        
        db.store_secret_usage(usage)
        print("✓ Secret usage stored")
        
        # Get historical usage
        history = db.get_historical_usage("secret_abc123", 30)
        print(f"✓ Historical usage retrieved: {len(history)} records")
        
        # Create test drift report
        drift_detection = DriftDetection(
            secret_id="secret_abc123",
            run_id="test_run_001",
            timestamp=datetime.now(),
            severity="HIGH",
            total_drift_score=75.5,
            is_drifted=True,
            anomaly_details=["Unusual stage usage", "New actor detected"],
            recommendation="Review recent changes"
        )
        
        drift_report = DriftReport(
            run_id="test_run_001",
            timestamp=datetime.now(),
            total_secrets_analyzed=2,
            drifted_secrets=[drift_detection],
            summary={'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 0, 'LOW': 0},
            baseline_status="OK"
        )
        
        report_id = db.store_drift_report(drift_report)
        print(f"✓ Drift report stored with ID: {report_id}")
        
        # Retrieve drift report
        retrieved_report = db.get_drift_report("test_run_001")
        print(f"✓ Drift report retrieved: {retrieved_report['total_drifted_secrets']} drifts")
        
        # Get drift history
        drift_history = db.get_drift_history(secret_id="secret_abc123", limit=10)
        print(f"✓ Drift history retrieved: {len(drift_history)} records")
        
        # Get statistics
        stats = db.get_statistics()
        print(f"✓ Statistics: {stats['total_pipeline_runs']} runs, {stats['total_drift_reports']} reports")
        
        db.close()
        
        # Cleanup
        os.unlink(db_path)
        
        print("\n✅ SDDA Storage: ALL TESTS PASSED\n")
        return True
        
    except Exception as e:
        print(f"\n❌ SDDA Storage Test Failed: {e}\n")
        import traceback
        traceback.print_exc()
        return False


def test_storage_utils():
    """Test storage utilities"""
    print("=" * 60)
    print("Testing Storage Utilities")
    print("=" * 60)
    
    try:
        from core.storage_utils import StorageManager, QueryHelper
        
        # Create temporary databases
        with tempfile.NamedTemporaryFile(suffix='_slga.db', delete=False) as f:
            slga_db_path = f.name
        with tempfile.NamedTemporaryFile(suffix='_sdda.db', delete=False) as f:
            sdda_db_path = f.name
        
        print(f"✓ SLGA DB: {slga_db_path}")
        print(f"✓ SDDA DB: {sdda_db_path}")
        
        # Initialize storage manager
        manager = StorageManager(slga_db_path, sdda_db_path)
        print("✓ StorageManager initialized")
        
        # Get combined statistics
        stats = manager.get_combined_statistics()
        print(f"✓ Combined statistics retrieved")
        
        # Test query helper
        activity = QueryHelper.get_recent_activity(slga_db_path, sdda_db_path, limit=5)
        print(f"✓ Recent activity retrieved")
        
        # Cleanup
        os.unlink(slga_db_path)
        os.unlink(sdda_db_path)
        
        print("\n✅ Storage Utilities: ALL TESTS PASSED\n")
        return True
        
    except Exception as e:
        print(f"\n❌ Storage Utilities Test Failed: {e}\n")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all storage tests"""
    print("\n" + "=" * 60)
    print("STORAGE IMPLEMENTATION VERIFICATION")
    print("=" * 60 + "\n")
    
    results = {
        "SLGA Storage": test_slga_storage(),
        "SDDA Storage": test_sdda_storage(),
        "Storage Utilities": test_storage_utils()
    }
    
    print("=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)
    
    all_passed = True
    for test_name, passed in results.items():
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{test_name}: {status}")
        if not passed:
            all_passed = False
    
    print("=" * 60)
    
    if all_passed:
        print("\n🎉 All storage tests passed successfully!\n")
        return 0
    else:
        print("\n⚠️  Some storage tests failed. Please review the output above.\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
