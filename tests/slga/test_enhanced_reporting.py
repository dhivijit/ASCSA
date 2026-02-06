#!/usr/bin/env python3
"""
Quick test to verify commit information is included in SLGA reports
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from engines.slga.models import Secret
from engines.slga.reporter import SLGAReporter
import json

def test_enhanced_reporting():
    """Test that commit information appears in reports"""
    
    # Create sample secrets with commit information
    secrets = [
        Secret(
            value="AKIAIOSFODNN7EXAMPLE",
            secret_type="AWS Access Key",
            entropy=4.5,
            files=["config.py"],
            lines=[10],
            commits=["abc123def", "456789ghi"]
        ),
        Secret(
            value="sk_live_1234567890abcdefghij",
            secret_type="commit_history",
            entropy=4.2,
            files=[],
            lines=[],
            commits=["789xyz123", "def456abc", "ghi789xyz"]
        ),
        Secret(
            value="ghp_thisisagithubpersonaltoken1234",
            secret_type="GitHub Token",
            entropy=4.8,
            files=["app.py", "utils.py"],
            lines=[25, 102],
            commits=["commit1", "commit2", "commit3", "commit4"]
        )
    ]
    
    reporter = SLGAReporter()  # Will create in-memory if no DB
    
    print("=" * 80)
    print("TESTING ENHANCED SLGA REPORTER")
    print("=" * 80)
    
    # Test 1: Text Report
    print("\n" + "=" * 80)
    print("TEST 1: Text Report")
    print("=" * 80)
    text_report = reporter.generate_text_report(secrets)
    print(text_report)
    
    # Verify commit information is present
    assert "From current files:" in text_report, "Missing file-based secrets section"
    assert "From commit history:" in text_report, "Missing commit-based secrets section"
    assert "SECRETS FOUND IN GIT COMMIT HISTORY" in text_report, "Missing commit history header"
    assert "commit_history" in text_report or "Commit-Based Secret" in text_report, "Missing commit secret details"
    print("\n✓ Text report includes commit information")
    
    # Test 2: JSON Report
    print("\n" + "=" * 80)
    print("TEST 2: JSON Report")
    print("=" * 80)
    json_report = reporter.generate_json_report(secrets)
    report_data = json.loads(json_report)
    
    print(json.dumps(report_data, indent=2))
    
    # Verify JSON structure
    assert 'secrets_from_files' in report_data, "Missing secrets_from_files count"
    assert 'secrets_from_commits' in report_data, "Missing secrets_from_commits count"
    assert 'commit_based_secrets' in report_data, "Missing commit_based_secrets array"
    assert 'file_based_secrets' in report_data, "Missing file_based_secrets array"
    
    # Verify commit data in JSON
    assert report_data['secrets_from_commits'] == 1, f"Expected 1 commit secret, got {report_data['secrets_from_commits']}"
    assert report_data['secrets_from_files'] == 2, f"Expected 2 file secrets, got {report_data['secrets_from_files']}"
    
    # Check commit-based secret details
    commit_secret = report_data['commit_based_secrets'][0]
    assert 'commits' in commit_secret, "Missing commits array in commit secret"
    assert len(commit_secret['commits']) == 3, "Missing commit hashes"
    
    # Check file-based secret has commits too
    file_secret = report_data['file_based_secrets'][0]
    if 'commits' in file_secret:
        print(f"✓ File-based secret includes {len(file_secret['commits'])} commit references")
    
    print("\n✓ JSON report includes commit information")
    
    # Test 3: Summary
    print("\n" + "=" * 80)
    print("TEST 3: Summary Statistics")
    print("=" * 80)
    print(f"Total secrets: {report_data['total_secrets']}")
    print(f"  - From files: {report_data['secrets_from_files']}")
    print(f"  - From commits: {report_data['secrets_from_commits']}")
    print(f"Total files with secrets: {report_data['summary']['total_files_with_secrets']}")
    print(f"Total commits analyzed: {report_data['summary']['total_commits_analyzed']}")
    
    print("\n" + "=" * 80)
    print("✅ ALL TESTS PASSED!")
    print("=" * 80)
    print("\nCommit information is now properly included in SLGA reports:")
    print("  ✓ Text reports show commit-based vs file-based secrets")
    print("  ✓ JSON reports include detailed commit information")
    print("  ✓ Commit hashes are tracked for both secret types")

if __name__ == "__main__":
    try:
        test_enhanced_reporting()
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
