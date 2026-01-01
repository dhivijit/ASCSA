"""
Simple test runner for HCRS tests
Run comprehensive tests of the HCRS module as a whole
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import unittest
import tempfile
import shutil
from engines.hcrs.scanner import HCRSScanner
from engines.hcrs.models import ViolationType

def test_complete_repository_scan():
    """Test complete HCRS workflow on a realistic repository"""
    print("\n" + "="*70)
    print("Test 1: Complete Repository Scan with Multiple Files and Languages")
    print("="*70)
    
    test_dir = tempfile.mkdtemp(prefix="hcrs_complete_test_")
    
    try:
        # Create Python file with multiple vulnerabilities
        py_file = os.path.join(test_dir, "backend.py")
        with open(py_file, 'w') as f:
            f.write("""
import os
import subprocess
import pickle

# CRITICAL: Hardcoded AWS credentials
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

# HIGH: Database credentials
DB_PASSWORD = "SuperSecret123!"
DB_CONNECTION = "postgresql://admin:hardcoded_pass@db.example.com/prod"

# HIGH: Command injection
def execute_user_command(user_input):
    os.system(f"cat {user_input}")
    subprocess.call(user_input, shell=True)

# HIGH: Deserialization
def load_data(data):
    return pickle.loads(data)

# MEDIUM: Path traversal
def read_user_file(filename):
    with open("/data/" + filename) as f:
        return f.read()
""")
        
        # Create JavaScript file with vulnerabilities
        js_file = os.path.join(test_dir, "frontend.js")
        with open(js_file, 'w') as f:
            f.write("""
const express = require('express');
const app = express();

// CRITICAL: Hardcoded API keys
const STRIPE_SECRET_KEY = "sk_live_1234567890abcdefghijklmnopqrstuvwxyz";
const GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";

// HIGH: XSS vulnerability
function renderUserContent(userInput) {
    document.getElementById('content').innerHTML = userInput;
}

// HIGH: eval usage
function executeCode(code) {
    eval(code);
}

// MEDIUM: Insecure random
function generateToken() {
    return Math.random().toString(36);
}
""")
        
        # Create a safe utility file
        util_file = os.path.join(test_dir, "utils.py")
        with open(util_file, 'w') as f:
            f.write("""
# Safe utility functions
import json
import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def parse_json(data):
    return json.loads(data)

def validate_input(user_input):
    # Proper validation
    if not user_input.isalnum():
        raise ValueError("Invalid input")
    return user_input
""")
        
        # Create requirements.txt with vulnerable dependencies
        req_file = os.path.join(test_dir, "requirements.txt")
        with open(req_file, 'w') as f:
            f.write("""requests==2.6.0
flask==1.0.0
django==2.0.0
pyyaml==5.1
""")
        
        print(f"\nTest repository created at: {test_dir}")
        print("Files created:")
        print("  - backend.py (Python with 8+ vulnerabilities)")
        print("  - frontend.js (JavaScript with 5+ vulnerabilities)")
        print("  - utils.py (Safe Python code)")
        print("  - requirements.txt (Vulnerable dependencies)")
        
        # Scan the repository
        print("\nScanning repository...")
        scanner = HCRSScanner()
        report = scanner.scan_repository(test_dir)
        
        # Display results
        print("\n" + "="*70)
        print("SCAN RESULTS")
        print("="*70)
        
        print(f"\n📁 Files Analyzed: {len(report.file_scores)}")
        print(f"⚠️  Total Code Violations: {sum(len(fs.violations) for fs in report.file_scores)}")
        print(f"🔒 Dependency Vulnerabilities: {len(report.dependency_vulnerabilities) if report.dependency_vulnerabilities else 0}")
        print(f"📊 Overall Risk Score: {report.total_score:.2f}/100")
        
        # Breakdown by file
        print("\n" + "-"*70)
        print("File-Level Analysis:")
        print("-"*70)
        
        for file_score in report.file_scores:
            filename = os.path.basename(file_score.file_path)
            print(f"\n📄 {filename}")
            print(f"   Risk Score: {file_score.total_score:.2f}/100")
            print(f"   Violations: {len(file_score.violations)}")
            
            if len(file_score.violations) > 0:
                # Count by severity
                by_severity = {}
                for v in file_score.violations:
                    sev = v.severity.name if hasattr(v.severity, 'name') else str(v.severity)
                    by_severity[sev] = by_severity.get(sev, 0) + 1
                
                for sev, count in sorted(by_severity.items(), reverse=True):
                    print(f"      {sev}: {count}")
                
                # Show top violations
                print(f"   Top Violations:")
                for i, v in enumerate(file_score.violations[:3], 1):
                    v_type = v.violation_type.name if hasattr(v.violation_type, 'name') else str(v.violation_type)
                    severity = v.severity.name if hasattr(v.severity, 'name') else str(v.severity)
                    print(f"      {i}. [{severity}] {v_type}")
                    if v.message:
                        print(f"         {v.message[:80]}...")
        
        # Dependency vulnerabilities
        if report.dependency_vulnerabilities and len(report.dependency_vulnerabilities) > 0:
            print("\n" + "-"*70)
            print("Dependency Vulnerabilities:")
            print("-"*70)
            
            # Group by package
            by_package = {}
            for vuln in report.dependency_vulnerabilities:
                pkg = vuln.get('package_name', 'unknown')
                by_package[pkg] = by_package.get(pkg, 0) + 1
            
            for pkg, count in sorted(by_package.items(), key=lambda x: x[1], reverse=True):
                print(f"   {pkg}: {count} vulnerabilities")
        
        # Summary
        print("\n" + "="*70)
        print("SUMMARY")
        print("="*70)
        
        # Check test expectations
        total_violations = sum(len(fs.violations) for fs in report.file_scores)
        
        print(f"\n✅ Successfully scanned {len(report.file_scores)} files")
        print(f"✅ Detected {total_violations} code vulnerabilities")
        print(f"✅ Found {len(report.dependency_vulnerabilities) if report.dependency_vulnerabilities else 0} dependency issues")
        print(f"✅ Calculated risk scores for each file")
        print(f"✅ Generated overall repository risk score: {report.total_score:.2f}/100")
        
        # Assertions
        assert len(report.file_scores) >= 3, "Should scan at least 3 files"
        assert total_violations > 5, f"Should detect multiple violations (found {total_violations})"
        assert report.total_score > 0, "Risk score should be non-zero"
        
        # Check that we found secrets
        all_violations = []
        for fs in report.file_scores:
            all_violations.extend(fs.violations)
        
        has_secrets = any(v.violation_type == ViolationType.HARDCODED_SECRET for v in all_violations)
        has_cmd_injection = any(v.violation_type == ViolationType.COMMAND_INJECTION for v in all_violations)
        
        assert has_secrets, "Should detect hardcoded secrets"
        assert has_cmd_injection, "Should detect command injections"
        
        print("\n✅ All test assertions passed!")
        
        return True
        
    finally:
        # Cleanup
        shutil.rmtree(test_dir, ignore_errors=True)

def test_individual_file_scan():
    """Test scanning individual files"""
    print("\n" + "="*70)
    print("Test 2: Individual File Scanning")
    print("="*70)
    
    test_dir = tempfile.mkdtemp(prefix="hcrs_file_test_")
    
    try:
        # Create test file
        test_file = os.path.join(test_dir, "test.py")
        with open(test_file, 'w') as f:
            f.write("""
# Test file with known vulnerabilities
API_KEY = "sk_test_1234567890abcdefghijklmnopqrstuvwxyz"
PASSWORD = "hardcoded_password_123"

import os
def run_command(cmd):
    os.system(cmd)  # Command injection
""")
        
        print(f"\nScanning file: {test_file}")
        
        scanner = HCRSScanner()
        report = scanner.scan_file(test_file)
        
        print(f"\n✅ File scanned successfully")
        print(f"   Violations found: {len(report.violations)}")
        print(f"   Risk score: {report.total_score:.2f}/100")
        
        for i, v in enumerate(report.violations, 1):
            v_type = v.violation_type.name if hasattr(v.violation_type, 'name') else str(v.violation_type)
            severity = v.severity.name if hasattr(v.severity, 'name') else str(v.severity)
            print(f"   {i}. [{severity}] {v_type}")
        
        assert len(report.violations) >= 2, "Should detect multiple violations"
        assert report.total_score > 0, "Should have non-zero risk score"
        
        print("\n✅ Individual file test passed!")
        
        return True
        
    finally:
        shutil.rmtree(test_dir, ignore_errors=True)

def test_empty_and_safe_code():
    """Test that safe code gets low scores"""
    print("\n" + "="*70)
    print("Test 3: Safe Code Detection (False Positive Avoidance)")
    print("="*70)
    
    test_dir = tempfile.mkdtemp(prefix="hcrs_safe_test_")
    
    try:
        # Create safe code
        safe_file = os.path.join(test_dir, "safe.py")
        with open(safe_file, 'w') as f:
            f.write("""
# Completely safe code
import json
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

def process_data(data: List[Dict]) -> Dict:
    '''Process data safely'''
    logger.info("Processing data")
    
    result = {
        'count': len(data),
        'items': []
    }
    
    for item in data:
        if 'id' in item and 'name' in item:
            result['items'].append({
                'id': item['id'],
                'name': item['name']
            })
    
    return result

def main():
    data = [{'id': 1, 'name': 'test'}]
    result = process_data(data)
    print(json.dumps(result))

if __name__ == '__main__':
    main()
""")
        
        print(f"\nScanning safe code file...")
        
        scanner = HCRSScanner()
        report = scanner.scan_file(safe_file)
        
        print(f"\n✅ Safe code scanned")
        print(f"   Violations found: {len(report.violations)}")
        print(f"   Risk score: {report.total_score:.2f}/100")
        
        assert len(report.violations) == 0, f"Safe code should have 0 violations, got {len(report.violations)}"
        assert report.total_score == 0.0, f"Safe code should have 0 risk score, got {report.total_score}"
        
        print("\n✅ Safe code test passed - no false positives!")
        
        return True
        
    finally:
        shutil.rmtree(test_dir, ignore_errors=True)

if __name__ == '__main__':
    print("\n" + "="*70)
    print("HCRS COMPLETE MODULE TEST SUITE")
    print("Testing the Hybrid Code Risk Scoring Engine as a whole")
    print("="*70)
    
    tests_passed = 0
    tests_failed = 0
    
    try:
        if test_complete_repository_scan():
            tests_passed += 1
    except Exception as e:
        print(f"\n❌ Test 1 FAILED: {e}")
        import traceback
        traceback.print_exc()
        tests_failed += 1
    
    try:
        if test_individual_file_scan():
            tests_passed += 1
    except Exception as e:
        print(f"\n❌ Test 2 FAILED: {e}")
        import traceback
        traceback.print_exc()
        tests_failed += 1
    
    try:
        if test_empty_and_safe_code():
            tests_passed += 1
    except Exception as e:
        print(f"\n❌ Test 3 FAILED: {e}")
        import traceback
        traceback.print_exc()
        tests_failed += 1
    
    # Final summary
    print("\n" + "="*70)
    print("FINAL RESULTS")
    print("="*70)
    print(f"\n✅ Tests Passed: {tests_passed}/3")
    print(f"❌ Tests Failed: {tests_failed}/3")
    
    if tests_failed == 0:
        print("\n🎉 ALL TESTS PASSED! HCRS module is working correctly.")
        sys.exit(0)
    else:
        print(f"\n⚠️  Some tests failed. Please review the errors above.")
        sys.exit(1)
