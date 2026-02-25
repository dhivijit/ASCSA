"""
Advanced integration tests for HCRS - Hybrid Code Risk Scoring Engine
Tests complex scenarios, multi-file scanning, and real-world use cases
"""

import unittest
import os
import tempfile
import shutil
from datetime import datetime
from pathlib import Path

from engines.hcrs.models import Severity, ViolationType
from engines.hcrs.scanner import HCRSScanner
from engines.hcrs.run import run_hcrs, scan_repository, scan_file
from engines.hcrs.osv_scanner import scan_dep_vulns


class TestMultiFileRepositoryScanning(unittest.TestCase):
    """Test scanning repositories with multiple files and languages"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="hcrs_adv_")
        
    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_mixed_language_repository(self):
        """Test scanning a repository with Python and JavaScript files"""
        # Create Python file with secrets
        py_file = os.path.join(self.test_dir, "backend.py")
        with open(py_file, 'w') as f:
            f.write("""
import os
import subprocess

# Database credentials
DB_PASSWORD = "hardcoded_password_123"
API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"

def execute_command(user_input):
    # Command injection vulnerability
    os.system(f"echo {user_input}")
    
def read_file(filename):
    # Path traversal vulnerability
    with open("/data/" + filename) as f:
        return f.read()
""")
        
        # Create JavaScript file with XSS
        js_file = os.path.join(self.test_dir, "frontend.js")
        with open(js_file, 'w') as f:
            f.write("""
const express = require('express');

function renderPage(userInput) {
    // XSS vulnerability
    document.getElementById('output').innerHTML = userInput;
}

function dangerousEval(code) {
    // eval usage
    eval(code);
}

// Hardcoded token
const githubToken = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
""")
        
        # Scan repository
        report = scan_repository(self.test_dir)
        
        # Verify multi-file scanning
        self.assertGreaterEqual(len(report.file_scores), 2, "Should scan both Python and JavaScript files")
        
        # Verify violations detected in both languages
        all_violations = []
        for file_score in report.file_scores:
            all_violations.extend(file_score.violations)
        
        self.assertGreater(len(all_violations), 3, "Should detect violations in both files")
        
        # Check for Python-specific violations
        py_violation_types = [v.violation_type for v in all_violations if 'backend.py' in v.file_path]
        self.assertTrue(any(t in [ViolationType.HARDCODED_SECRET, ViolationType.COMMAND_INJECTION] 
                          for t in py_violation_types))
        
        # Check for JavaScript-specific violations
        js_violation_types = [v.violation_type for v in all_violations if 'frontend.js' in v.file_path]
        self.assertTrue(any(t in [ViolationType.XSS, ViolationType.EVAL_USAGE] 
                          for t in js_violation_types))
    
    def test_large_repository_performance(self):
        """Test performance with a larger repository (50+ files)"""
        import time
        
        # Create 50 Python files
        for i in range(50):
            file_path = os.path.join(self.test_dir, f"module_{i}.py")
            with open(file_path, 'w') as f:
                if i % 10 == 0:  # Add violations to every 10th file
                    f.write(f'API_KEY = "secret_key_{i}"\n')
                else:
                    f.write(f'# Clean module {i}\nimport json\n')
        
        start = time.time()
        scanner = HCRSScanner()
        report = scanner.scan_repository(self.test_dir)
        elapsed = time.time() - start
        
        # Should complete in reasonable time
        self.assertLess(elapsed, 10.0, f"Scanning 50 files took {elapsed}s, should be under 10s")
        
        # Should scan all files
        self.assertEqual(len(report.file_scores), 50)
        
        # Should detect violations in 5 files (every 10th)
        files_with_violations = [fs for fs in report.file_scores if len(fs.violations) > 0]
        self.assertEqual(len(files_with_violations), 5)
    
    def test_nested_directory_structure(self):
        """Test scanning nested directory structures"""
        # Create nested structure
        os.makedirs(os.path.join(self.test_dir, "src", "api"), exist_ok=True)
        os.makedirs(os.path.join(self.test_dir, "src", "utils"), exist_ok=True)
        os.makedirs(os.path.join(self.test_dir, "tests"), exist_ok=True)
        
        # Add files at different levels
        files = [
            ("src/api/auth.py", 'TOKEN = "bearer_token_12345"\n'),
            ("src/utils/helper.py", 'import os\n'),
            ("tests/test_auth.py", 'PASSWORD = "test_password"\n'),
            ("main.py", 'SECRET = "main_secret"\n')
        ]
        
        for file_path, content in files:
            full_path = os.path.join(self.test_dir, file_path)
            with open(full_path, 'w') as f:
                f.write(content)
        
        scanner = HCRSScanner()
        report = scanner.scan_repository(self.test_dir)
        
        # Should find all Python files
        self.assertEqual(len(report.file_scores), 4)
        
        # Should detect secrets at different nesting levels
        all_violations = []
        for file_score in report.file_scores:
            all_violations.extend(file_score.violations)
        
        self.assertGreaterEqual(len(all_violations), 3)
    
    def test_repository_with_dependencies(self):
        """Test repository with dependency files and OSV integration"""
        # Create requirements.txt with vulnerable packages
        req_file = os.path.join(self.test_dir, "requirements.txt")
        with open(req_file, 'w') as f:
            f.write("""requests==2.6.0
flask==1.0.0
django==2.0.0
""")
        
        # Create Python files
        py_file = os.path.join(self.test_dir, "app.py")
        with open(py_file, 'w') as f:
            f.write('import flask\napp = flask.Flask(__name__)\n')
        
        # Scan repository
        scanner = HCRSScanner()
        report = scanner.scan_repository(self.test_dir)
        
        # Should include dependency vulnerabilities
        self.assertIsNotNone(report.dependency_vulnerabilities)
        self.assertGreater(len(report.dependency_vulnerabilities), 0, 
                          "Should detect vulnerabilities in old packages")
        
        # Verify specific vulnerabilities
        vuln_packages = {v['package_name'] for v in report.dependency_vulnerabilities}
        self.assertTrue(any(pkg in vuln_packages for pkg in ['requests', 'flask', 'django']))


class TestComplexVulnerabilityPatterns(unittest.TestCase):
    """Test detection of complex vulnerability patterns"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="hcrs_complex_")
    
    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_chained_vulnerabilities(self):
        """Test file with multiple chained vulnerabilities"""
        file_path = os.path.join(self.test_dir, "vulnerable.py")
        with open(file_path, 'w') as f:
            f.write("""
import pickle
import subprocess
import os

# Hardcoded credentials
DATABASE_URL = "postgresql://admin:SuperSecret123@db.example.com:5432/prod"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def dangerous_endpoint(user_data, command, filename):
    # 1. Deserialization vulnerability
    obj = pickle.loads(user_data)
    
    # 2. Command injection
    subprocess.call(command, shell=True)
    
    # 3. Path traversal
    with open("/var/data/" + filename) as f:
        content = f.read()
    
    # 4. SQL injection (simulated)
    query = f"SELECT * FROM users WHERE id = {obj.id}"
    
    return content
""")
        
        scanner = HCRSScanner()
        report = scanner.scan_file(file_path)
        
        # Should detect multiple vulnerabilities
        self.assertGreaterEqual(len(report.violations), 4)
        
        # Check for different violation types
        violation_types = {v.violation_type for v in report.violations}
        expected_types = {
            ViolationType.HARDCODED_SECRET,
            ViolationType.COMMAND_INJECTION,
            ViolationType.UNSAFE_DESERIALIZATION
        }
        self.assertTrue(expected_types.issubset(violation_types) or len(violation_types) >= 3)
        
        # Risk score should be high due to multiple issues
        self.assertGreater(report.risk_score, 50.0)
    
    def test_obfuscated_secrets(self):
        """Test detection of obfuscated or encoded secrets"""
        file_path = os.path.join(self.test_dir, "obfuscated.py")
        with open(file_path, 'w') as f:
            f.write("""
import base64

# Base64 encoded secret (still detectable by pattern)
API_KEY = "c2stMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6"

# Concatenated secret
SECRET_PART1 = "ghp_"
SECRET_PART2 = "1234567890abcdefghijklmnopqrstuvwxyz"
FULL_SECRET = SECRET_PART1 + SECRET_PART2

# Hex encoded
HEX_PASSWORD = "70617373776f726431323334"  # password1234 in hex
""")
        
        scanner = HCRSScanner()
        report = scanner.scan_file(file_path)
        
        # Should detect at least some patterns
        self.assertGreater(len(report.violations), 0)
        
        # Should flag suspicious patterns
        secrets_found = [v for v in report.violations if v.violation_type == ViolationType.HARDCODED_SECRET]
        self.assertGreater(len(secrets_found), 0)
    
    def test_context_aware_detection(self):
        """Test that context matters in vulnerability detection"""
        file_path = os.path.join(self.test_dir, "context.py")
        with open(file_path, 'w') as f:
            f.write("""
import os

# This should be flagged - actual vulnerability
def bad_function(user_input):
    os.system(f"cat {user_input}")

# This should NOT be flagged - safe context
def good_function():
    # Example in comment: os.system("rm -rf /")
    safe_var = "os.system"  # Just a string
    return "This is safe"

# This is documentation
'''
Example of unsafe code:
    os.system(user_input)
'''
""")
        
        scanner = HCRSScanner()
        report = scanner.scan_file(file_path)
        
        # Should detect the actual vulnerability
        cmd_injections = [v for v in report.violations if v.violation_type == ViolationType.COMMAND_INJECTION]
        
        # Should have at least one real violation, but not from comments/strings
        self.assertGreaterEqual(len(cmd_injections), 1)
        
        # Verify it's from the actual vulnerable line
        for violation in cmd_injections:
            # Line should be in the bad_function
            self.assertTrue(violation.line_number is None or violation.line_number <= 7)


class TestRiskScoringAccuracy(unittest.TestCase):
    """Test risk scoring algorithm accuracy"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="hcrs_scoring_")
    
    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_severity_impact_on_score(self):
        """Test that severity correctly impacts risk score"""
        # Critical violation
        critical_file = os.path.join(self.test_dir, "critical.py")
        with open(critical_file, 'w') as f:
            f.write('AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n')
        
        # Low severity violation
        low_file = os.path.join(self.test_dir, "low.py")
        with open(low_file, 'w') as f:
            f.write('# TODO: Add input validation\nimport os\n')
        
        scanner = HCRSScanner()
        critical_report = scanner.scan_file(critical_file)
        low_report = scanner.scan_file(low_file)
        
        # Critical should have much higher score
        if len(critical_report.violations) > 0 and len(low_report.violations) > 0:
            self.assertGreater(critical_report.risk_score, low_report.risk_score)
    
    def test_volume_impact_on_score(self):
        """Test that number of violations impacts score"""
        # Single violation
        single_file = os.path.join(self.test_dir, "single.py")
        with open(single_file, 'w') as f:
            f.write('API_KEY = "test_key_12345"\n')
        
        # Multiple violations
        multiple_file = os.path.join(self.test_dir, "multiple.py")
        with open(multiple_file, 'w') as f:
            f.write("""
API_KEY = "test_key_12345"
SECRET_TOKEN = "token_67890"
PASSWORD = "hardcoded_pass"
import os
os.system(user_input)
""")
        
        scanner = HCRSScanner()
        single_report = scanner.scan_file(single_file)
        multiple_report = scanner.scan_file(multiple_file)
        
        # Multiple violations should have higher score
        self.assertGreater(multiple_report.risk_score, single_report.risk_score)
    
    def test_repository_aggregate_score(self):
        """Test that repository score aggregates file scores correctly"""
        # Create multiple files with varying risk
        files = {
            "high_risk.py": 'AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"\nos.system(cmd)\n',
            "medium_risk.py": 'API_KEY = "test_key"\n',
            "low_risk.py": 'import json\n# Safe code\n',
        }
        
        for filename, content in files.items():
            with open(os.path.join(self.test_dir, filename), 'w') as f:
                f.write(content)
        
        scanner = HCRSScanner()
        report = scanner.scan_repository(self.test_dir)
        
        # Repository score should reflect aggregate risk
        self.assertGreater(report.risk_score, 0)
        
        # Should be influenced by highest risk files
        high_risk_files = [fs for fs in report.file_scores if fs.risk_score > 50]
        if len(high_risk_files) > 0:
            self.assertGreater(report.risk_score, 30)


class TestReportGenerationAndFormatting(unittest.TestCase):
    """Test report generation and formatting"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="hcrs_report_")
    
    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_json_report_completeness(self):
        """Test that JSON report contains all required fields"""
        # Create test file
        test_file = os.path.join(self.test_dir, "test.py")
        with open(test_file, 'w') as f:
            f.write('SECRET = "test_secret_123"\nimport os\nos.system(user_cmd)\n')
        
        from engines.hcrs.reporter import HCRSReporter
        import json
        
        scanner = HCRSScanner()
        repo_report = scanner.scan_repository(self.test_dir)
        json_str = HCRSReporter.generate_json_report(repo_report)
        json_report = json.loads(json_str)
        
        # Check required fields
        self.assertIn('repo_path', json_report)
        self.assertIn('total_score', json_report)
        self.assertIn('summary', json_report)
        self.assertIn('files_with_violations', json_report)
        
        # Check violations structure
        for fv in json_report['files_with_violations']:
            self.assertIn('violations', fv)
            for violation in fv['violations']:
                self.assertIn('type', violation)
                self.assertIn('severity', violation)
                self.assertIn('message', violation)
    
    def test_text_report_readability(self):
        """Test that text report is human-readable"""
        test_file = os.path.join(self.test_dir, "test.py")
        with open(test_file, 'w') as f:
            f.write('PASSWORD = "hardcoded_password"\n')
        
        from engines.hcrs.reporter import HCRSReporter
        
        scanner = HCRSScanner()
        repo_report = scanner.scan_repository(self.test_dir)
        text_report = HCRSReporter.generate_text_report(repo_report)
        
        # Should contain key information
        self.assertIn('Risk Score', text_report)
        self.assertIn('Violation', text_report)
        
        # Should be readable
        self.assertGreater(len(text_report), 50)
    
    def test_repository_summary_statistics(self):
        """Test repository report summary statistics"""
        # Create multiple files
        for i in range(5):
            file_path = os.path.join(self.test_dir, f"file_{i}.py")
            with open(file_path, 'w') as f:
                if i % 2 == 0:
                    f.write(f'SECRET_{i} = "secret_value"\n')
                else:
                    f.write('import json\n')
        
        scanner = HCRSScanner()
        report = scanner.scan_repository(self.test_dir)
        
        # Verify statistics
        self.assertEqual(len(report.file_scores), 5)
        
        # Count files with violations
        files_with_issues = sum(1 for fs in report.file_scores if len(fs.violations) > 0)
        self.assertEqual(files_with_issues, 3)  # Files 0, 2, 4
        
        # Total violations
        total_violations = sum(len(fs.violations) for fs in report.file_scores)
        self.assertGreater(total_violations, 0)


class TestOSVIntegrationAdvanced(unittest.TestCase):
    """Advanced tests for OSV dependency scanning integration"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="hcrs_osv_")
    
    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_requirements_and_package_json_together(self):
        """Test scanning repository with both Python and Node dependencies"""
        # Create requirements.txt
        req_file = os.path.join(self.test_dir, "requirements.txt")
        with open(req_file, 'w') as f:
            f.write("requests==2.6.0\nflask==1.0.0\n")
        
        # Create package.json
        pkg_file = os.path.join(self.test_dir, "package.json")
        with open(pkg_file, 'w') as f:
            f.write('{"dependencies": {"express": "4.17.0", "lodash": "4.17.15"}}\n')
        
        # Create code file
        py_file = os.path.join(self.test_dir, "app.py")
        with open(py_file, 'w') as f:
            f.write('import flask\n')
        
        scanner = HCRSScanner()
        report = scanner.scan_repository(self.test_dir)
        
        # Should scan both dependency files
        self.assertIsNotNone(report.dependency_vulnerabilities)
        self.assertGreater(len(report.dependency_vulnerabilities), 0)
        
        # Should have vulnerabilities from both ecosystems
        ecosystems = {v['ecosystem'] for v in report.dependency_vulnerabilities}
        # At least one ecosystem should be present
        self.assertTrue(len(ecosystems) > 0)
    
    def test_correlation_code_and_dependencies(self):
        """Test correlation between code vulnerabilities and dependency issues"""
        # Create vulnerable code using vulnerable library
        req_file = os.path.join(self.test_dir, "requirements.txt")
        with open(req_file, 'w') as f:
            f.write("requests==2.6.0\n")
        
        py_file = os.path.join(self.test_dir, "app.py")
        with open(py_file, 'w') as f:
            f.write("""
import requests

# Hardcoded secret
API_KEY = "sk_live_1234567890abcdefghijklmnopqrstuvwxyz"

def fetch_data(url):
    # Using vulnerable library + passing user input
    response = requests.get(url, verify=False)
    return response.text
""")
        
        scanner = HCRSScanner()
        report = scanner.scan_repository(self.test_dir)
        
        # Should have both code violations and dependency vulnerabilities
        total_code_violations = sum(len(fs.violations) for fs in report.file_scores)
        self.assertGreater(total_code_violations, 0, "Should detect code violations")
        self.assertGreater(len(report.dependency_vulnerabilities), 0, 
                          "Should detect dependency vulnerabilities")
        
        # Risk score should reflect both
        self.assertGreater(report.risk_score, 30)


class TestErrorHandlingAndEdgeCases(unittest.TestCase):
    """Test error handling in advanced scenarios"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="hcrs_edge_")
    
    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_empty_repository(self):
        """Test scanning empty repository"""
        scanner = HCRSScanner()
        report = scanner.scan_repository(self.test_dir)
        
        self.assertEqual(len(report.file_scores), 0)
        self.assertEqual(report.risk_score, 0.0)
    
    def test_binary_files_skipped(self):
        """Test that binary files are skipped"""
        # Create binary file
        bin_file = os.path.join(self.test_dir, "binary.bin")
        with open(bin_file, 'wb') as f:
            f.write(b'\x00\x01\x02\x03\xFF\xFE')
        
        # Create text file
        py_file = os.path.join(self.test_dir, "code.py")
        with open(py_file, 'w') as f:
            f.write('import os\n')
        
        scanner = HCRSScanner()
        report = scanner.scan_repository(self.test_dir)
        
        # Should only scan the Python file
        self.assertEqual(len(report.file_scores), 1)
        self.assertTrue(report.file_scores[0].file_path.endswith('code.py'))
    
    def test_very_large_file(self):
        """Test handling of very large files"""
        large_file = os.path.join(self.test_dir, "large.py")
        with open(large_file, 'w') as f:
            # Write 10000 lines
            for i in range(10000):
                if i == 5000:
                    f.write('SECRET = "hardcoded_secret"\n')
                else:
                    f.write(f'# Line {i}\n')
        
        # Should handle without crashing
        scanner = HCRSScanner()
        report = scanner.scan_file(large_file)
        
        self.assertIsNotNone(report)
        # Should still detect the secret
        secrets = [v for v in report.violations if v.violation_type == ViolationType.HARDCODED_SECRET]
        self.assertGreater(len(secrets), 0)
    
    def test_malformed_dependency_files(self):
        """Test handling of malformed dependency files"""
        # Malformed requirements.txt
        req_file = os.path.join(self.test_dir, "requirements.txt")
        with open(req_file, 'w') as f:
            f.write("requests==2.6.0\ninvalid line without version\nflask\n")
        
        # Should not crash
        try:
            scanner = HCRSScanner()
            report = scanner.scan_repository(self.test_dir)
            # May or may not find vulnerabilities depending on parsing
            self.assertIsNotNone(report)
        except Exception as e:
            self.fail(f"Should handle malformed dependency files gracefully: {e}")


if __name__ == '__main__':
    print("=" * 70)
    print("HCRS Advanced Integration Tests")
    print("=" * 70)
    unittest.main(verbosity=2)
