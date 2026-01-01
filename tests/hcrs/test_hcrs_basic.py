"""
Basic tests for HCRS engine
"""
import os
import sys
import tempfile
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from engines.hcrs.scanner import HCRSScanner
from engines.hcrs.models import Severity, ViolationType

def test_hardcoded_secret_detection():
    """Test detection of hardcoded secrets"""
    # Create temp file with hardcoded secret
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('API_KEY = "sk_live_1234567890abcdefghij"\\n')
        f.write('password = "SuperSecret123!"\\n')
        temp_file = f.name
    
    try:
        scanner = HCRSScanner()
        file_score = scanner.scan_file(temp_file, 'python')
        
        assert file_score is not None, "File score should not be None"
        assert len(file_score.violations) > 0, "Should detect hardcoded secrets"
        
        # Check for hardcoded secret violations
        secret_violations = [
            v for v in file_score.violations 
            if v.violation_type == ViolationType.HARDCODED_SECRET
        ]
        assert len(secret_violations) > 0, "Should detect hardcoded secrets"
        
        print("✓ Hardcoded secret detection test passed")
        print(f"  Found {len(secret_violations)} hardcoded secret(s)")
        
    finally:
        os.unlink(temp_file)

def test_command_injection_detection():
    """Test detection of command injection"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('import os\\n')
        f.write('user_input = request.args.get("cmd")\\n')
        f.write('os.system("ls " + user_input)\\n')
        temp_file = f.name
    
    try:
        scanner = HCRSScanner()
        file_score = scanner.scan_file(temp_file, 'python')
        
        assert file_score is not None
        assert len(file_score.violations) > 0, "Should detect command injection"
        
        cmd_violations = [
            v for v in file_score.violations 
            if v.violation_type == ViolationType.COMMAND_INJECTION
        ]
        assert len(cmd_violations) > 0, "Should detect command injection"
        
        print("✓ Command injection detection test passed")
        print(f"  Found {len(cmd_violations)} command injection(s)")
        
    finally:
        os.unlink(temp_file)

def test_javascript_eval_detection():
    """Test detection of eval in JavaScript"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
        f.write('const result = eval(userInput);\\n')
        f.write('const func = new Function("return " + code);\\n')
        temp_file = f.name
    
    try:
        scanner = HCRSScanner()
        file_score = scanner.scan_file(temp_file, 'javascript')
        
        assert file_score is not None
        assert len(file_score.violations) > 0, "Should detect eval usage"
        
        eval_violations = [
            v for v in file_score.violations 
            if v.violation_type == ViolationType.EVAL_USAGE
        ]
        assert len(eval_violations) > 0, "Should detect eval usage"
        
        print("✓ JavaScript eval detection test passed")
        print(f"  Found {len(eval_violations)} eval usage(s)")
        
    finally:
        os.unlink(temp_file)

def test_repository_scan():
    """Test scanning a repository"""
    # Create temp directory with multiple files
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Create vulnerable Python file
        py_file = os.path.join(temp_dir, 'app.py')
        with open(py_file, 'w') as f:
            f.write('password = "test123"\\n')
            f.write('import os\\n')
            f.write('os.system("echo hello")\\n')
        
        # Create vulnerable JS file
        js_file = os.path.join(temp_dir, 'app.js')
        with open(js_file, 'w') as f:
            f.write('const key = "sk_test_12345678";\\n')
            f.write('eval(userInput);\\n')
        
        # Scan repository
        scanner = HCRSScanner()
        repo_score = scanner.scan_repository(temp_dir)
        
        assert repo_score is not None
        assert repo_score.summary['total_files_analyzed'] == 2
        assert repo_score.summary['total_violations'] > 0
        
        print("✓ Repository scan test passed")
        print(f"  Files analyzed: {repo_score.summary['total_files_analyzed']}")
        print(f"  Total violations: {repo_score.summary['total_violations']}")
        print(f"  Risk score: {repo_score.total_score:.2f}")
        
    finally:
        import shutil
        shutil.rmtree(temp_dir)

def test_safe_code():
    """Test that safe code produces no violations"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('import hashlib\\n')
        f.write('def safe_function(data):\\n')
        f.write('    return hashlib.sha256(data.encode()).hexdigest()\\n')
        temp_file = f.name
    
    try:
        scanner = HCRSScanner()
        file_score = scanner.scan_file(temp_file, 'python')
        
        # Should have no violations (or only low severity)
        critical_high = [
            v for v in file_score.violations 
            if v.severity in [Severity.CRITICAL, Severity.HIGH]
        ]
        assert len(critical_high) == 0, "Safe code should have no critical/high violations"
        
        print("✓ Safe code test passed")
        print(f"  Total violations: {len(file_score.violations)}")
        
    finally:
        os.unlink(temp_file)

def run_tests():
    """Run all tests"""
    print("Running HCRS Tests...")
    print("=" * 60)
    
    tests = [
        test_hardcoded_secret_detection,
        test_command_injection_detection,
        test_javascript_eval_detection,
        test_repository_scan,
        test_safe_code
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            print(f"\\nRunning {test.__name__}...")
            test()
            passed += 1
        except AssertionError as e:
            print(f"✗ {test.__name__} failed: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ {test.__name__} error: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print()
    print("=" * 60)
    print(f"Tests passed: {passed}/{len(tests)}")
    print(f"Tests failed: {failed}/{len(tests)}")
    
    return failed == 0

if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
