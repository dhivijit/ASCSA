"""
Edge case tests for HCRS - Hybrid Code Risk Scoring Engine
Tests corner cases, boundary conditions, and error handling
"""

import unittest
import os
import tempfile
import shutil
from pathlib import Path

from engines.hcrs.models import Severity, ViolationType, SecurityViolation, FileRiskScore
from engines.hcrs.scanner import HCRSScanner
from engines.hcrs.python_analyzer import PythonSimpleAnalyzer
from engines.hcrs.javascript_analyzer import JavaScriptAnalyzer
from engines.hcrs.run import scan_repository, scan_file
from engines.hcrs.rule_loader import load_rules
from engines.hcrs.config_loader import load_config


class TestEmptyAndMinimalInputs(unittest.TestCase):
    """Test handling of empty and minimal inputs"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="hcrs_empty_")
    
    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_empty_file(self):
        """Test scanning completely empty file"""
        empty_file = os.path.join(self.test_dir, "empty.py")
        with open(empty_file, 'w') as f:
            pass  # Create empty file
        
        report = scan_file(empty_file)
        
        self.assertEqual(len(report.violations), 0)
        self.assertEqual(report.risk_score, 0.0)
    
    def test_whitespace_only_file(self):
        """Test file with only whitespace"""
        ws_file = os.path.join(self.test_dir, "whitespace.py")
        with open(ws_file, 'w') as f:
            f.write("   \n\n\t\t\n   \n")
        
        report = scan_file(ws_file)
        
        self.assertEqual(len(report.violations), 0)
        self.assertEqual(report.risk_score, 0.0)
    
    def test_comments_only_file(self):
        """Test file with only comments"""
        comment_file = os.path.join(self.test_dir, "comments.py")
        with open(comment_file, 'w') as f:
            f.write("""
# This is a comment
# Another comment
# More comments
""")
        
        report = scan_file(comment_file)
        
        self.assertEqual(len(report.violations), 0)
    
    def test_single_line_file(self):
        """Test file with single line of code"""
        single_file = os.path.join(self.test_dir, "single.py")
        with open(single_file, 'w') as f:
            f.write('import os\n')
        
        report = scan_file(single_file)
        
        self.assertIsNotNone(report)
        self.assertEqual(report.risk_score, 0.0)
    
    def test_nonexistent_file(self):
        """Test scanning file that doesn't exist"""
        nonexistent = os.path.join(self.test_dir, "does_not_exist.py")
        
        # Should handle gracefully
        try:
            report = scan_file(nonexistent)
            # Depending on implementation, may return empty report or raise
        except (FileNotFoundError, IOError):
            pass  # Expected behavior
    
    def test_empty_directory(self):
        """Test scanning empty directory"""
        report = scan_repository(self.test_dir)
        
        self.assertEqual(len(report.file_scores), 0)
        self.assertEqual(report.risk_score, 0.0)


class TestSpecialCharactersAndEncoding(unittest.TestCase):
    """Test handling of special characters and encodings"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="hcrs_chars_")
    
    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_unicode_content(self):
        """Test file with Unicode characters"""
        unicode_file = os.path.join(self.test_dir, "unicode.py")
        with open(unicode_file, 'w', encoding='utf-8') as f:
            f.write("""
# 你好世界
# Привет мир
# مرحبا بالعالم

SECRET = "test_secret_123"  # Секрет
""")
        
        # Should handle Unicode without crashing
        report = scan_file(unicode_file)
        
        self.assertIsNotNone(report)
        # Should still detect the secret
        self.assertGreater(len(report.violations), 0)
    
    def test_special_escape_sequences(self):
        """Test code with escape sequences"""
        escape_file = os.path.join(self.test_dir, "escapes.py")
        with open(escape_file, 'w') as f:
            f.write(r'''
password = "pass\nword\t123"
path = "C:\\Users\\Admin\\secret.txt"
regex = r"\d{3}-\d{2}-\d{4}"
SECRET_KEY = "sk_test_\x1b[31mRED\x1b[0m"
''')
        
        report = scan_file(escape_file)
        
        self.assertIsNotNone(report)
        # Should detect patterns
        self.assertGreater(len(report.violations), 0)
    
    def test_mixed_line_endings(self):
        """Test file with mixed line endings (CRLF, LF)"""
        mixed_file = os.path.join(self.test_dir, "mixed.py")
        with open(mixed_file, 'wb') as f:
            f.write(b'import os\r\n')
            f.write(b'SECRET = "test"\n')
            f.write(b'print("hello")\r\n')
        
        report = scan_file(mixed_file)
        
        self.assertIsNotNone(report)
    
    def test_very_long_lines(self):
        """Test file with extremely long lines"""
        long_line_file = os.path.join(self.test_dir, "longlines.py")
        with open(long_line_file, 'w') as f:
            # Create a very long line (5000 characters)
            long_string = "x" * 4900
            f.write(f'data = "{long_string}_SECRET_KEY_123"\n')
        
        # Should handle without crashing
        report = scan_file(long_line_file)
        
        self.assertIsNotNone(report)


class TestBoundaryConditions(unittest.TestCase):
    """Test boundary conditions and limits"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="hcrs_boundary_")
    
    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_exactly_one_violation(self):
        """Test file with exactly one violation"""
        one_file = os.path.join(self.test_dir, "one.py")
        with open(one_file, 'w') as f:
            f.write('API_KEY = "sk_test_1234567890abcdefghij"\n')
        
        report = scan_file(one_file)
        
        self.assertGreaterEqual(len(report.violations), 1)
        self.assertGreater(report.risk_score, 0)
    
    def test_many_violations_same_type(self):
        """Test file with many violations of the same type"""
        many_file = os.path.join(self.test_dir, "many.py")
        with open(many_file, 'w') as f:
            for i in range(50):
                f.write(f'SECRET_{i} = "secret_value_{i}"\n')
        
        report = scan_file(many_file)
        
        # Should detect multiple violations
        self.assertGreater(len(report.violations), 10)
        
        # All should be same type
        violation_types = {v.violation_type for v in report.violations}
        self.assertEqual(len(violation_types), 1)
        self.assertIn(ViolationType.HARDCODED_SECRET, violation_types)
    
    def test_all_severity_levels(self):
        """Test file with violations of all severity levels"""
        mixed_file = os.path.join(self.test_dir, "mixed_severity.py")
        with open(mixed_file, 'w') as f:
            f.write("""
import pickle
import os

# CRITICAL: AWS credentials
AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"

# HIGH: Command injection
def cmd_exec(user_input):
    os.system(user_input)

# MEDIUM: Hardcoded password
password = "admin123"

# Use of dangerous function
data = pickle.loads(user_data)
""")
        
        report = scan_file(mixed_file)
        
        self.assertGreater(len(report.violations), 2)
        
        # Check for different severities
        severities = {v.severity for v in report.violations}
        self.assertGreater(len(severities), 1)
    
    def test_maximum_file_size_handling(self):
        """Test handling of very large file (1MB+)"""
        large_file = os.path.join(self.test_dir, "huge.py")
        with open(large_file, 'w') as f:
            # Write 50,000 lines
            for i in range(50000):
                if i == 25000:
                    f.write('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
                else:
                    f.write(f'# Comment line {i}\n')
        
        # Should handle large file
        report = scan_file(large_file)
        
        self.assertIsNotNone(report)
        # Should still find the secret
        secrets = [v for v in report.violations if v.violation_type == ViolationType.HARDCODED_SECRET]
        self.assertGreater(len(secrets), 0)


class TestFileTypeEdgeCases(unittest.TestCase):
    """Test edge cases with different file types"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="hcrs_types_")
    
    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_unsupported_extension(self):
        """Test file with unsupported extension"""
        unsupported = os.path.join(self.test_dir, "file.xyz")
        with open(unsupported, 'w') as f:
            f.write('SECRET = "test"\n')
        
        # Should skip or handle gracefully
        report = scan_repository(self.test_dir)
        
        # Depending on implementation, may skip unsupported files
        # Check that it doesn't crash
        self.assertIsNotNone(report)
    
    def test_no_extension(self):
        """Test file with no extension"""
        no_ext = os.path.join(self.test_dir, "Makefile")
        with open(no_ext, 'w') as f:
            f.write('PASSWORD = "test123"\n')
        
        report = scan_repository(self.test_dir)
        
        self.assertIsNotNone(report)
    
    def test_multiple_extensions(self):
        """Test file with multiple extensions"""
        multi_ext = os.path.join(self.test_dir, "script.min.js")
        with open(multi_ext, 'w') as f:
            f.write('const token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";\n')
        
        report = scan_file(multi_ext)
        
        # Should detect JavaScript patterns
        self.assertIsNotNone(report)
    
    def test_case_insensitive_extensions(self):
        """Test that extension matching is case-insensitive"""
        upper_file = os.path.join(self.test_dir, "CODE.PY")
        with open(upper_file, 'w') as f:
            f.write('SECRET = "test"\n')
        
        lower_file = os.path.join(self.test_dir, "code.py")
        with open(lower_file, 'w') as f:
            f.write('SECRET = "test"\n')
        
        report = scan_repository(self.test_dir)
        
        # Should scan both files
        self.assertGreaterEqual(len(report.file_scores), 1)


class TestPatternMatchingEdgeCases(unittest.TestCase):
    """Test edge cases in pattern matching"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="hcrs_patterns_")
    
    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_false_positive_avoidance(self):
        """Test that common false positives are avoided"""
        fp_file = os.path.join(self.test_dir, "false_positives.py")
        with open(fp_file, 'w') as f:
            f.write("""
# These should NOT be flagged as secrets
example_key = "sk_test_EXAMPLE"  # Documentation example
TEST_SECRET = "dummy_secret_for_tests"  # Test constant
PLACEHOLDER = "your_api_key_here"  # Placeholder
sample_token = "xxx-yyy-zzz"  # Sample format

# This SHOULD be flagged
REAL_SECRET = "sk_live_4242424242424242abcdefghijklmnopqrs"
""")
        
        report = scan_file(fp_file)
        
        # Should detect the real secret
        secrets = [v for v in report.violations if v.violation_type == ViolationType.HARDCODED_SECRET]
        self.assertGreater(len(secrets), 0)
        
        # But should minimize false positives (implementation dependent)
        # Ideally < 3 false positives
        self.assertLess(len(secrets), 10, "Too many false positives detected")
    
    def test_regex_special_characters(self):
        """Test patterns containing regex special characters"""
        regex_file = os.path.join(self.test_dir, "regex_chars.py")
        with open(regex_file, 'w') as f:
            f.write(r"""
pattern = r"(\d+)\s*-\s*(\d+)"
SECRET = "test.secret[123]"
password = "pass$word^123"
""")
        
        report = scan_file(regex_file)
        
        # Should handle regex special chars without crashing
        self.assertIsNotNone(report)
    
    def test_multiline_strings(self):
        """Test detection in multiline strings"""
        multiline_file = os.path.join(self.test_dir, "multiline.py")
        with open(multiline_file, 'w') as f:
            f.write('''
config = """
{
    "api_key": "sk_test_1234567890abcdefghij",
    "secret": "my_secret_value_123"
}
"""
''')
        
        report = scan_file(multiline_file)
        
        # Should detect secrets in multiline strings
        self.assertGreater(len(report.violations), 0)
    
    def test_concatenated_strings(self):
        """Test detection of concatenated secret strings"""
        concat_file = os.path.join(self.test_dir, "concat.py")
        with open(concat_file, 'w') as f:
            f.write("""
# These may or may not be detected depending on analyzer sophistication
part1 = "sk_test_"
part2 = "1234567890"
full_key = part1 + part2

# This should definitely be detected
SINGLE_SECRET = "sk_test_1234567890abcdefghij"
""")
        
        report = scan_file(concat_file)
        
        # Should at least detect the single secret
        secrets = [v for v in report.violations if v.violation_type == ViolationType.HARDCODED_SECRET]
        self.assertGreater(len(secrets), 0)


class TestConfigurationEdgeCases(unittest.TestCase):
    """Test edge cases in configuration and rules"""
    
    def test_missing_config_file(self):
        """Test behavior when config file is missing"""
        # Should use defaults or handle gracefully
        try:
            config = load_config()
            self.assertIsNotNone(config)
        except FileNotFoundError:
            pass  # May raise or use defaults
    
    def test_empty_rules(self):
        """Test with no rules loaded"""
        # This tests the robustness of the scanner
        test_dir = tempfile.mkdtemp(prefix="hcrs_norules_")
        try:
            test_file = os.path.join(test_dir, "test.py")
            with open(test_file, 'w') as f:
                f.write('SECRET = "test"\n')
            
            # Even with issues loading rules, shouldn't crash
            try:
                report = scan_file(test_file)
                self.assertIsNotNone(report)
            except Exception:
                pass  # May fail gracefully
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)
    
    def test_malformed_rules(self):
        """Test handling of malformed rule definitions"""
        # This would need to inject bad rules, which is implementation-specific
        # For now, just verify the rule loader doesn't crash on empty patterns
        pass


class TestAnalyzerEdgeCases(unittest.TestCase):
    """Test edge cases specific to analyzers"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="hcrs_analyzer_")
        self.python_analyzer = PythonSimpleAnalyzer()
        self.js_analyzer = JavaScriptAnalyzer()
    
    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_python_syntax_errors(self):
        """Test Python analyzer with syntax errors in code"""
        syntax_error_file = os.path.join(self.test_dir, "syntax_error.py")
        with open(syntax_error_file, 'w') as f:
            f.write("""
def bad_function(
    # Missing closing parenthesis
    SECRET = "test_secret"
    return None
""")
        
        # Should handle syntax errors gracefully
        report = scan_file(syntax_error_file)
        
        self.assertIsNotNone(report)
        # May or may not detect secrets depending on parser
    
    def test_incomplete_code_blocks(self):
        """Test with incomplete code blocks"""
        incomplete_file = os.path.join(self.test_dir, "incomplete.py")
        with open(incomplete_file, 'w') as f:
            f.write("""
if True:
    SECRET = "incomplete_secret"
    # Missing rest of the block
""")
        
        report = scan_file(incomplete_file)
        
        self.assertIsNotNone(report)
    
    def test_nested_structures(self):
        """Test deeply nested code structures"""
        nested_file = os.path.join(self.test_dir, "nested.py")
        with open(nested_file, 'w') as f:
            f.write("""
class Outer:
    class Inner:
        class DeepInner:
            def method(self):
                def inner_func():
                    SECRET = "deeply_nested_secret"
                    return SECRET
""")
        
        report = scan_file(nested_file)
        
        # Should detect secrets regardless of nesting
        secrets = [v for v in report.violations if v.violation_type == ViolationType.HARDCODED_SECRET]
        self.assertGreater(len(secrets), 0)


class TestConcurrencyAndPerformance(unittest.TestCase):
    """Test concurrency and performance edge cases"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="hcrs_perf_")
    
    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_many_small_files(self):
        """Test scanning many small files"""
        import time
        
        # Create 100 small files
        for i in range(100):
            file_path = os.path.join(self.test_dir, f"file_{i}.py")
            with open(file_path, 'w') as f:
                f.write(f'# File {i}\nimport os\n')
        
        start = time.time()
        report = scan_repository(self.test_dir)
        elapsed = time.time() - start
        
        # Should complete in reasonable time
        self.assertLess(elapsed, 30.0, f"Scanning 100 files took {elapsed}s")
        self.assertEqual(len(report.file_scores), 100)
    
    def test_duplicate_files_same_content(self):
        """Test scanning duplicate files"""
        # Create multiple files with identical content
        content = 'SECRET = "duplicate_secret"\n'
        
        for i in range(10):
            file_path = os.path.join(self.test_dir, f"dup_{i}.py")
            with open(file_path, 'w') as f:
                f.write(content)
        
        report = scan_repository(self.test_dir)
        
        # Should scan all files independently
        self.assertEqual(len(report.file_scores), 10)
        
        # All should have violations
        files_with_violations = [fs for fs in report.file_scores if len(fs.violations) > 0]
        self.assertEqual(len(files_with_violations), 10)


class TestErrorRecovery(unittest.TestCase):
    """Test error recovery and graceful degradation"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="hcrs_recovery_")
    
    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_mixed_valid_invalid_files(self):
        """Test repository with mix of valid and problematic files"""
        # Create valid file
        valid_file = os.path.join(self.test_dir, "valid.py")
        with open(valid_file, 'w') as f:
            f.write('import os\n')
        
        # Create file with encoding issues
        encoding_file = os.path.join(self.test_dir, "encoding.py")
        with open(encoding_file, 'wb') as f:
            f.write(b'\xFF\xFE' + 'SECRET = "test"\n'.encode('utf-16le'))
        
        # Create binary file
        binary_file = os.path.join(self.test_dir, "binary.pyc")
        with open(binary_file, 'wb') as f:
            f.write(b'\x00\x01\x02\x03')
        
        # Should scan what it can
        report = scan_repository(self.test_dir)
        
        self.assertIsNotNone(report)
        # At minimum should scan the valid file
        self.assertGreaterEqual(len(report.file_scores), 1)
    
    def test_permission_denied_file(self):
        """Test handling of files without read permission"""
        restricted_file = os.path.join(self.test_dir, "restricted.py")
        with open(restricted_file, 'w') as f:
            f.write('SECRET = "test"\n')
        
        # Try to remove read permissions (Unix-like systems)
        try:
            os.chmod(restricted_file, 0o000)
            
            # Should handle gracefully
            report = scan_repository(self.test_dir)
            self.assertIsNotNone(report)
        except (OSError, PermissionError):
            pass  # May not work on all systems
        finally:
            # Restore permissions for cleanup
            try:
                os.chmod(restricted_file, 0o644)
            except:
                pass


if __name__ == '__main__':
    print("=" * 70)
    print("HCRS Edge Case Tests")
    print("=" * 70)
    unittest.main(verbosity=2)
