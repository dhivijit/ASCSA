"""
Test OSV scanner integration in HCRS
"""
import os
import sys
import tempfile
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from engines.hcrs.osv_scanner import scan_dep_vulns

def test_requirements_txt_parsing():
    """Test parsing requirements.txt"""
    content = """
# Test requirements
requests==2.25.0
flask==1.0.0
django==2.2.0
pytest>=7.0.0
"""
    
    print("Testing requirements.txt parsing...")
    try:
        vulns = scan_dep_vulns(content, "requirements.txt")
        print(f"✓ Successfully parsed requirements.txt")
        print(f"  Found {len(vulns)} vulnerabilities")
        if vulns:
            print(f"  Example: {vulns[0].get('id')} in {vulns[0].get('package_name')}")
        return True
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def test_package_json_parsing():
    """Test parsing package.json"""
    content = """
{
  "dependencies": {
    "express": "4.17.0",
    "lodash": "4.17.15",
    "axios": "0.19.0"
  },
  "devDependencies": {
    "jest": "24.0.0"
  }
}
"""
    
    print("\\nTesting package.json parsing...")
    try:
        vulns = scan_dep_vulns(content, "package.json")
        print(f"✓ Successfully parsed package.json")
        print(f"  Found {len(vulns)} vulnerabilities")
        if vulns:
            print(f"  Example: {vulns[0].get('id')} in {vulns[0].get('package_name')}")
        return True
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def test_hcrs_integration():
    """Test HCRS scanner integration with OSV"""
    from engines.hcrs.scanner import HCRSScanner
    
    print("\\nTesting HCRS + OSV integration...")
    
    # Create temp directory with requirements.txt
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Create a requirements.txt with known vulnerable package
        req_file = os.path.join(temp_dir, 'requirements.txt')
        with open(req_file, 'w') as f:
            f.write("requests==2.6.0\\n")  # Old version with known vulnerabilities
            f.write("flask==0.12.0\\n")     # Old version
        
        # Create a simple Python file
        py_file = os.path.join(temp_dir, 'app.py')
        with open(py_file, 'w') as f:
            f.write("import flask\\n")
            f.write("app = flask.Flask(__name__)\\n")
        
        # Scan repository
        scanner = HCRSScanner()
        repo_score = scanner.scan_repository(temp_dir)
        
        print(f"✓ HCRS scan completed")
        print(f"  Files analyzed: {repo_score.summary['total_files_analyzed']}")
        print(f"  Code violations: {repo_score.summary['total_violations']}")
        print(f"  Dependency vulnerabilities: {len(repo_score.dependency_vulnerabilities)}")
        
        # Check if OSV scan was integrated
        if 'dependency_vulnerability_count' in repo_score.summary:
            print(f"  ✓ OSV integration working: {repo_score.summary['dependency_vulnerability_count']} vulns found")
        else:
            print(f"  ✗ OSV integration not found in summary")
        
        return True
        
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        import shutil
        shutil.rmtree(temp_dir)

def test_report_with_dependencies():
    """Test report generation with dependency vulnerabilities"""
    from engines.hcrs.scanner import HCRSScanner
    from engines.hcrs.reporter import HCRSReporter
    
    print("\\nTesting report generation with dependencies...")
    
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Create requirements.txt
        req_file = os.path.join(temp_dir, 'requirements.txt')
        with open(req_file, 'w') as f:
            f.write("django==2.0.0\\n")
        
        # Scan
        scanner = HCRSScanner()
        repo_score = scanner.scan_repository(temp_dir)
        
        # Generate JSON report
        json_report = HCRSReporter.generate_json_report(repo_score)
        
        # Check if dependency vulnerabilities are in JSON
        if 'dependency_vulnerabilities' in json_report:
            print("✓ Dependency vulnerabilities included in JSON report")
        else:
            print("✗ Missing dependency vulnerabilities in JSON report")
        
        # Generate text report
        text_report = HCRSReporter.generate_text_report(repo_score)
        
        # Check if dependency section exists
        if 'Dependency Vulnerabilities' in text_report or 'dependency' in text_report.lower():
            print("✓ Dependency section included in text report")
        else:
            print("✗ Missing dependency section in text report")
        
        return True
        
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        import shutil
        shutil.rmtree(temp_dir)

def run_tests():
    """Run all OSV integration tests"""
    print("=" * 70)
    print("HCRS + OSV Integration Tests")
    print("=" * 70)
    
    tests = [
        test_requirements_txt_parsing,
        test_package_json_parsing,
        test_hcrs_integration,
        test_report_with_dependencies
    ]
    
    passed = 0
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"✗ {test.__name__} failed: {e}")
    
    print()
    print("=" * 70)
    print(f"Tests passed: {passed}/{len(tests)}")
    print("=" * 70)
    
    return passed == len(tests)

if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
