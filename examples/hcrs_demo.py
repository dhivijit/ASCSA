#!/usr/bin/env python3
"""
HCRS Demo - Demonstrates the Hybrid Code Risk Scoring Engine

This script creates sample vulnerable code and scans it to show HCRS capabilities.
"""

import os
import tempfile
import shutil
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from engines.hcrs.scanner import HCRSScanner
from engines.hcrs.reporter import HCRSReporter

# Sample vulnerable Python code
VULNERABLE_PYTHON_CODE = '''
import os
import subprocess
import hashlib
import pickle
import yaml

# CRITICAL: Hardcoded secrets
API_KEY = "sk_live_1234567890abcdefghijklmn"
DATABASE_PASSWORD = "SuperSecret123!"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

def process_user_input(user_data):
    """Multiple vulnerabilities in one function"""
    
    # CRITICAL: Command injection
    command = "ls -la " + user_data
    os.system(command)
    
    # HIGH: SQL injection
    query = f"SELECT * FROM users WHERE name = '{user_data}'"
    db.execute(query)
    
    # MEDIUM: Weak cryptography
    password_hash = hashlib.md5(user_data.encode()).hexdigest()
    
    # HIGH: Unsafe deserialization
    data = pickle.loads(user_data)
    config = yaml.load(open('config.yaml'))
    
    # HIGH: Sensitive logging
    print(f"User password: {DATABASE_PASSWORD}")
    logging.info(f"API Key: {API_KEY}")
    
    # CRITICAL: Eval usage
    result = eval(user_data)
    
    return result

def unsafe_file_operations(filename):
    """Path traversal vulnerability"""
    # HIGH: Path traversal
    with open("./data/" + filename, 'r') as f:
        return f.read()

class CryptoUtils:
    """Insecure crypto practices"""
    
    def generate_token(self):
        # MEDIUM: Insecure random
        import random
        return random.randint(1000, 9999)
    
    def encrypt_data(self, data):
        # MEDIUM: Weak hash
        return hashlib.sha1(data.encode()).hexdigest()

# More hardcoded secrets
STRIPE_KEY = "sk_test_abcdefghijklmnopqrstuvwxyz"
GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz123456"
'''

# Sample vulnerable JavaScript code
VULNERABLE_JS_CODE = '''
const crypto = require('crypto');
const child_process = require('child_process');

// CRITICAL: Hardcoded secrets
const API_KEY = "sk_live_1234567890abcdefg";
const DB_PASSWORD = "MySecretPassword123";

function processUserInput(userInput) {
    // CRITICAL: Command injection
    const command = `ls -la ${userInput}`;
    child_process.exec(command, (error, stdout) => {
        console.log(stdout);
    });
    
    // CRITICAL: Eval usage
    const result = eval(userInput);
    
    // HIGH: XSS vulnerability
    document.getElementById('output').innerHTML = userInput;
    
    // HIGH: SQL injection
    const query = `SELECT * FROM users WHERE name = '${userInput}'`;
    db.query(query);
    
    // MEDIUM: Weak crypto
    const hash = crypto.createHash('md5').update(userInput).digest('hex');
    
    return result;
}

// MEDIUM: Insecure random
function generateToken() {
    return Math.random().toString(36).substring(7);
}

// MEDIUM: CORS misconfiguration
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    next();
});

// More XSS
function renderContent(html) {
    document.write(html);
}
'''

def create_test_repository():
    """Create a temporary repository with vulnerable code"""
    temp_dir = tempfile.mkdtemp(prefix='hcrs_demo_')
    
    # Create Python file
    python_file = os.path.join(temp_dir, 'vulnerable_app.py')
    with open(python_file, 'w') as f:
        f.write(VULNERABLE_PYTHON_CODE)
    
    # Create JavaScript file
    js_file = os.path.join(temp_dir, 'vulnerable_app.js')
    with open(js_file, 'w') as f:
        f.write(VULNERABLE_JS_CODE)
    
    # Create a safe file (should have no violations)
    safe_file = os.path.join(temp_dir, 'safe_utils.py')
    with open(safe_file, 'w') as f:
        f.write('''
import hashlib

def safe_hash(data):
    """Uses secure SHA-256"""
    return hashlib.sha256(data.encode()).hexdigest()

def process_data(items):
    """Clean processing logic"""
    return [item.strip() for item in items if item]
''')
    
    print(f"Created test repository at: {temp_dir}")
    return temp_dir

def run_demo():
    """Run HCRS demo"""
    print("=" * 80)
    print("HCRS Demo - Hybrid Code Risk Scoring Engine")
    print("=" * 80)
    print()
    
    # Create test repository
    repo_path = create_test_repository()
    
    try:
        # Initialize scanner
        print("Initializing HCRS scanner...")
        scanner = HCRSScanner()
        
        # Scan repository
        print(f"Scanning repository: {repo_path}")
        print()
        
        repo_score = scanner.scan_repository(repo_path)
        
        # Generate and display report
        print()
        print("=" * 80)
        report = HCRSReporter.generate_text_report(repo_score)
        print(report)
        
        # Save JSON report
        json_output = os.path.join(repo_path, 'hcrs_report.json')
        HCRSReporter.save_report(repo_score, json_output, format='json')
        
        print()
        print(f"📄 JSON report saved to: {json_output}")
        print(f"📁 Test repository location: {repo_path}")
        print()
        print("You can:")
        print(f"  - View the vulnerable code: {repo_path}")
        print(f"  - Check the JSON report: {json_output}")
        print(f"  - Modify config/rules.yaml to customize detection")
        print()
        
    except Exception as e:
        print(f"Error during scan: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Ask if user wants to keep the test repository
        try:
            keep = input("Keep test repository? (y/N): ").strip().lower()
            if keep != 'y':
                shutil.rmtree(repo_path)
                print(f"Cleaned up: {repo_path}")
        except KeyboardInterrupt:
            print()
            print(f"Test repository kept at: {repo_path}")

if __name__ == '__main__':
    run_demo()
