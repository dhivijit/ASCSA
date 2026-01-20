#!/usr/bin/env python3
"""
Example: Using ASCSA-CI with Cloud Upload

This example demonstrates how to run ASCSA-CI scans and 
automatically upload reports to cloud storage (S3/R2).
"""

import os
import sys

def main():
    print("=" * 60)
    print("ASCSA-CI Cloud Upload Example")
    print("=" * 60)
    print()
    
    # Check if environment variables are set
    print("Checking environment variables...")
    
    required_vars = {
        'bucket': os.getenv('R2_BUCKET_NAME') or os.getenv('S3_BUCKET_NAME'),
        'access_key': os.getenv('R2_ACCESS_KEY_ID') or os.getenv('AWS_ACCESS_KEY_ID'),
        'secret_key': os.getenv('R2_SECRET_ACCESS_KEY') or os.getenv('AWS_SECRET_ACCESS_KEY'),
    }
    
    optional_vars = {
        'endpoint': os.getenv('R2_ENDPOINT_URL') or os.getenv('S3_ENDPOINT_URL'),
    }
    
    # Validate required variables
    missing = [k for k, v in required_vars.items() if not v]
    
    if missing:
        print("❌ Missing required environment variables:")
        print()
        print("Please set the following environment variables:")
        print()
        print("For Cloudflare R2:")
        print("  export R2_BUCKET_NAME='your-bucket-name'")
        print("  export R2_ACCESS_KEY_ID='your-access-key-id'")
        print("  export R2_SECRET_ACCESS_KEY='your-secret-key'")
        print("  export R2_ENDPOINT_URL='https://account-id.r2.cloudflarestorage.com'")
        print()
        print("For AWS S3:")
        print("  export S3_BUCKET_NAME='your-bucket-name'")
        print("  export AWS_ACCESS_KEY_ID='your-access-key-id'")
        print("  export AWS_SECRET_ACCESS_KEY='your-secret-key'")
        print()
        return 1
    
    print("✓ Bucket:", required_vars['bucket'])
    print("✓ Access key: ***" + required_vars['access_key'][-4:])
    print("✓ Secret key: ***" + required_vars['secret_key'][-4:])
    if optional_vars['endpoint']:
        print("✓ Endpoint:", optional_vars['endpoint'])
    print()
    
    # Check if boto3 is installed
    try:
        import boto3
        print("✓ boto3 is installed (version {})".format(boto3.__version__))
    except ImportError:
        print("❌ boto3 is not installed")
        print()
        print("Install it with: pip install boto3")
        print()
        return 1
    
    print()
    print("=" * 60)
    print("Example Commands")
    print("=" * 60)
    print()
    
    print("1. Scan current directory and upload reports:")
    print("   ascsa . --upload")
    print()
    
    print("2. Scan with custom upload prefix:")
    print("   ascsa . --upload --upload-prefix 'scans/2026-01-19/my-project/'")
    print()
    
    print("3. Quick scan (HCRS only) with upload:")
    print("   ascsa . --skip-slga --skip-sdda --upload")
    print()
    
    print("4. Upload existing reports manually:")
    print("   python upload_reports.py /path/to/reports")
    print()
    
    print("5. List uploaded files:")
    print("   python upload_reports.py --list")
    print()
    
    print("=" * 60)
    print("Example Usage in CI/CD")
    print("=" * 60)
    print()
    
    print("GitHub Actions:")
    print("""
  - name: Run Security Scan
    env:
      R2_BUCKET_NAME: ${{ secrets.R2_BUCKET_NAME }}
      R2_ACCESS_KEY_ID: ${{ secrets.R2_ACCESS_KEY_ID }}
      R2_SECRET_ACCESS_KEY: ${{ secrets.R2_SECRET_ACCESS_KEY }}
      R2_ENDPOINT_URL: ${{ secrets.R2_ENDPOINT_URL }}
    run: |
      ascsa . --upload --upload-prefix "scans/${{ github.repository }}/${{ github.run_number }}/"
""")
    
    print()
    print("=" * 60)
    
    # Ask if user wants to run a test upload
    print()
    response = input("Would you like to test the upload with a quick scan? (y/N): ")
    
    if response.lower() == 'y':
        print()
        print("Running test scan with upload...")
        print()
        
        # Run the scan
        import subprocess
        result = subprocess.run([
            sys.executable, '-m', 'cli.main',
            '.',
            '--skip-slga',
            '--skip-sdda',
            '--upload',
            '--upload-prefix', 'test-scans/',
            '--verbose'
        ])
        
        return result.returncode
    else:
        print()
        print("Skipping test. You can run commands manually using the examples above.")
        return 0


if __name__ == '__main__':
    sys.exit(main())
