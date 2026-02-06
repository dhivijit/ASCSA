#!/usr/bin/env python3
"""
SLGA Commit Scanning Demo
Demonstrates how to use SLGA to scan git commit history for secrets
"""

import os
import sys
import logging

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from engines.slga.run import run_slga
from engines.slga.git_parser import get_all_commits

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def demo_commit_scanning():
    """
    Demonstrates scanning git commits for secrets
    """
    print("=" * 70)
    print("SLGA - Git Commit Content Scanning Demo")
    print("=" * 70)
    
    # Use current repository as example
    repo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    
    if not os.path.exists(os.path.join(repo_path, '.git')):
        print(f"\nError: {repo_path} is not a git repository")
        return
    
    print(f"\nScanning repository: {repo_path}")
    
    # Example 1: Get commits with content
    print("\n" + "=" * 70)
    print("Example 1: Fetching commit history with content")
    print("=" * 70)
    
    commits = get_all_commits(repo_path, max_count=10, fetch_content=True)
    
    print(f"\nFetched {len(commits)} commits")
    for i, commit in enumerate(commits[:3], 1):
        print(f"\n{i}. Commit: {commit.hash[:8]}")
        print(f"   Author: {commit.author}")
        print(f"   Date: {commit.date}")
        print(f"   Message: {commit.message[:50]}...")
        print(f"   Changed files: {len(commit.changed_files)}")
        if commit.secrets_found:
            print(f"   ⚠️  SECRETS FOUND: {len(commit.secrets_found)}")
            for secret in commit.secrets_found[:2]:
                print(f"      - {secret[:30]}...")
        else:
            print(f"   ✓ No secrets detected")
    
    # Example 2: Run full SLGA scan with commit scanning
    print("\n" + "=" * 70)
    print("Example 2: Full SLGA scan with commit history")
    print("=" * 70)
    
    print("\nRunning SLGA with commit scanning enabled...")
    print("(This will scan up to 100 commits for secrets)")
    
    # Run SLGA with commit scanning
    graph, secrets, db_path, propagation = run_slga(
        repo_path=repo_path,
        scan_commits=True,  # Enable commit scanning
        max_commits=50,     # Scan last 50 commits
        store_to_db=True,
        db_path="slga_commit_demo.db"
    )
    
    print(f"\n✓ Scan complete!")
    print(f"  Total secrets found: {len(secrets)}")
    
    # Categorize secrets by source
    file_secrets = [s for s in secrets if s.files]
    commit_secrets = [s for s in secrets if s.secret_type == "commit_history"]
    
    print(f"  - From current files: {len(file_secrets)}")
    print(f"  - From commit history: {len(commit_secrets)}")
    
    if commit_secrets:
        print(f"\n⚠️  Secrets found in git history:")
        for i, secret in enumerate(commit_secrets[:5], 1):
            print(f"  {i}. {secret.value[:40]}...")
            print(f"     Found in commits: {', '.join(c[:8] for c in secret.commits)}")
    
    # Example 3: Show propagation analysis if available
    if propagation:
        print("\n" + "=" * 70)
        print("Example 3: Propagation Analysis")
        print("=" * 70)
        
        print(f"\nAnalyzed {len(propagation['individual_analysis'])} secrets")
        
        for analysis in propagation['individual_analysis'][:3]:
            print(f"\n🔍 Secret: {analysis['secret_value'][:30]}...")
            print(f"   Severity: {analysis['severity']} (Risk Score: {analysis['risk_score']})")
            print(f"   Propagation:")
            print(f"   - Files: {analysis['propagation_scope']['files']}")
            print(f"   - Commits: {analysis['propagation_scope']['commits']}")
            print(f"   - Stages: {analysis['propagation_scope']['stages']}")
            print(f"   - Logs: {analysis['propagation_scope']['logs']}")
            
            if analysis['risk_factors']:
                print(f"   Risk Factors:")
                for factor in analysis['risk_factors']:
                    print(f"   - {factor}")
    
    print("\n" + "=" * 70)
    print("Demo complete!")
    print("=" * 70)
    print(f"\nDatabase saved to: {db_path}")
    print("You can query this database for detailed secret lineage information.")

if __name__ == "__main__":
    try:
        demo_commit_scanning()
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
