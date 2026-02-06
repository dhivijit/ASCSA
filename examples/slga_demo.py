#!/usr/bin/env python3
"""
SLGA (Shift Left Git Analysis) Demo
Demonstrates secret detection and lineage tracking
"""

import os
import sys
import logging

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from engines.slga.run import run_slga

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def main():
    print("=" * 70)
    print("SLGA - Shift Left Git Analysis Demo")
    print("=" * 70)
    
    # Use current repository as example
    repo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    
    print(f"\nScanning repository: {repo_path}")
    
    # Run SLGA with all features enabled
    # NEW: scan_commits parameter enables git history scanning
    graph, secrets, db_path, propagation = run_slga(
        repo_path=repo_path,
        scan_commits=True,      # NEW: Scan git commit history
        max_commits=100,        # NEW: Maximum commits to scan
        store_to_db=True,
        db_path="slga.db"
    )
    
    print(f"\n✓ Scan complete!")
    print(f"  Total secrets found: {len(secrets)}")
    print(f"  Database: {db_path}")
    
    # Show secret breakdown
    file_secrets = [s for s in secrets if s.files]
    commit_secrets = [s for s in secrets if s.secret_type == "commit_history"]
    
    print(f"\n📊 Secret Sources:")
    print(f"  - Current files: {len(file_secrets)}")
    print(f"  - Git history: {len(commit_secrets)}")
    
    if propagation:
        print(f"\n🔍 Propagation Analysis:")
        high_risk = sum(1 for a in propagation['individual_analysis'] 
                       if a['severity'] in ['CRITICAL', 'HIGH'])
        print(f"  - High-risk secrets: {high_risk}")
    
    print("\n" + "=" * 70)

if __name__ == "__main__":
    main()
