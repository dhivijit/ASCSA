#!/usr/bin/env python3
"""
HCRS CLI - Command-line interface for Hybrid Code Risk Scoring Engine

Usage:
    python -m engines.hcrs.cli scan /path/to/repo
    python -m engines.hcrs.cli scan /path/to/repo --output report.json
    python -m engines.hcrs.cli scan /path/to/repo --format text
"""

import argparse
import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from engines.hcrs.scanner import HCRSScanner
from engines.hcrs.reporter import HCRSReporter

def main():
    parser = argparse.ArgumentParser(
        description='HCRS - Hybrid Code Risk Scoring Engine',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Scan a repository
  python -m engines.hcrs.cli scan /path/to/repo
  
  # Scan with custom rules
  python -m engines.hcrs.cli scan /path/to/repo --rules custom_rules.yaml
  
  # Generate JSON report
  python -m engines.hcrs.cli scan /path/to/repo --output report.json --format json
  
  # Scan specific files
  python -m engines.hcrs.cli scan /path/to/repo --files file1.py file2.js
        '''
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan repository for vulnerabilities')
    scan_parser.add_argument('repo_path', help='Path to repository to scan')
    scan_parser.add_argument('--config', help='Path to custom config file')
    scan_parser.add_argument('--rules', help='Path to custom rules file')
    scan_parser.add_argument('--output', '-o', help='Output file path')
    scan_parser.add_argument('--format', '-f', choices=['json', 'text'], default='text',
                            help='Output format (default: text)')
    scan_parser.add_argument('--files', nargs='+', help='Specific files to scan')
    
    args = parser.parse_args()
    
    if args.command == 'scan':
        scan_repository(args)
    else:
        parser.print_help()
        sys.exit(1)

def scan_repository(args):
    """Execute repository scan"""
    if not os.path.exists(args.repo_path):
        print(f"Error: Repository path not found: {args.repo_path}")
        sys.exit(1)
    
    print("=" * 80)
    print("HCRS - Hybrid Code Risk Scoring Engine")
    print("=" * 80)
    print()
    
    # Create scanner
    scanner = HCRSScanner(args.config, args.rules)
    
    # Scan repository or specific files
    if args.files:
        repo_score = scanner.scan_diff(args.repo_path, args.files)
    else:
        repo_score = scanner.scan_repository(args.repo_path)
    
    # Generate report
    if args.format == 'json':
        report = HCRSReporter.generate_json_report(repo_score)
    else:
        report = HCRSReporter.generate_text_report(repo_score)
    
    # Output report
    if args.output:
        HCRSReporter.save_report(repo_score, args.output, args.format)
        print(f"\nReport saved to: {args.output}")
    else:
        print(report)
    
    # Exit with appropriate code
    if repo_score.critical_count > 0:
        print("\n⛔ Exiting with error code due to critical vulnerabilities")
        sys.exit(2)
    elif repo_score.high_count > 0:
        print("\n⚠️  Exiting with warning code due to high-severity vulnerabilities")
        sys.exit(1)
    else:
        print("\n✅ No critical or high-severity issues found")
        sys.exit(0)

if __name__ == '__main__':
    main()
