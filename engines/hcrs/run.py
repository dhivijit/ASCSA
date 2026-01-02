def scan_file(filepath: str):
    """
    Scan a single file for code risks using HCRSScanner.
    Returns a risk report for the file.
    """
    from .scanner import HCRSScanner
    scanner = HCRSScanner()
    return scanner.scan_file(filepath)

def scan_repository(repo_path: str):
    """
    Scan an entire repository for code risks using HCRSScanner.
    Returns a repository risk report.
    """
    from .scanner import HCRSScanner
    scanner = HCRSScanner()
    return scanner.scan_repository(repo_path)
# HCRS run logic - Main entry point
from typing import Optional, List
from .scanner import HCRSScanner
from .models import RepositoryRiskScore
from .osv_scanner import scan_dep_vulns
from .risk_engine import compute_risk
from core.contracts import RiskScore

def run_hcrs(repo_path: str, 
             config_path: str = None,
             rules_path: str = None,
             changed_files: List[str] = None) -> RepositoryRiskScore:
    """
    Main entry point for Hybrid Code Risk Scoring Engine.
    
    Args:
        repo_path: Path to repository to scan
        config_path: Optional path to custom configuration file
        rules_path: Optional path to custom rules file
        changed_files: Optional list of changed files (for PR analysis)
    
    Returns:
        RepositoryRiskScore with complete risk analysis
    """
    scanner = HCRSScanner(config_path, rules_path)
    
    if changed_files:
        # Scan only changed files (PR mode)
        return scanner.scan_diff(repo_path, changed_files)
    else:
        # Full repository scan
        return scanner.scan_repository(repo_path)

def run(lineage, drift_report, context) -> RiskScore:
    """
    Legacy entry point for backward compatibility with orchestrator.
    Integrates HCRS with SLGA lineage and SDDA drift detection.
    """
    from .osv_scanner import scan_dep_vulns
    
    # Scan for dependency vulnerabilities
    osv_results = []
    if hasattr(context, 'repo_path'):
        # Try to find requirements.txt or package.json
        import os
        req_files = [
            os.path.join(context.repo_path, 'requirements.txt'),
            os.path.join(context.repo_path, 'package.json')
        ]
        for req_file in req_files:
            if os.path.exists(req_file):
                try:
                    with open(req_file, 'r') as f:
                        content = f.read()
                    vulns = scan_dep_vulns(content, os.path.basename(req_file))
                    osv_results.extend(vulns)
                except Exception as e:
                    print(f"Error scanning {req_file}: {e}")
    
    # Compute composite risk
    return compute_risk(lineage, drift_report, osv_results)
