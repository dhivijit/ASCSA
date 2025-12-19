# HCRS run logic
from .osv_scanner import scan_dependencies
from .risk_engine import compute_risk
from core.contracts import RiskScore

def run(lineage, drift_report, context) -> RiskScore:
    osv_results = scan_dependencies(context.repo_path)
    return compute_risk(lineage, drift_report, osv_results)
