# HCRS risk engine
def compute_risk(lineage, drift_report, osv_results):
    score = 0
    breakdown = {}

    breakdown["dependencies"] = len(osv_results) * 10
    breakdown["secret_lineage"] = len(lineage.secrets) * 5
    breakdown["secret_drift"] = len(drift_report.drifts) * 15

    score = sum(breakdown.values())

    if score > 80:
        decision = "BLOCK"
    elif score > 50:
        decision = "WARN"
    else:
        decision = "ALLOW"

    return {
        "total": score,
        "breakdown": breakdown,
        "recommendation": decision
    }
