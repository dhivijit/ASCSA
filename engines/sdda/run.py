# SDDA run logic
from .drift_detector import detect_drift
from core.contracts import DriftReport

def run(lineage, context) -> DriftReport:
    drifts = detect_drift(lineage, context.environment)
    return DriftReport(drifts=drifts)
