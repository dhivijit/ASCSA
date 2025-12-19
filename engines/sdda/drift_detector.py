# SDDA drift detector
def detect_drift(lineage, environment):
    drifts = []
    for secret in lineage.secrets:
        # example drift rule
        if environment == "production" and "test" in secret.services:
            drifts.append({
                "secret_id": secret.id,
                "drift_type": "ENV_ESCALATION",
                "severity": "HIGH"
            })
    return drifts
