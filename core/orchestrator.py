# Core orchestrator logic
from engines.slga.run import run as run_slga
from engines.sdda.run import run as run_sdda
from engines.hcrs.run import run as run_hcrs

def run_pipeline(context):
    lineage = run_slga(context)
    drift = run_sdda(lineage, context)
    risk = run_hcrs(lineage, drift, context)
    return risk
