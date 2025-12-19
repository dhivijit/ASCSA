# SLGA run logic
from .detector import detect_secrets
from .graph import build_lineage_graph
from core.contracts import SecretLineage

def run(context) -> SecretLineage:
    secrets = detect_secrets(context.repo_path)
    lineage = build_lineage_graph(secrets, context.git_history)
    return lineage
