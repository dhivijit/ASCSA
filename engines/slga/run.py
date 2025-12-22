# SLGA run logic
import os
from .detector import detect_secrets
from .git_parser import get_commits_for_file
from .graph import build_lineage_graph
from .pipeline_scanner import scan_pipeline_stages, scan_logs_for_secrets, scan_artifacts_for_secrets

def run_slga(repo_path, ci_config_path=None, log_dir=None, artifact_dir=None):
    """
    Main entry for Secret Lineage Graph Construction.
    Scans repo, pipeline config, logs, artifacts; builds graph in Neo4j.
    """
    secrets = detect_secrets(repo_path)
    file_to_commits = {}
    for secret in secrets:
        for file in secret.files:
            if file not in file_to_commits:
                file_to_commits[file] = get_commits_for_file(repo_path, file)

    secret_values = [s.value for s in secrets]
    stages = scan_pipeline_stages(ci_config_path) if ci_config_path else []
    logs = scan_logs_for_secrets(log_dir, secret_values) if log_dir else []
    artifacts = scan_artifacts_for_secrets(artifact_dir, secret_values) if artifact_dir else []

    neo4j_uri = os.environ.get('NEO4J_URI')
    neo4j_user = os.environ.get('NEO4J_USER')
    neo4j_pass = os.environ.get('NEO4J_PASS')
    if not (neo4j_uri and neo4j_user and neo4j_pass):
        raise RuntimeError("NEO4J credentials must be set in environment for secure operation.")

    graph = build_lineage_graph(
        secrets, file_to_commits, neo4j_uri, neo4j_user, neo4j_pass,
        stages=stages, logs=logs, artifacts=artifacts
    )
    return graph
