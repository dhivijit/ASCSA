# SLGA run logic
import os
from datetime import datetime
from .detector import detect_secrets
from .git_parser import get_commits_for_file
from .graph import build_lineage_graph
from .pipeline_scanner import scan_pipeline_stages, scan_logs_for_secrets, scan_artifacts_for_secrets
from .database import SLGADatabase
from .reporter import SLGAReporter

def run_slga(repo_path, ci_config_path=None, log_dir=None, artifact_dir=None, 
             db_path=None, scan_id=None, store_to_db=True):
    """
    Main entry for Secret Lineage Graph Construction.
    Scans repo, pipeline config, logs, artifacts; builds graph in Neo4j and stores in SQLite.
    
    Args:
        repo_path: Path to repository to scan
        ci_config_path: Path to CI/CD configuration file
        log_dir: Directory containing logs to scan
        artifact_dir: Directory containing artifacts to scan
        db_path: Path to SQLite database (default: slga.db)
        scan_id: Unique identifier for this scan (auto-generated if None)
        store_to_db: Whether to store results in database (default: True)
    
    Returns:
        Tuple of (LineageGraph, secrets, db_path)
    """
    # Detect secrets in repository
    secrets = detect_secrets(repo_path)
    
    # Get commit history for files containing secrets
    file_to_commits = {}
    for secret in secrets:
        for file in secret.files:
            if file not in file_to_commits:
                file_to_commits[file] = get_commits_for_file(repo_path, file)
    
    # Scan pipeline, logs, and artifacts
    secret_values = [s.value for s in secrets]
    stages = scan_pipeline_stages(ci_config_path) if ci_config_path else []
    logs = scan_logs_for_secrets(log_dir, secret_values) if log_dir else []
    artifacts = scan_artifacts_for_secrets(artifact_dir, secret_values) if artifact_dir else []
    
    # Store to database if enabled
    if store_to_db:
        db_path = db_path or "slga.db"
        db = SLGADatabase(db_path)
        scan_id = scan_id or f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Store all secrets and their relationships
        for secret in secrets:
            secret_id = db.store_secret(secret)
            
            # Link secret to files
            for file_path, line_num in zip(secret.files, secret.lines):
                file_id = db.store_file(file_path)
                db.link_secret_to_file(secret_id, file_id, line_num)
                
                # Link files to commits
                if file_path in file_to_commits:
                    for commit in file_to_commits[file_path]:
                        commit_id = db.store_commit(commit)
                        db.link_file_to_commit(file_id, commit_id)
        
        # Store stages and their secret relationships
        for stage in stages:
            stage_id = db.store_stage(stage.name)
            for secret_value in getattr(stage, 'secrets', []):
                # Find corresponding secret
                for secret in secrets:
                    if secret.value == secret_value:
                        secret_id = db.store_secret(secret)
                        db.link_secret_to_stage(secret_id, stage_id)
                        break
        
        # Store logs and their secret relationships
        for log in logs:
            log_id = db.store_log(log.path)
            for secret_value in getattr(log, 'secrets', []):
                for secret in secrets:
                    if secret.value == secret_value:
                        secret_id = db.store_secret(secret)
                        db.link_secret_to_log(secret_id, log_id)
                        break
        
        # Store artifacts and their secret relationships
        for artifact in artifacts:
            artifact_id = db.store_artifact(artifact.path)
            for secret_value in getattr(artifact, 'secrets', []):
                for secret in secrets:
                    if secret.value == secret_value:
                        secret_id = db.store_secret(secret)
                        db.link_secret_to_artifact(secret_id, artifact_id)
                        break
        
        # Store scan history
        db.store_scan_history(
            scan_id=scan_id,
            repo_path=repo_path,
            ci_config_path=ci_config_path,
            log_dir=log_dir,
            artifact_dir=artifact_dir,
            total_secrets=len(secrets),
            total_files=len(set(f for s in secrets for f in s.files)),
            total_commits=len(set(c.hash for commits in file_to_commits.values() for c in commits)),
            total_stages=len(stages),
            total_logs=len(logs),
            total_artifacts=len(artifacts)
        )
        
        db.close()
    
    # Build Neo4j graph if credentials are available
    graph = None
    neo4j_uri = os.environ.get('NEO4J_URI')
    neo4j_user = os.environ.get('NEO4J_USER')
    neo4j_pass = os.environ.get('NEO4J_PASS')
    
    if neo4j_uri and neo4j_user and neo4j_pass:
        graph = build_lineage_graph(
            secrets, file_to_commits, neo4j_uri, neo4j_user, neo4j_pass,
            stages=stages, logs=logs, artifacts=artifacts
        )
    
    return graph, secrets, db_path if store_to_db else None
