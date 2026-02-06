# SLGA run logic
import os
import logging
from datetime import datetime
from .detector import detect_secrets
from .git_parser import get_commits_for_file
from .graph import build_lineage_graph
from .pipeline_scanner import scan_pipeline_stages, scan_logs_for_secrets, scan_artifacts_for_secrets
from .database import SLGADatabase
from .reporter import SLGAReporter

logger = logging.getLogger(__name__)

def run_slga(repo_path, ci_config_path=None, log_dir=None, artifact_dir=None, 
             db_path=None, scan_id=None, store_to_db=True, scan_commits=True, max_commits=100):
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
        scan_commits: Whether to fetch and scan commit content (default: True)
        max_commits: Maximum commits to scan when scan_commits=True (default: 100)
    
    Returns:
        Tuple of (LineageGraph, secrets, db_path, propagation_analysis)
    """
    # Detect secrets in repository
    secrets = detect_secrets(repo_path)
    
    logger.info(f"Found {len(secrets)} secrets in repository files")
    
    logger.info(f"Found {len(secrets)} secrets in repository files")
    
    # Get commit history for files containing secrets
    file_to_commits = {}
    commit_secrets = []  # Secrets found in commit diffs
    
    if scan_commits:
        logger.info(f"Scanning commit history (max {max_commits} commits)...")
        from .git_parser import get_all_commits
        
        # Scan all commits for secrets in diffs
        all_commits = get_all_commits(repo_path, max_count=max_commits, fetch_content=True)
        logger.info(f"Scanned {len(all_commits)} commits")
        
        # Extract secrets found in commits
        for commit in all_commits:
            if commit.secrets_found:
                for secret_value in commit.secrets_found:
                    # Create Secret object for commit-based secrets
                    from .models import Secret
                    commit_secret = Secret(
                        value=secret_value,
                        secret_type="commit_history",
                        entropy=4.0,  # Approximate
                        files=[],
                        lines=[],
                        commits=[commit.hash]
                    )
                    commit_secrets.append(commit_secret)
                    logger.info(f"Found secret in commit {commit.hash[:8]}: {secret_value[:20]}...")
        
        # Group commits by file for existing file-based secrets
        for secret in secrets:
            for file in secret.files:
                if file not in file_to_commits:
                    file_to_commits[file] = get_commits_for_file(repo_path, file, fetch_content=True)
        
        # Populate secret.commits field with commit hashes from file history
        for secret in secrets:
            commit_hashes = set()
            for file in secret.files:
                if file in file_to_commits:
                    for commit in file_to_commits[file]:
                        commit_hashes.add(commit.hash)
            secret.commits = list(commit_hashes)
                    
        logger.info(f"Found {len(commit_secrets)} additional secrets in commit history")
    else:
        # Original behavior: just get commit metadata
        for secret in secrets:
            for file in secret.files:
                if file not in file_to_commits:
                    file_to_commits[file] = get_commits_for_file(repo_path, file, fetch_content=False)
        
        # Populate secret.commits field even without content scanning
        for secret in secrets:
            commit_hashes = set()
            for file in secret.files:
                if file in file_to_commits:
                    for commit in file_to_commits[file]:
                        commit_hashes.add(commit.hash)
            secret.commits = list(commit_hashes)
    
    # Combine file-based and commit-based secrets
    all_secrets = secrets + commit_secrets
    logger.info(f"Total secrets discovered: {len(all_secrets)}")
    
    # Scan pipeline, logs, and artifacts
    secret_values = [s.value for s in all_secrets]
    stages = scan_pipeline_stages(ci_config_path) if ci_config_path else []
    logs = scan_logs_for_secrets(log_dir, secret_values) if log_dir else []
    artifacts = scan_artifacts_for_secrets(artifact_dir, secret_values) if artifact_dir else []
    
    # Store to database if enabled
    if store_to_db:
        db_path = db_path or "slga.db"
        db = SLGADatabase(db_path)
        scan_id = scan_id or f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Store all secrets and their relationships
        for secret in all_secrets:
            secret_id = db.store_secret(secret)
            
            # Link secret to files (if found in files)
            for file_path, line_num in zip(secret.files, secret.lines):
                file_id = db.store_file(file_path)
                db.link_secret_to_file(secret_id, file_id, line_num)
                
                # Link files to commits
                if file_path in file_to_commits:
                    for commit in file_to_commits[file_path]:
                        commit_id = db.store_commit(commit)
                        db.link_file_to_commit(file_id, commit_id)
            
            # Link secret to commits (if found in commit diffs)
            for commit_hash in secret.commits:
                # Find the full commit object
                for commits_list in file_to_commits.values():
                    for commit in commits_list:
                        if commit.hash == commit_hash:
                            commit_id = db.store_commit(commit)
                            # Create a direct secret-to-commit link for commit-based secrets
                            # (this link differs from file-commit-secret chain)
                            break
        
        # Store stages and their secret relationships
        for stage in stages:
            stage_id = db.store_stage(stage.name)
            for secret_value in getattr(stage, 'secrets', []):
                # Find corresponding secret
                for secret in all_secrets:
                    if secret.value == secret_value:
                        secret_id = db.store_secret(secret)
                        db.link_secret_to_stage(secret_id, stage_id)
                        break
        
        # Store logs and their secret relationships
        for log in logs:
            log_id = db.store_log(log.path)
            for secret_value in getattr(log, 'secrets', []):
                for secret in all_secrets:
                    if secret.value == secret_value:
                        secret_id = db.store_secret(secret)
                        db.link_secret_to_log(secret_id, log_id)
                        break
        
        # Store artifacts and their secret relationships
        for artifact in artifacts:
            artifact_id = db.store_artifact(artifact.path)
            for secret_value in getattr(artifact, 'secrets', []):
                for secret in all_secrets:
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
            total_secrets=len(all_secrets),
            total_files=len(set(f for s in all_secrets for f in s.files)),
            total_commits=len(set(c.hash for commits in file_to_commits.values() for c in commits)),
            total_stages=len(stages),
            total_logs=len(logs),
            total_artifacts=len(artifacts)
        )
        
        db.close()
    
    # Build Neo4j graph if credentials are available
    graph = None
    propagation_analysis = None
    neo4j_uri = os.environ.get('NEO4J_URI')
    neo4j_user = os.environ.get('NEO4J_USER')
    neo4j_pass = os.environ.get('NEO4J_PASSWORD')
    
    if neo4j_uri and neo4j_user and neo4j_pass:
        try:
            graph = build_lineage_graph(
                all_secrets, file_to_commits, neo4j_uri, neo4j_user, neo4j_pass,
                stages=stages, logs=logs, artifacts=artifacts
            )
            logger.info("Neo4j graph successfully created with lineage data")
            
            # Perform propagation analysis on the graph
            logger.info("Performing Neo4j propagation analysis...")
            try:
                propagation_analysis = {
                    'summary': graph.get_all_secrets_propagation_summary(),
                    'critical_chains': graph.find_critical_propagation_chains(),
                    'individual_analysis': []
                }
                
                # Analyze top secrets (limit to 10 for performance)
                for secret in all_secrets[:10]:
                    analysis = graph.analyze_secret_propagation(secret.value)
                    if analysis:
                        propagation_analysis['individual_analysis'].append(analysis)
                
                # Count high-risk secrets
                high_risk_count = sum(1 for a in propagation_analysis['individual_analysis'] 
                                     if a['severity'] in ['CRITICAL', 'HIGH'])
                logger.info(f"Propagation analysis complete: {high_risk_count} high-risk secrets identified")
                
            except Exception as e:
                logger.error(f"Failed to perform propagation analysis: {e}")
                propagation_analysis = None
            
        except Exception as e:
            logger.error(f"Failed to create Neo4j graph: {e}")
            logger.warning("Continuing with SQLite-only storage. Neo4j lineage graph unavailable.")
    else:
        logger.warning("Neo4j credentials not found (NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD). Skipping graph creation. Using SQLite-only storage.")
    
    return graph, all_secrets, db_path if store_to_db else None, propagation_analysis
