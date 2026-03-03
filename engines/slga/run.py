"""
SLGA Run — Entry point for Secret Lineage Graph Analysis.

Orchestrates the full SLGA pipeline:
  1. Detect secrets in repository files (with scan coverage tracking)
  2. Scan git commit history for secrets in diffs
  3. Scan CI/CD pipeline configs, logs, and artifacts
  4. Store results in SQLite database
  5. Build Neo4j lineage graph (if credentials available)
  6. Perform propagation analysis on the graph

Returns a 5-tuple: (graph, secrets, db_path, propagation_analysis, scan_stats).
"""
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
             db_path=None, scan_id=None, store_to_db=True, scan_commits=True, max_commits=100,
             enable_code_analysis=True):
    """Main entry for Secret Lineage Graph Construction.

    Scans repo, pipeline config, logs, and artifacts; builds graph in Neo4j
    and stores in SQLite.

    Args:
        repo_path: Path to repository to scan.
        ci_config_path: Path to CI/CD configuration file.
        log_dir: Directory containing logs to scan.
        artifact_dir: Directory containing artifacts to scan.
        db_path: Path to SQLite database (default: slga.db).
        scan_id: Unique identifier for this scan (auto-generated if None).
        store_to_db: Whether to store results in database (default: True).
        scan_commits: Whether to fetch and scan commit content (default: True).
        max_commits: Maximum commits to scan when scan_commits=True (default: 100).
        enable_code_analysis: Whether to run tree-sitter code symbol analysis (default: True).
            No-op when tree-sitter is not installed.

    Returns:
        Tuple of (LineageGraph, secrets, db_path, propagation_analysis, scan_stats)
        where scan_stats contains coverage metrics from detect_secrets.
    """
    # Detect secrets in repository (now returns scan_stats too)
    secrets, scan_stats = detect_secrets(repo_path, ci_config_path, log_dir, artifact_dir)

    logger.info(f"Found {len(secrets)} secrets in repository files "
                f"(scanned {scan_stats['files_scanned']} files across "
                f"{scan_stats['directories_walked']} directories)")
    
    # Get commit history for files containing secrets
    file_to_commits = {}
    commit_secrets = []  # Secrets found in commit diffs
    
    if scan_commits:
        logger.info(f"Scanning commit history (max {max_commits} commits)...")
        from .git_parser import get_all_commits
        
        # Scan all commits for secrets in diffs
        all_commits = get_all_commits(repo_path, max_count=max_commits, fetch_content=True)
        logger.info(f"Scanned {len(all_commits)} commits")
        scan_stats['commits_scanned'] = len(all_commits)
        
        # Extract secrets found in commits
        for commit in all_commits:
            if commit.secrets_found:
                for secret_value in commit.secrets_found:
                    from .models import Secret
                    commit_secret = Secret(
                        value=secret_value,
                        secret_type="commit_history",
                        entropy=4.0,
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
        scan_stats['commits_scanned'] = 0
        # Original behavior: just get commit metadata
        for secret in secrets:
            for file in secret.files:
                if file not in file_to_commits:
                    file_to_commits[file] = get_commits_for_file(repo_path, file, fetch_content=False)
        
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
        
        for secret in all_secrets:
            secret_id = db.store_secret(secret)
            for file_path, line_num in zip(secret.files, secret.lines):
                file_id = db.store_file(file_path)
                db.link_secret_to_file(secret_id, file_id, line_num)
                if file_path in file_to_commits:
                    for commit in file_to_commits[file_path]:
                        commit_id = db.store_commit(commit)
                        db.link_file_to_commit(file_id, commit_id)
            for commit_hash in secret.commits:
                for commits_list in file_to_commits.values():
                    for commit in commits_list:
                        if commit.hash == commit_hash:
                            db.store_commit(commit)
                            break
        
        for stage in stages:
            stage_id = db.store_stage(stage.name)
            for secret_value in getattr(stage, 'secrets', []):
                for secret in all_secrets:
                    if secret.value == secret_value:
                        secret_id = db.store_secret(secret)
                        db.link_secret_to_stage(secret_id, stage_id)
                        break
        
        for log in logs:
            log_id = db.store_log(log.path)
            for secret_value in getattr(log, 'secrets', []):
                for secret in all_secrets:
                    if secret.value == secret_value:
                        secret_id = db.store_secret(secret)
                        db.link_secret_to_log(secret_id, log_id)
                        break
        
        for artifact in artifacts:
            artifact_id = db.store_artifact(artifact.path)
            for secret_value in getattr(artifact, 'secrets', []):
                for secret in all_secrets:
                    if secret.value == secret_value:
                        secret_id = db.store_secret(secret)
                        db.link_secret_to_artifact(secret_id, artifact_id)
                        break
        
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

    # --- Code symbol analysis (tree-sitter) & git context (GitPython) ---
    code_analysis = None
    git_context = None

    if enable_code_analysis:
        try:
            from .code_parser import CodeParser, _TS_AVAILABLE
            logger.info(f"Code analysis engine: {'tree-sitter (AST)' if _TS_AVAILABLE else 'disabled (tree-sitter not installed)'}")
            parser = CodeParser()
            code_analysis = parser.parse_directory(repo_path)
            if code_analysis:
                total_functions = sum(s.function_count for s in code_analysis)
                total_classes = sum(s.class_count for s in code_analysis)
                total_variables = sum(s.variable_count for s in code_analysis)
                total_imports = sum(s.import_count for s in code_analysis)
                total_call_edges = sum(len(s.call_edges) for s in code_analysis)
                logger.info(
                    f"Code analysis: {len(code_analysis)} files parsed — "
                    f"{total_functions} functions, {total_classes} classes, "
                    f"{total_imports} imports, {total_call_edges} call edges"
                )
                scan_stats['code_analysis'] = {
                    'files_parsed': len(code_analysis),
                    'total_functions': total_functions,
                    'total_classes': total_classes,
                    'total_variables': total_variables,
                    'total_imports': total_imports,
                    'total_call_edges': total_call_edges,
                    'languages': list({s.language for s in code_analysis}),
                }
            else:
                logger.info("Code analysis: no parseable files found (tree-sitter grammars may not be installed)")
                scan_stats['code_analysis'] = None
        except Exception as e:
            logger.warning(f"Code analysis failed: {e}")
            scan_stats['code_analysis'] = None

        try:
            from .git_context import GitContextAnalyzer
            git_analyzer = GitContextAnalyzer(repo_path)
            git_context = git_analyzer.analyze_repository(max_files=200, max_commits=max_commits)
            if git_context:
                logger.info(
                    f"Git context: {git_context['total_commits']} commits, "
                    f"{len(git_context['contributors'])} contributors, "
                    f"{len(git_context['hotspots'])} hotspot(s)"
                )
                scan_stats['git_context'] = {
                    'total_commits': git_context['total_commits'],
                    'total_contributors': len(git_context['contributors']),
                    'total_files_analyzed': git_context['total_files_analyzed'],
                    'hotspot_count': len(git_context['hotspots']),
                    'contributors': [
                        {'name': c.name, 'email': c.email, 'commits': c.commits_count}
                        for c in git_context['contributors']
                    ],
                    'hotspots': [h.file_path for h in git_context['hotspots']],
                }
        except Exception as e:
            logger.warning(f"Git context analysis failed: {e}")
            scan_stats['git_context'] = None
    
    if neo4j_uri and neo4j_user and neo4j_pass:
        try:
            logger.info(f"Connecting to Neo4j at {neo4j_uri} and building lineage graph...")
            graph = build_lineage_graph(
                all_secrets, file_to_commits, neo4j_uri, neo4j_user, neo4j_pass,
                stages=stages, logs=logs, artifacts=artifacts,
                code_analysis=code_analysis, git_context=git_context,
            )
            logger.info("Neo4j graph successfully created with lineage data")
            
            logger.info("Performing Neo4j propagation analysis...")
            try:
                propagation_analysis = {
                    'summary': graph.get_all_secrets_propagation_summary(),
                    'critical_chains': graph.find_critical_propagation_chains(),
                    'individual_analysis': []
                }
                
                for secret in all_secrets[:10]:
                    analysis = graph.analyze_secret_propagation(secret.value)
                    if analysis:
                        propagation_analysis['individual_analysis'].append(analysis)
                
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
        logger.warning("Neo4j credentials not found. Skipping graph creation. Using SQLite-only storage.")
    
    return graph, all_secrets, db_path if store_to_db else None, propagation_analysis, scan_stats
