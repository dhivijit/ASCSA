# CLI context management
"""Context management for ASCSA-CI pipeline."""

import os
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict
from datetime import datetime
import uuid

logger = logging.getLogger(__name__)

@dataclass
class ScanContext:
    """Context object passed between all engines."""

    # Required fields
    repo_path: str
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)

    # Optional scan parameters
    changed_files: Optional[List[str]] = None
    branch: str = "main"
    environment: str = "development"
    actor: str = "cli-user"

    # CI/CD specific paths (optional)
    ci_config_path: Optional[str] = None
    log_dir: Optional[str] = None
    artifact_dir: Optional[str] = None

    # Configuration paths
    config_path: Optional[str] = None
    rules_path: Optional[str] = None
    thresholds_path: Optional[str] = None

    # Engine control flags
    skip_slga: bool = False
    skip_sdda: bool = False
    skip_hcrs: bool = False

    # Output options
    output_format: str = "console"  # console, json, yaml
    output_file: Optional[str] = None
    verbose: bool = False
    reportout_dir: Optional[str] = None  # Directory for per-engine/main outputs

    # Database configuration
    sdda_db_path: Optional[str] = None
    slga_db_path: Optional[str] = None
    neo4j_uri: Optional[str] = None
    neo4j_user: Optional[str] = None
    neo4j_pass: Optional[str] = None

    def __post_init__(self):
        """Validate and normalize context."""
        # Normalize repo path
        self.repo_path = os.path.abspath(self.repo_path)
        
        # Validate repo exists
        if not os.path.exists(self.repo_path):
            raise ValueError(f"Repository path does not exist: {self.repo_path}")
        
        if not os.path.isdir(self.repo_path):
            raise ValueError(f"Repository path is not a directory: {self.repo_path}")
        
        # Set default config paths if not provided
        if not self.config_path:
            default_config = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                'config', 'thresholds.yaml'
            )
            if os.path.exists(default_config):
                self.config_path = default_config
        
        # Load Neo4j credentials from environment if not provided
        if not self.neo4j_uri:
            self.neo4j_uri = os.environ.get('NEO4J_URI')
        if not self.neo4j_user:
            self.neo4j_user = os.environ.get('NEO4J_USER')
        if not self.neo4j_pass:
            self.neo4j_pass = os.environ.get('NEO4J_PASS')
        
        logger.debug(f"Context created for scan: {self.run_id}")
        logger.debug(f"Repository: {self.repo_path}")
        logger.debug(f"Branch: {self.branch}, Environment: {self.environment}")


def build_context(
    repo_path: str,
    branch: str = None,
    environment: str = None,
    ci_config: str = None,
    log_dir: str = None,
    artifact_dir: str = None,
    changed_files: List[str] = None,
    skip_slga: bool = False,
    skip_sdda: bool = False,
    skip_hcrs: bool = False,
    output_format: str = "console",
    output_file: str = None,
    verbose: bool = False,
    **kwargs
) -> ScanContext:
    """Build a scan context from CLI arguments.
    
    Args:
        repo_path: Path to repository to scan
        branch: Git branch name
        environment: Environment (dev/staging/prod)
        ci_config: Path to CI configuration file
        log_dir: Path to CI logs directory
        artifact_dir: Path to CI artifacts directory
        changed_files: List of changed files (for PR mode)
        skip_slga: Skip Secret Lineage Graph Analysis
        skip_sdda: Skip Secret Drift Detection
        skip_hcrs: Skip Hybrid Code Risk Scoring
        output_format: Output format (console/json/yaml)
        output_file: File to write output to
        verbose: Enable verbose logging
        **kwargs: Additional context parameters
    
    Returns:
        ScanContext object
    """
    # Detect branch from git if not provided
    if not branch:
        try:
            import git
            repo = git.Repo(repo_path)
            branch = repo.active_branch.name
        except Exception as e:
            logger.debug(f"Could not detect git branch: {e}")
            branch = "unknown"
    
    # Detect environment from CI environment variables
    if not environment:
        if os.environ.get('CI'):
            environment = "ci"
        elif os.environ.get('GITHUB_ACTIONS'):
            environment = "github-actions"
        elif os.environ.get('GITLAB_CI'):
            environment = "gitlab-ci"
        else:
            environment = "local"
    
    # Get actor
    actor = kwargs.pop('actor', None) or os.environ.get('USER') or os.environ.get('USERNAME') or "unknown"
    
    # Extract other kwargs that are context attributes
    config_path = kwargs.pop('config_path', None)
    rules_path = kwargs.pop('rules_path', None)
    sdda_db_path = kwargs.pop('sdda_db_path', None)
    slga_db_path = kwargs.pop('slga_db_path', None)
    neo4j_uri = kwargs.pop('neo4j_uri', None)
    neo4j_user = kwargs.pop('neo4j_user', None)
    neo4j_pass = kwargs.pop('neo4j_pass', None)
    reportout_dir = kwargs.pop('reportout_dir', None)

    return ScanContext(
        repo_path=repo_path,
        branch=branch,
        environment=environment,
        actor=actor,
        ci_config_path=ci_config,
        log_dir=log_dir,
        artifact_dir=artifact_dir,
        changed_files=changed_files,
        skip_slga=skip_slga,
        skip_sdda=skip_sdda,
        skip_hcrs=skip_hcrs,
        output_format=output_format,
        output_file=output_file,
        verbose=verbose,
        config_path=config_path,
        rules_path=rules_path,
        sdda_db_path=sdda_db_path,
        slga_db_path=slga_db_path,
        neo4j_uri=neo4j_uri,
        neo4j_user=neo4j_user,
        neo4j_pass=neo4j_pass,
        reportout_dir=reportout_dir
    )
