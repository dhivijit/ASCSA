"""
SDDA Run — Entry point for Secret Drift Detection Algorithm.

Detects behavioral drift in how secrets are used across CI/CD pipeline
runs by comparing current usage patterns against statistical baselines.

Drift dimensions: stage usage, access frequency, actor identity,
environment, and branch patterns.
"""
from datetime import datetime
from typing import List, Dict, Optional
from .models import PipelineRun, SecretUsage, DriftReport
from .database import SDDADatabase
from .baseline_manager import BaselineManager
from .drift_detector import DriftDetector
import yaml
import os

def load_config(config_path: str = None) -> dict:
    """Load SDDA configuration from YAML file.

    Falls back to built-in defaults if the config file is missing.
    """
    if config_path is None:
        config_path = os.path.join(os.path.dirname(__file__), '..', '..', 'config', 'thresholds.yaml')

    default_config = {
        'sdda': {
            'baseline_window_days': 30,
            'min_samples': 20,
            'zscore_threshold': 3.0,
            'db_path': 'sdda.db'
        }
    }

    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f) or {}
            return config_data.get('sdda', default_config['sdda'])

    return default_config['sdda']

def run_sdda(pipeline_run: PipelineRun,
             secret_usages: List[SecretUsage],
             config_path: str = None,
             db_path: str = None,
             store_report: bool = True) -> DriftReport:
    """Run the Secret Drift Detection Algorithm.

    Args:
        pipeline_run: Current pipeline run metadata.
        secret_usages: List of secret usage events in this run.
        config_path: Path to configuration file (optional).
        db_path: Path to SQLite database (optional).
        store_report: Whether to store the drift report in database.

    Returns:
        DriftReport with detected drifts and baseline status.
    """
    config = load_config(config_path)

    if db_path:
        config['db_path'] = db_path

    db = SDDADatabase(config['db_path'])
    baseline_manager = BaselineManager(db, config)
    drift_detector = DriftDetector(baseline_manager, config)

    db.store_pipeline_run(pipeline_run)

    for usage in secret_usages:
        db.store_secret_usage(usage)

    total_secrets = len(set(usage.secret_id for usage in secret_usages))

    # Handle the "no secrets to analyze" case explicitly
    if total_secrets == 0:
        report = DriftReport(
            run_id=pipeline_run.run_id,
            timestamp=pipeline_run.timestamp,
            total_secrets_analyzed=0,
            drifted_secrets=[],
            summary={'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
            baseline_status="NO_SECRETS_DETECTED"
        )
        if store_report:
            db.store_drift_report(report)
        db.close()
        return report

    # Detect drift for all secrets in this run
    drift_detections = drift_detector.detect_drift_batch(secret_usages)

    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for detection in drift_detections:
        severity_counts[detection.severity] = severity_counts.get(detection.severity, 0) + 1

    # Determine baseline status
    baselines_available = sum(
        1 for usage in secret_usages
        if db.get_baseline(usage.secret_id) is not None
    )

    if baselines_available == 0:
        baseline_status = f"NO_BASELINES (0/{total_secrets} secrets have baselines — first run?)"
    elif baselines_available < total_secrets * 0.5:
        baseline_status = f"INSUFFICIENT_DATA ({baselines_available}/{total_secrets} baselines)"
    else:
        drifted_count = sum(1 for d in drift_detections if d.is_drifted)
        if drifted_count == 0:
            baseline_status = f"OK ({total_secrets} secrets analyzed, no drift detected)"
        else:
            baseline_status = f"DRIFT_DETECTED ({drifted_count}/{total_secrets} secrets drifted)"

    report = DriftReport(
        run_id=pipeline_run.run_id,
        timestamp=pipeline_run.timestamp,
        total_secrets_analyzed=total_secrets,
        drifted_secrets=drift_detections,
        summary=severity_counts,
        baseline_status=baseline_status
    )

    if store_report:
        db.store_drift_report(report)

    db.close()

    return report

def run_sdda_git_diff(
    current_secrets,
    previous_secrets,
    run_id: str,
    timestamp,
) -> DriftReport:
    """
    Stateless SDDA using git-snapshot diff comparison.

    Compares SLGA secrets at the current HEAD against HEAD~1 to detect
    ADDED, REMOVED, and MOVED secrets without a persistent database.
    Suitable for CI/CD pipelines where sdda.db is ephemeral or absent.

    Args:
        current_secrets: List[Secret] from the current HEAD SLGA scan.
        previous_secrets: List[Secret] from the HEAD~1 SLGA scan.
        run_id: Unique identifier for the current pipeline run.
        timestamp: Datetime of the current run.

    Returns:
        DriftReport with detected drift events and baseline_status.
    """
    from .git_drift_detector import diff_snapshots

    detections = diff_snapshots(current_secrets, previous_secrets, run_id, timestamp)

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for d in detections:
        severity_counts[d.severity] = severity_counts.get(d.severity, 0) + 1

    total_current = len(
        {s.value for s in current_secrets if s.files and s.secret_type != "commit_history"}
    )

    if detections:
        baseline_status = f"DRIFT_DETECTED ({len(detections)} change(s) vs HEAD~1)"
    else:
        baseline_status = f"OK (no secret drift vs HEAD~1, {total_current} secret(s) stable)"

    return DriftReport(
        run_id=run_id,
        timestamp=timestamp,
        total_secrets_analyzed=total_current,
        drifted_secrets=detections,
        summary=severity_counts,
        baseline_status=baseline_status,
    )


def rebuild_baselines(config_path: str = None, db_path: str = None) -> int:
    """
    Rebuild all baselines from historical data.
    Useful for initial setup or after configuration changes.
    
    Returns:
        Number of baselines rebuilt
    """
    config = load_config(config_path)
    
    if db_path:
        config['db_path'] = db_path
    
    db = SDDADatabase(config['db_path'])
    baseline_manager = BaselineManager(db, config)
    
    count = baseline_manager.rebuild_all_baselines()
    
    db.close()
    
    return count

def analyze_secret(secret_id: str, 
                   config_path: str = None, 
                   db_path: str = None) -> Dict:
    """
    Analyze a specific secret's historical behavior and current baseline.
    
    Returns:
        Dictionary with behavioral features and baseline statistics
    """
    config = load_config(config_path)
    
    if db_path:
        config['db_path'] = db_path
    
    db = SDDADatabase(config['db_path'])
    baseline_manager = BaselineManager(db, config)
    
    # Get historical usage
    usages = db.get_historical_usage(secret_id, config['baseline_window_days'])
    
    # Get baseline
    baseline = baseline_manager.get_or_create_baseline(secret_id)
    
    # Compute features
    features = baseline_manager.compute_behavioral_features(usages)
    
    analysis = {
        'secret_id': secret_id,
        'total_runs': len(usages),
        'time_window_days': config['baseline_window_days'],
        'behavioral_features': {
            'stages': list(features.stages_used),
            'actors': list(features.actors),
            'environments': list(features.environments),
            'total_accesses': features.total_accesses,
            'avg_accesses_per_run': features.avg_accesses_per_run
        },
        'baseline': None
    }
    
    if baseline:
        analysis['baseline'] = {
            'stage_mean': baseline.stage_mean,
            'stage_std': baseline.stage_std,
            'access_mean': baseline.access_mean,
            'access_std': baseline.access_std,
            'sample_count': baseline.sample_count,
            'updated_at': baseline.updated_at.isoformat()
        }
    
    db.close()
    
    return analysis
