# SDDA comparators
import math
from typing import List, Set, Dict, Optional
from .models import BehavioralFeatures, Baseline, DriftScore

def calculate_z_score(value: float, mean: float, std: float) -> float:
    """Calculate Z-score for anomaly detection"""
    if std == 0:
        # If std is 0, check if value differs from mean
        if abs(value - mean) > 0.01:  # Small epsilon for floating point
            return 999.0  # Extremely high z-score to indicate anomaly
        return 0.0
    return abs(value - mean) / std

def calculate_set_similarity(current: Set, baseline: Set) -> float:
    """Calculate Jaccard similarity between two sets"""
    if not baseline:
        return 1.0 if not current else 0.0
    if not current:
        return 0.0
    intersection = len(current & baseline)
    union = len(current | baseline)
    return intersection / union if union > 0 else 0.0

def compare_stage_usage(current_stages: Set[str], 
                        baseline: Baseline, 
                        threshold: float = 3.0) -> DriftScore:
    """Detect drift in pipeline stages accessing the secret"""
    # Check for new/unexpected stages
    new_stages = current_stages - baseline.normal_stages
    similarity = calculate_set_similarity(current_stages, baseline.normal_stages)
    
    # Z-score based on number of stages
    stage_count = len(current_stages)
    z_score = calculate_z_score(stage_count, baseline.stage_mean, baseline.stage_std)
    
    is_anomaly = z_score > threshold or len(new_stages) > 0
    
    details = []
    if new_stages:
        details.append(f"New stages detected: {', '.join(new_stages)}")
    if z_score > threshold:
        details.append(f"Unusual stage count: {stage_count} (baseline: {baseline.stage_mean:.1f})")
    
    return DriftScore(
        feature_name="stage_usage",
        z_score=z_score,
        is_anomaly=is_anomaly,
        threshold=threshold,
        current_value=stage_count,
        baseline_mean=baseline.stage_mean,
        baseline_std=baseline.stage_std,
        details="; ".join(details) if details else "No drift detected"
    )

def compare_frequency(current_access_count: int, 
                      baseline: Baseline, 
                      threshold: float = 3.0) -> DriftScore:
    """Detect drift in access frequency"""
    z_score = calculate_z_score(current_access_count, baseline.access_mean, baseline.access_std)
    is_anomaly = z_score > threshold
    
    details = ""
    if is_anomaly:
        if current_access_count > baseline.access_mean:
            details = f"Spike in access frequency: {current_access_count} (baseline: {baseline.access_mean:.1f})"
        else:
            details = f"Drop in access frequency: {current_access_count} (baseline: {baseline.access_mean:.1f})"
    else:
        details = "Access frequency within normal range"
    
    return DriftScore(
        feature_name="access_frequency",
        z_score=z_score,
        is_anomaly=is_anomaly,
        threshold=threshold,
        current_value=float(current_access_count),
        baseline_mean=baseline.access_mean,
        baseline_std=baseline.access_std,
        details=details
    )

def compare_actors(current_actor: str, 
                   baseline: Baseline, 
                   threshold: float = 3.0) -> DriftScore:
    """Detect drift in actors/identities accessing the secret"""
    is_new_actor = current_actor not in baseline.normal_actors
    
    # Z-score based on actor diversity (number of unique actors)
    z_score = 0.0
    if is_new_actor and baseline.actor_std > 0:
        z_score = threshold + 1  # Force anomaly for new actors
    
    is_anomaly = is_new_actor
    
    details = ""
    if is_new_actor:
        details = f"New actor detected: '{current_actor}' (known actors: {', '.join(list(baseline.normal_actors)[:3])})"
    else:
        details = f"Known actor: '{current_actor}'"
    
    return DriftScore(
        feature_name="actor",
        z_score=z_score,
        is_anomaly=is_anomaly,
        threshold=threshold,
        current_value=1.0 if is_new_actor else 0.0,
        baseline_mean=baseline.actor_mean,
        baseline_std=baseline.actor_std,
        details=details
    )

def compare_environment(current_env: str, 
                        baseline: Baseline, 
                        threshold: float = 3.0) -> DriftScore:
    """Detect drift in environment (critical for prod misuse)"""
    is_new_env = current_env not in baseline.normal_environments
    
    # Critical check: production misuse
    is_prod_misuse = (
        current_env.lower() in ['prod', 'production'] and 
        current_env not in baseline.normal_environments
    )
    
    # Z-score (simplified for environment)
    z_score = 0.0
    if is_new_env:
        z_score = threshold + 2 if is_prod_misuse else threshold + 0.5
    
    is_anomaly = is_new_env
    
    details = ""
    if is_prod_misuse:
        details = f"CRITICAL: Secret used in PRODUCTION for first time! (normal envs: {', '.join(baseline.normal_environments)})"
    elif is_new_env:
        details = f"New environment detected: '{current_env}' (known: {', '.join(baseline.normal_environments)})"
    else:
        details = f"Expected environment: '{current_env}'"
    
    return DriftScore(
        feature_name="environment",
        z_score=z_score,
        is_anomaly=is_anomaly,
        threshold=threshold,
        current_value=1.0 if is_new_env else 0.0,
        baseline_mean=baseline.env_mean,
        baseline_std=baseline.env_std,
        details=details
    )

def calculate_severity(drift_scores: List[DriftScore]) -> str:
    """Calculate overall severity based on individual drift scores"""
    if not drift_scores:
        return "LOW"
    
    max_z = max(score.z_score for score in drift_scores)
    anomaly_count = sum(1 for score in drift_scores if score.is_anomaly)
    
    # Check for production environment drift
    has_prod_drift = any(
        score.feature_name == "environment" and "PRODUCTION" in score.details.upper()
        for score in drift_scores
    )
    
    if has_prod_drift:
        return "CRITICAL"
    elif max_z > 5.0 or anomaly_count >= 3:
        return "HIGH"
    elif max_z > 3.5 or anomaly_count >= 2:
        return "MEDIUM"
    else:
        return "LOW"
