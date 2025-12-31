# SDDA drift detector
from datetime import datetime
from typing import List, Optional
from .models import SecretUsage, Baseline, DriftDetection, DriftScore
from .comparators import (
    compare_stage_usage,
    compare_frequency,
    compare_actors,
    compare_environment,
    calculate_severity
)
from .baseline_manager import BaselineManager

class DriftDetector:
    """Detects behavioral drift in secret usage"""
    
    def __init__(self, baseline_manager: BaselineManager, config: dict):
        self.baseline_manager = baseline_manager
        self.zscore_threshold = config.get('zscore_threshold', 3.0)
    
    def detect_drift(self, secret_usage: SecretUsage) -> Optional[DriftDetection]:
        """
        Detect drift for a single secret usage event.
        Returns DriftDetection if drift is found, None otherwise.
        """
        # Get or create baseline
        baseline = self.baseline_manager.get_or_create_baseline(secret_usage.secret_id)
        
        if not baseline:
            # Not enough historical data to establish baseline
            return None
        
        # Compare each behavioral feature
        drift_scores = []
        
        # 1. Stage drift
        stage_drift = compare_stage_usage(
            secret_usage.stages,
            baseline,
            self.zscore_threshold
        )
        drift_scores.append(stage_drift)
        
        # 2. Frequency drift
        frequency_drift = compare_frequency(
            secret_usage.access_count,
            baseline,
            self.zscore_threshold
        )
        drift_scores.append(frequency_drift)
        
        # 3. Actor drift
        actor_drift = compare_actors(
            secret_usage.actor,
            baseline,
            self.zscore_threshold
        )
        drift_scores.append(actor_drift)
        
        # 4. Environment drift
        environment_drift = compare_environment(
            secret_usage.environment,
            baseline,
            self.zscore_threshold
        )
        drift_scores.append(environment_drift)
        
        # Calculate overall drift
        total_drift_score = sum(score.z_score for score in drift_scores)
        severity = calculate_severity(drift_scores)
        is_drifted = any(score.is_anomaly for score in drift_scores)
        
        # Collect anomaly details
        anomaly_details = [
            score.details for score in drift_scores if score.is_anomaly
        ]
        
        # Generate recommendation
        recommendation = self._generate_recommendation(drift_scores, severity)
        
        detection = DriftDetection(
            secret_id=secret_usage.secret_id,
            run_id=secret_usage.run_id,
            timestamp=secret_usage.timestamp,
            stage_drift=stage_drift,
            frequency_drift=frequency_drift,
            actor_drift=actor_drift,
            environment_drift=environment_drift,
            total_drift_score=total_drift_score,
            severity=severity,
            is_drifted=is_drifted,
            anomaly_details=anomaly_details,
            recommendation=recommendation
        )
        
        return detection if is_drifted else None
    
    def detect_drift_batch(self, secret_usages: List[SecretUsage]) -> List[DriftDetection]:
        """Detect drift for multiple secret usage events"""
        detections = []
        
        for usage in secret_usages:
            detection = self.detect_drift(usage)
            if detection:
                detections.append(detection)
        
        return detections
    
    def _generate_recommendation(self, drift_scores: List[DriftScore], severity: str) -> str:
        """Generate actionable recommendation based on drift patterns"""
        recommendations = []
        
        for score in drift_scores:
            if not score.is_anomaly:
                continue
            
            if score.feature_name == "stage_usage":
                recommendations.append(
                    "Review pipeline configuration - secret accessed by unexpected stages. "
                    "Consider restricting secret scope in CI/CD configuration."
                )
            
            elif score.feature_name == "access_frequency":
                if score.current_value > score.baseline_mean:
                    recommendations.append(
                        "Investigate spike in secret access frequency. "
                        "Possible causes: retry loops, new service integration, or malicious activity."
                    )
                else:
                    recommendations.append(
                        "Unusual drop in secret access frequency detected. "
                        "Verify pipeline functionality and secret availability."
                    )
            
            elif score.feature_name == "actor":
                recommendations.append(
                    "New actor/identity detected accessing secret. "
                    "Verify this is authorized. Review IAM policies and audit logs."
                )
            
            elif score.feature_name == "environment":
                if "PRODUCTION" in score.details.upper():
                    recommendations.append(
                        "CRITICAL: Secret accessed in production environment for the first time. "
                        "Immediately verify authorization. Consider rotating the secret. "
                        "Review all access logs."
                    )
                else:
                    recommendations.append(
                        "Secret accessed in new environment. "
                        "Verify this is intentional and environment-specific secrets are in use."
                    )
        
        if not recommendations:
            return "No immediate action required."
        
        return " ".join(recommendations)
