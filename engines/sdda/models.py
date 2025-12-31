# SDDA models
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from datetime import datetime

@dataclass
class PipelineRun:
    """Represents a single pipeline execution"""
    run_id: str
    timestamp: datetime
    branch: str
    environment: str
    actor: str  # who/what triggered the pipeline
    secrets_used: List[str] = field(default_factory=list)
    stages: List[str] = field(default_factory=list)
    
@dataclass
class SecretUsage:
    """Tracks how a secret is used in a pipeline run"""
    secret_id: str
    run_id: str
    timestamp: datetime
    stages: Set[str] = field(default_factory=set)
    access_count: int = 0
    actor: str = ""
    environment: str = ""
    branch: str = ""

@dataclass
class BehavioralFeatures:
    """Behavioral characteristics of a secret's usage"""
    secret_id: str
    # Stage features
    stages_used: Set[str] = field(default_factory=set)
    stage_frequency: Dict[str, int] = field(default_factory=dict)
    
    # Access frequency
    total_accesses: int = 0
    avg_accesses_per_run: float = 0.0
    
    # Actor features
    actors: Set[str] = field(default_factory=set)
    actor_frequency: Dict[str, int] = field(default_factory=dict)
    
    # Environment features
    environments: Set[str] = field(default_factory=set)
    environment_frequency: Dict[str, int] = field(default_factory=dict)
    
    # Temporal features
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    total_runs: int = 0

@dataclass
class Baseline:
    """Statistical baseline for a secret's normal behavior"""
    secret_id: str
    window_days: int
    
    # Stage baseline
    normal_stages: Set[str] = field(default_factory=set)
    stage_mean: float = 0.0
    stage_std: float = 0.0
    
    # Frequency baseline
    access_mean: float = 0.0
    access_std: float = 0.0
    
    # Actor baseline
    normal_actors: Set[str] = field(default_factory=set)
    actor_mean: float = 0.0
    actor_std: float = 0.0
    
    # Environment baseline
    normal_environments: Set[str] = field(default_factory=set)
    env_mean: float = 0.0
    env_std: float = 0.0
    
    # Metadata
    sample_count: int = 0
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

@dataclass
class DriftScore:
    """Drift score for a specific feature"""
    feature_name: str
    z_score: float
    is_anomaly: bool
    threshold: float
    current_value: float
    baseline_mean: float
    baseline_std: float
    details: str = ""

@dataclass
class DriftDetection:
    """Complete drift analysis for a secret"""
    secret_id: str
    run_id: str
    timestamp: datetime
    
    # Individual feature scores
    stage_drift: Optional[DriftScore] = None
    frequency_drift: Optional[DriftScore] = None
    actor_drift: Optional[DriftScore] = None
    environment_drift: Optional[DriftScore] = None
    
    # Overall drift
    total_drift_score: float = 0.0
    severity: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    is_drifted: bool = False
    
    # Details
    anomaly_details: List[str] = field(default_factory=list)
    recommendation: str = ""

@dataclass
class DriftReport:
    """Summary report for all detected drifts"""
    run_id: str
    timestamp: datetime
    total_secrets_analyzed: int
    drifted_secrets: List[DriftDetection] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)  # severity counts
    baseline_status: str = "OK"
