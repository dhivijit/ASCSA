# SDDA baseline manager
import statistics
from datetime import datetime
from typing import List, Optional
from .models import SecretUsage, Baseline, BehavioralFeatures
from .database import SDDADatabase

class BaselineManager:
    """Manages baseline creation and updates"""
    
    def __init__(self, db: SDDADatabase, config: dict):
        self.db = db
        self.window_days = config.get('baseline_window_days', 30)
        self.min_samples = config.get('min_samples', 20)
    
    def compute_behavioral_features(self, usages: List[SecretUsage]) -> BehavioralFeatures:
        """Extract behavioral features from usage history"""
        if not usages:
            return BehavioralFeatures(secret_id="unknown")
        
        secret_id = usages[0].secret_id
        
        # Aggregate stages
        all_stages = set()
        stage_freq = {}
        for usage in usages:
            for stage in usage.stages:
                all_stages.add(stage)
                stage_freq[stage] = stage_freq.get(stage, 0) + 1
        
        # Aggregate actors
        all_actors = set()
        actor_freq = {}
        for usage in usages:
            all_actors.add(usage.actor)
            actor_freq[usage.actor] = actor_freq.get(usage.actor, 0) + 1
        
        # Aggregate environments
        all_envs = set()
        env_freq = {}
        for usage in usages:
            all_envs.add(usage.environment)
            env_freq[usage.environment] = env_freq.get(usage.environment, 0) + 1
        
        # Calculate access statistics
        total_accesses = sum(usage.access_count for usage in usages)
        avg_accesses = total_accesses / len(usages) if usages else 0.0
        
        # Temporal info
        timestamps = [usage.timestamp for usage in usages]
        first_seen = min(timestamps) if timestamps else None
        last_seen = max(timestamps) if timestamps else None
        
        return BehavioralFeatures(
            secret_id=secret_id,
            stages_used=all_stages,
            stage_frequency=stage_freq,
            total_accesses=total_accesses,
            avg_accesses_per_run=avg_accesses,
            actors=all_actors,
            actor_frequency=actor_freq,
            environments=all_envs,
            environment_frequency=env_freq,
            first_seen=first_seen,
            last_seen=last_seen,
            total_runs=len(usages)
        )
    
    def create_baseline(self, secret_id: str) -> Optional[Baseline]:
        """Create baseline from historical usage data"""
        # Get historical data
        usages = self.db.get_historical_usage(secret_id, self.window_days)
        
        # Check minimum sample requirement
        if len(usages) < self.min_samples:
            return None
        
        # Extract features
        features = self.compute_behavioral_features(usages)
        
        # Calculate statistics for stages
        stage_counts = [len(usage.stages) for usage in usages]
        stage_mean = statistics.mean(stage_counts) if stage_counts else 0.0
        stage_std = statistics.stdev(stage_counts) if len(stage_counts) > 1 else 0.0
        
        # Calculate statistics for access frequency
        access_counts = [usage.access_count for usage in usages]
        access_mean = statistics.mean(access_counts) if access_counts else 0.0
        access_std = statistics.stdev(access_counts) if len(access_counts) > 1 else 0.0
        
        # Actor statistics (diversity)
        actor_counts = list(features.actor_frequency.values())
        actor_mean = statistics.mean(actor_counts) if actor_counts else 0.0
        actor_std = statistics.stdev(actor_counts) if len(actor_counts) > 1 else 0.0
        
        # Environment statistics
        env_counts = list(features.environment_frequency.values())
        env_mean = statistics.mean(env_counts) if env_counts else 0.0
        env_std = statistics.stdev(env_counts) if len(env_counts) > 1 else 0.0
        
        baseline = Baseline(
            secret_id=secret_id,
            window_days=self.window_days,
            normal_stages=features.stages_used,
            stage_mean=stage_mean,
            stage_std=stage_std,
            access_mean=access_mean,
            access_std=access_std,
            normal_actors=features.actors,
            actor_mean=actor_mean,
            actor_std=actor_std,
            normal_environments=features.environments,
            env_mean=env_mean,
            env_std=env_std,
            sample_count=len(usages),
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        return baseline
    
    def update_baseline(self, secret_id: str) -> Optional[Baseline]:
        """Update baseline with new data (rolling window)"""
        baseline = self.create_baseline(secret_id)
        if baseline:
            self.db.store_baseline(baseline)
        return baseline
    
    def get_or_create_baseline(self, secret_id: str) -> Optional[Baseline]:
        """Get existing baseline or create new one"""
        baseline = self.db.get_baseline(secret_id)
        
        if baseline:
            # Check if baseline is stale (older than window_days)
            age_days = (datetime.now() - baseline.updated_at).days
            if age_days > self.window_days // 2:
                # Update baseline with rolling window
                baseline = self.update_baseline(secret_id)
        else:
            # Create new baseline
            baseline = self.create_baseline(secret_id)
            if baseline:
                self.db.store_baseline(baseline)
        
        return baseline
    
    def rebuild_all_baselines(self) -> int:
        """Rebuild baselines for all secrets in the database"""
        secret_ids = self.db.get_all_secret_ids()
        rebuilt_count = 0
        
        for secret_id in secret_ids:
            baseline = self.update_baseline(secret_id)
            if baseline:
                rebuilt_count += 1
        
        return rebuilt_count
