# SDDA database layer (SQLite)
import sqlite3
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Set
from .models import PipelineRun, SecretUsage, Baseline, BehavioralFeatures

class SDDADatabase:
    """SQLite database for storing pipeline runs and baselines"""
    
    def __init__(self, db_path: str = "sdda.db"):
        self.db_path = db_path
        self.conn = None
        self._init_database()
    
    def _init_database(self):
        """Initialize database schema"""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        cursor = self.conn.cursor()
        
        # Pipeline runs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pipeline_runs (
                run_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                branch TEXT,
                environment TEXT,
                actor TEXT,
                secrets_used TEXT,
                stages TEXT
            )
        """)
        
        # Secret usage table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS secret_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                secret_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                stages TEXT,
                access_count INTEGER,
                actor TEXT,
                environment TEXT,
                branch TEXT,
                FOREIGN KEY (run_id) REFERENCES pipeline_runs(run_id)
            )
        """)
        
        # Baselines table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS baselines (
                secret_id TEXT PRIMARY KEY,
                window_days INTEGER,
                normal_stages TEXT,
                stage_mean REAL,
                stage_std REAL,
                access_mean REAL,
                access_std REAL,
                normal_actors TEXT,
                actor_mean REAL,
                actor_std REAL,
                normal_environments TEXT,
                env_mean REAL,
                env_std REAL,
                sample_count INTEGER,
                created_at TEXT,
                updated_at TEXT
            )
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_secret_usage_secret ON secret_usage(secret_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_secret_usage_timestamp ON secret_usage(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_pipeline_runs_timestamp ON pipeline_runs(timestamp)")
        
        self.conn.commit()
    
    def store_pipeline_run(self, run: PipelineRun):
        """Store a pipeline run"""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO pipeline_runs 
            (run_id, timestamp, branch, environment, actor, secrets_used, stages)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            run.run_id,
            run.timestamp.isoformat(),
            run.branch,
            run.environment,
            run.actor,
            json.dumps(run.secrets_used),
            json.dumps(run.stages)
        ))
        self.conn.commit()
    
    def store_secret_usage(self, usage: SecretUsage):
        """Store secret usage data"""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO secret_usage 
            (secret_id, run_id, timestamp, stages, access_count, actor, environment, branch)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            usage.secret_id,
            usage.run_id,
            usage.timestamp.isoformat(),
            json.dumps(list(usage.stages)),
            usage.access_count,
            usage.actor,
            usage.environment,
            usage.branch
        ))
        self.conn.commit()
    
    def get_historical_usage(self, secret_id: str, window_days: int) -> List[SecretUsage]:
        """Get historical usage for a secret within a time window"""
        cursor = self.conn.cursor()
        # Add a small buffer to be inclusive of boundary cases
        cutoff_date = (datetime.now() - timedelta(days=window_days, hours=1)).isoformat()
        
        cursor.execute("""
            SELECT * FROM secret_usage 
            WHERE secret_id = ? AND timestamp >= ?
            ORDER BY timestamp DESC
        """, (secret_id, cutoff_date))
        
        usages = []
        for row in cursor.fetchall():
            usages.append(SecretUsage(
                secret_id=row['secret_id'],
                run_id=row['run_id'],
                timestamp=datetime.fromisoformat(row['timestamp']),
                stages=set(json.loads(row['stages'])),
                access_count=row['access_count'],
                actor=row['actor'],
                environment=row['environment'],
                branch=row['branch']
            ))
        return usages
    
    def store_baseline(self, baseline: Baseline):
        """Store or update baseline"""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO baselines 
            (secret_id, window_days, normal_stages, stage_mean, stage_std,
             access_mean, access_std, normal_actors, actor_mean, actor_std,
             normal_environments, env_mean, env_std, sample_count, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            baseline.secret_id,
            baseline.window_days,
            json.dumps(list(baseline.normal_stages)),
            baseline.stage_mean,
            baseline.stage_std,
            baseline.access_mean,
            baseline.access_std,
            json.dumps(list(baseline.normal_actors)),
            baseline.actor_mean,
            baseline.actor_std,
            json.dumps(list(baseline.normal_environments)),
            baseline.env_mean,
            baseline.env_std,
            baseline.sample_count,
            baseline.created_at.isoformat(),
            baseline.updated_at.isoformat()
        ))
        self.conn.commit()
    
    def get_baseline(self, secret_id: str) -> Optional[Baseline]:
        """Retrieve baseline for a secret"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM baselines WHERE secret_id = ?", (secret_id,))
        row = cursor.fetchone()
        
        if not row:
            return None
        
        return Baseline(
            secret_id=row['secret_id'],
            window_days=row['window_days'],
            normal_stages=set(json.loads(row['normal_stages'])),
            stage_mean=row['stage_mean'],
            stage_std=row['stage_std'],
            access_mean=row['access_mean'],
            access_std=row['access_std'],
            normal_actors=set(json.loads(row['normal_actors'])),
            actor_mean=row['actor_mean'],
            actor_std=row['actor_std'],
            normal_environments=set(json.loads(row['normal_environments'])),
            env_mean=row['env_mean'],
            env_std=row['env_std'],
            sample_count=row['sample_count'],
            created_at=datetime.fromisoformat(row['created_at']),
            updated_at=datetime.fromisoformat(row['updated_at'])
        )
    
    def get_all_secret_ids(self) -> List[str]:
        """Get all unique secret IDs from usage history"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT DISTINCT secret_id FROM secret_usage")
        return [row['secret_id'] for row in cursor.fetchall()]
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
