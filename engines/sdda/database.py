# SDDA database layer (SQLite)
import sqlite3
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Set
from .models import PipelineRun, SecretUsage, Baseline, BehavioralFeatures
from .security import SecretEncryption, InputValidator, AuditLogger, SecurityConfig

class SDDADatabase:
    """SQLite database for storing pipeline runs and baselines"""
    
    def __init__(self, db_path: str = "sdda.db", encryption_key: Optional[str] = None):
        self.db_path = db_path
        self.conn = None
        
        # Initialize security components
        self.security_config = SecurityConfig()
        self.encryptor = SecretEncryption(encryption_key) if self.security_config.encryption_enabled else None
        self.validator = InputValidator()
        self.audit_logger = AuditLogger()
        
        # Validate database path
        if not self.validator.validate_path(db_path):
            raise ValueError(f"Invalid database path: {db_path}")
        
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
                normal_branches TEXT,
                branch_mean REAL,
                branch_std REAL,
                sample_count INTEGER,
                created_at TEXT,
                updated_at TEXT
            )
        """)
        
        # Drift reports table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS drift_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                total_secrets_analyzed INTEGER,
                total_drifted_secrets INTEGER,
                critical_count INTEGER,
                high_count INTEGER,
                medium_count INTEGER,
                low_count INTEGER,
                baseline_status TEXT,
                report_data TEXT,
                FOREIGN KEY (run_id) REFERENCES pipeline_runs(run_id)
            )
        """)
        
        # Drift detections table (individual drift events)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS drift_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER NOT NULL,
                secret_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                severity TEXT,
                total_drift_score REAL,
                is_drifted BOOLEAN,
                stage_drift_score REAL,
                frequency_drift_score REAL,
                actor_drift_score REAL,
                environment_drift_score REAL,
                branch_drift_score REAL,
                anomaly_details TEXT,
                recommendation TEXT,
                FOREIGN KEY (report_id) REFERENCES drift_reports(id),
                FOREIGN KEY (run_id) REFERENCES pipeline_runs(run_id)
            )
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_secret_usage_secret ON secret_usage(secret_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_secret_usage_timestamp ON secret_usage(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_pipeline_runs_timestamp ON pipeline_runs(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_drift_reports_run ON drift_reports(run_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_drift_reports_timestamp ON drift_reports(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_drift_detections_report ON drift_detections(report_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_drift_detections_secret ON drift_detections(secret_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_drift_detections_severity ON drift_detections(severity)")
        
        self.conn.commit()
    
    def store_pipeline_run(self, run: PipelineRun):
        """Store a pipeline run"""
        # Validate inputs
        if self.security_config.validation_enabled:
            if not self.validator.validate_run_id(run.run_id):
                self.audit_logger.log_validation_failure('run_id', run.run_id, 'Invalid format')
                raise ValueError(f"Invalid run_id format: {run.run_id}")
            if not self.validator.validate_actor(run.actor):
                self.audit_logger.log_validation_failure('actor', run.actor, 'Invalid format')
                raise ValueError(f"Invalid actor format: {run.actor}")
            if not self.validator.validate_environment(run.environment):
                self.audit_logger.log_validation_failure('environment', run.environment, 'Invalid format')
                raise ValueError(f"Invalid environment format: {run.environment}")
            if not self.validator.validate_branch(run.branch):
                self.audit_logger.log_validation_failure('branch', run.branch, 'Invalid format')
                raise ValueError(f"Invalid branch format: {run.branch}")
        
        # Encrypt secrets if enabled
        secrets_to_store = run.secrets_used
        if self.encryptor and self.security_config.encryption_enabled:
            secrets_to_store = [self.encryptor.encrypt(s) for s in run.secrets_used]
        
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
            json.dumps(secrets_to_store),
            json.dumps(run.stages)
        ))
        self.conn.commit()
        
        # Audit log
        self.audit_logger.log_database_operation('INSERT', 'pipeline_runs', 1)
    
    def store_secret_usage(self, usage: SecretUsage):
        """Store secret usage data"""
        # Validate inputs
        if self.security_config.validation_enabled:
            if not self.validator.validate_secret_id(usage.secret_id):
                self.audit_logger.log_validation_failure('secret_id', usage.secret_id, 'Invalid format')
                raise ValueError(f"Invalid secret_id format: {usage.secret_id}")
            if not self.validator.validate_run_id(usage.run_id):
                self.audit_logger.log_validation_failure('run_id', usage.run_id, 'Invalid format')
                raise ValueError(f"Invalid run_id format: {usage.run_id}")
        
        # Encrypt secret_id if enabled
        secret_id_to_store = usage.secret_id
        if self.encryptor and self.security_config.encryption_enabled:
            secret_id_to_store = self.encryptor.encrypt(usage.secret_id)
        
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO secret_usage 
            (secret_id, run_id, timestamp, stages, access_count, actor, environment, branch)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            secret_id_to_store,
            usage.run_id,
            usage.timestamp.isoformat(),
            json.dumps(list(usage.stages)),
            usage.access_count,
            usage.actor,
            usage.environment,
            usage.branch
        ))
        self.conn.commit()
        
        # Audit log
        self.audit_logger.log_secret_access(usage.secret_id, usage.actor, usage.run_id, 'STORE')
        self.audit_logger.log_database_operation('INSERT', 'secret_usage', 1)
    
    def get_historical_usage(self, secret_id: str, window_days: int) -> List[SecretUsage]:
        """Get historical usage for a secret within a time window"""
        # Encrypt secret_id for lookup if encryption is enabled
        secret_id_lookup = secret_id
        if self.encryptor and self.security_config.encryption_enabled:
            secret_id_lookup = self.encryptor.encrypt(secret_id)
        
        cursor = self.conn.cursor()
        # Add a small buffer to be inclusive of boundary cases
        cutoff_date = (datetime.now() - timedelta(days=window_days, hours=1)).isoformat()
        
        cursor.execute("""
            SELECT * FROM secret_usage 
            WHERE secret_id = ? AND timestamp >= ?
            ORDER BY timestamp DESC
        """, (secret_id_lookup, cutoff_date))
        
        usages = []
        for row in cursor.fetchall():
            # Decrypt secret_id if encryption is enabled
            retrieved_secret_id = row['secret_id']
            if self.encryptor and self.security_config.encryption_enabled:
                retrieved_secret_id = self.encryptor.decrypt(retrieved_secret_id)
            
            usages.append(SecretUsage(
                secret_id=retrieved_secret_id,
                run_id=row['run_id'],
                timestamp=datetime.fromisoformat(row['timestamp']),
                stages=set(json.loads(row['stages'])),
                access_count=row['access_count'],
                actor=row['actor'],
                environment=row['environment'],
                branch=row['branch']
            ))
        
        # Audit log
        self.audit_logger.log_secret_access(secret_id, 'SYSTEM', 'QUERY', 'RETRIEVE')
        
        return usages
    
    def store_baseline(self, baseline: Baseline):
        """Store or update baseline"""
        # Encrypt secret_id if enabled
        secret_id_to_store = baseline.secret_id
        if self.encryptor and self.security_config.encryption_enabled:
            secret_id_to_store = self.encryptor.encrypt(baseline.secret_id)
        
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO baselines 
            (secret_id, window_days, normal_stages, stage_mean, stage_std,
             access_mean, access_std, normal_actors, actor_mean, actor_std,
             normal_environments, env_mean, env_std, normal_branches, branch_mean, branch_std,
             sample_count, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            secret_id_to_store,
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
            json.dumps(list(baseline.normal_branches)),
            baseline.branch_mean,
            baseline.branch_std,
            baseline.sample_count,
            baseline.created_at.isoformat(),
            baseline.updated_at.isoformat()
        ))
        self.conn.commit()
        
        # Audit log
        self.audit_logger.log_baseline_update(baseline.secret_id, baseline.sample_count)
    
    def get_baseline(self, secret_id: str) -> Optional[Baseline]:
        """Retrieve baseline for a secret"""
        # Encrypt secret_id for lookup if encryption is enabled
        secret_id_lookup = secret_id
        if self.encryptor and self.security_config.encryption_enabled:
            secret_id_lookup = self.encryptor.encrypt(secret_id)
        
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM baselines WHERE secret_id = ?", (secret_id_lookup,))
        row = cursor.fetchone()
        
        if not row:
            return None
        
        # Decrypt secret_id if encryption is enabled
        retrieved_secret_id = row['secret_id']
        if self.encryptor and self.security_config.encryption_enabled:
            retrieved_secret_id = self.encryptor.decrypt(retrieved_secret_id)
        
        return Baseline(
            secret_id=retrieved_secret_id,
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
            normal_branches=set(json.loads(row['normal_branches'])),
            branch_mean=row['branch_mean'],
            branch_std=row['branch_std'],
            sample_count=row['sample_count'],
            created_at=datetime.fromisoformat(row['created_at']),
            updated_at=datetime.fromisoformat(row['updated_at'])
        )
    
    def get_all_secret_ids(self) -> List[str]:
        """Get all unique secret IDs from usage history"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT DISTINCT secret_id FROM secret_usage")
        secret_ids = []
        for row in cursor.fetchall():
            secret_id = row['secret_id']
            # Decrypt if encryption is enabled
            if self.encryptor and self.security_config.encryption_enabled:
                secret_id = self.encryptor.decrypt(secret_id)
            secret_ids.append(secret_id)
        return secret_ids
    
    def store_drift_report(self, drift_report) -> int:
        """
        Store a drift report and its detections
        
        Args:
            drift_report: DriftReport object
        
        Returns:
            Report ID
        """
        from .models import DriftReport
        
        cursor = self.conn.cursor()
        
        # Store main report
        cursor.execute("""
            INSERT INTO drift_reports 
            (run_id, timestamp, total_secrets_analyzed, total_drifted_secrets,
             critical_count, high_count, medium_count, low_count, baseline_status, report_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            drift_report.run_id,
            drift_report.timestamp.isoformat(),
            drift_report.total_secrets_analyzed,
            len(drift_report.drifted_secrets),
            drift_report.summary.get('CRITICAL', 0),
            drift_report.summary.get('HIGH', 0),
            drift_report.summary.get('MEDIUM', 0),
            drift_report.summary.get('LOW', 0),
            drift_report.baseline_status,
            json.dumps(drift_report.summary)
        ))
        
        report_id = cursor.lastrowid
        
        # Store individual detections
        for detection in drift_report.drifted_secrets:
            # Encrypt secret_id if encryption is enabled
            secret_id_to_store = detection.secret_id
            if self.encryptor and self.security_config.encryption_enabled:
                secret_id_to_store = self.encryptor.encrypt(detection.secret_id)
            
            cursor.execute("""
                INSERT INTO drift_detections 
                (report_id, secret_id, run_id, timestamp, severity, total_drift_score, is_drifted,
                 stage_drift_score, frequency_drift_score, actor_drift_score, 
                 environment_drift_score, branch_drift_score, anomaly_details, recommendation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report_id,
                secret_id_to_store,
                detection.run_id,
                detection.timestamp.isoformat(),
                detection.severity,
                detection.total_drift_score,
                detection.is_drifted,
                detection.stage_drift.z_score if detection.stage_drift else None,
                detection.frequency_drift.z_score if detection.frequency_drift else None,
                detection.actor_drift.z_score if detection.actor_drift else None,
                detection.environment_drift.z_score if detection.environment_drift else None,
                detection.branch_drift.z_score if detection.branch_drift else None,
                json.dumps(detection.anomaly_details),
                detection.recommendation
            ))
        
        self.conn.commit()
        
        # Audit log
        self.audit_logger.log_database_operation('INSERT', 'drift_reports', 1)
        
        return report_id
    
    def get_drift_report(self, run_id: str) -> Optional[Dict]:
        """Get drift report for a specific run"""
        cursor = self.conn.cursor()
        
        # Get report
        cursor.execute("""
            SELECT * FROM drift_reports WHERE run_id = ?
        """, (run_id,))
        
        report_row = cursor.fetchone()
        if not report_row:
            return None
        
        report_id = report_row['id']
        
        # Get detections
        cursor.execute("""
            SELECT * FROM drift_detections WHERE report_id = ?
        """, (report_id,))
        
        detections = []
        for row in cursor.fetchall():
            # Decrypt secret_id if encryption is enabled
            secret_id = row['secret_id']
            if self.encryptor and self.security_config.encryption_enabled:
                secret_id = self.encryptor.decrypt(secret_id)
            
            detections.append({
                'secret_id': secret_id,
                'run_id': row['run_id'],
                'timestamp': row['timestamp'],
                'severity': row['severity'],
                'total_drift_score': row['total_drift_score'],
                'is_drifted': bool(row['is_drifted']),
                'stage_drift_score': row['stage_drift_score'],
                'frequency_drift_score': row['frequency_drift_score'],
                'actor_drift_score': row['actor_drift_score'],
                'environment_drift_score': row['environment_drift_score'],
                'branch_drift_score': row['branch_drift_score'],
                'anomaly_details': json.loads(row['anomaly_details']) if row['anomaly_details'] else [],
                'recommendation': row['recommendation']
            })
        
        return {
            'run_id': report_row['run_id'],
            'timestamp': report_row['timestamp'],
            'total_secrets_analyzed': report_row['total_secrets_analyzed'],
            'total_drifted_secrets': report_row['total_drifted_secrets'],
            'summary': {
                'CRITICAL': report_row['critical_count'],
                'HIGH': report_row['high_count'],
                'MEDIUM': report_row['medium_count'],
                'LOW': report_row['low_count']
            },
            'baseline_status': report_row['baseline_status'],
            'detections': detections
        }
    
    def get_drift_history(self, secret_id: str = None, limit: int = 10) -> List[Dict]:
        """
        Get drift history, optionally filtered by secret_id
        
        Args:
            secret_id: Optional secret ID to filter by
            limit: Maximum number of records to return
        
        Returns:
            List of drift reports
        """
        cursor = self.conn.cursor()
        
        if secret_id:
            # Encrypt for lookup if needed
            secret_id_lookup = secret_id
            if self.encryptor and self.security_config.encryption_enabled:
                secret_id_lookup = self.encryptor.encrypt(secret_id)
            
            cursor.execute("""
                SELECT DISTINCT dr.*
                FROM drift_reports dr
                JOIN drift_detections dd ON dr.id = dd.report_id
                WHERE dd.secret_id = ?
                ORDER BY dr.timestamp DESC
                LIMIT ?
            """, (secret_id_lookup, limit))
        else:
            cursor.execute("""
                SELECT * FROM drift_reports
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
        
        reports = []
        for row in cursor.fetchall():
            reports.append({
                'run_id': row['run_id'],
                'timestamp': row['timestamp'],
                'total_secrets_analyzed': row['total_secrets_analyzed'],
                'total_drifted_secrets': row['total_drifted_secrets'],
                'critical_count': row['critical_count'],
                'high_count': row['high_count'],
                'medium_count': row['medium_count'],
                'low_count': row['low_count'],
                'baseline_status': row['baseline_status']
            })
        
        return reports
    
    def get_statistics(self) -> Dict:
        """Get comprehensive database statistics"""
        cursor = self.conn.cursor()
        
        stats = {}
        
        # Total records
        cursor.execute("SELECT COUNT(*) as count FROM pipeline_runs")
        stats['total_pipeline_runs'] = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM secret_usage")
        stats['total_secret_usages'] = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM baselines")
        stats['total_baselines'] = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM drift_reports")
        stats['total_drift_reports'] = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM drift_detections")
        stats['total_drift_detections'] = cursor.fetchone()['count']
        
        # Drift severity breakdown
        cursor.execute("""
            SELECT severity, COUNT(*) as count 
            FROM drift_detections 
            GROUP BY severity
        """)
        stats['drift_by_severity'] = {row['severity']: row['count'] for row in cursor.fetchall()}
        
        # Recent activity
        cursor.execute("""
            SELECT MIN(timestamp) as first_run, MAX(timestamp) as last_run
            FROM pipeline_runs
        """)
        row = cursor.fetchone()
        stats['first_run'] = row['first_run']
        stats['last_run'] = row['last_run']
        
        return stats
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
