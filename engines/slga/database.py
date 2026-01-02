# SLGA database layer (SQLite)
"""
Persistent storage for Secret Lineage Graph Analysis (SLGA).
Stores secrets, files, commits, stages, logs, artifacts and their relationships.
"""

import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Optional, Set
from .models import Secret, File, Commit, Stage, Log, Artifact, PropagationEdge

class SLGADatabase:
    """SQLite database for storing secret lineage graph data"""
    
    def __init__(self, db_path: str = "slga.db"):
        self.db_path = db_path
        self.conn = None
        self._init_database()
    
    def _init_database(self):
        """Initialize database schema"""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        cursor = self.conn.cursor()
        
        # Secrets table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                value TEXT NOT NULL,
                secret_type TEXT NOT NULL,
                entropy REAL,
                first_seen TEXT,
                last_seen TEXT,
                UNIQUE(value)
            )
        """)
        
        # Files table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL UNIQUE,
                first_seen TEXT,
                last_seen TEXT
            )
        """)
        
        # Commits table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS commits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hash TEXT NOT NULL UNIQUE,
                message TEXT,
                author TEXT,
                date TEXT,
                first_seen TEXT
            )
        """)
        
        # Stages table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS stages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                first_seen TEXT,
                last_seen TEXT
            )
        """)
        
        # Logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL UNIQUE,
                first_seen TEXT,
                last_seen TEXT
            )
        """)
        
        # Artifacts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL UNIQUE,
                first_seen TEXT,
                last_seen TEXT
            )
        """)
        
        # Relationship: Secret appears in File
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS secret_in_file (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                secret_id INTEGER NOT NULL,
                file_id INTEGER NOT NULL,
                line_number INTEGER,
                first_seen TEXT,
                last_seen TEXT,
                FOREIGN KEY (secret_id) REFERENCES secrets(id),
                FOREIGN KEY (file_id) REFERENCES files(id),
                UNIQUE(secret_id, file_id, line_number)
            )
        """)
        
        # Relationship: File in Commit
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS file_in_commit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER NOT NULL,
                commit_id INTEGER NOT NULL,
                first_seen TEXT,
                FOREIGN KEY (file_id) REFERENCES files(id),
                FOREIGN KEY (commit_id) REFERENCES commits(id),
                UNIQUE(file_id, commit_id)
            )
        """)
        
        # Relationship: Secret used in Stage
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS secret_in_stage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                secret_id INTEGER NOT NULL,
                stage_id INTEGER NOT NULL,
                first_seen TEXT,
                last_seen TEXT,
                FOREIGN KEY (secret_id) REFERENCES secrets(id),
                FOREIGN KEY (stage_id) REFERENCES stages(id),
                UNIQUE(secret_id, stage_id)
            )
        """)
        
        # Relationship: Secret appears in Log
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS secret_in_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                secret_id INTEGER NOT NULL,
                log_id INTEGER NOT NULL,
                first_seen TEXT,
                last_seen TEXT,
                FOREIGN KEY (secret_id) REFERENCES secrets(id),
                FOREIGN KEY (log_id) REFERENCES logs(id),
                UNIQUE(secret_id, log_id)
            )
        """)
        
        # Relationship: Secret appears in Artifact
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS secret_in_artifact (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                secret_id INTEGER NOT NULL,
                artifact_id INTEGER NOT NULL,
                first_seen TEXT,
                last_seen TEXT,
                FOREIGN KEY (secret_id) REFERENCES secrets(id),
                FOREIGN KEY (artifact_id) REFERENCES artifacts(id),
                UNIQUE(secret_id, artifact_id)
            )
        """)
        
        # Scan history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                repo_path TEXT,
                ci_config_path TEXT,
                log_dir TEXT,
                artifact_dir TEXT,
                total_secrets INTEGER,
                total_files INTEGER,
                total_commits INTEGER,
                total_stages INTEGER,
                total_logs INTEGER,
                total_artifacts INTEGER
            )
        """)
        
        # Create indexes for performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_secrets_value ON secrets(value)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_files_path ON files(path)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_commits_hash ON commits(hash)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_secret_in_file_secret ON secret_in_file(secret_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_secret_in_file_file ON secret_in_file(file_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_in_commit_file ON file_in_commit(file_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_in_commit_commit ON file_in_commit(commit_id)")
        
        self.conn.commit()
    
    def store_secret(self, secret: Secret) -> int:
        """Store or update a secret and return its ID"""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        # Check if secret exists
        cursor.execute("SELECT id FROM secrets WHERE value = ?", (secret.value,))
        row = cursor.fetchone()
        
        if row:
            secret_id = row['id']
            # Update last_seen
            cursor.execute("""
                UPDATE secrets SET last_seen = ? WHERE id = ?
            """, (now, secret_id))
        else:
            # Insert new secret
            cursor.execute("""
                INSERT INTO secrets (value, secret_type, entropy, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
            """, (secret.value, secret.secret_type, secret.entropy, now, now))
            secret_id = cursor.lastrowid
        
        self.conn.commit()
        return secret_id
    
    def store_file(self, file_path: str) -> int:
        """Store or update a file and return its ID"""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute("SELECT id FROM files WHERE path = ?", (file_path,))
        row = cursor.fetchone()
        
        if row:
            file_id = row['id']
            cursor.execute("UPDATE files SET last_seen = ? WHERE id = ?", (now, file_id))
        else:
            cursor.execute("""
                INSERT INTO files (path, first_seen, last_seen)
                VALUES (?, ?, ?)
            """, (file_path, now, now))
            file_id = cursor.lastrowid
        
        self.conn.commit()
        return file_id
    
    def store_commit(self, commit: Commit) -> int:
        """Store or update a commit and return its ID"""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute("SELECT id FROM commits WHERE hash = ?", (commit.hash,))
        row = cursor.fetchone()
        
        if row:
            commit_id = row['id']
        else:
            cursor.execute("""
                INSERT INTO commits (hash, message, author, date, first_seen)
                VALUES (?, ?, ?, ?, ?)
            """, (commit.hash, commit.message, commit.author, commit.date, now))
            commit_id = cursor.lastrowid
        
        self.conn.commit()
        return commit_id
    
    def store_stage(self, stage_name: str) -> int:
        """Store or update a stage and return its ID"""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute("SELECT id FROM stages WHERE name = ?", (stage_name,))
        row = cursor.fetchone()
        
        if row:
            stage_id = row['id']
            cursor.execute("UPDATE stages SET last_seen = ? WHERE id = ?", (now, stage_id))
        else:
            cursor.execute("""
                INSERT INTO stages (name, first_seen, last_seen)
                VALUES (?, ?, ?)
            """, (stage_name, now, now))
            stage_id = cursor.lastrowid
        
        self.conn.commit()
        return stage_id
    
    def store_log(self, log_path: str) -> int:
        """Store or update a log and return its ID"""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute("SELECT id FROM logs WHERE path = ?", (log_path,))
        row = cursor.fetchone()
        
        if row:
            log_id = row['id']
            cursor.execute("UPDATE logs SET last_seen = ? WHERE id = ?", (now, log_id))
        else:
            cursor.execute("""
                INSERT INTO logs (path, first_seen, last_seen)
                VALUES (?, ?, ?)
            """, (log_path, now, now))
            log_id = cursor.lastrowid
        
        self.conn.commit()
        return log_id
    
    def store_artifact(self, artifact_path: str) -> int:
        """Store or update an artifact and return its ID"""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute("SELECT id FROM artifacts WHERE path = ?", (artifact_path,))
        row = cursor.fetchone()
        
        if row:
            artifact_id = row['id']
            cursor.execute("UPDATE artifacts SET last_seen = ? WHERE id = ?", (now, artifact_id))
        else:
            cursor.execute("""
                INSERT INTO artifacts (path, first_seen, last_seen)
                VALUES (?, ?, ?)
            """, (artifact_path, now, now))
            artifact_id = cursor.lastrowid
        
        self.conn.commit()
        return artifact_id
    
    def link_secret_to_file(self, secret_id: int, file_id: int, line_number: int = None):
        """Create or update relationship between secret and file"""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute("""
            SELECT id FROM secret_in_file WHERE secret_id = ? AND file_id = ? AND line_number = ?
        """, (secret_id, file_id, line_number))
        row = cursor.fetchone()
        
        if row:
            cursor.execute("""
                UPDATE secret_in_file SET last_seen = ? WHERE id = ?
            """, (now, row['id']))
        else:
            cursor.execute("""
                INSERT INTO secret_in_file (secret_id, file_id, line_number, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
            """, (secret_id, file_id, line_number, now, now))
        
        self.conn.commit()
    
    def link_file_to_commit(self, file_id: int, commit_id: int):
        """Create relationship between file and commit"""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute("""
            SELECT id FROM file_in_commit WHERE file_id = ? AND commit_id = ?
        """, (file_id, commit_id))
        row = cursor.fetchone()
        
        if not row:
            cursor.execute("""
                INSERT INTO file_in_commit (file_id, commit_id, first_seen)
                VALUES (?, ?, ?)
            """, (file_id, commit_id, now))
            self.conn.commit()
    
    def link_secret_to_stage(self, secret_id: int, stage_id: int):
        """Create or update relationship between secret and stage"""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute("""
            SELECT id FROM secret_in_stage WHERE secret_id = ? AND stage_id = ?
        """, (secret_id, stage_id))
        row = cursor.fetchone()
        
        if row:
            cursor.execute("""
                UPDATE secret_in_stage SET last_seen = ? WHERE id = ?
            """, (now, row['id']))
        else:
            cursor.execute("""
                INSERT INTO secret_in_stage (secret_id, stage_id, first_seen, last_seen)
                VALUES (?, ?, ?, ?)
            """, (secret_id, stage_id, now, now))
        
        self.conn.commit()
    
    def link_secret_to_log(self, secret_id: int, log_id: int):
        """Create or update relationship between secret and log"""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute("""
            SELECT id FROM secret_in_log WHERE secret_id = ? AND log_id = ?
        """, (secret_id, log_id))
        row = cursor.fetchone()
        
        if row:
            cursor.execute("""
                UPDATE secret_in_log SET last_seen = ? WHERE id = ?
            """, (now, row['id']))
        else:
            cursor.execute("""
                INSERT INTO secret_in_log (secret_id, log_id, first_seen, last_seen)
                VALUES (?, ?, ?, ?)
            """, (secret_id, log_id, now, now))
        
        self.conn.commit()
    
    def link_secret_to_artifact(self, secret_id: int, artifact_id: int):
        """Create or update relationship between secret and artifact"""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute("""
            SELECT id FROM secret_in_artifact WHERE secret_id = ? AND artifact_id = ?
        """, (secret_id, artifact_id))
        row = cursor.fetchone()
        
        if row:
            cursor.execute("""
                UPDATE secret_in_artifact SET last_seen = ? WHERE id = ?
            """, (now, row['id']))
        else:
            cursor.execute("""
                INSERT INTO secret_in_artifact (secret_id, artifact_id, first_seen, last_seen)
                VALUES (?, ?, ?, ?)
            """, (secret_id, artifact_id, now, now))
        
        self.conn.commit()
    
    def store_scan_history(self, scan_id: str, repo_path: str, ci_config_path: str = None,
                          log_dir: str = None, artifact_dir: str = None,
                          total_secrets: int = 0, total_files: int = 0, total_commits: int = 0,
                          total_stages: int = 0, total_logs: int = 0, total_artifacts: int = 0):
        """Store scan execution history"""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute("""
            INSERT OR REPLACE INTO scan_history 
            (scan_id, timestamp, repo_path, ci_config_path, log_dir, artifact_dir,
             total_secrets, total_files, total_commits, total_stages, total_logs, total_artifacts)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, now, repo_path, ci_config_path, log_dir, artifact_dir,
              total_secrets, total_files, total_commits, total_stages, total_logs, total_artifacts))
        
        self.conn.commit()
    
    def get_secret_lineage(self, secret_value: str) -> Dict:
        """Get complete lineage for a secret"""
        cursor = self.conn.cursor()
        
        # Get secret
        cursor.execute("SELECT * FROM secrets WHERE value = ?", (secret_value,))
        secret_row = cursor.fetchone()
        
        if not secret_row:
            return None
        
        secret_id = secret_row['id']
        
        # Get files containing this secret
        cursor.execute("""
            SELECT f.path, sif.line_number 
            FROM files f
            JOIN secret_in_file sif ON f.id = sif.file_id
            WHERE sif.secret_id = ?
        """, (secret_id,))
        files = [{'path': row['path'], 'line': row['line_number']} for row in cursor.fetchall()]
        
        # Get commits
        cursor.execute("""
            SELECT DISTINCT c.hash, c.message, c.author, c.date
            FROM commits c
            JOIN file_in_commit fic ON c.id = fic.commit_id
            JOIN secret_in_file sif ON fic.file_id = sif.file_id
            WHERE sif.secret_id = ?
        """, (secret_id,))
        commits = [dict(row) for row in cursor.fetchall()]
        
        # Get stages
        cursor.execute("""
            SELECT s.name
            FROM stages s
            JOIN secret_in_stage sis ON s.id = sis.stage_id
            WHERE sis.secret_id = ?
        """, (secret_id,))
        stages = [row['name'] for row in cursor.fetchall()]
        
        # Get logs
        cursor.execute("""
            SELECT l.path
            FROM logs l
            JOIN secret_in_log sil ON l.id = sil.log_id
            WHERE sil.secret_id = ?
        """, (secret_id,))
        logs = [row['path'] for row in cursor.fetchall()]
        
        # Get artifacts
        cursor.execute("""
            SELECT a.path
            FROM artifacts a
            JOIN secret_in_artifact sia ON a.id = sia.artifact_id
            WHERE sia.secret_id = ?
        """, (secret_id,))
        artifacts = [row['path'] for row in cursor.fetchall()]
        
        return {
            'secret': dict(secret_row),
            'files': files,
            'commits': commits,
            'stages': stages,
            'logs': logs,
            'artifacts': artifacts
        }
    
    def get_all_secrets(self) -> List[Dict]:
        """Get all secrets in database"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM secrets ORDER BY last_seen DESC")
        return [dict(row) for row in cursor.fetchall()]
    
    def get_scan_history(self, limit: int = 10) -> List[Dict]:
        """Get recent scan history"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM scan_history 
            ORDER BY timestamp DESC 
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        cursor = self.conn.cursor()
        
        stats = {}
        
        for table in ['secrets', 'files', 'commits', 'stages', 'logs', 'artifacts']:
            cursor.execute(f"SELECT COUNT(*) as count FROM {table}")
            stats[f'total_{table}'] = cursor.fetchone()['count']
        
        return stats
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
