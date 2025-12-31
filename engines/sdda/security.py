# SDDA security module
import os
import hashlib
import re
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

class SecretEncryption:
    """Handles encryption/decryption of secrets in database"""
    
    def __init__(self, encryption_key: Optional[str] = None):
        """
        Initialize encryption with a key.
        If no key provided, generates one from environment or creates new.
        """
        if encryption_key:
            self.key = self._derive_key(encryption_key)
        else:
            # Try to get key from environment
            env_key = os.environ.get('SDDA_ENCRYPTION_KEY')
            if env_key:
                self.key = self._derive_key(env_key)
            else:
                # Generate new key (should be stored securely)
                self.key = Fernet.generate_key()
        
        self.cipher = Fernet(self.key)
    
    def _derive_key(self, password: str, salt: Optional[bytes] = None) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        if salt is None:
            salt = b'sdda_salt_v1'  # Fixed salt for deterministic key
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt a secret value"""
        if not plaintext:
            return ""
        encrypted = self.cipher.encrypt(plaintext.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a secret value"""
        if not ciphertext:
            return ""
        decoded = base64.urlsafe_b64decode(ciphertext.encode())
        decrypted = self.cipher.decrypt(decoded)
        return decrypted.decode()
    
    def mask_secret(self, secret: str, show_chars: int = 4) -> str:
        """Mask a secret for safe display"""
        if not secret or len(secret) <= show_chars:
            return "***"
        return f"{secret[:show_chars]}...{'*' * (len(secret) - show_chars)}"


class InputValidator:
    """Validates and sanitizes inputs to prevent injection attacks"""
    
    # Allowed patterns
    SECRET_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\.]{1,255}$')
    RUN_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]{1,255}$')
    ACTOR_PATTERN = re.compile(r'^[a-zA-Z0-9_\-@\.]{1,255}$')
    ENVIRONMENT_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]{1,100}$')
    BRANCH_PATTERN = re.compile(r'^[a-zA-Z0-9_\-/\.]{1,255}$')
    STAGE_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\s]{1,100}$')
    
    @staticmethod
    def validate_secret_id(secret_id: str) -> bool:
        """Validate secret ID format"""
        if not secret_id:
            return False
        return bool(InputValidator.SECRET_ID_PATTERN.match(secret_id))
    
    @staticmethod
    def validate_run_id(run_id: str) -> bool:
        """Validate run ID format"""
        if not run_id:
            return False
        return bool(InputValidator.RUN_ID_PATTERN.match(run_id))
    
    @staticmethod
    def validate_actor(actor: str) -> bool:
        """Validate actor/username format"""
        if not actor:
            return False
        return bool(InputValidator.ACTOR_PATTERN.match(actor))
    
    @staticmethod
    def validate_environment(environment: str) -> bool:
        """Validate environment name"""
        if not environment:
            return False
        return bool(InputValidator.ENVIRONMENT_PATTERN.match(environment))
    
    @staticmethod
    def validate_branch(branch: str) -> bool:
        """Validate branch name"""
        if not branch:
            return False
        return bool(InputValidator.BRANCH_PATTERN.match(branch))
    
    @staticmethod
    def validate_stage(stage: str) -> bool:
        """Validate stage name"""
        if not stage:
            return False
        return bool(InputValidator.STAGE_PATTERN.match(stage))
    
    @staticmethod
    def sanitize_sql_value(value: str) -> str:
        """Sanitize value for SQL (removes dangerous characters)"""
        if not value:
            return ""
        # Remove SQL injection characters
        dangerous = ["'", '"', ';', '--', '/*', '*/', 'xp_', 'sp_', 'DROP', 'DELETE', 'INSERT', 'UPDATE']
        sanitized = value
        for pattern in dangerous:
            sanitized = sanitized.replace(pattern, '')
        return sanitized
    
    @staticmethod
    def validate_path(path: str) -> bool:
        """Validate file path to prevent path traversal"""
        if not path:
            return False
        # Check for path traversal patterns
        dangerous_patterns = ['..', '~/', '/etc/', '/root/', 'C:\\Windows']
        for pattern in dangerous_patterns:
            if pattern in path:
                return False
        return True


class AuditLogger:
    """Logs security-relevant events for audit trail"""
    
    def __init__(self, log_file: Optional[str] = None):
        """Initialize audit logger"""
        self.log_file = log_file or os.environ.get('SDDA_AUDIT_LOG', 'sdda_audit.log')
        self.enabled = os.environ.get('SDDA_AUDIT_ENABLED', 'true').lower() == 'true'
    
    def log_event(self, event_type: str, details: dict):
        """Log an audit event"""
        if not self.enabled:
            return
        
        import json
        from datetime import datetime
        
        event = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'details': details
        }
        
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(event) + '\n')
        except Exception as e:
            # Fail silently to avoid breaking the application
            print(f"Audit logging error: {e}")
    
    def log_secret_access(self, secret_id: str, actor: str, run_id: str, operation: str):
        """Log secret access event"""
        self.log_event('SECRET_ACCESS', {
            'secret_id': secret_id,
            'actor': actor,
            'run_id': run_id,
            'operation': operation
        })
    
    def log_drift_detection(self, secret_id: str, severity: str, run_id: str):
        """Log drift detection event"""
        self.log_event('DRIFT_DETECTION', {
            'secret_id': secret_id,
            'severity': severity,
            'run_id': run_id
        })
    
    def log_baseline_update(self, secret_id: str, sample_count: int):
        """Log baseline update event"""
        self.log_event('BASELINE_UPDATE', {
            'secret_id': secret_id,
            'sample_count': sample_count
        })
    
    def log_validation_failure(self, field: str, value: str, reason: str):
        """Log input validation failure"""
        self.log_event('VALIDATION_FAILURE', {
            'field': field,
            'value': value[:50],  # Truncate for safety
            'reason': reason
        })
    
    def log_database_operation(self, operation: str, table: str, record_count: int):
        """Log database operations"""
        self.log_event('DATABASE_OPERATION', {
            'operation': operation,
            'table': table,
            'record_count': record_count
        })


class SecurityConfig:
    """Security configuration management"""
    
    def __init__(self):
        self.encryption_enabled = os.environ.get('SDDA_ENCRYPTION_ENABLED', 'true').lower() == 'true'
        self.validation_enabled = os.environ.get('SDDA_VALIDATION_ENABLED', 'true').lower() == 'true'
        self.audit_enabled = os.environ.get('SDDA_AUDIT_ENABLED', 'true').lower() == 'true'
        self.mask_secrets_in_logs = os.environ.get('SDDA_MASK_SECRETS', 'true').lower() == 'true'
        self.max_retention_days = int(os.environ.get('SDDA_MAX_RETENTION_DAYS', '365'))
    
    def get_config(self) -> dict:
        """Get security configuration as dict"""
        return {
            'encryption_enabled': self.encryption_enabled,
            'validation_enabled': self.validation_enabled,
            'audit_enabled': self.audit_enabled,
            'mask_secrets_in_logs': self.mask_secrets_in_logs,
            'max_retention_days': self.max_retention_days
        }
