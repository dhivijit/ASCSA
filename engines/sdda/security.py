# SDDA security module
import os
import hmac as _hmac
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

    _SALT_LENGTH = 16

    def __init__(self, encryption_key: Optional[str] = None):
        """
        Initialize encryption with a key.
        If no key provided, generates one from environment or creates new.
        """
        if encryption_key:
            self._password = encryption_key
        else:
            env_key = os.environ.get('SDDA_ENCRYPTION_KEY')
            if env_key:
                self._password = env_key
            else:
                self._password = None

        # When no password is provided, encryption is session-only and
        # cross-connection lookups will break.  Store _static_key=None so
        # hash_for_lookup() falls back to an empty key (still deterministic).
        if self._password is None:
            self._static_key = None
        else:
            self._static_key = None

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2 with caller-supplied salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a secret value.

        When a password was provided, a fresh random salt is generated per
        call and prepended to the ciphertext so that decrypt() can recover it.
        """
        if not plaintext:
            return ""
        if self._password is not None:
            salt = os.urandom(self._SALT_LENGTH)
            key = self._derive_key(self._password, salt)
            cipher = Fernet(key)
            encrypted = cipher.encrypt(plaintext.encode())
            # Format: base64( salt || fernet_token )
            return base64.urlsafe_b64encode(salt + encrypted).decode()
        else:
            cipher = Fernet(self._static_key)
            encrypted = cipher.encrypt(plaintext.encode())
            return base64.urlsafe_b64encode(encrypted).decode()

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a secret value."""
        if not ciphertext:
            return ""
        raw = base64.urlsafe_b64decode(ciphertext.encode())
        if self._password is not None:
            salt = raw[:self._SALT_LENGTH]
            token = raw[self._SALT_LENGTH:]
            key = self._derive_key(self._password, salt)
            cipher = Fernet(key)
            return cipher.decrypt(token).decode()
        else:
            cipher = Fernet(self._static_key)
            return cipher.decrypt(raw).decode()
    
    def hash_for_lookup(self, plaintext: str) -> str:
        """Deterministic keyed hash for use as a SQL lookup key.

        Unlike encrypt(), this always produces the same output for the same
        input, making it safe to use in WHERE clauses across DB connections.
        """
        if not plaintext:
            return ""
        key: bytes
        if self._password is not None:
            key = self._password.encode()
        else:
            # No persistent key: use a zero key (deterministic but unkeyed)
            key = b"sdda-default"
        return _hmac.new(key, plaintext.encode(), hashlib.sha256).hexdigest()

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
        # Encryption is only meaningful when a persistent key is available;
        # without one every SDDADatabase connection generates a new random key,
        # making cross-connection lookups impossible.
        key_present = bool(os.environ.get('SDDA_ENCRYPTION_KEY'))
        enc_flag = os.environ.get('SDDA_ENCRYPTION_ENABLED', '').lower()
        self.encryption_enabled = key_present or (enc_flag == 'true')
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
