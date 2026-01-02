# HCRS models
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from datetime import datetime
from enum import Enum

class Severity(Enum):
    """Risk severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class ViolationType(Enum):
    """Types of security violations"""
    HARDCODED_SECRET = "hardcoded_secret"
    COMMAND_INJECTION = "command_injection"
    SQL_INJECTION = "sql_injection"
    PATH_TRAVERSAL = "path_traversal"
    UNSAFE_DESERIALIZATION = "unsafe_deserialization"
    WEAK_CRYPTO = "weak_crypto"
    SENSITIVE_LOGGING = "sensitive_logging"
    UNSAFE_API = "unsafe_api"
    XSS_VULNERABILITY = "xss_vulnerability"
    XSS = "xss_vulnerability"  # Alias for test compatibility
    UNSANITIZED_INPUT = "unsanitized_input"
    DANGEROUS_FILE_OPS = "dangerous_file_ops"
    INSECURE_RANDOM = "insecure_random"
    EVAL_USAGE = "eval_usage"
    CORS_MISCONFIGURATION = "cors_misconfiguration"

@dataclass
class CodeLocation:
    """Represents a location in source code"""
    file_path: str
    line_start: int
    line_end: int
    column_start: int = 0
    column_end: int = 0
    snippet: str = ""

@dataclass
class SecurityViolation:
    """Represents a detected security violation"""
    violation_type: ViolationType
    severity: Severity
    location: CodeLocation
    message: str
    description: str = ""
    cwe_id: Optional[str] = None  # Common Weakness Enumeration ID
    recommendation: str = ""
    confidence: float = 1.0  # 0.0 to 1.0

    @property
    def file_path(self) -> str:
        return self.location.file_path if self.location else None

    @property
    def line_number(self) -> Optional[int]:
        return self.location.line_start if self.location else None
    
@dataclass
class FileRiskScore:
    """Risk score for a single file"""
    file_path: str
    language: str
    total_score: float = 0.0
    violations: List[SecurityViolation] = field(default_factory=list)
    severity_breakdown: Dict[str, int] = field(default_factory=dict)
    lines_analyzed: int = 0

    @property
    def risk_score(self) -> float:
        return self.total_score
    
@dataclass
class RepositoryRiskScore:
    """Aggregate risk score for entire repository"""
    repo_path: str
    timestamp: datetime
    total_score: float = 0.0
    file_scores: List[FileRiskScore] = field(default_factory=list)
    summary: Dict[str, any] = field(default_factory=dict)
    recommendation: str = ""
    dependency_vulnerabilities: List[Dict] = field(default_factory=list)  # OSV scan results

    @property
    def risk_score(self) -> float:
        return self.total_score
    
    @property
    def critical_count(self) -> int:
        return sum(1 for fs in self.file_scores for v in fs.violations if v.severity == Severity.CRITICAL)
    
    @property
    def high_count(self) -> int:
        return sum(1 for fs in self.file_scores for v in fs.violations if v.severity == Severity.HIGH)
    
    @property
    def medium_count(self) -> int:
        return sum(1 for fs in self.file_scores for v in fs.violations if v.severity == Severity.MEDIUM)
    
    @property
    def low_count(self) -> int:
        return sum(1 for fs in self.file_scores for v in fs.violations if v.severity == Severity.LOW)

@dataclass
class SecurityRule:
    """Defines a security detection rule"""
    rule_id: str
    name: str
    violation_type: ViolationType
    severity: Severity
    language: str  # 'python', 'javascript', 'all'
    pattern_type: str  # 'ast', 'regex', 'semantic'
    pattern: str  # Pattern to match (AST node type, regex, etc.)
    message: str
    description: str = ""
    cwe_id: Optional[str] = None
    recommendation: str = ""
    weight: float = 1.0
    enabled: bool = True
    confidence: float = 1.0
