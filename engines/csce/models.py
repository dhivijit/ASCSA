# CSCE models
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum

class CorrelationType(Enum):
    """Types of correlations between different security signals"""
    SPATIAL = "spatial"  # Same file/location
    TEMPORAL = "temporal"  # Same time period
    BEHAVIORAL = "behavioral"  # Secret behavior + code risk
    SECRET_MATCH = "secret_match"  # Direct secret value match
    PROPAGATION = "propagation"  # Secret propagated through risky code

class CorrelationSeverity(Enum):
    """Severity of correlated findings"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass
class Correlation:
    """Represents a correlation between multiple security signals"""
    correlation_id: str
    correlation_type: CorrelationType
    severity: CorrelationSeverity
    confidence: float  # 0.0 to 1.0
    
    # References to source findings
    hcrs_violation_ids: List[str] = field(default_factory=list)
    sdda_drift_ids: List[str] = field(default_factory=list)
    slga_secret_ids: List[str] = field(default_factory=list)
    
    # Details
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    
    # Metadata
    timestamp: datetime = field(default_factory=datetime.now)
    
    @property
    def is_critical(self) -> bool:
        return self.severity == CorrelationSeverity.CRITICAL
    
    @property
    def is_high_confidence(self) -> bool:
        return self.confidence >= 0.7

@dataclass
class CorrelationReport:
    """Summary report of all correlations found"""
    timestamp: datetime
    total_correlations: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    
    correlations: List[Correlation] = field(default_factory=list)
    
    # Statistics
    avg_confidence: float = 0.0
    high_confidence_count: int = 0
    
    # Recommendations
    top_priorities: List[Correlation] = field(default_factory=list)
    
    def get_by_severity(self, severity: CorrelationSeverity) -> List[Correlation]:
        """Get all correlations of a specific severity"""
        return [c for c in self.correlations if c.severity == severity]
    
    def get_high_confidence(self) -> List[Correlation]:
        """Get all high-confidence correlations"""
        return [c for c in self.correlations if c.is_high_confidence]
    
    def get_critical_alerts(self) -> List[Correlation]:
        """Get all critical severity correlations"""
        return [c for c in self.correlations if c.is_critical]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary for JSON serialization"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'summary': {
                'total_correlations': self.total_correlations,
                'critical_count': self.critical_count,
                'high_count': self.high_count,
                'medium_count': self.medium_count,
                'low_count': self.low_count,
                'avg_confidence': round(self.avg_confidence, 2),
                'high_confidence_count': self.high_confidence_count
            },
            'correlations': [
                {
                    'id': c.correlation_id,
                    'type': c.correlation_type.value,
                    'severity': c.severity.value,
                    'confidence': round(c.confidence, 2),
                    'description': c.description,
                    'evidence': c.evidence,
                    'recommendation': c.recommendation,
                    'hcrs_violations': c.hcrs_violation_ids,
                    'sdda_drifts': c.sdda_drift_ids,
                    'slga_secrets': c.slga_secret_ids
                }
                for c in self.correlations
            ],
            'top_priorities': [
                {
                    'id': c.correlation_id,
                    'severity': c.severity.value,
                    'description': c.description,
                    'recommendation': c.recommendation
                }
                for c in self.top_priorities[:5]
            ]
        }
