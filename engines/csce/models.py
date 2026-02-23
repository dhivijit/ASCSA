"""
CSCE Models — Data structures for Cross-engine Security Correlation.

Defines the Correlation, CorrelationReport, and supporting enums used
by the correlation engine and reporters.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum


class CorrelationType(Enum):
    """Types of correlations between different security signals."""
    SPATIAL = "spatial"
    TEMPORAL = "temporal"
    BEHAVIORAL = "behavioral"
    SECRET_MATCH = "secret_match"
    PROPAGATION = "propagation"


class CorrelationSeverity(Enum):
    """Severity of correlated findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Correlation:
    """Represents a correlation between multiple security signals."""
    correlation_id: str
    correlation_type: CorrelationType
    severity: CorrelationSeverity
    confidence: float

    hcrs_violation_ids: List[str] = field(default_factory=list)
    sdda_drift_ids: List[str] = field(default_factory=list)
    slga_secret_ids: List[str] = field(default_factory=list)

    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def is_critical(self) -> bool:
        return self.severity == CorrelationSeverity.CRITICAL

    @property
    def is_high_confidence(self) -> bool:
        return self.confidence >= 0.7


@dataclass
class CorrelationReport:
    """Summary report of all correlations found.

    Includes ``input_summary`` so downstream consumers (LLM, CI dashboards)
    can see what each engine contributed, even when the counts are zero.
    """
    timestamp: datetime
    total_correlations: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int

    correlations: List[Correlation] = field(default_factory=list)

    avg_confidence: float = 0.0
    high_confidence_count: int = 0

    top_priorities: List[Correlation] = field(default_factory=list)

    # Input summary — what each engine contributed to correlation
    input_summary: Dict[str, int] = field(default_factory=lambda: {
        'hcrs_violations': 0,
        'sdda_drifts': 0,
        'slga_secrets': 0,
    })

    def get_by_severity(self, severity: CorrelationSeverity) -> List[Correlation]:
        return [c for c in self.correlations if c.severity == severity]

    def get_high_confidence(self) -> List[Correlation]:
        return [c for c in self.correlations if c.is_high_confidence]

    def get_critical_alerts(self) -> List[Correlation]:
        return [c for c in self.correlations if c.is_critical]

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary for JSON serialization."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'input_summary': self.input_summary,
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
