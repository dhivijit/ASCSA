# Core contracts
from dataclasses import dataclass
from typing import List, Dict, Optional

@dataclass
class Secret:
    id: str
    type: str
    introduced_commit: str
    files: List[str]
    services: List[str]

@dataclass
class SecretLineage:
    secrets: List[Secret]

@dataclass
class DriftEvent:
    secret_id: str
    drift_type: str
    severity: str
    details: Dict

@dataclass
class DriftReport:
    drifts: List[DriftEvent]

@dataclass
class RiskScore:
    total: int
    breakdown: Dict[str, int]
    recommendation: str
