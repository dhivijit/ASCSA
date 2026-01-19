# CSCE - Code-Secret Correlation Engine
"""
Correlates outputs from HCRS, SDDA, and SLGA to identify high-confidence security risks.
Multi-signal fusion for intelligent security alerting.
"""

from .correlator import CorrelationEngine, run_csce
from .models import Correlation, CorrelationReport, CorrelationType, CorrelationSeverity

__all__ = [
    'CorrelationEngine',
    'run_csce',
    'Correlation',
    'CorrelationReport',
    'CorrelationType',
    'CorrelationSeverity',
]
