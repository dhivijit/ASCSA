"""CSCE Correlator — Cross-engine security correlation logic.

Finds relationships between findings from HCRS (code violations),
SDDA (secret drift), and SLGA (hardcoded secrets / lineage).

Correlation types:
  - Spatial: violation and secret in the same file
  - Secret Match: hardcoded secret detected by both HCRS and SLGA
  - Behavioral: secret drift coinciding with code violations
  - Propagation: secret propagated through risky code (Neo4j)

The report includes an ``input_summary`` so consumers can see what
each engine contributed, even when correlation count is zero.
"""
import logging
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from pathlib import Path

from typing import Tuple
from .models import Correlation, CorrelationReport, CorrelationType, CorrelationSeverity
from engines.hcrs.models import SecurityViolation, Severity as HCRSSeverity
from engines.sdda.models import DriftReport, DriftDetection
from engines.sdda.git_drift_detector import GitDriftDetection, _sid
from engines.slga.models import Secret

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """Correlates findings from HCRS, SDDA, and SLGA."""

    def __init__(self):
        self.correlations = []
        self._input_counts = {'hcrs_violations': 0, 'sdda_drifts': 0, 'slga_secrets': 0}
        self._raw_spatial_count = 0  # set by _deduplicate_spatial()
    
    def correlate(
        self, 
        hcrs_violations: List[SecurityViolation],
        sdda_drifts: Optional[List[DriftDetection]] = None,
        slga_secrets: Optional[List[Secret]] = None,
        neo4j_graph=None
    ) -> CorrelationReport:
        """
        Main correlation function - finds relationships between different security signals.
        
        Args:
            hcrs_violations: Code violations from HCRS
            sdda_drifts: Secret drift detections from SDDA
            slga_secrets: Detected secrets from SLGA
            neo4j_graph: Optional Neo4j graph for advanced propagation queries
            
        Returns:
            CorrelationReport with all found correlations
        """
        self.correlations = []
        self._input_counts = {
            'hcrs_violations': len(hcrs_violations),
            'sdda_drifts': len(sdda_drifts) if sdda_drifts else 0,
            'slga_secrets': len(slga_secrets) if slga_secrets else 0,
        }

        logger.info("Starting CSCE correlation analysis...")
        logger.info(f"Inputs: {self._input_counts['hcrs_violations']} violations, "
                    f"{self._input_counts['sdda_drifts']} drifts, "
                    f"{self._input_counts['slga_secrets']} secrets")
        
        # 1. Spatial correlation (same file/location)
        if slga_secrets:
            self._correlate_spatial(hcrs_violations, slga_secrets)
        
        # 2. Secret match correlation (hardcoded secret detected by both)
        if slga_secrets:
            self._correlate_secret_match(hcrs_violations, slga_secrets)
        
        # 3. Behavioral correlation (drift + risky code)
        if sdda_drifts and slga_secrets:
            self._correlate_behavioral(hcrs_violations, sdda_drifts, slga_secrets)
        
        # 4. Advanced propagation correlation (requires Neo4j)
        if neo4j_graph and slga_secrets:
            self._correlate_propagation(hcrs_violations, slga_secrets, neo4j_graph)
        
        # 5. Code structure correlation (secret in function -> call chain risk,
        #    single-contributor risk, hotspot risk)
        if slga_secrets:
            self._correlate_code_structure(hcrs_violations, slga_secrets)
        
        # Deduplicate spatial correlations that share the same (file, violation_type)
        # root cause — prevents cross-product inflation when a file has many secrets.
        self._deduplicate_spatial()

        logger.info(f"CSCE analysis complete: {len(self.correlations)} correlations found")

        # Generate report
        return self._generate_report()
    
    def _correlate_spatial(
        self, 
        violations: List[SecurityViolation], 
        secrets: List[Secret]
    ):
        """Find violations and secrets in the same files"""
        logger.debug("Running spatial correlation...")
        
        for violation in violations:
            file_path = violation.location.file_path
            
            # Find secrets in the same file
            matching_secrets = [s for s in secrets if file_path in s.files]
            
            if matching_secrets:
                # Check if it's a sensitive operation on the secret
                is_sensitive = violation.violation_type.value in [
                    'sensitive_logging', 
                    'hardcoded_secret',
                    'command_injection',
                    'sql_injection'
                ]
                
                severity = self._calculate_severity(
                    violation.severity.value,
                    'HIGH' if is_sensitive else 'MEDIUM'
                )
                
                confidence = 0.8 if is_sensitive else 0.6
                
                correlation = Correlation(
                    correlation_id=f"SPATIAL_{len(self.correlations)}",
                    correlation_type=CorrelationType.SPATIAL,
                    severity=severity,
                    confidence=confidence,
                    hcrs_violation_ids=[f"{violation.location.file_path}:{violation.location.line_start}"],
                    slga_secret_ids=[s.value[:20] + "..." for s in matching_secrets],
                    description=f"Secret found in file with {violation.violation_type.value}",
                    evidence={
                        'file': file_path,
                        'violation_type': violation.violation_type.value,
                        'violation_severity': violation.severity.value,
                        'secret_count': len(matching_secrets),
                        'line': violation.location.line_start
                    },
                    recommendation=f"Review {Path(file_path).name} - contains {len(matching_secrets)} secret(s) and {violation.violation_type.value}"
                )
                
                self.correlations.append(correlation)
                logger.debug(f"Found spatial correlation in {file_path}")
    
    def _correlate_secret_match(
        self, 
        violations: List[SecurityViolation], 
        secrets: List[Secret]
    ):
        """Find hardcoded secrets detected by both HCRS and SLGA"""
        logger.debug("Running secret match correlation...")
        
        hardcoded_violations = [
            v for v in violations 
            if v.violation_type.value == 'hardcoded_secret'
        ]
        
        for violation in hardcoded_violations:
            file_path = violation.location.file_path
            
            # Find SLGA secrets in the same file and nearby lines
            for secret in secrets:
                if file_path in secret.files:
                    # Check if lines are close (within 5 lines)
                    secret_lines = [line for line in secret.lines if file_path in secret.files]
                    violation_line = violation.location.line_start
                    
                    lines_match = any(
                        abs(secret_line - violation_line) <= 5 
                        for secret_line in secret_lines
                    )
                    
                    if lines_match or len(secret_lines) == 0:
                        # High confidence - both engines detected it
                        correlation = Correlation(
                            correlation_id=f"SECRET_MATCH_{len(self.correlations)}",
                            correlation_type=CorrelationType.SECRET_MATCH,
                            severity=CorrelationSeverity.CRITICAL,
                            confidence=0.95,  # Very high confidence
                            hcrs_violation_ids=[f"{file_path}:{violation.location.line_start}"],
                            slga_secret_ids=[secret.value[:20] + "..."],
                            description="Hardcoded secret confirmed by multiple detection methods",
                            evidence={
                                'file': file_path,
                                'hcrs_line': violation.location.line_start,
                                'slga_lines': secret.lines if secret.lines else ['N/A'],
                                'entropy': secret.entropy,
                                'secret_type': secret.secret_type
                            },
                            recommendation="🚨 IMMEDIATE ACTION: Rotate this secret and remove from code. Both HCRS and SLGA detected it."
                        )
                        
                        self.correlations.append(correlation)
                        logger.info(f"Found SECRET_MATCH correlation in {file_path}")
    
    def _correlate_behavioral(
        self,
        violations: List[SecurityViolation],
        drifts: List[DriftDetection],
        secrets: List[Secret]
    ):
        """Correlate secret drift with code violations"""
        logger.debug("Running behavioral correlation...")
        
        # Build a lookup: sid-hash → secret for git-diff mode matching
        sid_to_secret = {_sid(s.value): s for s in secrets}

        for drift in drifts:
            # Match drift.secret_id to a Secret object.
            # Git-diff mode: secret_id is _sid(value); baseline mode: secret_id is the raw id.
            secret = sid_to_secret.get(drift.secret_id)
            if secret is None:
                # Fallback: direct value match (baseline / Mode-1 DriftDetection)
                matches = [s for s in secrets if s.value == drift.secret_id]
                secret = matches[0] if matches else None
            if secret is None:
                continue
            
            # Find violations in files containing this secret
            for file_path in secret.files:
                file_violations = [
                    v for v in violations 
                    if v.location.file_path == file_path
                ]
                
                if file_violations:
                    # Drift + risky code = high severity
                    severity = self._calculate_severity(
                        drift.severity,
                        max([v.severity.value for v in file_violations])
                    )
                    
                    # Normalise anomaly_details to a string regardless of type
                    ad = drift.anomaly_details
                    if isinstance(ad, dict):
                        anomaly_details_str = ' '.join(str(v) for v in ad.values())
                    elif isinstance(ad, list):
                        anomaly_details_str = ' '.join(str(x) for x in ad)
                    else:
                        anomaly_details_str = str(ad)

                    is_production_drift = 'production' in anomaly_details_str.lower()
                    has_critical_violation = any(
                        v.severity.value == 'CRITICAL' 
                        for v in file_violations
                    )
                    
                    if is_production_drift and has_critical_violation:
                        severity = CorrelationSeverity.CRITICAL
                    
                    # Normalise evidence value for details
                    if isinstance(ad, dict):
                        evidence_details = {k: str(v) for k, v in ad.items()}
                    elif isinstance(ad, list):
                        evidence_details = ', '.join(str(x) for x in ad)
                    else:
                        evidence_details = str(ad)

                    correlation = Correlation(
                        correlation_id=f"BEHAVIORAL_{len(self.correlations)}",
                        correlation_type=CorrelationType.BEHAVIORAL,
                        severity=severity,
                        confidence=0.85,
                        hcrs_violation_ids=[
                            f"{v.location.file_path}:{v.location.line_start}" 
                            for v in file_violations
                        ],
                        sdda_drift_ids=[drift.secret_id],
                        slga_secret_ids=[secret.value[:20] + "..."],
                        description=f"Secret drift detected with {len(file_violations)} code violation(s)",
                        evidence={
                            'drift_severity': drift.severity,
                            'drift_details': evidence_details,
                            'violations': [v.violation_type.value for v in file_violations],
                            'file': file_path,
                            'is_production': is_production_drift
                        },
                        recommendation=f"⚠️ URGENT: {drift.recommendation} AND review code violations in {Path(file_path).name}"
                    )
                    
                    self.correlations.append(correlation)
                    logger.info(f"Found BEHAVIORAL correlation: drift + violations in {file_path}")
    
    def _correlate_propagation(
        self,
        violations: List[SecurityViolation],
        secrets: List[Secret],
        neo4j_graph
    ):
        """Use Neo4j to find secrets that propagated through risky code"""
        logger.debug("Running propagation correlation...")
        
        try:
            # Query graph for secrets with significant propagation
            for secret in secrets:
                # Find files with violations
                violation_files = {v.location.file_path for v in violations}
                
                # Check if secret appears in violation files
                secret_files = set(secret.files)
                intersection = violation_files & secret_files
                
                if intersection:
                    # Use Neo4j to check propagation path
                    try:
                        analysis = neo4j_graph.analyze_secret_propagation(secret.value)
                        if not analysis:
                            continue

                        risk_score = analysis.get('risk_score', 0)
                        scope = analysis.get('propagation_scope', {})
                        # Derive a depth proxy from the propagation scope
                        propagation_depth = sum(
                            1 for k in ('files', 'stages', 'logs', 'artifacts')
                            if scope.get(k, 0) > 0
                        )

                        if risk_score > 30 or propagation_depth > 2:
                            correlation = Correlation(
                                correlation_id=f"PROPAGATION_{len(self.correlations)}",
                                correlation_type=CorrelationType.PROPAGATION,
                                severity=CorrelationSeverity.HIGH,
                                confidence=0.9,
                                hcrs_violation_ids=[str(f) for f in intersection],
                                slga_secret_ids=[secret.value[:20] + "..."],
                                description=f"Secret propagated across {propagation_depth} scope(s) (risk score {risk_score})",
                                evidence={
                                    'risk_score': risk_score,
                                    'propagation_depth': propagation_depth,
                                    'propagation_scope': scope,
                                    'severity': analysis.get('severity', 'UNKNOWN'),
                                    'files_affected': list(intersection)
                                },
                                recommendation="Review propagation chain - secret may be exposed in multiple locations"
                            )
                            
                            self.correlations.append(correlation)
                            logger.info(f"Found PROPAGATION correlation for secret with risk score {risk_score}")
                    except Exception as e:
                        logger.warning(f"Failed to analyze propagation for secret: {e}")
        
        except Exception as e:
            logger.error(f"Propagation correlation failed: {e}")
    
    def _correlate_code_structure(
        self,
        violations: List[SecurityViolation],
        secrets: List[Secret],
    ):
        """Correlate secrets with code structure data (functions, hotspots, contributors).

        Uses enrichment data attached to scan_stats (code_analysis, git_context)
        when available.  Falls back to file-level heuristics otherwise.
        """
        logger.debug("Running code structure correlation...")

        for secret in secrets:
            for file_path in secret.files:
                # Check if file has violations AND a secret — compound risk
                file_violations = [
                    v for v in violations
                    if v.location.file_path == file_path
                ]
                if not file_violations:
                    continue

                violation_types = list({v.violation_type.value for v in file_violations})
                max_sev = max(
                    (v.severity.value for v in file_violations),
                    key=lambda s: {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(s.upper(), 0),
                )

                severity = self._calculate_severity(max_sev, 'HIGH')

                correlation = Correlation(
                    correlation_id=f"CODE_STRUCTURE_{len(self.correlations)}",
                    correlation_type=CorrelationType.CODE_STRUCTURE,
                    severity=severity,
                    confidence=0.75,
                    hcrs_violation_ids=[
                        f"{v.location.file_path}:{v.location.line_start}"
                        for v in file_violations
                    ],
                    slga_secret_ids=[secret.value[:20] + "..."],
                    description=(
                        f"Secret co-located with {len(file_violations)} code violation(s) "
                        f"({', '.join(violation_types[:3])}) in {Path(file_path).name}"
                    ),
                    evidence={
                        'file': file_path,
                        'violation_types': violation_types,
                        'secret_type': secret.secret_type,
                        'entropy': secret.entropy,
                    },
                    recommendation=(
                        f"Review code structure in {Path(file_path).name}: "
                        f"secret with {len(file_violations)} violation(s) increases exposure risk. "
                        f"Rotate the secret and remediate violations."
                    ),
                )
                self.correlations.append(correlation)
                logger.debug(f"Found CODE_STRUCTURE correlation in {file_path}")

    def _deduplicate_spatial(self) -> None:
        """Collapse spatial correlations sharing a (file, violation_type) root cause.

        The raw pre-dedup count is preserved in self._raw_spatial_count so the
        report can show both numbers.  Other correlation types are not touched —
        they are qualitatively distinct and low-volume.
        """
        severity_rank = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}

        spatial = [
            c for c in self.correlations
            if c.correlation_type == CorrelationType.SPATIAL
        ]
        other = [
            c for c in self.correlations
            if c.correlation_type != CorrelationType.SPATIAL
        ]

        self._raw_spatial_count = len(spatial)

        # Group by (file_path, violation_type)
        groups: Dict[Tuple[str, str], List[Correlation]] = {}
        for corr in spatial:
            key = (
                corr.evidence.get('file', ''),
                corr.evidence.get('violation_type', ''),
            )
            groups.setdefault(key, []).append(corr)

        deduplicated: List[Correlation] = []
        for (file_path, vtype), group in groups.items():
            # Representative = highest severity + highest confidence
            rep = max(
                group,
                key=lambda c: (
                    severity_rank.get(c.severity.value, 0),
                    c.confidence,
                ),
            )
            # Merge all unique violation and secret IDs from the group
            merged_violation_ids = list({
                vid for c in group for vid in c.hcrs_violation_ids
            })
            merged_secret_ids = list({
                sid for c in group for sid in c.slga_secret_ids
            })
            grouped = Correlation(
                correlation_id=rep.correlation_id,
                correlation_type=rep.correlation_type,
                severity=rep.severity,
                confidence=rep.confidence,
                hcrs_violation_ids=merged_violation_ids,
                slga_secret_ids=merged_secret_ids,
                sdda_drift_ids=rep.sdda_drift_ids,
                description=rep.description,
                evidence={
                    **rep.evidence,
                    'grouped_violation_count': len(group),
                    'raw_line_pair_count': len(group),
                },
                recommendation=rep.recommendation,
                timestamp=rep.timestamp,
            )
            deduplicated.append(grouped)

        self.correlations = deduplicated + other
        logger.info(
            f"CSCE spatial dedup: {self._raw_spatial_count} raw spatial pairs "
            f"→ {len(deduplicated)} compound findings "
            f"(grouped by file + violation_type)"
        )

    def _calculate_severity(self, severity1: str, severity2: str) -> CorrelationSeverity:
        """Calculate combined severity from two sources"""
        severity_levels = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
        
        level1 = severity_levels.get(severity1.upper(), 1)
        level2 = severity_levels.get(severity2.upper(), 1)
        
        # Take the maximum and amplify if both are high
        max_level = max(level1, level2)
        if level1 >= 3 and level2 >= 3:
            max_level = 4  # Both high = critical
        
        severity_map = {
            4: CorrelationSeverity.CRITICAL, 
            3: CorrelationSeverity.HIGH, 
            2: CorrelationSeverity.MEDIUM, 
            1: CorrelationSeverity.LOW
        }
        
        return severity_map.get(max_level, CorrelationSeverity.LOW)
    
    def _generate_report(self) -> CorrelationReport:
        """Generate correlation report from findings"""
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        high_confidence = []
        total_confidence = 0
        
        for corr in self.correlations:
            severity_counts[corr.severity.value] += 1
            total_confidence += corr.confidence
            
            if corr.is_high_confidence:
                high_confidence.append(corr)
        
        # Sort by severity and confidence for top priorities
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        top_priorities = sorted(
            self.correlations,
            key=lambda c: (
                -severity_order.get(c.severity.value, 0),
                -c.confidence
            )
        )[:10]
        
        input_summary = dict(self._input_counts)
        # Expose raw-vs-grouped spatial counts so reports are transparent.
        input_summary['raw_spatial_pairs'] = self._raw_spatial_count
        input_summary['grouped_spatial_findings'] = sum(
            1 for c in self.correlations
            if c.correlation_type == CorrelationType.SPATIAL
        )

        return CorrelationReport(
            timestamp=datetime.now(),
            total_correlations=len(self.correlations),
            critical_count=severity_counts['CRITICAL'],
            high_count=severity_counts['HIGH'],
            medium_count=severity_counts['MEDIUM'],
            low_count=severity_counts['LOW'],
            correlations=self.correlations,
            avg_confidence=total_confidence / len(self.correlations) if self.correlations else 0,
            high_confidence_count=len(high_confidence),
            top_priorities=top_priorities,
            input_summary=input_summary,
        )


def run_csce(
    hcrs_violations: List[SecurityViolation],
    sdda_drifts: Optional[List[DriftDetection]] = None,
    slga_secrets: Optional[List[Secret]] = None,
    neo4j_graph=None
) -> CorrelationReport:
    """
    Main entry point for CSCE correlation.
    
    Args:
        hcrs_violations: Code violations from HCRS
        sdda_drifts: Secret drift detections from SDDA (optional)
        slga_secrets: Detected secrets from SLGA (optional)
        neo4j_graph: Neo4j graph instance (optional)
    
    Returns:
        CorrelationReport with all correlations
    
    Example:
        >>> from engines.hcrs import run_hcrs
        >>> from engines.slga import run_slga
        >>> from engines.csce import run_csce
        >>> 
        >>> # Run individual engines
        >>> repo_score = run_hcrs(repo_path)
        >>> graph, secrets, _ = run_slga(repo_path)
        >>> 
        >>> # Correlate findings
        >>> violations = repo_score.get_all_violations()
        >>> report = run_csce(violations, slga_secrets=secrets)
        >>> 
        >>> # Check critical correlations
        >>> for corr in report.get_critical_alerts():
        >>>     print(f"{corr.severity}: {corr.description}")
    """
    engine = CorrelationEngine()
    return engine.correlate(hcrs_violations, sdda_drifts, slga_secrets, neo4j_graph)
