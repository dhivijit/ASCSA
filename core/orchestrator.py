# Core orchestrator logic
"""
Main orchestrator for ASCSA-CI security pipeline.
Coordinates execution of SLGA, SDDA, and HCRS engines.
"""

import logging
from typing import Dict, Any, List
from datetime import datetime
from cli.context import ScanContext
from cli import exit_codes

logger = logging.getLogger(__name__)


class PipelineOrchestrator:
    """Orchestrates the execution of all security engines."""
    
    def __init__(self, context: ScanContext):
        self.context = context
        self.results = {
            'summary': {
                'run_id': context.run_id,
                'timestamp': context.timestamp.isoformat(),
                'repo_path': context.repo_path,
                'branch': context.branch,
                'environment': context.environment,
                'actor': context.actor
            },
            'slga': None,
            'sdda': None,
            'hcrs': None,
            'slga_skipped': False,
            'sdda_skipped': False,
            'hcrs_skipped': False,
            'recommendation': 'UNKNOWN',
            'recommendations': [],
            'exit_code': exit_codes.SUCCESS
        }
    
    def run(self) -> Dict[str, Any]:
        """Execute the complete security pipeline."""
        import os
        import json
        from datetime import datetime
        logger.info(f"Starting ASCSA-CI security scan: {self.context.run_id}")
        logger.info(f"Repository: {self.context.repo_path}")
        logger.info(f"Branch: {self.context.branch}, Environment: {self.context.environment}")

        # Determine output directory
        output_dir = self.context.reportout_dir or self.context.repo_path
        os.makedirs(output_dir, exist_ok=True)

        # Phase 1: Secret Lineage Graph Analysis (SLGA)
        slga_result = None
        if not self.context.skip_slga:
            slga_graph, slga_secrets = self._run_slga()
            from core.contracts import SecretLineage
            slga_result = SecretLineage(secrets=slga_secrets)  # For downstream compatibility
            # Save SLGA output
            try:
                slga_path = os.path.join(output_dir, "slga.txt")
                with open(slga_path, "w", encoding="utf-8") as f:
                    json.dump(self.results.get('slga', {}), f, indent=2, default=str)
                logger.info(f"SLGA output saved to {slga_path}")
            except Exception as e:
                logger.error(f"Failed to write SLGA output: {e}")
        else:
            logger.info("SLGA: Skipped by configuration")
            self.results['slga_skipped'] = True

        # Phase 2: Secret Drift Detection (SDDA)
        sdda_result = None
        if not self.context.skip_sdda and slga_result:
            sdda_result = self._run_sdda(slga_result)
            # Save SDDA output
            try:
                sdda_path = os.path.join(output_dir, "sdda.txt")
                with open(sdda_path, "w", encoding="utf-8") as f:
                    json.dump(self.results.get('sdda', {}), f, indent=2, default=str)
                logger.info(f"SDDA output saved to {sdda_path}")
            except Exception as e:
                logger.error(f"Failed to write SDDA output: {e}")
        else:
            if self.context.skip_sdda:
                logger.info("SDDA: Skipped by configuration")
            else:
                logger.info("SDDA: Skipped (requires SLGA results)")
            self.results['sdda_skipped'] = True

        # Phase 3: Hybrid Code Risk Scoring (HCRS)
        hcrs_result = None
        if not self.context.skip_hcrs:
            hcrs_result = self._run_hcrs(slga_result, sdda_result)
            # Save HCRS output
            try:
                hcrs_path = os.path.join(output_dir, "hcrs.txt")
                with open(hcrs_path, "w", encoding="utf-8") as f:
                    json.dump(self.results.get('hcrs', {}), f, indent=2, default=str)
                logger.info(f"HCRS output saved to {hcrs_path}")
            except Exception as e:
                logger.error(f"Failed to write HCRS output: {e}")
        else:
            logger.info("HCRS: Skipped by configuration")
            self.results['hcrs_skipped'] = True

        # Phase 4: Correlation & Risk Assessment
        self._correlate_results(slga_result, sdda_result, hcrs_result)

        # Phase 5: Generate Recommendations
        self._generate_recommendations()

        # Phase 6: Determine Exit Code
        self._determine_exit_code()

        # Save main report (all results)
        try:
            report_path = os.path.join(output_dir, "ascsa_report.json")
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(self.results, f, indent=2, default=str)
            logger.info(f"Main report saved to {report_path}")
        except Exception as e:
            logger.error(f"Failed to write main report: {e}")

        logger.info(f"Scan complete. Recommendation: {self.results['recommendation']}")

        return self.results
    
    def _run_slga(self) -> Any:
        """Execute Secret Lineage Graph Analysis."""
        logger.info("=" * 80)
        logger.info("Phase 1: Secret Lineage Graph Analysis (SLGA)")
        logger.info("=" * 80)

        try:
            from engines.slga.run import run_slga

            # Check for Neo4j credentials
            if not (self.context.neo4j_uri and self.context.neo4j_user and self.context.neo4j_pass):
                logger.warning("Neo4j credentials not configured. SLGA will run in limited mode.")
                logger.warning("Set NEO4J_URI, NEO4J_USER, NEO4J_PASS environment variables for full functionality.")
                self.results['slga_skipped'] = True
                return None, []

            graph, secrets = run_slga(
                repo_path=self.context.repo_path,
                ci_config_path=self.context.ci_config_path,
                log_dir=self.context.log_dir,
                artifact_dir=self.context.artifact_dir
            )

            # Extract summary
            total_secrets = len(secrets)
            total_files = len(set(f for s in secrets for f in s.files))
            total_commits = len(set(c for s in secrets for c in s.commits))

            self.results['slga'] = {
                'total_secrets': total_secrets,
                'total_files': total_files,
                'total_commits': total_commits,
                'graph_nodes': getattr(graph, 'node_count', 0),
                'graph_edges': getattr(graph, 'edge_count', 0)
            }

            logger.info(f"SLGA: Found {total_secrets} secrets across {total_files} files")

            return graph, secrets

        except ImportError as e:
            logger.error(f"SLGA: Engine import failed: {e}")
            self.results['slga_skipped'] = True
            return None, []
        except Exception as e:
            logger.error(f"SLGA: Execution failed: {e}", exc_info=True)
            self.results['slga_skipped'] = True
            return None, []
    
    def _run_sdda(self, slga_result) -> Any:
        """Execute Secret Drift Detection Analysis."""
        logger.info("=" * 80)
        logger.info("Phase 2: Secret Drift Detection Analysis (SDDA)")
        logger.info("=" * 80)
        
        try:
            from engines.sdda.run import run_sdda
            from engines.sdda.models import PipelineRun, SecretUsage
            
            # Build PipelineRun from context
            pipeline_run = PipelineRun(
                run_id=self.context.run_id,
                timestamp=self.context.timestamp,
                branch=self.context.branch,
                environment=self.context.environment,
                actor=self.context.actor
            )
            
            # Extract secret usages from SLGA results
            secret_usages = []
            if hasattr(slga_result, 'secrets'):
                for secret in slga_result.secrets:
                    usage = SecretUsage(
                        secret_id=secret.value[:20] + "...",  # Truncate for ID
                        run_id=self.context.run_id,
                        timestamp=self.context.timestamp,
                        stages=set(),
                        access_count=len(secret.files),
                        actor=self.context.actor,
                        environment=self.context.environment,
                        branch=self.context.branch
                    )
                    secret_usages.append(usage)
            
            result = run_sdda(
                pipeline_run=pipeline_run,
                secret_usages=secret_usages,
                config_path=self.context.config_path,
                db_path=self.context.sdda_db_path
            )
            
            # Extract summary
            self.results['sdda'] = {
                'total_secrets_analyzed': result.total_secrets_analyzed,
                'drifted_secrets': [
                    {
                        'secret_id': d.secret_id,
                        'severity': d.severity,
                        'drift_score': d.total_drift_score,
                        'details': d.anomaly_details
                    }
                    for d in result.drifted_secrets
                ],
                'summary': result.summary,
                'baseline_status': result.baseline_status
            }
            
            logger.info(f"SDDA: Analyzed {result.total_secrets_analyzed} secrets, found {len(result.drifted_secrets)} drifts")
            
            return result
            
        except ImportError as e:
            logger.error(f"SDDA: Engine import failed: {e}")
            self.results['sdda_skipped'] = True
            return None
        except Exception as e:
            logger.error(f"SDDA: Execution failed: {e}", exc_info=True)
            self.results['sdda_skipped'] = True
            return None
    
    def _run_hcrs(self, slga_result=None, sdda_result=None) -> Any:
        """Execute Hybrid Code Risk Scoring and include dependency vulnerabilities."""
        logger.info("=" * 80)
        logger.info("Phase 3: Hybrid Code Risk Scoring (HCRS)")
        logger.info("=" * 80)

        try:
            from engines.hcrs.run import run

            # Use the legacy run() to include dep vulns, passing lineage and drift_report
            hcrs_result = run(slga_result, sdda_result, self.context)

            # Try to extract dependency vulnerabilities if present
            dep_vulns = []
            if hasattr(hcrs_result, 'dependency_vulnerabilities'):
                dep_vulns = hcrs_result.dependency_vulnerabilities
            elif hasattr(hcrs_result, 'osv_results'):
                dep_vulns = hcrs_result.osv_results
            elif hasattr(hcrs_result, 'breakdown') and 'dependency_vulnerabilities' in hcrs_result.breakdown:
                dep_vulns = hcrs_result.breakdown['dependency_vulnerabilities']

            self.results['hcrs'] = {
                'total_score': getattr(hcrs_result, 'total', None) or getattr(hcrs_result, 'total_score', None),
                'breakdown': getattr(hcrs_result, 'breakdown', {}),
                'recommendation': getattr(hcrs_result, 'recommendation', None),
                'dependency_vulnerabilities': dep_vulns
            }

            logger.info(f"HCRS: total score: {self.results['hcrs']['total_score']}")
            if dep_vulns:
                logger.info(f"HCRS: Found {len(dep_vulns)} dependency vulnerabilities")

            return hcrs_result

        except ImportError as e:
            logger.error(f"HCRS: Engine import failed: {e}")
            self.results['hcrs_skipped'] = True
            return None
        except Exception as e:
            logger.error(f"HCRS: Execution failed: {e}", exc_info=True)
            self.results['hcrs_skipped'] = True
            return None
    
    def _correlate_results(self, slga_result, sdda_result, hcrs_result):
        """Correlate results from all engines to identify compound risks."""
        logger.info("=" * 80)
        logger.info("Phase 4: Correlation & Risk Assessment")
        logger.info("=" * 80)
        
        correlation_findings = []
        
        # Check for secrets in drifted state with code violations
        if sdda_result and hcrs_result:
            drifted_count = len(sdda_result.drifted_secrets) if hasattr(sdda_result, 'drifted_secrets') else 0
            violations_count = sum(1 for fs in hcrs_result.file_scores for v in fs.violations)
            
            if drifted_count > 0 and violations_count > 0:
                correlation_findings.append(
                    f"Found {drifted_count} drifted secrets AND {violations_count} code violations - high risk of secret exposure"
                )
        
        if correlation_findings:
            logger.warning("Correlation Analysis:")
            for finding in correlation_findings:
                logger.warning(f"  - {finding}")
        else:
            logger.info("Correlation Analysis: No compound risks detected")
        
        self.results['correlation_findings'] = correlation_findings
    
    def _generate_recommendations(self):
        """Generate actionable recommendations based on findings."""
        recommendations = []
        
        # SLGA recommendations
        if self.results.get('slga'):
            secret_count = self.results['slga'].get('total_secrets', 0)
            if secret_count > 0:
                recommendations.append(
                    f"Remove {secret_count} hardcoded secret(s) from repository. Use environment variables or secret management services."
                )
        
        # SDDA recommendations
        if self.results.get('sdda'):
            drifted = self.results['sdda'].get('drifted_secrets', [])
            for drift in drifted:
                if drift['severity'] in ['CRITICAL', 'HIGH']:
                    recommendations.append(
                        f"Secret '{drift['secret_id']}' shows {drift['severity']} drift. Review usage pattern changes and validate authorization."
                    )
        
        # HCRS recommendations
        if self.results.get('hcrs'):
            top_violations = self.results['hcrs'].get('top_violations', [])
            for violation in top_violations[:5]:
                if violation.get('recommendation'):
                    recommendations.append(
                        f"{violation['file']}:{violation['line']} - {violation['recommendation']}"
                    )
        
        self.results['recommendations'] = recommendations
    
    def _determine_exit_code(self):
        """Determine appropriate exit code based on findings."""
        critical_count = 0
        high_count = 0
        medium_count = 0
        
        # Count HCRS violations
        if self.results.get('hcrs'):
            critical_count += self.results['hcrs'].get('critical_count', 0)
            high_count += self.results['hcrs'].get('high_count', 0)
            medium_count += self.results['hcrs'].get('medium_count', 0)
        
        # Count SDDA drifts
        if self.results.get('sdda'):
            summary = self.results['sdda'].get('summary', {})
            critical_count += summary.get('CRITICAL', 0)
            high_count += summary.get('HIGH', 0)
            medium_count += summary.get('MEDIUM', 0)
        
        # Determine recommendation and exit code
        if critical_count > 0:
            self.results['recommendation'] = 'BLOCK - CRITICAL'
            self.results['exit_code'] = exit_codes.RISK_CRITICAL
        elif high_count > 0:
            self.results['recommendation'] = 'BLOCK - HIGH RISK'
            self.results['exit_code'] = exit_codes.RISK_HIGH
        elif medium_count > 0:
            self.results['recommendation'] = 'WARN - MEDIUM RISK'
            self.results['exit_code'] = exit_codes.WARN
        else:
            self.results['recommendation'] = 'PASS'
            self.results['exit_code'] = exit_codes.SUCCESS


def run_pipeline(context: ScanContext) -> Dict[str, Any]:
    """Main entry point for the security pipeline.
    
    Args:
        context: Scan context with all configuration
    
    Returns:
        Dictionary with complete scan results
    """
    orchestrator = PipelineOrchestrator(context)
    return orchestrator.run()
