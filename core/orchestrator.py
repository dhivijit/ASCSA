# Core orchestrator logic
"""
Main orchestrator for ASCSA-CI security pipeline.
Coordinates execution of SLGA, SDDA, and HCRS engines.
"""

import logging
import os
import json
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
            'csce': None,
            'slga_skipped': False,
            'sdda_skipped': False,
            'hcrs_skipped': False,
            'csce_skipped': False,
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
            slga_result = self._run_slga()  # Returns SecretLineage object
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
            # Save HCRS output - both text and JSON reports
            if hcrs_result:
                try:
                    from engines.hcrs.reporter import HCRSReporter
                    
                    # Save detailed text report
                    hcrs_text_path = os.path.join(output_dir, "hcrs.txt")
                    text_report = HCRSReporter.generate_text_report(hcrs_result)
                    with open(hcrs_text_path, "w", encoding="utf-8") as f:
                        f.write(text_report)
                    logger.info(f"HCRS text report saved to {hcrs_text_path}")
                    
                    # Save detailed JSON report
                    hcrs_json_path = os.path.join(output_dir, "hcrs.json")
                    json_report = HCRSReporter.generate_json_report(hcrs_result)
                    with open(hcrs_json_path, "w", encoding="utf-8") as f:
                        f.write(json_report)
                    logger.info(f"HCRS JSON report saved to {hcrs_json_path}")
                    
                except Exception as e:
                    logger.error(f"Failed to write HCRS reports: {e}", exc_info=True)
        else:
            logger.info("HCRS: Skipped by configuration")
            self.results['hcrs_skipped'] = True

        # Phase 4: CSCE - Code-Secret Correlation Engine
        csce_result = self._run_csce(hcrs_result, sdda_result, slga_result)

        # Phase 5: Correlation & Risk Assessment (Legacy)
        self._correlate_results(slga_result, sdda_result, hcrs_result)

        # Phase 6: Generate Recommendations
        self._generate_recommendations()

        # Phase 7: Determine Exit Code
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
            from engines.slga.reporter import SLGAReporter

            # Determine database path
            slga_db_path = getattr(self.context, 'slga_db_path', None) or 'slga.db'
            
            # Run SLGA with storage enabled
            result = run_slga(
                repo_path=self.context.repo_path,
                ci_config_path=self.context.ci_config_path,
                log_dir=self.context.log_dir,
                artifact_dir=self.context.artifact_dir,
                db_path=slga_db_path,
                scan_id=self.context.run_id,
                store_to_db=True
            )
            
            # Unpack results (supports both old and new return format)
            if len(result) == 4:
                graph, secrets, db_path, propagation_analysis = result
            else:
                graph, secrets, db_path = result
                propagation_analysis = None

            # Extract summary
            total_secrets = len(secrets)
            total_files = len(set(f for s in secrets for f in s.files))
            total_commits = len(set(c for s in secrets for c in s.commits))

            self.results['slga'] = {
                'total_secrets': total_secrets,
                'total_files': total_files,
                'total_commits': total_commits,
                'graph_nodes': getattr(graph, 'node_count', 0) if graph else 0,
                'graph_edges': getattr(graph, 'edge_count', 0) if graph else 0,
                'database_path': db_path,
                'neo4j_analysis_available': propagation_analysis is not None
            }
            
            # Add propagation analysis if available
            if propagation_analysis:
                high_risk_secrets = [a for a in propagation_analysis.get('individual_analysis', []) 
                                    if a['severity'] in ['CRITICAL', 'HIGH']]
                
                self.results['slga']['propagation_analysis'] = {
                    'total_analyzed': len(propagation_analysis.get('individual_analysis', [])),
                    'high_risk_count': len(high_risk_secrets),
                    'critical_chains': len(propagation_analysis.get('critical_chains', [])),
                    'high_risk_secrets': high_risk_secrets[:5]  # Top 5 for summary
                }
                
                logger.info(f"Neo4j propagation analysis: {len(high_risk_secrets)} high-risk secrets detected")
                
                # Save detailed propagation analysis
                try:
                    output_dir = self.context.reportout_dir or self.context.repo_path
                    propagation_path = os.path.join(output_dir, "slga_propagation_analysis.json")
                    with open(propagation_path, "w", encoding="utf-8") as f:
                        json.dump(propagation_analysis, f, indent=2, default=str)
                    logger.info(f"Propagation analysis saved to {propagation_path}")
                except Exception as e:
                    logger.error(f"Failed to save propagation analysis: {e}")

            logger.info(f"SLGA: Found {total_secrets} secrets across {total_files} files")
            logger.info(f"SLGA: Data stored in database: {db_path}")
            
            # Generate and save text report
            try:
                reporter = SLGAReporter(db_path)
                text_report = reporter.generate_text_report(secrets)
                json_report = reporter.generate_json_report(secrets)
                reporter.close()
                
                output_dir = self.context.reportout_dir or self.context.repo_path
                
                slga_text_path = os.path.join(output_dir, "slga.txt")
                with open(slga_text_path, "w", encoding="utf-8") as f:
                    f.write(text_report)
                logger.info(f"SLGA text report saved to {slga_text_path}")
                
                slga_json_path = os.path.join(output_dir, "slga.json")
                with open(slga_json_path, "w", encoding="utf-8") as f:
                    f.write(json_report)
                logger.info(f"SLGA JSON report saved to {slga_json_path}")
            except Exception as e:
                logger.error(f"Failed to generate SLGA reports: {e}", exc_info=True)

            # Wrap results in SecretLineage for downstream engines
            from core.contracts import SecretLineage
            lineage = SecretLineage(secrets=secrets)
            lineage.graph = graph  # Attach graph for CSCE access
            
            return lineage

        except ImportError as e:
            logger.error(f"SLGA: Engine import failed: {e}")
            self.results['slga_skipped'] = True
            from core.contracts import SecretLineage
            return SecretLineage(secrets=[])
        except Exception as e:
            logger.error(f"SLGA: Execution failed: {e}", exc_info=True)
            self.results['slga_skipped'] = True
            from core.contracts import SecretLineage
            return SecretLineage(secrets=[])
    
    def _run_sdda(self, slga_result) -> Any:
        """Execute Secret Drift Detection Analysis."""
        logger.info("=" * 80)
        logger.info("Phase 2: Secret Drift Detection Analysis (SDDA)")
        logger.info("=" * 80)
        
        try:
            from engines.sdda.run import run_sdda
            from engines.sdda.models import PipelineRun, SecretUsage
            from engines.sdda.database import SDDADatabase
            
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
                import hashlib
                for secret in slga_result.secrets:
                    # Hash the secret value to create a valid secret_id
                    # that conforms to InputValidator.SECRET_ID_PATTERN: ^[a-zA-Z0-9_\-\.]{1,255}$
                    secret_hash = hashlib.sha256(secret.value.encode()).hexdigest()[:16]
                    secret_id = f"secret_{secret_hash}"
                    
                    usage = SecretUsage(
                        secret_id=secret_id,
                        run_id=self.context.run_id,
                        timestamp=self.context.timestamp,
                        stages=set(),
                        access_count=len(secret.files),
                        actor=self.context.actor,
                        environment=self.context.environment,
                        branch=self.context.branch
                    )
                    secret_usages.append(usage)
            
            # Run SDDA with storage enabled
            result = run_sdda(
                pipeline_run=pipeline_run,
                secret_usages=secret_usages,
                config_path=self.context.config_path,
                db_path=self.context.sdda_db_path,
                store_report=True
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
                'baseline_status': result.baseline_status,
                'database_path': self.context.sdda_db_path
            }
            
            logger.info(f"SDDA: Analyzed {result.total_secrets_analyzed} secrets, found {len(result.drifted_secrets)} drifts")
            logger.info(f"SDDA: Data stored in database: {self.context.sdda_db_path}")
            
            # Generate additional reports
            try:
                output_dir = self.context.reportout_dir or self.context.repo_path
                
                # Get database statistics
                db = SDDADatabase(self.context.sdda_db_path)
                stats = db.get_statistics()
                drift_history = db.get_drift_history(limit=10)
                db.close()
                
                # Generate stats report
                stats_report = {
                    'generated_at': datetime.now().isoformat(),
                    'database_statistics': stats,
                    'recent_drift_history': drift_history
                }
                
                sdda_stats_path = os.path.join(output_dir, "sdda_stats.json")
                with open(sdda_stats_path, "w", encoding="utf-8") as f:
                    json.dump(stats_report, f, indent=2, default=str)
                logger.info(f"SDDA statistics report saved to {sdda_stats_path}")
                
            except Exception as e:
                logger.error(f"Failed to generate SDDA statistics: {e}", exc_info=True)
            
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
            from engines.hcrs.scanner import HCRSScanner
            from engines.hcrs.reporter import HCRSReporter

            # Create scanner and perform full repository scan
            scanner = HCRSScanner(
                config_path=self.context.config_path,
                rules_path=self.context.rules_path
            )
            
            # Perform full scan
            hcrs_result = scanner.scan_repository(self.context.repo_path)

            # Extract summary data
            self.results['hcrs'] = {
                'total_score': hcrs_result.total_score,
                'total_files_analyzed': hcrs_result.summary['total_files_analyzed'],
                'total_violations': hcrs_result.summary['total_violations'],
                'critical_count': hcrs_result.critical_count,
                'high_count': hcrs_result.high_count,
                'medium_count': hcrs_result.medium_count,
                'low_count': hcrs_result.low_count,
                'severity_counts': hcrs_result.summary['severity_counts'],
                'violation_type_counts': hcrs_result.summary.get('violation_type_counts', {}),
                'dependency_vulnerability_count': hcrs_result.summary.get('dependency_vulnerability_count', 0),
                'recommendation': hcrs_result.recommendation,
                'high_risk_files': hcrs_result.summary.get('high_risk_files', []),
                'dependency_vulnerabilities': hcrs_result.dependency_vulnerabilities
            }

            logger.info(f"HCRS: total score: {hcrs_result.total_score:.2f}")
            logger.info(f"HCRS: violations found - Critical: {hcrs_result.critical_count}, High: {hcrs_result.high_count}, Medium: {hcrs_result.medium_count}, Low: {hcrs_result.low_count}")
            if hcrs_result.dependency_vulnerabilities:
                logger.info(f"HCRS: Found {len(hcrs_result.dependency_vulnerabilities)} dependency vulnerabilities")

            return hcrs_result

        except ImportError as e:
            logger.error(f"HCRS: Engine import failed: {e}")
            self.results['hcrs_skipped'] = True
            return None
        except Exception as e:
            logger.error(f"HCRS: Execution failed: {e}", exc_info=True)
            self.results['hcrs_skipped'] = True
            return None
    
    def _run_csce(self, hcrs_result, sdda_result, slga_result):
        """Execute Code-Secret Correlation Engine."""
        logger.info("=" * 80)
        logger.info("Phase 4: Code-Secret Correlation Engine (CSCE)")
        logger.info("=" * 80)
        
        # Check if we have enough data for correlation
        if not hcrs_result:
            logger.info("CSCE: Skipped (requires HCRS results)")
            self.results['csce_skipped'] = True
            return None
        
        try:
            from engines.csce import run_csce
            from engines.csce.reporter import CSCEReporter
            
            # Extract data from engine results
            violations = []
            secrets = []
            drifts = []
            neo4j_graph = None
            
            # Get HCRS violations
            if hcrs_result:
                # hcrs_result is a RepositoryRiskScore object
                for file_score in hcrs_result.file_scores:
                    violations.extend(file_score.violations)
                logger.info(f"CSCE: Loaded {len(violations)} HCRS violations")
            
            # Get SLGA secrets and graph
            if slga_result:
                # slga_result is a SecretLineage object with secrets list and optional graph
                if hasattr(slga_result, 'secrets'):
                    secrets = slga_result.secrets
                    neo4j_graph = getattr(slga_result, 'graph', None)
                    
                    if isinstance(secrets, list):
                        logger.info(f"CSCE: Loaded {len(secrets)} SLGA secrets")
                    if neo4j_graph:
                        logger.info("CSCE: Neo4j graph available for propagation correlation")
                else:
                    logger.warning(f"CSCE: Unexpected SLGA result type: {type(slga_result)}")
            
            # Get SDDA drifts
            if sdda_result and hasattr(sdda_result, 'drifted_secrets'):
                drifts = sdda_result.drifted_secrets
                logger.info(f"CSCE: Loaded {len(drifts)} SDDA drifts")
            
            # Run correlation
            csce_report = run_csce(
                hcrs_violations=violations,
                sdda_drifts=drifts if drifts else None,
                slga_secrets=secrets if secrets else None,
                neo4j_graph=neo4j_graph
            )
            
            # Extract summary
            self.results['csce'] = {
                'total_correlations': csce_report.total_correlations,
                'critical_count': csce_report.critical_count,
                'high_count': csce_report.high_count,
                'medium_count': csce_report.medium_count,
                'low_count': csce_report.low_count,
                'avg_confidence': round(csce_report.avg_confidence, 2),
                'high_confidence_count': csce_report.high_confidence_count,
                'top_priorities': [
                    {
                        'id': c.correlation_id,
                        'type': c.correlation_type.value,
                        'severity': c.severity.value,
                        'confidence': round(c.confidence, 2),
                        'description': c.description,
                        'recommendation': c.recommendation
                    }
                    for c in csce_report.top_priorities[:10]
                ]
            }
            
            logger.info(f"CSCE: Found {csce_report.total_correlations} correlations")
            logger.info(f"CSCE: Critical: {csce_report.critical_count}, High: {csce_report.high_count}, Medium: {csce_report.medium_count}")
            logger.info(f"CSCE: Average confidence: {csce_report.avg_confidence:.1%}")
            
            # Generate and save reports
            try:
                output_dir = self.context.reportout_dir or self.context.repo_path
                
                # Save text report
                csce_text_path = os.path.join(output_dir, "csce.txt")
                text_report = CSCEReporter.generate_text_report(csce_report)
                with open(csce_text_path, "w", encoding="utf-8") as f:
                    f.write(text_report)
                logger.info(f"CSCE text report saved to {csce_text_path}")
                
                # Save JSON report
                csce_json_path = os.path.join(output_dir, "csce.json")
                CSCEReporter.save_report(csce_report, csce_json_path, format='json')
                logger.info(f"CSCE JSON report saved to {csce_json_path}")
                
            except Exception as e:
                logger.error(f"Failed to save CSCE reports: {e}", exc_info=True)
            
            return csce_report
            
        except ImportError as e:
            logger.error(f"CSCE: Engine import failed: {e}")
            self.results['csce_skipped'] = True
            return None
        except Exception as e:
            logger.error(f"CSCE: Execution failed: {e}", exc_info=True)
            self.results['csce_skipped'] = True
            return None
    
    def _correlate_results(self, slga_result, sdda_result, hcrs_result):
        """Correlate results from all engines to identify compound risks (Legacy - now handled by CSCE)."""
        logger.info("=" * 80)
        logger.info("Phase 5: Legacy Correlation & Risk Assessment")
        logger.info("=" * 80)
        
        correlation_findings = []
        
        # Check for secrets in drifted state with code violations
        if sdda_result and hcrs_result:
            drifted_count = len(sdda_result.drifted_secrets) if hasattr(sdda_result, 'drifted_secrets') else 0
            violations_count = hcrs_result.summary.get('total_violations', 0) if hasattr(hcrs_result, 'summary') else 0
            
            if drifted_count > 0 and violations_count > 0:
                correlation_findings.append(
                    f"Found {drifted_count} drifted secrets AND {violations_count} code violations - high risk of secret exposure"
                )
        
        # Check for Neo4j propagation analysis results
        if self.results.get('slga', {}).get('propagation_analysis'):
            prop_analysis = self.results['slga']['propagation_analysis']
            high_risk_count = prop_analysis.get('high_risk_count', 0)
            critical_chains = prop_analysis.get('critical_chains', 0)
            
            if high_risk_count > 0:
                correlation_findings.append(
                    f"Neo4j analysis: {high_risk_count} secrets with HIGH/CRITICAL propagation risk detected"
                )
            
            if critical_chains > 0:
                correlation_findings.append(
                    f"Neo4j analysis: {critical_chains} critical propagation chain(s) found (code -> pipeline -> logs/artifacts)"
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
        
        # CSCE recommendations (highest priority)
        if self.results.get('csce') and not self.results.get('csce_skipped'):
            top_priorities = self.results['csce'].get('top_priorities', [])
            critical_correlations = [p for p in top_priorities if p['severity'] == 'CRITICAL']
            
            if critical_correlations:
                recommendations.append(
                    f"🚨 CSCE: {len(critical_correlations)} CRITICAL correlation(s) detected - immediate action required!"
                )
                
                # Add top 3 critical recommendations
                for corr in critical_correlations[:3]:
                    recommendations.append(
                        f"  → {corr['type'].upper()}: {corr['recommendation']}"
                    )
            
            high_correlations = [p for p in top_priorities if p['severity'] == 'HIGH']
            if high_correlations:
                recommendations.append(
                    f"⚠️  CSCE: {len(high_correlations)} HIGH confidence correlation(s) require review"
                )
        
        # SLGA recommendations
        if self.results.get('slga'):
            secret_count = self.results['slga'].get('total_secrets', 0)
            if secret_count > 0:
                recommendations.append(
                    f"Remove {secret_count} hardcoded secret(s) from repository. Use environment variables or secret management services."
                )
            
            # Neo4j propagation analysis recommendations
            if self.results['slga'].get('propagation_analysis'):
                prop_analysis = self.results['slga']['propagation_analysis']
                high_risk_secrets = prop_analysis.get('high_risk_secrets', [])
                
                for secret_analysis in high_risk_secrets[:3]:  # Top 3 high-risk secrets
                    severity = secret_analysis.get('severity', 'UNKNOWN')
                    risk_score = secret_analysis.get('risk_score', 0)
                    risk_factors = secret_analysis.get('risk_factors', [])
                    
                    recommendations.append(
                        f"{severity} propagation risk (score: {risk_score}): {'; '.join(risk_factors[:2])}"
                    )
                
                critical_chains = prop_analysis.get('critical_chains', 0)
                if critical_chains > 0:
                    recommendations.append(
                        f"URGENT: {critical_chains} secret(s) propagated from code to pipeline to logs/artifacts - immediate remediation required"
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
            # Get high-risk files
            high_risk_files = self.results['hcrs'].get('high_risk_files', [])
            for file_info in high_risk_files[:5]:
                recommendations.append(
                    f"Review {file_info['file']} - Score: {file_info['score']:.2f}, Critical: {file_info['critical_count']}, High: {file_info['high_count']}"
                )
            
            # Add general recommendation if there are vulnerabilities
            dep_vuln_count = self.results['hcrs'].get('dependency_vulnerability_count', 0)
            if dep_vuln_count > 0:
                recommendations.append(
                    f"Update dependencies to fix {dep_vuln_count} known vulnerabilities"
                )
        
        self.results['recommendations'] = recommendations
    
    def _determine_exit_code(self):
        """Determine appropriate exit code based on findings."""
        critical_count = 0
        high_count = 0
        medium_count = 0
        
        # Count CSCE correlations (highest priority)
        if self.results.get('csce') and not self.results.get('csce_skipped'):
            critical_count += self.results['csce'].get('critical_count', 0)
            high_count += self.results['csce'].get('high_count', 0)
            medium_count += self.results['csce'].get('medium_count', 0)
        else:
            # Fallback to individual engine counts if CSCE not run
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
