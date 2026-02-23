"""
Main orchestrator for ASCSA-CI security pipeline.

Coordinates execution of SLGA, SDDA, HCRS, and CSCE engines,
generates all report files, and produces the master ascsa_report.json
with scan metadata and LLM-friendly context.
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
        scan_start = datetime.now()
        logger.info(f"Starting ASCSA-CI security scan: {self.context.run_id}")
        logger.info(f"Repository: {self.context.repo_path}")
        logger.info(f"Branch: {self.context.branch}, Environment: {self.context.environment}")

        # Determine output directory
        output_dir = self.context.reportout_dir or self.context.repo_path
        os.makedirs(output_dir, exist_ok=True)

        # Phase 1: Secret Lineage Graph Analysis (SLGA)
        slga_result = None
        if not self.context.skip_slga:
            slga_result = self._run_slga()
            # NOTE: slga.txt, slga.json, slga_propagation_analysis.json
            # are written inside _run_slga() — no duplicate write here.
        else:
            logger.info("SLGA: Skipped by configuration")
            self.results['slga_skipped'] = True

        # Phase 2: Secret Drift Detection (SDDA)
        sdda_result = None
        if not self.context.skip_sdda and slga_result:
            sdda_result = self._run_sdda(slga_result)
            # Save SDDA text report
            try:
                sdda_text_path = os.path.join(output_dir, "sdda.txt")
                sdda_text = self._format_sdda_text(sdda_result)
                with open(sdda_text_path, "w", encoding="utf-8") as f:
                    f.write(sdda_text)
                logger.info(f"SDDA text report saved to {sdda_text_path}")
            except Exception as e:
                logger.error(f"Failed to write SDDA text report: {e}")
        else:
            if self.context.skip_sdda:
                logger.info("SDDA: Skipped by configuration")
            else:
                logger.info("SDDA: Skipped (requires SLGA results with detected secrets)")
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

        # Save main report (all results) with scan metadata
        scan_end = datetime.now()
        scan_duration = (scan_end - scan_start).total_seconds()

        self.results['scan_metadata'] = {
            'scan_start': scan_start.isoformat(),
            'scan_end': scan_end.isoformat(),
            'scan_duration_seconds': round(scan_duration, 2),
            'engines_run': {
                'slga': not self.results.get('slga_skipped', False),
                'sdda': not self.results.get('sdda_skipped', False),
                'hcrs': not self.results.get('hcrs_skipped', False),
                'csce': not self.results.get('csce_skipped', False),
            },
        }

        self.results['llm_context'] = self._build_llm_context()

        try:
            report_path = os.path.join(output_dir, "ascsa_report.json")
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(self.results, f, indent=2, default=str)
            logger.info(f"Main report saved to {report_path}")
        except Exception as e:
            logger.error(f"Failed to write main report: {e}")

        # Upload reports to cloud storage if enabled
        if self.context.enable_upload:
            self._upload_reports(output_dir)

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
            
            # Get commit scanning parameters from context (with defaults)
            scan_commits = getattr(self.context, 'slga_scan_commits', True)
            max_commits = getattr(self.context, 'slga_max_commits', 100)
            
            logger.info(f"SLGA: Commit scanning {'enabled' if scan_commits else 'disabled'}")
            if scan_commits:
                logger.info(f"SLGA: Will scan up to {max_commits} commits")
            
            # Run SLGA with storage enabled
            result = run_slga(
                repo_path=self.context.repo_path,
                ci_config_path=self.context.ci_config_path,
                log_dir=self.context.log_dir,
                artifact_dir=self.context.artifact_dir,
                db_path=slga_db_path,
                scan_id=self.context.run_id,
                store_to_db=True,
                scan_commits=scan_commits,
                max_commits=max_commits
            )
            
            # Unpack results (supports old 4-tuple and new 5-tuple with scan_stats)
            scan_stats = None
            if len(result) == 5:
                graph, secrets, db_path, propagation_analysis, scan_stats = result
            elif len(result) == 4:
                graph, secrets, db_path, propagation_analysis = result
            else:
                graph, secrets, db_path = result
                propagation_analysis = None

            # Extract summary
            total_secrets = len(secrets)
            total_files = len(set(f for s in secrets for f in s.files))
            total_commits = len(set(c for s in secrets for c in s.commits))
            
            # Categorize secrets by source
            file_secrets = [s for s in secrets if s.files]
            commit_secrets = [s for s in secrets if s.secret_type == "commit_history"]

            self.results['slga'] = {
                'total_secrets': total_secrets,
                'secrets_from_files': len(file_secrets),
                'secrets_from_commits': len(commit_secrets),
                'total_files': total_files,
                'total_commits': total_commits,
                'commit_scanning_enabled': scan_commits,
                'max_commits_scanned': max_commits if scan_commits else 0,
                'commits_with_secrets': len([s for s in secrets if s.commits]),
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
            else:
                # Always create the file so downstream consumers have a consistent set of outputs
                try:
                    output_dir = self.context.reportout_dir or self.context.repo_path
                    propagation_path = os.path.join(output_dir, "slga_propagation_analysis.json")
                    placeholder = {
                        "status": "not_available",
                        "reason": "Neo4j credentials not configured or no secrets detected for propagation analysis",
                        "individual_analysis": [],
                        "critical_chains": []
                    }
                    with open(propagation_path, "w", encoding="utf-8") as f:
                        json.dump(placeholder, f, indent=2)
                    logger.info(f"Propagation analysis placeholder saved to {propagation_path}")
                except Exception as e:
                    logger.error(f"Failed to save propagation analysis placeholder: {e}")

            logger.info(f"SLGA: Found {total_secrets} secrets total")
            logger.info(f"SLGA:   - Current files: {len(file_secrets)} secrets in {total_files} files")
            logger.info(f"SLGA:   - Commit history: {len(commit_secrets)} secrets from git commits")
            logger.info(f"SLGA:   - Total commits analyzed: {total_commits}")
            logger.info(f"SLGA: Data stored in database: {db_path}")
            
            # Add scan_stats to results if available
            if scan_stats:
                self.results['slga']['scan_stats'] = scan_stats
                # Surface code analysis and git context at top level for downstream use
                if scan_stats.get('code_analysis'):
                    self.results['slga']['code_analysis'] = scan_stats['code_analysis']
                if scan_stats.get('git_context'):
                    self.results['slga']['git_context'] = scan_stats['git_context']

            # Generate and save text report
            try:
                reporter = SLGAReporter(db_path)
                text_report = reporter.generate_text_report(secrets, scan_stats=scan_stats)
                json_report = reporter.generate_json_report(secrets, scan_stats=scan_stats)
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
                    f"CRITICAL: CSCE found {len(critical_correlations)} CRITICAL correlation(s) - immediate action required!"
                )
                
                # Add top 3 critical recommendations
                for corr in critical_correlations[:3]:
                    recommendations.append(
                        f"  → {corr['type'].upper()}: {corr['recommendation']}"
                    )
            
            high_correlations = [p for p in top_priorities if p['severity'] == 'HIGH']
            if high_correlations:
                recommendations.append(
                    f"HIGH: CSCE found {len(high_correlations)} HIGH confidence correlation(s) requiring review"
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
        
        # Clean repo: provide positive confirmation so LLM has useful context
        if not recommendations:
            recommendations.append(
                "PASS: No security issues detected. The repository appears clean."
            )
            if not self.results.get('slga_skipped'):
                recommendations.append(
                    "SLGA: No hardcoded secrets found in code or commit history."
                )
            if not self.results.get('hcrs_skipped'):
                recommendations.append(
                    "HCRS: No code-level security violations detected."
                )
        
        self.results['recommendations'] = recommendations
    
    def _build_llm_context(self) -> Dict[str, Any]:
        """Build a structured summary designed for LLM-based remediation.

        Returns a dict with a natural-language narrative plus key metrics
        so an LLM can quickly understand what was found and what to fix.
        """
        engines_run = []
        engines_skipped = []
        for eng in ('slga', 'sdda', 'hcrs', 'csce'):
            if self.results.get(f'{eng}_skipped', False):
                engines_skipped.append(eng.upper())
            else:
                engines_run.append(eng.upper())

        finding_bullets = []
        slga = self.results.get('slga')
        if slga:
            n = slga.get('total_secrets', 0)
            if n:
                finding_bullets.append(f"SLGA detected {n} hardcoded secret(s) across {slga.get('total_files', 0)} file(s).")
            else:
                finding_bullets.append("SLGA: No hardcoded secrets detected.")
            ca = slga.get('code_analysis')
            if ca:
                finding_bullets.append(
                    f"SLGA code analysis: {ca.get('total_functions', 0)} functions, "
                    f"{ca.get('total_classes', 0)} classes across {ca.get('files_parsed', 0)} files "
                    f"({', '.join(ca.get('languages', []))})."
                )
            gc = slga.get('git_context')
            if gc:
                finding_bullets.append(
                    f"SLGA git context: {gc.get('total_contributors', 0)} contributor(s), "
                    f"{gc.get('hotspot_count', 0)} file hotspot(s)."
                )

        hcrs = self.results.get('hcrs')
        if hcrs:
            v = hcrs.get('total_violations', 0)
            if v:
                finding_bullets.append(
                    f"HCRS found {v} code violation(s) — Critical: {hcrs.get('critical_count', 0)}, "
                    f"High: {hcrs.get('high_count', 0)}, Medium: {hcrs.get('medium_count', 0)}, "
                    f"Low: {hcrs.get('low_count', 0)}."
                )
            else:
                finding_bullets.append("HCRS: No code violations detected.")
            dep = hcrs.get('dependency_vulnerability_count', 0)
            if dep:
                finding_bullets.append(f"HCRS: {dep} dependency vulnerability/ies via OSV.")

        sdda = self.results.get('sdda')
        if sdda:
            d = len(sdda.get('drifted_secrets', []))
            if d:
                finding_bullets.append(f"SDDA detected behavioral drift in {d} secret(s).")
            else:
                finding_bullets.append(f"SDDA: No secret drift detected ({sdda.get('baseline_status', 'OK')}).")

        csce = self.results.get('csce')
        if csce:
            c = csce.get('total_correlations', 0)
            if c:
                finding_bullets.append(
                    f"CSCE found {c} cross-engine correlation(s) — "
                    f"Critical: {csce.get('critical_count', 0)}, High: {csce.get('high_count', 0)}."
                )
            else:
                finding_bullets.append("CSCE: No cross-engine correlations found.")

        is_clean = all(
            not self.results.get(eng) or (
                self.results[eng].get('total_secrets', 0) == 0
                and self.results[eng].get('total_violations', 0) == 0
                and self.results[eng].get('total_correlations', 0) == 0
                and len(self.results[eng].get('drifted_secrets', [])) == 0
            )
            for eng in ('slga', 'hcrs', 'sdda', 'csce')
        )

        return {
            'overall_status': self.results.get('recommendation', 'UNKNOWN'),
            'is_clean_repo': is_clean,
            'engines_executed': engines_run,
            'engines_skipped': engines_skipped,
            'findings_summary': finding_bullets,
            'recommendations': self.results.get('recommendations', []),
            'narrative': (
                "The repository appears clean from a security perspective. "
                "No hardcoded secrets, code violations, behavioral drift, or cross-engine "
                "correlations were detected."
            ) if is_clean else (
                "Security findings require attention. See findings_summary and recommendations "
                "for details. Prioritize CRITICAL and HIGH severity items first."
            ),
        }

    def _format_sdda_text(self, sdda_result) -> str:
        """Format SDDA results as a human-readable text report."""
        lines = []
        lines.append("=" * 72)
        lines.append("SDDA - Secret Drift Detection Analysis Report")
        lines.append("=" * 72)
        lines.append("")

        total = getattr(sdda_result, 'total_secrets_analyzed', 0)
        baseline = getattr(sdda_result, 'baseline_status', 'UNKNOWN')
        drifted = getattr(sdda_result, 'drifted_secrets', [])

        lines.append(f"Secrets Analyzed:  {total}")
        lines.append(f"Baseline Status:   {baseline}")
        lines.append(f"Drifted Secrets:   {len(drifted)}")
        lines.append("")

        if drifted:
            lines.append("-" * 72)
            lines.append("DRIFT DETAILS")
            lines.append("-" * 72)
            for d in drifted:
                lines.append(f"  Secret:   {d.secret_id}")
                lines.append(f"  Severity: {d.severity}")
                lines.append(f"  Score:    {d.total_drift_score:.4f}")
                if d.anomaly_details:
                    for dim, detail in d.anomaly_details.items():
                        lines.append(f"    {dim}: {detail}")
                lines.append("")
        else:
            lines.append("No behavioral drift detected.")
            if total == 0:
                lines.append("No secrets were provided for drift analysis.")
            else:
                lines.append(f"All {total} secret(s) are within expected behavioral baselines.")
        lines.append("")

        summary = getattr(sdda_result, 'summary', {})
        if summary:
            lines.append("-" * 72)
            lines.append("SUMMARY")
            lines.append("-" * 72)
            for k, v in summary.items():
                lines.append(f"  {k}: {v}")
            lines.append("")

        lines.append("=" * 72)
        lines.append("End of SDDA Report")
        lines.append("=" * 72)
        return "\n".join(lines)
    
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
    
    def _upload_reports(self, report_dir: str):
        """Upload generated reports to cloud storage."""
        logger.info("=" * 80)
        logger.info("Uploading reports to cloud storage")
        logger.info("=" * 80)
        
        try:
            from core.cloud_uploader import CloudUploader
            
            # Initialize uploader (will read from environment variables)
            uploader = CloudUploader()
            
            # Upload all reports
            results = uploader.upload_reports(
                report_dir=report_dir,
                run_id=self.context.run_id,
                timestamp=self.context.timestamp,
                prefix=self.context.upload_prefix
            )
            
            # Log results
            successful = sum(1 for v in results.values() if v)
            total = len(results)
            
            if successful > 0:
                logger.info(f"✓ Successfully uploaded {successful}/{total} report files")
                
                # Generate folder name for display
                datetime_suffix = self.context.timestamp.strftime("%Y%m%d%H%M")
                folder_name = f"{datetime_suffix}_{self.context.run_id}"
                
                # Log access URL with run_id
                logger.info(f"Access ASCSA output files at https://ascsa.dhivijit.dev/run/{folder_name}")
                
                # Add upload info to results
                self.results['upload'] = {
                    'success': True,
                    'uploaded_files': successful,
                    'total_files': total,
                    'bucket': uploader.bucket_name,
                    'folder': folder_name,
                    'prefix': self.context.upload_prefix or folder_name
                }
            else:
                logger.error("✗ No files were uploaded")
                self.results['upload'] = {
                    'success': False,
                    'error': 'No files were uploaded'
                }
                
        except ImportError as e:
            logger.error(f"Cloud upload failed: boto3 not installed. Install with: pip install boto3")
            self.results['upload'] = {
                'success': False,
                'error': 'boto3 not installed'
            }
        except ValueError as e:
            logger.error(f"Cloud upload configuration error: {e}")
            logger.info("Set environment variables: R2_BUCKET_NAME/S3_BUCKET_NAME, R2_ACCESS_KEY_ID/AWS_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY/AWS_SECRET_ACCESS_KEY")
            self.results['upload'] = {
                'success': False,
                'error': str(e)
            }
        except Exception as e:
            logger.error(f"Cloud upload failed: {e}", exc_info=True)
            self.results['upload'] = {
                'success': False,
                'error': str(e)
            }


def run_pipeline(context: ScanContext) -> Dict[str, Any]:
    """Main entry point for the security pipeline.
    
    Args:
        context: Scan context with all configuration
    
    Returns:
        Dictionary with complete scan results
    """
    orchestrator = PipelineOrchestrator(context)
    return orchestrator.run()
