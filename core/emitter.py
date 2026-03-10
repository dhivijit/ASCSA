"""Output formatting and emission for ASCSA-CI results.

Provides console (colored), JSON, and YAML output of scan results.
"""

import logging
import json
import yaml
from typing import Dict, Any
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init(autoreset=True)

logger = logging.getLogger(__name__)


class ResultEmitter:
    """Formats and emits scan results in various formats."""
    
    def __init__(self, format: str = "console", output_file: str = None):
        self.format = format
        self.output_file = output_file
    
    def emit(self, results: Dict[str, Any]):
        """Emit results in the configured format."""
        if self.format == "json":
            output = self._format_json(results)
        elif self.format == "yaml":
            output = self._format_yaml(results)
        else:
            output = self._format_console(results)
        
        if self.output_file:
            with open(self.output_file, 'w') as f:
                f.write(output)
            logger.info(f"Results written to {self.output_file}")
        else:
            print(output)
    
    def _format_json(self, results: Dict[str, Any]) -> str:
        """Format results as JSON."""
        # Convert datetime objects to ISO format
        def default(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            elif hasattr(obj, '__dict__'):
                return obj.__dict__
            return str(obj)
        
        return json.dumps(results, indent=2, default=default)
    
    def _format_yaml(self, results: Dict[str, Any]) -> str:
        """Format results as YAML."""
        return yaml.dump(results, default_flow_style=False)
    
    def _format_console(self, results: Dict[str, Any]) -> str:
        """Format results for console output with colors."""
        lines = []
        
        # Header
        lines.append("\n" + "=" * 80)
        lines.append(f"{Fore.CYAN}{Style.BRIGHT}ASCSA-CI Security Scan Results{Style.RESET_ALL}")
        lines.append("=" * 80)
        
        # Summary
        summary = results.get('summary', {})
        lines.append(f"\n{Fore.YELLOW}Run ID:{Style.RESET_ALL} {summary.get('run_id', 'N/A')}")
        lines.append(f"{Fore.YELLOW}Timestamp:{Style.RESET_ALL} {summary.get('timestamp', 'N/A')}")
        lines.append(f"{Fore.YELLOW}Repository:{Style.RESET_ALL} {summary.get('repo_path', 'N/A')}")
        lines.append(f"{Fore.YELLOW}Branch:{Style.RESET_ALL} {summary.get('branch', 'N/A')}")
        
        # Overall Risk
        recommendation = results.get('recommendation', 'UNKNOWN')
        risk_color = self._get_risk_color(recommendation)
        lines.append(f"\n{Fore.YELLOW}Overall Risk:{Style.RESET_ALL} {risk_color}{recommendation}{Style.RESET_ALL}")
        
        # SLGA Results
        if 'slga' in results and not results.get('slga_skipped'):
            lines.append(f"\n{Fore.CYAN}{'─' * 80}{Style.RESET_ALL}")
            lines.append(f"{Fore.CYAN}{Style.BRIGHT}Secret Lineage Graph Analysis (SLGA){Style.RESET_ALL}")
            lines.append(f"{Fore.CYAN}{'─' * 80}{Style.RESET_ALL}")
            slga = results['slga']
            lines.append(f"  Secrets Detected: {slga.get('total_secrets', 0)}")
            lines.append(f"  Files Affected: {slga.get('total_files', 0)}")
            lines.append(f"  Commits Analyzed: {slga.get('total_commits', 0)}")
            ca = slga.get('code_analysis')
            if ca:
                lines.append(f"  Code Analysis: {ca.get('total_functions', 0)} functions, "
                             f"{ca.get('total_classes', 0)} classes, "
                             f"{ca.get('total_imports', 0)} imports "
                             f"({', '.join(ca.get('languages', []))})")
            gc = slga.get('git_context')
            if gc:
                lines.append(f"  Git Context: {gc.get('total_contributors', 0)} contributor(s), "
                             f"{gc.get('hotspot_count', 0)} hotspot(s)")
        elif results.get('slga_skipped'):
            lines.append(f"\n{Fore.YELLOW}SLGA: Skipped{Style.RESET_ALL}")
        
        # SDDA Results
        if 'sdda' in results and not results.get('sdda_skipped'):
            lines.append(f"\n{Fore.CYAN}{'─' * 80}{Style.RESET_ALL}")
            lines.append(f"{Fore.CYAN}{Style.BRIGHT}Secret Drift Detection Analysis (SDDA){Style.RESET_ALL}")
            lines.append(f"{Fore.CYAN}{'─' * 80}{Style.RESET_ALL}")
            sdda = results['sdda']
            lines.append(f"  Secrets Analyzed: {sdda.get('total_secrets_analyzed', 0)}")
            lines.append(f"  Drifted Secrets: {len(sdda.get('drifted_secrets', []))}")
            
            severity_summary = sdda.get('summary', {})
            if severity_summary:
                lines.append("\n  Severity Breakdown:")
                for severity, count in severity_summary.items():
                    if count > 0:
                        color = self._get_severity_color(severity)
                        lines.append(f"    {color}{severity}: {count}{Style.RESET_ALL}")
        elif results.get('sdda_skipped'):
            lines.append(f"\n{Fore.YELLOW}SDDA: Skipped (requires SLGA results with detected secrets){Style.RESET_ALL}")
        
        # HCRS Results
        if 'hcrs' in results and not results.get('hcrs_skipped'):
            lines.append(f"\n{Fore.CYAN}{'─' * 80}{Style.RESET_ALL}")
            lines.append(f"{Fore.CYAN}{Style.BRIGHT}Hybrid Code Risk Scoring (HCRS){Style.RESET_ALL}")
            lines.append(f"{Fore.CYAN}{'─' * 80}{Style.RESET_ALL}")
            hcrs = results['hcrs']
            total_score = hcrs.get('total_score') or 0
            lines.append(f"  Total Risk Score: {total_score:.2f}")
            lines.append(f"  Files Analyzed: {hcrs.get('total_files_analyzed', 0)}")
            
            # Violation counts
            lines.append("\n  Security Violations:")
            lines.append(f"    {Fore.RED}CRITICAL: {hcrs.get('critical_count', 0)}{Style.RESET_ALL}")
            lines.append(f"    {Fore.MAGENTA}HIGH: {hcrs.get('high_count', 0)}{Style.RESET_ALL}")
            lines.append(f"    {Fore.YELLOW}MEDIUM: {hcrs.get('medium_count', 0)}{Style.RESET_ALL}")
            lines.append(f"    {Fore.CYAN}LOW: {hcrs.get('low_count', 0)}{Style.RESET_ALL}")
            
            # Show top violations
            violations = hcrs.get('top_violations', [])
            if violations:
                lines.append("\n  Top Violations:")
                for i, v in enumerate(violations[:5], 1):
                    severity_color = self._get_severity_color(v.get('severity', 'LOW'))
                    lines.append(f"    {i}. [{severity_color}{v.get('severity')}{Style.RESET_ALL}] "
                               f"{v.get('violation_type')} in {v.get('file')}:{v.get('line')}")
                    lines.append(f"       {v.get('message')}")
        elif results.get('hcrs_skipped'):
            lines.append(f"\n{Fore.YELLOW}HCRS: Skipped{Style.RESET_ALL}")
        
        # CSCE Results
        if 'csce' in results and not results.get('csce_skipped'):
            lines.append(f"\n{Fore.CYAN}{'─' * 80}{Style.RESET_ALL}")
            lines.append(f"{Fore.CYAN}{Style.BRIGHT}Code-Secret Correlation Engine (CSCE){Style.RESET_ALL}")
            lines.append(f"{Fore.CYAN}{'─' * 80}{Style.RESET_ALL}")
            csce = results['csce']
            lines.append(f"  Total Correlations: {csce.get('total_correlations', 0)}")
            lines.append(f"  Average Confidence: {csce.get('avg_confidence', 0):.0%}")
            lines.append(f"\n  Severity Breakdown:")
            lines.append(f"    {Fore.RED}CRITICAL: {csce.get('critical_count', 0)}{Style.RESET_ALL}")
            lines.append(f"    {Fore.MAGENTA}HIGH: {csce.get('high_count', 0)}{Style.RESET_ALL}")
            lines.append(f"    {Fore.YELLOW}MEDIUM: {csce.get('medium_count', 0)}{Style.RESET_ALL}")
            lines.append(f"    {Fore.CYAN}LOW: {csce.get('low_count', 0)}{Style.RESET_ALL}")
            top = csce.get('top_priorities', [])
            if top:
                lines.append(f"\n  Top Correlations:")
                for i, c in enumerate(top[:5], 1):
                    sev_color = self._get_severity_color(c.get('severity', 'LOW'))
                    lines.append(f"    {i}. [{sev_color}{c.get('severity')}{Style.RESET_ALL}] "
                               f"{c.get('type', '').upper()} — {c.get('description', '')}")
        elif results.get('csce_skipped'):
            lines.append(f"\n{Fore.YELLOW}CSCE: Skipped{Style.RESET_ALL}")
        
        # Recommendations
        if 'recommendations' in results and results['recommendations']:
            lines.append(f"\n{Fore.CYAN}{'─' * 80}{Style.RESET_ALL}")
            lines.append(f"{Fore.CYAN}{Style.BRIGHT}Recommendations{Style.RESET_ALL}")
            lines.append(f"{Fore.CYAN}{'─' * 80}{Style.RESET_ALL}")
            for rec in results['recommendations'][:10]:
                lines.append(f"  • {rec}")
        
        lines.append("\n" + "=" * 80 + "\n")
        
        return "\n".join(lines)
    
    def _get_risk_color(self, risk: str) -> str:
        """Get color for risk level."""
        risk_upper = str(risk).upper()
        if 'CRITICAL' in risk_upper or 'BLOCK' in risk_upper:
            return Fore.RED + Style.BRIGHT
        elif 'HIGH' in risk_upper:
            return Fore.MAGENTA
        elif 'MEDIUM' in risk_upper or 'WARN' in risk_upper:
            return Fore.YELLOW
        elif 'LOW' in risk_upper or 'PASS' in risk_upper:
            return Fore.GREEN
        return Fore.WHITE
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level."""
        severity_upper = str(severity).upper()
        if 'CRITICAL' in severity_upper:
            return Fore.RED + Style.BRIGHT
        elif 'HIGH' in severity_upper:
            return Fore.MAGENTA
        elif 'MEDIUM' in severity_upper:
            return Fore.YELLOW
        elif 'LOW' in severity_upper:
            return Fore.CYAN
        return Fore.WHITE


def setup_logging(verbose: bool = False):
    """Configure logging for the application."""
    level = logging.DEBUG if verbose else logging.INFO
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Silence noisy third-party loggers
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('neo4j').setLevel(logging.WARNING)
    logging.getLogger('git').setLevel(logging.WARNING)
    logging.getLogger('boto3').setLevel(logging.WARNING)
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('s3transfer').setLevel(logging.WARNING)
