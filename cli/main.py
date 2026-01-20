#!/usr/bin/env python3
# Entry point for CLI
"""
ASCSA-CI Command Line Interface
Main entry point for the Autonomous Secret & Code Security Agent
"""

import sys
import argparse
import logging
from pathlib import Path

from cli.context import build_context
from cli import exit_codes
from core.orchestrator import run_pipeline
from core.emitter import ResultEmitter, setup_logging

logger = logging.getLogger(__name__)


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog='ascsa',
        description='ASCSA-CI: Autonomous Secret & Code Security Agent for CI/CD',
        epilog='For more information, visit: https://github.com/yourusername/ascsa-ci'
    )
    
    # Required arguments
    parser.add_argument(
        'repo_path',
        type=str,
        help='Path to the repository to scan'
    )
    
    # Optional arguments - scan configuration
    parser.add_argument(
        '--branch', '-b',
        type=str,
        help='Git branch name (auto-detected if not provided)'
    )
    
    parser.add_argument(
        '--environment', '-e',
        type=str,
        choices=['development', 'staging', 'production', 'ci'],
        help='Environment type (default: auto-detected)'
    )
    
    parser.add_argument(
        '--actor', '-a',
        type=str,
        help='Actor/user triggering the scan (default: current user)'
    )
    
    # CI/CD specific options
    ci_group = parser.add_argument_group('CI/CD options')
    ci_group.add_argument(
        '--ci-config',
        type=str,
        help='Path to CI configuration file (e.g., .github/workflows/main.yml)'
    )
    
    ci_group.add_argument(
        '--log-dir',
        type=str,
        help='Path to CI logs directory for secret scanning'
    )
    
    ci_group.add_argument(
        '--artifact-dir',
        type=str,
        help='Path to CI artifacts directory for secret scanning'
    )
    
    ci_group.add_argument(
        '--changed-files',
        type=str,
        nargs='+',
        help='List of changed files (for PR/diff mode)'
    )
    
    # Engine control
    engine_group = parser.add_argument_group('engine control')
    engine_group.add_argument(
        '--skip-slga',
        action='store_true',
        help='Skip Secret Lineage Graph Analysis'
    )
    
    engine_group.add_argument(
        '--skip-sdda',
        action='store_true',
        help='Skip Secret Drift Detection Analysis'
    )
    
    engine_group.add_argument(
        '--skip-hcrs',
        action='store_true',
        help='Skip Hybrid Code Risk Scoring'
    )
    
    # Configuration files
    config_group = parser.add_argument_group('configuration')
    config_group.add_argument(
        '--config',
        type=str,
        help='Path to configuration file (default: config/thresholds.yaml)'
    )
    
    config_group.add_argument(
        '--rules',
        type=str,
        help='Path to custom rules file'
    )
    
    # Database configuration
    db_group = parser.add_argument_group('database')
    db_group.add_argument(
        '--sdda-db',
        type=str,
        help='Path to SDDA SQLite database (default: sdda.db)'
    )
    
    db_group.add_argument(
        '--neo4j-uri',
        type=str,
        help='Neo4j URI (default: from NEO4J_URI env var)'
    )
    
    db_group.add_argument(
        '--neo4j-user',
        type=str,
        help='Neo4j username (default: from NEO4J_USER env var)'
    )
    
    db_group.add_argument(
        '--neo4j-pass',
        type=str,
        help='Neo4j password (default: from NEO4J_PASSWORD env var)'
    )
    
    # Output options
    output_group = parser.add_argument_group('output')
    output_group.add_argument(
        '--format', '-f',
        type=str,
        choices=['console', 'json', 'yaml'],
        default='console',
        help='Output format (default: console)'
    )

    output_group.add_argument(
        '--output', '-o',
        type=str,
        help='Output file path (default: stdout)'
    )

    output_group.add_argument(
        '--reportout',
        type=str,
        help='Directory to save per-engine and main report outputs (default: scan target directory)'
    )

    output_group.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )

    output_group.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress all output except errors'
    )
    
    # Cloud upload options
    upload_group = parser.add_argument_group('cloud upload')
    upload_group.add_argument(
        '--upload',
        action='store_true',
        help='Upload reports to cloud storage (S3/R2)'
    )
    upload_group.add_argument(
        '--upload-prefix',
        type=str,
        default=None,
        help='Custom prefix for uploaded files (default: ascsa-reports/<run-id>/)'
    )

    return parser.parse_args()


def main():
    """Main entry point for ASCSA-CI CLI."""
    try:
        # Parse arguments
        args = parse_arguments()
        
        # Setup logging
        if args.quiet:
            setup_logging(verbose=False)
            logging.getLogger().setLevel(logging.ERROR)
        else:
            setup_logging(verbose=args.verbose)
        
        logger.info("ASCSA-CI: Autonomous Secret & Code Security Agent")
        logger.info("=" * 80)
        
        # Validate repository path
        repo_path = Path(args.repo_path)
        if not repo_path.exists():
            logger.error(f"Repository path does not exist: {args.repo_path}")
            return exit_codes.REPO_ERROR
        
        if not repo_path.is_dir():
            logger.error(f"Repository path is not a directory: {args.repo_path}")
            return exit_codes.REPO_ERROR
        
        # Build scan context
        try:
            context = build_context(
                repo_path=str(repo_path.absolute()),
                branch=args.branch,
                environment=args.environment,
                ci_config=args.ci_config,
                log_dir=args.log_dir,
                artifact_dir=args.artifact_dir,
                changed_files=args.changed_files,
                skip_slga=args.skip_slga,
                skip_sdda=args.skip_sdda,
                skip_hcrs=args.skip_hcrs,
                output_format=args.format,
                output_file=args.output,
                verbose=args.verbose,
                actor=args.actor,
                config_path=args.config,
                rules_path=args.rules,
                sdda_db_path=args.sdda_db,
                neo4j_uri=args.neo4j_uri,
                neo4j_user=args.neo4j_user,
                neo4j_pass=args.neo4j_pass,
                reportout_dir=args.reportout,
                enable_upload=args.upload,
                upload_prefix=args.upload_prefix
            )
        except ValueError as e:
            logger.error(f"Configuration error: {e}")
            return exit_codes.CONFIG_ERROR
        except Exception as e:
            logger.error(f"Failed to build context: {e}", exc_info=True)
            return exit_codes.CONFIG_ERROR
        
        # Run the security pipeline
        try:
            results = run_pipeline(context)
        except ImportError as e:
            logger.error(f"Missing dependency: {e}")
            logger.error("Please install required dependencies: pip install -r requirements.txt")
            return exit_codes.DEPENDENCY_ERROR
        except Exception as e:
            logger.error(f"Pipeline execution failed: {e}", exc_info=True)
            return exit_codes.ENGINE_ERROR
        
        # Emit results
        if not args.quiet:
            try:
                emitter = ResultEmitter(format=args.format, output_file=args.output)
                emitter.emit(results)
            except Exception as e:
                logger.error(f"Failed to emit results: {e}", exc_info=True)
                # Don't fail the scan if only output fails
        
        # Return appropriate exit code
        exit_code = results.get('exit_code', exit_codes.SUCCESS)
        
        if exit_code == exit_codes.SUCCESS:
            logger.info("✓ Scan completed successfully - no critical issues found")
        elif exit_code == exit_codes.WARN:
            logger.warning("⚠ Scan completed with warnings")
        elif exit_code == exit_codes.RISK_HIGH:
            logger.error("✗ Scan found HIGH risk issues")
        elif exit_code == exit_codes.RISK_CRITICAL:
            logger.error("✗ Scan found CRITICAL risk issues")
        
        return exit_code
        
    except KeyboardInterrupt:
        logger.info("\nScan interrupted by user")
        return exit_codes.SUCCESS
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return exit_codes.ENGINE_ERROR


if __name__ == '__main__':
    sys.exit(main())
