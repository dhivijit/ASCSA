#!/usr/bin/env python3
"""
Standalone script to upload ASCSA-CI reports to cloud storage (S3/R2).

Usage:
    python upload_reports.py [report_directory]

Environment Variables:
    R2_BUCKET_NAME or S3_BUCKET_NAME - Bucket name
    R2_ACCESS_KEY_ID or AWS_ACCESS_KEY_ID - Access key
    R2_SECRET_ACCESS_KEY or AWS_SECRET_ACCESS_KEY - Secret key
    R2_ENDPOINT_URL or S3_ENDPOINT_URL - Custom endpoint (optional, for R2)
"""

import sys
import os
import argparse
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description="Upload ASCSA-CI reports to cloud storage (S3/R2)"
    )
    parser.add_argument(
        'report_dir',
        nargs='?',
        default='.',
        help='Directory containing report files (default: current directory)'
    )
    parser.add_argument(
        '--run-id',
        help='Scan run ID (extracted from ascsa_report.json if not provided)'
    )
    parser.add_argument(
        '--prefix',
        help='Custom prefix for uploaded files (default: ascsa-reports/<run-id>/)'
    )
    parser.add_argument(
        '--bucket',
        help='Override bucket name from environment variable'
    )
    parser.add_argument(
        '--endpoint',
        help='Override endpoint URL from environment variable'
    )
    parser.add_argument(
        '--list',
        action='store_true',
        help='List uploaded files instead of uploading'
    )
    
    args = parser.parse_args()
    
    # Check for boto3
    try:
        import boto3
    except ImportError:
        logger.error("boto3 is required for cloud uploads")
        logger.error("Install with: pip install boto3")
        return 1
    
    from core.cloud_uploader import CloudUploader
    
    try:
        # Initialize uploader
        uploader = CloudUploader(
            bucket_name=args.bucket,
            endpoint_url=args.endpoint
        )
        
        # List mode
        if args.list:
            logger.info(f"Listing files in bucket: {uploader.bucket_name}")
            files = uploader.list_uploads(prefix=args.prefix or "ascsa-reports/")
            
            if not files:
                logger.info("No files found")
                return 0
            
            print(f"\nFound {len(files)} file(s):\n")
            for f in files:
                print(f"  {f['key']}")
                print(f"    Size: {f['size']:,} bytes")
                print(f"    Modified: {f['last_modified']}")
                print()
            
            return 0
        
        # Upload mode
        report_dir = Path(args.report_dir).resolve()
        
        if not report_dir.exists():
            logger.error(f"Directory not found: {report_dir}")
            return 1
        
        # Try to extract run_id from ascsa_report.json
        run_id = args.run_id
        timestamp = None
        
        if not run_id:
            report_file = report_dir / "ascsa_report.json"
            if report_file.exists():
                import json
                from datetime import datetime
                try:
                    with open(report_file) as f:
                        data = json.load(f)
                        run_id = data.get('summary', {}).get('run_id', 'unknown')
                        timestamp_str = data.get('summary', {}).get('timestamp')
                        if timestamp_str:
                            # Parse ISO format timestamp
                            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        logger.info(f"Extracted run ID from report: {run_id}")
                except Exception as e:
                    logger.warning(f"Could not read run ID from report: {e}")
                    run_id = "unknown"
            else:
                run_id = "unknown"
        
        # Upload reports
        logger.info(f"Uploading reports from: {report_dir}")
        logger.info(f"Bucket: {uploader.bucket_name}")
        
        results = uploader.upload_reports(
            report_dir=str(report_dir),
            run_id=run_id,
            timestamp=timestamp,
            prefix=args.prefix
        )
        
        # Print summary
        successful = sum(1 for v in results.values() if v)
        total = len(results)
        
        # Generate folder name
        from datetime import datetime
        if timestamp:
            datetime_suffix = timestamp.strftime("%Y%m%d%H%M")
        else:
            datetime_suffix = datetime.now().strftime("%Y%m%d%H%M")
        folder_name = f"{datetime_suffix}_{run_id}"
        
        print(f"\n{'='*60}")
        print(f"Upload Summary")
        print(f"{'='*60}")
        print(f"Successfully uploaded: {successful}/{total} files")
        print(f"Bucket: {uploader.bucket_name}")
        
        if args.prefix:
            print(f"Prefix: {args.prefix}")
        else:
            print(f"Folder: {folder_name}/")
        
        print(f"{'='*60}\n")
        
        if successful < total:
            logger.warning(f"{total - successful} file(s) failed to upload")
            return 1
        
        return 0
        
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        logger.info("\nRequired environment variables:")
        logger.info("  R2_BUCKET_NAME or S3_BUCKET_NAME")
        logger.info("  R2_ACCESS_KEY_ID or AWS_ACCESS_KEY_ID")
        logger.info("  R2_SECRET_ACCESS_KEY or AWS_SECRET_ACCESS_KEY")
        logger.info("  R2_ENDPOINT_URL or S3_ENDPOINT_URL (optional, for R2)")
        return 1
    except Exception as e:
        logger.error(f"Upload failed: {e}", exc_info=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
