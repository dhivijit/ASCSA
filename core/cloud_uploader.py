"""Cloud storage uploader for ASCSA-CI reports.

Supports uploading reports to S3-compatible storage (AWS S3, Cloudflare R2, etc.)
"""

import os
import logging
from pathlib import Path
from typing import List, Optional, Dict
from datetime import datetime

logger = logging.getLogger(__name__)


class CloudUploader:
    """Uploads ASCSA-CI reports to cloud storage (S3/R2)."""
    
    def __init__(
        self,
        bucket_name: Optional[str] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        endpoint_url: Optional[str] = None,
        region: str = "auto"
    ):
        """Initialize cloud uploader.
        
        Args:
            bucket_name: S3/R2 bucket name (or from env: R2_BUCKET_NAME / S3_BUCKET_NAME)
            access_key: Access key ID (or from env: R2_ACCESS_KEY_ID / AWS_ACCESS_KEY_ID)
            secret_key: Secret access key (or from env: R2_SECRET_ACCESS_KEY / AWS_SECRET_ACCESS_KEY)
            endpoint_url: Custom endpoint URL for R2/S3-compatible services (or from env: R2_ENDPOINT_URL / S3_ENDPOINT_URL)
            region: AWS region (default: auto for R2)
        """
        self.bucket_name = bucket_name or os.getenv("R2_BUCKET_NAME") or os.getenv("S3_BUCKET_NAME")
        self.access_key = access_key or os.getenv("R2_ACCESS_KEY_ID") or os.getenv("AWS_ACCESS_KEY_ID")
        self.secret_key = secret_key or os.getenv("R2_SECRET_ACCESS_KEY") or os.getenv("AWS_SECRET_ACCESS_KEY")
        self.endpoint_url = endpoint_url or os.getenv("R2_ENDPOINT_URL") or os.getenv("S3_ENDPOINT_URL")
        self.region = region
        
        self._client = None
        self._validate_config()
    
    def _validate_config(self):
        """Validate that required configuration is present."""
        if not self.bucket_name:
            raise ValueError(
                "Bucket name not provided. Set via parameter or environment variable "
                "(R2_BUCKET_NAME/S3_BUCKET_NAME)"
            )
        
        if not self.access_key or not self.secret_key:
            raise ValueError(
                "Access credentials not provided. Set via parameters or environment variables "
                "(R2_ACCESS_KEY_ID/AWS_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY/AWS_SECRET_ACCESS_KEY)"
            )
    
    def _get_client(self):
        """Lazily initialize boto3 S3 client."""
        if self._client is None:
            try:
                import boto3
            except ImportError:
                raise ImportError(
                    "boto3 is required for cloud uploads. Install it with: pip install boto3"
                )
            
            client_kwargs = {
                'aws_access_key_id': self.access_key,
                'aws_secret_access_key': self.secret_key,
                'region_name': self.region
            }
            
            if self.endpoint_url:
                client_kwargs['endpoint_url'] = self.endpoint_url
            
            self._client = boto3.client('s3', **client_kwargs)
            logger.info(f"Initialized S3 client for bucket: {self.bucket_name}")
        
        return self._client
    
    def upload_file(
        self,
        local_path: str,
        remote_path: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None
    ) -> bool:
        """Upload a single file to cloud storage.
        
        Args:
            local_path: Path to local file
            remote_path: Remote path in bucket (defaults to filename)
            metadata: Optional metadata dict to attach to the object
            
        Returns:
            True if upload succeeded, False otherwise
        """
        if not os.path.exists(local_path):
            logger.error(f"File not found: {local_path}")
            return False
        
        if remote_path is None:
            remote_path = os.path.basename(local_path)
        
        try:
            client = self._get_client()
            
            extra_args = {}
            if metadata:
                extra_args['Metadata'] = metadata
            
            # Add content type based on file extension
            if local_path.endswith('.json'):
                extra_args['ContentType'] = 'application/json'
            elif local_path.endswith('.txt'):
                extra_args['ContentType'] = 'text/plain'
            elif local_path.endswith('.yaml') or local_path.endswith('.yml'):
                extra_args['ContentType'] = 'text/yaml'
            
            client.upload_file(local_path, self.bucket_name, remote_path, ExtraArgs=extra_args)
            logger.info(f"Uploaded: {local_path} → s3://{self.bucket_name}/{remote_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to upload {local_path}: {e}", exc_info=True)
            return False
    
    def upload_reports(
        self,
        report_dir: str,
        run_id: str,
        timestamp: Optional[datetime] = None,
        prefix: Optional[str] = None
    ) -> Dict[str, bool]:
        """Upload all ASCSA-CI report files from a directory.
        
        Args:
            report_dir: Directory containing report files
            run_id: Scan run ID (UUID)
            timestamp: Scan timestamp (defaults to now)
            prefix: Optional prefix for remote paths (overrides default YYYYMMDDHHMM_UUID format)
            
        Returns:
            Dictionary mapping local file paths to upload success status
        """
        report_dir = Path(report_dir)
        if not report_dir.exists():
            logger.error(f"Report directory not found: {report_dir}")
            return {}
        
        # Define report files to upload
        report_files = [
            "ascsa_report.json",
            "slga.txt",
            "slga.json",
            "slga_propagation_analysis.json",
            "sdda.txt",
            "sdda_stats.json",
            "hcrs.txt",
            "hcrs.json",
            "csce.txt",
            "csce.json"
        ]
        
        # Generate folder name: YYYYMMDDHHMM_UUID
        if timestamp is None:
            timestamp = datetime.now()
        datetime_suffix = timestamp.strftime("%Y%m%d%H%M")
        folder_name = f"{datetime_suffix}_{run_id}"
        
        results = {}
        metadata = {
            'run-id': run_id,
            'upload-timestamp': datetime.now().isoformat(),
            'scan-timestamp': timestamp.isoformat(),
            'tool': 'ascsa-ci'
        }
        
        for filename in report_files:
            local_path = report_dir / filename
            if not local_path.exists():
                logger.debug(f"Skipping non-existent file: {filename}")
                continue
            
            # Build remote path
            if prefix:
                remote_path = f"{prefix.rstrip('/')}/{filename}"
            else:
                remote_path = f"{folder_name}/{filename}"
            
            success = self.upload_file(
                str(local_path),
                remote_path,
                metadata=metadata
            )
            results[str(local_path)] = success
        
        # Log summary
        successful = sum(1 for v in results.values() if v)
        total = len(results)
        
        if successful > 0:
            logger.info(f"Upload complete: {successful}/{total} files uploaded to {folder_name}/")
        else:
            logger.error("Upload failed: No files were uploaded")
        
        return results
    
    def list_uploads(self, prefix: Optional[str] = None, max_items: int = 100) -> List[Dict]:
        """List uploaded files in the bucket.
        
        Args:
            prefix: Optional prefix to filter results
            max_items: Maximum number of items to return
            
        Returns:
            List of dictionaries with file information
        """
        try:
            client = self._get_client()
            
            kwargs = {'Bucket': self.bucket_name, 'MaxKeys': max_items}
            if prefix:
                kwargs['Prefix'] = prefix
            
            response = client.list_objects_v2(**kwargs)
            
            if 'Contents' not in response:
                return []
            
            files = []
            for obj in response['Contents']:
                files.append({
                    'key': obj['Key'],
                    'size': obj['Size'],
                    'last_modified': obj['LastModified'].isoformat(),
                    'url': f"s3://{self.bucket_name}/{obj['Key']}"
                })
            
            return files
            
        except Exception as e:
            logger.error(f"Failed to list uploads: {e}", exc_info=True)
            return []
