# Storage utilities for ASCSA-CI
"""
Common utilities for managing storage across SLGA and SDDA engines.
Provides unified interfaces for querying, reporting, and managing stored data.
"""

import os
import json
from typing import Dict, List, Optional
from datetime import datetime


class StorageManager:
    """Manages access to both SLGA and SDDA storage"""
    
    def __init__(self, slga_db_path: str = "slga.db", sdda_db_path: str = "sdda.db"):
        self.slga_db_path = slga_db_path
        self.sdda_db_path = sdda_db_path
    
    def get_slga_statistics(self) -> Dict:
        """Get SLGA database statistics"""
        try:
            from engines.slga.database import SLGADatabase
            db = SLGADatabase(self.slga_db_path)
            stats = db.get_statistics()
            db.close()
            return stats
        except Exception as e:
            return {'error': str(e)}
    
    def get_sdda_statistics(self) -> Dict:
        """Get SDDA database statistics"""
        try:
            from engines.sdda.database import SDDADatabase
            db = SDDADatabase(self.sdda_db_path)
            stats = db.get_statistics()
            db.close()
            return stats
        except Exception as e:
            return {'error': str(e)}
    
    def get_combined_statistics(self) -> Dict:
        """Get combined statistics from both engines"""
        return {
            'timestamp': datetime.now().isoformat(),
            'slga': self.get_slga_statistics(),
            'sdda': self.get_sdda_statistics()
        }
    
    def get_secret_analysis(self, secret_value: str = None, secret_id: str = None) -> Dict:
        """
        Get comprehensive analysis of a secret from both SLGA and SDDA
        
        Args:
            secret_value: Secret value for SLGA lookup
            secret_id: Secret ID for SDDA lookup
        
        Returns:
            Combined analysis from both engines
        """
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'slga_lineage': None,
            'sdda_drift_history': None
        }
        
        # Get SLGA lineage
        if secret_value:
            try:
                from engines.slga.database import SLGADatabase
                db = SLGADatabase(self.slga_db_path)
                analysis['slga_lineage'] = db.get_secret_lineage(secret_value)
                db.close()
            except Exception as e:
                analysis['slga_error'] = str(e)
        
        # Get SDDA drift history
        if secret_id:
            try:
                from engines.sdda.database import SDDADatabase
                db = SDDADatabase(self.sdda_db_path)
                analysis['sdda_drift_history'] = db.get_drift_history(secret_id, limit=20)
                db.close()
            except Exception as e:
                analysis['sdda_error'] = str(e)
        
        return analysis
    
    def generate_consolidated_report(self, output_dir: str = ".") -> str:
        """
        Generate a consolidated report from both storage systems
        
        Args:
            output_dir: Directory to save the report
        
        Returns:
            Path to generated report file
        """
        report = {
            'generated_at': datetime.now().isoformat(),
            'report_type': 'consolidated_storage_report',
            'statistics': self.get_combined_statistics()
        }
        
        # Add SLGA data
        try:
            from engines.slga.database import SLGADatabase
            db = SLGADatabase(self.slga_db_path)
            report['slga'] = {
                'all_secrets': db.get_all_secrets(),
                'scan_history': db.get_scan_history(limit=10)
            }
            db.close()
        except Exception as e:
            report['slga_error'] = str(e)
        
        # Add SDDA data
        try:
            from engines.sdda.database import SDDADatabase
            db = SDDADatabase(self.sdda_db_path)
            report['sdda'] = {
                'drift_history': db.get_drift_history(limit=20)
            }
            db.close()
        except Exception as e:
            report['sdda_error'] = str(e)
        
        # Save report
        report_path = os.path.join(output_dir, f"consolidated_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)
        
        return report_path
    
    def export_data(self, output_dir: str = ".", format: str = "json") -> Dict[str, str]:
        """
        Export data from both storage systems
        
        Args:
            output_dir: Directory to save exported data
            format: Export format ('json' only for now)
        
        Returns:
            Dictionary with paths to exported files
        """
        exports = {}
        
        # Export SLGA data
        try:
            from engines.slga.reporter import SLGAReporter
            reporter = SLGAReporter(self.slga_db_path)
            
            slga_export_path = os.path.join(output_dir, f"slga_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(slga_export_path, 'w', encoding='utf-8') as f:
                f.write(reporter.generate_json_report())
            
            exports['slga'] = slga_export_path
            reporter.close()
        except Exception as e:
            exports['slga_error'] = str(e)
        
        # Export SDDA data
        try:
            from engines.sdda.database import SDDADatabase
            db = SDDADatabase(self.sdda_db_path)
            
            sdda_data = {
                'statistics': db.get_statistics(),
                'drift_history': db.get_drift_history(limit=100),
                'all_secret_ids': db.get_all_secret_ids()
            }
            
            sdda_export_path = os.path.join(output_dir, f"sdda_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(sdda_export_path, 'w', encoding='utf-8') as f:
                json.dump(sdda_data, f, indent=2, default=str)
            
            exports['sdda'] = sdda_export_path
            db.close()
        except Exception as e:
            exports['sdda_error'] = str(e)
        
        return exports


class QueryHelper:
    """Helper class for common storage queries"""
    
    @staticmethod
    def find_high_risk_secrets(slga_db_path: str = "slga.db", sdda_db_path: str = "sdda.db") -> List[Dict]:
        """
        Find secrets that are both widely propagated (SLGA) and drifting (SDDA)
        
        Returns:
            List of high-risk secrets with analysis
        """
        high_risk = []
        
        try:
            from engines.slga.database import SLGADatabase
            from engines.slga.reporter import SLGAReporter
            from engines.sdda.database import SDDADatabase
            
            # Get all secrets from SLGA
            slga_db = SLGADatabase(slga_db_path)
            all_secrets = slga_db.get_all_secrets()
            
            # Get reporter for risk analysis
            reporter = SLGAReporter(slga_db_path)
            
            for secret in all_secrets:
                # Get propagation analysis
                prop_report = reporter.generate_propagation_report(secret['value'])
                
                # If high risk in SLGA
                if prop_report.get('severity') in ['CRITICAL', 'HIGH']:
                    high_risk.append({
                        'secret_value_hash': f"sha256_{hash(secret['value']) % 1000000:06d}",
                        'slga_severity': prop_report['severity'],
                        'slga_risk_score': prop_report['risk_score'],
                        'propagation_scope': prop_report['propagation_scope']
                    })
            
            slga_db.close()
            reporter.close()
            
        except Exception as e:
            return [{'error': f'Failed to analyze secrets: {str(e)}'}]
        
        return high_risk
    
    @staticmethod
    def get_recent_activity(slga_db_path: str = "slga.db", sdda_db_path: str = "sdda.db", 
                           limit: int = 10) -> Dict:
        """
        Get recent activity from both engines
        
        Returns:
            Dictionary with recent scans and drift reports
        """
        activity = {
            'timestamp': datetime.now().isoformat(),
            'slga_scans': [],
            'sdda_reports': []
        }
        
        try:
            from engines.slga.database import SLGADatabase
            slga_db = SLGADatabase(slga_db_path)
            activity['slga_scans'] = slga_db.get_scan_history(limit)
            slga_db.close()
        except Exception as e:
            activity['slga_error'] = str(e)
        
        try:
            from engines.sdda.database import SDDADatabase
            sdda_db = SDDADatabase(sdda_db_path)
            activity['sdda_reports'] = sdda_db.get_drift_history(limit=limit)
            sdda_db.close()
        except Exception as e:
            activity['sdda_error'] = str(e)
        
        return activity
