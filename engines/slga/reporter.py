# SLGA reporter for generating reports from stored data
"""
Reporter module for Secret Lineage Graph Analysis (SLGA).
Generates various reports from stored lineage data.
"""

import json
from typing import List, Dict, Optional
from datetime import datetime
from .database import SLGADatabase
from .models import Secret


class SLGAReporter:
    """Reporter for SLGA data"""
    
    def __init__(self, db_path: str = "slga.db"):
        self.db = SLGADatabase(db_path)
    
    def generate_summary_report(self) -> Dict:
        """Generate summary report of all stored data"""
        stats = self.db.get_statistics()
        recent_scans = self.db.get_scan_history(limit=5)
        
        return {
            'generated_at': datetime.now().isoformat(),
            'statistics': stats,
            'recent_scans': recent_scans
        }
    
    def generate_secret_report(self, secret_value: str = None) -> Dict:
        """Generate detailed report for a specific secret or all secrets"""
        if secret_value:
            lineage = self.db.get_secret_lineage(secret_value)
            if not lineage:
                return {'error': f'Secret not found: {secret_value}'}
            
            return {
                'generated_at': datetime.now().isoformat(),
                'secret_lineage': lineage
            }
        else:
            secrets = self.db.get_all_secrets()
            return {
                'generated_at': datetime.now().isoformat(),
                'total_secrets': len(secrets),
                'secrets': secrets
            }
    
    def generate_propagation_report(self, secret_value: str) -> Dict:
        """Generate propagation analysis report for a secret"""
        lineage = self.db.get_secret_lineage(secret_value)
        
        if not lineage:
            return {'error': f'Secret not found: {secret_value}'}
        
        # Analyze propagation scope
        propagation_scope = {
            'files_affected': len(lineage['files']),
            'commits_involved': len(lineage['commits']),
            'stages_using': len(lineage['stages']),
            'logs_containing': len(lineage['logs']),
            'artifacts_containing': len(lineage['artifacts'])
        }
        
        # Calculate risk score based on propagation
        risk_score = 0
        risk_factors = []
        
        if propagation_scope['files_affected'] > 5:
            risk_score += 30
            risk_factors.append(f"High file spread ({propagation_scope['files_affected']} files)")
        elif propagation_scope['files_affected'] > 2:
            risk_score += 15
            risk_factors.append(f"Moderate file spread ({propagation_scope['files_affected']} files)")
        
        if propagation_scope['commits_involved'] > 10:
            risk_score += 20
            risk_factors.append(f"High commit history ({propagation_scope['commits_involved']} commits)")
        elif propagation_scope['commits_involved'] > 5:
            risk_score += 10
            risk_factors.append(f"Moderate commit history ({propagation_scope['commits_involved']} commits)")
        
        if propagation_scope['stages_using'] > 0:
            risk_score += 25
            risk_factors.append(f"Used in CI/CD stages ({propagation_scope['stages_using']} stages)")
        
        if propagation_scope['logs_containing'] > 0:
            risk_score += 15
            risk_factors.append(f"Appears in logs ({propagation_scope['logs_containing']} logs)")
        
        if propagation_scope['artifacts_containing'] > 0:
            risk_score += 10
            risk_factors.append(f"Appears in artifacts ({propagation_scope['artifacts_containing']} artifacts)")
        
        # Determine severity
        if risk_score >= 70:
            severity = "CRITICAL"
        elif risk_score >= 50:
            severity = "HIGH"
        elif risk_score >= 30:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        
        return {
            'generated_at': datetime.now().isoformat(),
            'secret_value': secret_value,
            'propagation_scope': propagation_scope,
            'risk_score': risk_score,
            'severity': severity,
            'risk_factors': risk_factors,
            'lineage_details': lineage
        }
    
    def generate_text_report(self, secrets: List[Secret] = None) -> str:
        """Generate human-readable text report"""
        if secrets:
            # Generate report from provided secrets
            lines = []
            lines.append("=" * 80)
            lines.append("SECRET LINEAGE GRAPH ANALYSIS (SLGA) REPORT")
            lines.append("=" * 80)
            lines.append(f"Generated: {datetime.now().isoformat()}")
            lines.append("")
            lines.append(f"Total Secrets Found: {len(secrets)}")
            lines.append("")
            
            for idx, secret in enumerate(secrets, 1):
                lines.append(f"\n{idx}. Secret Details:")
                lines.append(f"   Type: {secret.secret_type}")
                lines.append(f"   Entropy: {secret.entropy:.2f}")
                lines.append(f"   Files: {len(secret.files)}")
                lines.append(f"   Commits: {len(secret.commits)}")
                
                if secret.files:
                    lines.append(f"   File Locations:")
                    for file_path in secret.files[:5]:  # Show first 5
                        lines.append(f"     - {file_path}")
                    if len(secret.files) > 5:
                        lines.append(f"     ... and {len(secret.files) - 5} more")
            
            lines.append("\n" + "=" * 80)
            return "\n".join(lines)
        else:
            # Generate report from database
            stats = self.db.get_statistics()
            all_secrets = self.db.get_all_secrets()
            
            lines = []
            lines.append("=" * 80)
            lines.append("SECRET LINEAGE GRAPH ANALYSIS (SLGA) DATABASE REPORT")
            lines.append("=" * 80)
            lines.append(f"Generated: {datetime.now().isoformat()}")
            lines.append("")
            lines.append("DATABASE STATISTICS:")
            for key, value in stats.items():
                lines.append(f"  {key}: {value}")
            lines.append("")
            
            if all_secrets:
                lines.append(f"\nRECENT SECRETS (Last {min(10, len(all_secrets))}):")
                for idx, secret in enumerate(all_secrets[:10], 1):
                    lines.append(f"\n{idx}. Secret:")
                    lines.append(f"   Type: {secret['secret_type']}")
                    lines.append(f"   Entropy: {secret['entropy']:.2f}")
                    lines.append(f"   First Seen: {secret['first_seen']}")
                    lines.append(f"   Last Seen: {secret['last_seen']}")
            
            lines.append("\n" + "=" * 80)
            return "\n".join(lines)
    
    def generate_json_report(self, secrets: List[Secret] = None) -> str:
        """Generate JSON report"""
        if secrets:
            report = {
                'generated_at': datetime.now().isoformat(),
                'total_secrets': len(secrets),
                'secrets': [
                    {
                        'value_hash': f"sha256_{hash(s.value) % 1000000:06d}",  # Anonymized
                        'type': s.secret_type,
                        'entropy': s.entropy,
                        'files_count': len(s.files),
                        'commits_count': len(s.commits),
                        'files': s.files[:10],  # Limit to first 10
                    }
                    for s in secrets
                ]
            }
        else:
            stats = self.db.get_statistics()
            all_secrets = self.db.get_all_secrets()
            
            report = {
                'generated_at': datetime.now().isoformat(),
                'statistics': stats,
                'total_secrets': len(all_secrets),
                'secrets': all_secrets[:50]  # Limit to first 50
            }
        
        return json.dumps(report, indent=2, default=str)
    
    def close(self):
        """Close database connection"""
        self.db.close()
