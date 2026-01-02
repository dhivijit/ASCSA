def load_config(config_path: str = None):
    """
    Backward-compatible function to load config, returns the HCRS config dict.
    """
    return load_hcrs_config(config_path)
# HCRS configuration loader
import os
import yaml
from typing import Dict

def load_hcrs_config(config_path: str = None) -> dict:
    """Load HCRS configuration from YAML file"""
    if config_path is None:
        config_path = os.path.join(
            os.path.dirname(__file__), '..', '..', 'config', 'thresholds.yaml'
        )
    
    default_config = {
        'hcrs': {
            'risk_weights': {
                'hardcoded_secret': 100,
                'command_injection': 90,
                'sql_injection': 85,
                'path_traversal': 80,
                'unsafe_deserialization': 90,
                'weak_crypto': 70,
                'sensitive_logging': 60,
                'unsafe_api': 75,
                'xss_vulnerability': 80,
                'unsanitized_input': 70,
                'dangerous_file_ops': 75,
                'insecure_random': 50,
                'eval_usage': 85,
                'cors_misconfiguration': 65
            },
            'severity_thresholds': {
                'critical': 200,
                'high': 100,
                'medium': 50,
                'low': 10
            },
            'max_file_size_kb': 500,
            'max_files': 10000,
            'python_extensions': ['.py'],
            'javascript_extensions': ['.js', '.jsx', '.ts', '.tsx', '.mjs']
        }
    }
    
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f) or {}
            if 'hcrs' in config_data:
                # Merge with defaults
                default_config['hcrs'].update(config_data['hcrs'])
    
    return default_config['hcrs']

def get_risk_weight(violation_type: str, config: dict = None) -> float:
    """Get risk weight for a violation type"""
    if config is None:
        config = load_hcrs_config()
    
    return config.get('risk_weights', {}).get(violation_type, 50)

def should_analyze_file(file_path: str, config: dict = None) -> tuple:
    """
    Check if file should be analyzed based on extension.
    Returns (should_analyze: bool, language: str)
    """
    if config is None:
        config = load_hcrs_config()
    
    ext = os.path.splitext(file_path)[1].lower()
    
    if ext in config.get('python_extensions', ['.py']):
        return (True, 'python')
    
    if ext in config.get('javascript_extensions', ['.js', '.jsx', '.ts', '.tsx']):
        return (True, 'javascript')
    
    return (False, None)
