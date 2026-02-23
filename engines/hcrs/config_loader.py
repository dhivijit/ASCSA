"""
HCRS Config Loader — Configuration management for Hybrid Code Risk Scoring.

Loads HCRS settings from ``config/thresholds.yaml``, applying a recursive
deep merge with built-in defaults so that partial YAML overrides don't
clobber entire sub-dicts (e.g. ``risk_weights``).

The loaded config is cached after the first call so repeated
``load_hcrs_config()`` invocations don't re-read the file.
"""
import os
import yaml
from typing import Dict, Tuple

# Module-level config cache: (config_path -> config_dict)
_config_cache: Dict[str, dict] = {}

# Default configuration
_DEFAULT_CONFIG = {
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


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into *base*, returning a new dict.

    Sub-dicts are merged recursively instead of being replaced wholesale.
    """
    merged = dict(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_hcrs_config(config_path: str = None) -> dict:
    """Load HCRS configuration, with deep merge and caching.

    Args:
        config_path: Path to thresholds.yaml. Defaults to
                     ``<project_root>/config/thresholds.yaml``.

    Returns:
        Merged config dict for the ``hcrs`` section.
    """
    if config_path is None:
        config_path = os.path.join(
            os.path.dirname(__file__), '..', '..', 'config', 'thresholds.yaml'
        )
    config_path = os.path.normpath(config_path)

    if config_path in _config_cache:
        return _config_cache[config_path]

    import copy
    config = copy.deepcopy(_DEFAULT_CONFIG)

    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f) or {}
            if 'hcrs' in config_data:
                config = _deep_merge(config, config_data['hcrs'])

    _config_cache[config_path] = config
    return config


def load_config(config_path: str = None):
    """Backward-compatible alias for ``load_hcrs_config``."""
    return load_hcrs_config(config_path)


def get_risk_weight(violation_type: str, config: dict = None) -> float:
    """Get risk weight for a violation type."""
    if config is None:
        config = load_hcrs_config()
    return config.get('risk_weights', {}).get(violation_type, 50)


def should_analyze_file(file_path: str, config: dict = None) -> Tuple[bool, str]:
    """Check if file should be analyzed based on extension.

    Returns:
        (should_analyze, language) tuple.
    """
    if config is None:
        config = load_hcrs_config()

    ext = os.path.splitext(file_path)[1].lower()

    if ext in config.get('python_extensions', ['.py']):
        return (True, 'python')

    if ext in config.get('javascript_extensions', ['.js', '.jsx', '.ts', '.tsx']):
        return (True, 'javascript')

    return (False, None)
