"""
SLGA Secret Detector — scans repository files, CI configs, logs, and artifacts for hardcoded secrets.

Supports Python, JavaScript/TypeScript, configuration files (.yaml, .json, .env, .toml, etc.),
shell scripts, Dockerfiles, and more. Uses regex pattern matching with Shannon entropy validation
to reduce false positives.

Returns both the detected secrets and scan coverage statistics so reports are informative
even when no secrets are found.
"""
import os
import re
import math
from typing import List, Dict, Tuple, Any
from .models import Secret

# Directories to skip during repo scanning
SKIP_DIRS = {
    '.git', '.svn', '.hg',
    'node_modules', '__pycache__', '.pytest_cache',
    'venv', 'env', '.venv', '.env',
    'build', 'dist', '.next', '.nuxt',
    'coverage', '.coverage', 'htmlcov',
    '.tox', '.mypy_cache', '.ruff_cache',
    'ascsa_ci.egg-info',
}

# File extensions to scan for secrets, grouped by category
CODE_EXTENSIONS = {'.py', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
CONFIG_EXTENSIONS = {'.yaml', '.yml', '.json', '.toml', '.cfg', '.ini', '.xml', '.properties'}
SCRIPT_EXTENSIONS = {'.sh', '.bash', '.zsh', '.ps1', '.bat', '.cmd'}
SPECIAL_FILES = {'Dockerfile', '.dockerignore', '.env', '.env.local', '.env.production',
                 '.env.development', '.env.example', '.gitignore'}
ALL_SCANNABLE_EXTENSIONS = CODE_EXTENSIONS | CONFIG_EXTENSIONS | SCRIPT_EXTENSIONS

SECRET_REGEXES = [
    re.compile(r'(?i)(api[_-]?key|secret|token|password|passwd|access[_-]?key)["\']?\s*[:=]\s*["\']([^"\']{8,})["\']'),
    re.compile(r'AKIA[0-9A-Z]{16}'),  # AWS Access Key
    re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),  # Stripe
    re.compile(r'ghp_[0-9a-zA-Z]{36,}'),  # GitHub token
]

# Patterns indicating the line is likely a false positive (comment, test fixture, placeholder)
FALSE_POSITIVE_INDICATORS = re.compile(
    r'(?i)(example|placeholder|dummy|test[_-]?value|your[_-]?api[_-]?key|changeme|'
    r'xxx+|replace[_-]?me|insert[_-]?here|TODO|FIXME|HACK|fake[_-]?|mock[_-]?|sample[_-]?)'
)

# Comment line patterns per language
COMMENT_PATTERNS = {
    '.py': re.compile(r'^\s*#'),
    '.js': re.compile(r'^\s*(//|/\*|\*)'),
    '.jsx': re.compile(r'^\s*(//|/\*|\*)'),
    '.ts': re.compile(r'^\s*(//|/\*|\*)'),
    '.tsx': re.compile(r'^\s*(//|/\*|\*)'),
    '.mjs': re.compile(r'^\s*(//|/\*|\*)'),
    '.cjs': re.compile(r'^\s*(//|/\*|\*)'),
    '.sh': re.compile(r'^\s*#'),
    '.bash': re.compile(r'^\s*#'),
    '.zsh': re.compile(r'^\s*#'),
    '.yaml': re.compile(r'^\s*#'),
    '.yml': re.compile(r'^\s*#'),
    '.toml': re.compile(r'^\s*#'),
    '.cfg': re.compile(r'^\s*[#;]'),
    '.ini': re.compile(r'^\s*[#;]'),
    '.properties': re.compile(r'^\s*[#!]'),
    '.xml': re.compile(r'^\s*<!--'),
}


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string to measure randomness.

    Higher entropy (>3.5) suggests the string may be a real secret rather
    than a common word or placeholder.
    """
    if not data:
        return 0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy


def _is_false_positive(value: str, line: str, file_ext: str) -> bool:
    """Check if a detected secret is likely a false positive.

    Filters out matches in comments, docstrings, and lines containing
    placeholder/test indicators.
    """
    # Check for comment lines based on file extension
    comment_pat = COMMENT_PATTERNS.get(file_ext)
    if comment_pat and comment_pat.match(line):
        return True

    # Check for placeholder/test indicators in the matched value or surrounding line
    if FALSE_POSITIVE_INDICATORS.search(value):
        return True
    if FALSE_POSITIVE_INDICATORS.search(line):
        return True

    return False


def _should_scan_file(filename: str) -> bool:
    """Determine if a file should be scanned based on its name and extension."""
    # Check special filenames (no extension)
    if filename in SPECIAL_FILES:
        return True
    _, ext = os.path.splitext(filename)
    return ext.lower() in ALL_SCANNABLE_EXTENSIONS


def _get_file_extension(filepath: str) -> str:
    """Get normalized file extension for comment detection."""
    _, ext = os.path.splitext(filepath)
    return ext.lower()


def _scan_file_for_secrets(filepath: str, secrets: List[Secret], scan_stats: Dict[str, Any]) -> None:
    """Scan a single file for secrets. Appends findings to the secrets list.

    This is the shared core scanning loop used by all scan phases (code files,
    CI config, logs/artifacts) to eliminate duplication.
    """
    file_ext = _get_file_extension(filepath)
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f, 1):
                for regex in SECRET_REGEXES:
                    for match in regex.finditer(line):
                        value = match.group(2) if match.lastindex and match.lastindex >= 2 else match.group(0)
                        entropy = shannon_entropy(value)
                        if entropy > 3.5 or len(value) > 12:
                            # Filter false positives
                            if _is_false_positive(value, line, file_ext):
                                scan_stats['false_positives_filtered'] += 1
                                continue
                            secrets.append(Secret(
                                value=value,
                                secret_type=regex.pattern,
                                entropy=entropy,
                                files=[filepath],
                                lines=[i],
                                commits=[]
                            ))
    except Exception:
        scan_stats['files_skipped_errors'] += 1


def detect_secrets(
    repo_path: str,
    ci_config_path: str = None,
    log_dir: str = None,
    artifact_dir: str = None
) -> Tuple[List[Secret], Dict[str, Any]]:
    """Detect hardcoded secrets in repository files, CI config, logs, and artifacts.

    Args:
        repo_path: Root path of the repository to scan.
        ci_config_path: Optional path to a CI/CD config file (e.g., .github/workflows/ci.yml).
        log_dir: Optional directory containing build/CI log files.
        artifact_dir: Optional directory containing build artifacts.

    Returns:
        A tuple of (secrets, scan_stats) where scan_stats is a dict with coverage metrics:
        - files_scanned: total files scanned
        - files_by_type: dict mapping extension → count
        - directories_walked: number of directories traversed
        - directories_skipped: number of directories skipped
        - files_skipped_errors: files that couldn't be read
        - false_positives_filtered: matches rejected by false-positive filter
    """
    secrets: List[Secret] = []
    scan_stats: Dict[str, Any] = {
        'files_scanned': 0,
        'files_by_type': {},
        'directories_walked': 0,
        'directories_skipped': 0,
        'files_skipped_errors': 0,
        'false_positives_filtered': 0,
    }

    # Phase 1: Scan code and config files in the repository
    for root, dirs, files in os.walk(repo_path):
        # Skip known non-source directories
        original_dir_count = len(dirs)
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        scan_stats['directories_skipped'] += original_dir_count - len(dirs)
        scan_stats['directories_walked'] += 1

        for filename in files:
            if _should_scan_file(filename):
                filepath = os.path.join(root, filename)
                ext = _get_file_extension(filepath) or filename
                scan_stats['files_scanned'] += 1
                scan_stats['files_by_type'][ext] = scan_stats['files_by_type'].get(ext, 0) + 1
                _scan_file_for_secrets(filepath, secrets, scan_stats)

    # Phase 2: Scan CI/CD config file
    if ci_config_path and os.path.exists(ci_config_path):
        scan_stats['files_scanned'] += 1
        _scan_file_for_secrets(ci_config_path, secrets, scan_stats)

    # Phase 3: Scan log and artifact directories
    for scan_dir, label in [(log_dir, 'log'), (artifact_dir, 'artifact')]:
        if scan_dir and os.path.exists(scan_dir):
            for root, dirs, files in os.walk(scan_dir):
                scan_stats['directories_walked'] += 1
                for filename in files:
                    filepath = os.path.join(root, filename)
                    scan_stats['files_scanned'] += 1
                    _scan_file_for_secrets(filepath, secrets, scan_stats)

    return secrets, scan_stats
