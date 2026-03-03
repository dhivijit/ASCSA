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
import json
import math
import base64
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

# Generated lockfiles — contain hashes/resolved URLs, never hand-written secrets
SKIP_FILES = {
    'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
    'composer.lock', 'Gemfile.lock', 'poetry.lock',
    'Pipfile.lock', 'cargo.lock', 'packages.lock.json',
}

# File extensions to scan for secrets, grouped by category
CODE_EXTENSIONS = {'.py', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
CONFIG_EXTENSIONS = {'.yaml', '.yml', '.json', '.toml', '.cfg', '.ini', '.xml', '.properties',
                     '.tf', '.tfvars', '.hcl'}  # Terraform/HCL added
SCRIPT_EXTENSIONS = {'.sh', '.bash', '.zsh', '.ps1', '.bat', '.cmd'}
SPECIAL_FILES = {'Dockerfile', '.dockerignore', '.env', '.env.local', '.env.production',
                 '.env.development', '.env.example', '.gitignore',
                 '.npmrc', '.pypirc', '.netrc', '.pgpass',  # Auth config files
                 'terraform.tfvars', 'terraform.tfstate'}   # Terraform state (often committed accidentally)
NOTEBOOK_EXTENSIONS = {'.ipynb'}  # Jupyter notebooks — scanned specially (JSON with output cells)
ALL_SCANNABLE_EXTENSIONS = CODE_EXTENSIONS | CONFIG_EXTENSIONS | SCRIPT_EXTENSIONS | NOTEBOOK_EXTENSIONS

SECRET_REGEXES = [
    # --- Generic keyword-based patterns ---
    # Quoted value:  api_key = "abc..."  or  secret: 'abc...'
    re.compile(r'(?i)(api[_-]?key|secret[_-]?key?|auth[_-]?token|access[_-]?token|access[_-]?key|'
               r'password|passwd|private[_-]?key|client[_-]?secret|consumer[_-]?secret|'
               r'encryption[_-]?key|signing[_-]?key|webhook[_-]?secret)'
               r'["\']?\s*[:=]\s*["\']([^"\']{8,})["\']'),
    # Bare assignment without quotes around key: SECRET_KEY = abc...  (env-style)
    re.compile(r'(?i)^[ \t]*(API_KEY|SECRET_KEY|AUTH_TOKEN|ACCESS_TOKEN|ACCESS_KEY|'
               r'PASSWORD|PASSWD|PRIVATE_KEY|CLIENT_SECRET|ENCRYPTION_KEY|SIGNING_KEY|'
               r'DATABASE_PASSWORD|DB_PASSWORD|DB_PASS)\s*=\s*(?!["\']?\s*$)([^\s#]{8,})'),

    # --- AWS ---
    re.compile(r'AKIA[0-9A-Z]{16}'),                                          # AWS Access Key ID
    re.compile(r'(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])'),    # AWS Secret Access Key (40-char base64)

    # --- Stripe ---
    re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),                                  # Stripe live secret key
    re.compile(r'sk_test_[0-9a-zA-Z]{24,}'),                                  # Stripe test secret key
    re.compile(r'rk_live_[0-9a-zA-Z]{24,}'),                                  # Stripe restricted key
    re.compile(r'whsec_[a-zA-Z0-9]{32,}'),                                    # Stripe webhook secret

    # --- GitHub ---
    re.compile(r'ghp_[0-9a-zA-Z]{36,}'),                                      # GitHub classic PAT
    re.compile(r'github_pat_[A-Za-z0-9_]{82}'),                               # GitHub fine-grained PAT
    re.compile(r'gho_[0-9a-zA-Z]{36,}'),                                      # GitHub OAuth token
    re.compile(r'ghs_[0-9a-zA-Z]{36,}'),                                      # GitHub Actions token
    re.compile(r'ghr_[0-9a-zA-Z]{36,}'),                                      # GitHub refresh token

    # --- GitLab ---
    re.compile(r'glpat-[0-9a-zA-Z\-_]{20,}'),                                # GitLab PAT
    re.compile(r'glcbt-[0-9a-zA-Z\-_]{20,}'),                                # GitLab CI job token
    re.compile(r'gldt-[0-9a-zA-Z\-_]{20,}'),                                 # GitLab deploy token

    # --- npm / PyPI ---
    re.compile(r'npm_[A-Za-z0-9]{36}'),                                       # npm token
    re.compile(r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}'),                  # PyPI API token

    # --- Slack ---
    re.compile(r'xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}'),                 # Slack bot token
    re.compile(r'xoxp-[0-9A-Za-z\-]{70,}'),                                   # Slack user token (min 70 chars)
    re.compile(r'xoxa-[0-9A-Za-z\-]{70,}'),                                   # Slack app-level token
    re.compile(r'xoxr-[0-9A-Za-z\-]{70,}'),                                   # Slack refresh token

    # --- Google / GCP ---
    re.compile(r'AIza[0-9A-Za-z\-_]{35}'),                                    # Google API key
    re.compile(r'"type"\s*:\s*"service_account"'),                             # GCP service account JSON
    re.compile(r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'),                  # Firebase Cloud Messaging key

    # --- Azure ---
    re.compile(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;'),          # Azure Storage connection string
    re.compile(r'Endpoint=sb://[^;]+;SharedAccessKeyName=[^;]+;SharedAccessKey=[^;"]+'),  # Azure Service Bus
    re.compile(r'Endpoint=sb://[^;]+;SharedAccessKeyName=[^;]+;SharedAccessKey=[^;"]+'),  # Azure Event Hub (same format)
    re.compile(r'Server=tcp:[^,]+,1433;.*Password=[^;]{8,}'),                 # Azure SQL connection string
    re.compile(r'AccountKey=[A-Za-z0-9+/]{64,}={0,2}'),                       # Azure Storage account key

    # --- Twilio ---
    re.compile(r'\bAC[a-zA-Z0-9]{32}\b'),                                     # Twilio Account SID (word-bounded)
    re.compile(r'SK[a-f0-9]{32}'),                                             # Twilio API key SID

    # --- SendGrid / Mailgun / Mailchimp ---
    re.compile(r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}'),               # SendGrid API key
    re.compile(r'key-[a-zA-Z0-9]{32}'),                                        # Mailgun API key
    re.compile(r'[a-zA-Z0-9]{32}-us[0-9]{1,2}'),                              # Mailchimp API key

    # --- DigitalOcean / Heroku / Cloudflare ---
    re.compile(r'dop_v1_[a-f0-9]{64}'),                                        # DigitalOcean PAT
    re.compile(r'doo_v1_[a-f0-9]{64}'),                                        # DigitalOcean OAuth token
    re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'),  # Heroku API key (UUID format)

    # --- HashiCorp Vault ---
    re.compile(r'hvs\.[A-Za-z0-9_\-]{90,}'),                                  # Vault service token
    re.compile(r'hvb\.[A-Za-z0-9_\-]{90,}'),                                  # Vault batch token
    re.compile(r'hvr\.[A-Za-z0-9_\-]{90,}'),                                  # Vault recovery token

    # --- Database URIs with embedded credentials ---
    re.compile(r'(postgres|postgresql|mysql|mongodb(\+srv)?|redis|mssql|sqlserver)'
               r'://[^:@\s]{1,64}:[^@\s]{8,}@[^\s"\']+'),                     # DB URI with user:pass

    # --- Private keys & certificates ---
    re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----'),  # PEM private key / PGP

    # --- JWT ---
    re.compile(r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+'),  # JWT (3-part)

    # --- Discord / Telegram ---
    re.compile(r'[MNO][a-zA-Z0-9]{23}\.[a-zA-Z0-9\-_]{6}\.[a-zA-Z0-9\-_]{27}'),  # Discord bot token
    re.compile(r'[0-9]{8,10}:[a-zA-Z0-9_\-]{35}'),                            # Telegram bot token

    # --- Docker build-arg secrets in CI configs ---
    re.compile(r'--build-arg\s+([A-Z_]{3,}(?:KEY|SECRET|TOKEN|PASSWORD|PASS|PWD))=([^\s\'"]{8,})'),  # --build-arg SECRET=value

    # --- Kubernetes Secret manifests ---
    # base64-encoded values in a k8s Secret data block are NOT real secrets by themselves,
    # but the field name + base64 value pattern is worth flagging for review
    re.compile(r'(?i)kind:\s*Secret[\s\S]{0,500}?data:\s*\n((?:\s+\S+:\s*[A-Za-z0-9+/]{16,}={0,2}\n)+)',
               re.MULTILINE),  # K8s Secret manifest

    # --- Terraform / HCL hardcoded values ---
    re.compile(r'(?i)(password|secret|access_key|secret_key|token|api_key)\s*=\s*"([^"]{8,})"'),  # TF string assignment

    # --- .npmrc / .netrc auth tokens ---
    re.compile(r'(?i)(//[^:]+:_authToken|//[^:]+:_password)\s*=\s*(.{8,})'),  # .npmrc registry token
    re.compile(r'(?i)^\s*password\s+(.{8,})$'),                               # .netrc password line
    re.compile(r'(?i)^\s*password\s*=\s*(.{8,})$'),                           # .pypirc password

    # --- New Relic ---
    re.compile(r'NRAK-[A-Z0-9]{27}'),                                          # New Relic user key
    re.compile(r'[a-zA-Z0-9]{40}NRAL'),                                        # New Relic license key
]

# Patterns indicating the line is likely a false positive (comment, test fixture, placeholder)
FALSE_POSITIVE_INDICATORS = re.compile(
    r'(?i)(example|placeholder|dummy|test[_-]?value|your[_-]?api[_-]?key|changeme|'
    r'xxx+|replace[_-]?me|insert[_-]?here|TODO|FIXME|HACK|fake[_-]?|mock[_-]?|sample[_-]?)'
)

# SRI / package integrity hashes — sha512-<base64>, sha256-<base64>, sha1-<base64>, sha384-<base64>
# These appear in package-lock.json, yarn.lock, HTML <script integrity=...>, etc.
_SRI_HASH_RE = re.compile(r'\bsha(512|384|256|1)-[A-Za-z0-9+/=]{20,}')

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


# Maximum file size to scan (bytes) — skip minified/binary blobs
_MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MB

# Path segments that indicate a test/mock/fixture context — lower severity
TEST_PATH_PATTERNS = re.compile(
    r'(?i)([\\/]|^)(test[s]?|spec[s]?|__test__|__mocks__|__fixtures__|'  
    r'fixtures?|mocks?|fakes?|stubs?|samples?|demo[s]?|example[s]?)([\\/]|$)'
)


def get_path_context(filepath: str) -> str:
    """Return 'test' if the path looks like a test/mock/fixture context, else 'production'."""
    return 'test' if TEST_PATH_PATTERNS.search(filepath) else 'production'


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

    # SRI / package integrity hashes (sha512-..., sha256-..., etc.)
    if _SRI_HASH_RE.search(line):
        return True

    return False


def _should_scan_file(filename: str) -> bool:
    """Determine if a file should be scanned based on its name and extension."""
    # Skip generated lockfiles — they contain hashes/resolved URLs, not secrets
    if filename in SKIP_FILES:
        return False
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
    # File size guard — skip very large files (minified bundles, binaries accidentally committed)
    try:
        if os.path.getsize(filepath) > _MAX_FILE_BYTES:
            scan_stats.setdefault('files_skipped_too_large', 0)
            scan_stats['files_skipped_too_large'] += 1
            return
    except OSError:
        return

    file_ext = _get_file_extension(filepath)

    # Jupyter notebooks — parse JSON and scan source + output cells specially
    if file_ext == '.ipynb':
        _scan_notebook_for_secrets(filepath, secrets, scan_stats)
        return

    # Terraform state files — parse JSON, look only inside "value" fields
    if filepath.endswith('.tfstate') or filepath.endswith('.tfstate.backup'):
        _scan_tfstate_for_secrets(filepath, secrets, scan_stats)
        return

    path_context = get_path_context(filepath)
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f, 1):
                for regex in SECRET_REGEXES:
                    for match in regex.finditer(line):
                        # Use last capture group if present (keyword-based patterns
                        # put the secret value in group 2), otherwise use full match
                        if match.lastindex and match.lastindex >= 2:
                            value = match.group(match.lastindex)
                        elif match.lastindex == 1:
                            value = match.group(1)
                        else:
                            value = match.group(0)
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
                                commits=[],
                                path_context=path_context,
                            ))
    except Exception:
        scan_stats['files_skipped_errors'] += 1


def _scan_notebook_for_secrets(
    filepath: str, secrets: List[Secret], scan_stats: Dict[str, Any]
) -> None:
    """Scan a Jupyter notebook (.ipynb) for secrets in source and output cells."""
    path_context = get_path_context(filepath)
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            nb = json.load(f)
    except Exception:
        scan_stats['files_skipped_errors'] += 1
        return

    lines_to_scan: List[tuple] = []  # (line_number, text)
    line_num = 0
    for cell in nb.get('cells', []):
        # Source lines
        for src_line in cell.get('source', []):
            line_num += 1
            lines_to_scan.append((line_num, src_line))
        # Output cells (stdout, text, data)
        for output in cell.get('outputs', []):
            for text_line in output.get('text', []):
                line_num += 1
                lines_to_scan.append((line_num, text_line))
            for _mime, content in output.get('data', {}).items():
                if isinstance(content, list):
                    for text_line in content:
                        line_num += 1
                        lines_to_scan.append((line_num, text_line))
                elif isinstance(content, str):
                    line_num += 1
                    lines_to_scan.append((line_num, content))

    for i, line in lines_to_scan:
        for regex in SECRET_REGEXES:
            for match in regex.finditer(line):
                if match.lastindex and match.lastindex >= 2:
                    value = match.group(match.lastindex)
                elif match.lastindex == 1:
                    value = match.group(1)
                else:
                    value = match.group(0)
                entropy = shannon_entropy(value)
                if entropy > 3.5 or len(value) > 12:
                    if _is_false_positive(value, line, '.ipynb'):
                        scan_stats['false_positives_filtered'] += 1
                        continue
                    secrets.append(Secret(
                        value=value,
                        secret_type=regex.pattern,
                        entropy=entropy,
                        files=[filepath],
                        lines=[i],
                        commits=[],
                        path_context=path_context,
                    ))


def _scan_tfstate_for_secrets(
    filepath: str, secrets: List[Secret], scan_stats: Dict[str, Any]
) -> None:
    """Scan a Terraform state file for secrets in resource output values."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            state = json.load(f)
    except Exception:
        scan_stats['files_skipped_errors'] += 1
        return

    def _walk_state(obj, path_parts):
        if isinstance(obj, dict):
            for k, v in obj.items():
                _walk_state(v, path_parts + [str(k)])
        elif isinstance(obj, list):
            for item in obj:
                _walk_state(item, path_parts)
        elif isinstance(obj, str) and len(obj) >= 8:
            key_context = path_parts[-1].lower() if path_parts else ''
            sensitive_keys = {'password', 'secret', 'token', 'key', 'credential',
                              'private_key', 'access_key', 'auth', 'api_key'}
            if not any(sk in key_context for sk in sensitive_keys):
                return
            entropy = shannon_entropy(obj)
            if entropy > 3.5:
                secrets.append(Secret(
                    value=obj,
                    secret_type='terraform_state_value',
                    entropy=entropy,
                    files=[filepath],
                    lines=[0],
                    commits=[],
                    path_context='production',
                ))

    _walk_state(state, [])


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
            # Also catch .tfstate files regardless of normal extension filter
            elif filename.endswith('.tfstate') or filename.endswith('.tfstate.backup'):
                filepath = os.path.join(root, filename)
                scan_stats['files_scanned'] += 1
                scan_stats['files_by_type']['.tfstate'] = scan_stats['files_by_type'].get('.tfstate', 0) + 1
                _scan_tfstate_for_secrets(filepath, secrets, scan_stats)

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
