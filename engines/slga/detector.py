# SLGA detector logic
import os
import re
import math
from .models import Secret

SECRET_REGEXES = [
    re.compile(r'(?i)(api[_-]?key|secret|token|password|passwd|access[_-]?key)["\']?\s*[:=]\s*["\']([^"\']{8,})["\']'),
    re.compile(r'AKIA[0-9A-Z]{16}'),  # AWS Access Key
    re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),  # Stripe
    re.compile(r'ghp_[0-9a-zA-Z]{36,}'),  # GitHub token
]

def shannon_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy

def detect_secrets(repo_path, ci_config_path=None, log_dir=None, artifact_dir=None):
    secrets = []
    # Scan code files
    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith(('.py', '.js', '.jsx', '.ts', '.tsx')):
                path = os.path.join(root, file)
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    for i, line in enumerate(f, 1):
                        for regex in SECRET_REGEXES:
                            for match in regex.finditer(line):
                                value = match.group(2) if match.lastindex and match.lastindex >= 2 else match.group(0)
                                entropy = shannon_entropy(value)
                                if entropy > 3.5 or len(value) > 12:
                                    secrets.append(Secret(
                                        value=value,
                                        secret_type=regex.pattern,
                                        entropy=entropy,
                                        files=[path],
                                        lines=[i],
                                        commits=[]
                                    ))
    # Optionally scan pipeline config, logs, artifacts
    if ci_config_path and os.path.exists(ci_config_path):
        try:
            with open(ci_config_path, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f, 1):
                    for regex in SECRET_REGEXES:
                        for match in regex.finditer(line):
                            value = match.group(2) if match.lastindex and match.lastindex >= 2 else match.group(0)
                            entropy = shannon_entropy(value)
                            if entropy > 3.5 or len(value) > 12:
                                secrets.append(Secret(
                                    value=value,
                                    secret_type=regex.pattern,
                                    entropy=entropy,
                                    files=[ci_config_path],
                                    lines=[i],
                                    commits=[]
                                ))
        except Exception:
            pass
    for scan_dir, label in [(log_dir, 'log'), (artifact_dir, 'artifact')]:
        if scan_dir and os.path.exists(scan_dir):
            for root, _, files in os.walk(scan_dir):
                for file in files:
                    path = os.path.join(root, file)
                    try:
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            for i, line in enumerate(f, 1):
                                for regex in SECRET_REGEXES:
                                    for match in regex.finditer(line):
                                        value = match.group(2) if match.lastindex and match.lastindex >= 2 else match.group(0)
                                        entropy = shannon_entropy(value)
                                        if entropy > 3.5 or len(value) > 12:
                                            secrets.append(Secret(
                                                value=value,
                                                secret_type=regex.pattern,
                                                entropy=entropy,
                                                files=[path],
                                                lines=[i],
                                                commits=[]
                                            ))
                    except Exception:
                        continue
    return secrets
