# SLGA pipeline, log, and artifact scanner
import os
import re
from .models import Stage, Log, Artifact

def scan_pipeline_stages(ci_config_path):
    """
    Dummy parser for CI pipeline config (YAML/JSON). Returns list of Stage objects.
    Extend this to parse real pipeline configs (GitHub Actions, GitLab, etc).
    """
    stages = []
    if not os.path.exists(ci_config_path):
        return stages
    try:
        with open(ci_config_path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f, 1):
                m = re.search(r'stage[s]?:\s*([\w-]+)', line, re.IGNORECASE)
                if m:
                    stages.append(Stage(name=m.group(1)))
    except Exception:
        pass
    return stages

def scan_logs_for_secrets(log_dir, secret_values):
    logs = []
    for root, _, files in os.walk(log_dir):
        for file in files:
            if file.endswith(('.log', '.txt')):
                path = os.path.join(root, file)
                found = []
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        for i, line in enumerate(f, 1):
                            for secret in secret_values:
                                if secret in line:
                                    found.append(secret)
                except Exception:
                    continue
                if found:
                    logs.append(Log(path=path, secrets=found))
    return logs

def scan_artifacts_for_secrets(artifact_dir, secret_values):
    artifacts = []
    for root, _, files in os.walk(artifact_dir):
        for file in files:
            path = os.path.join(root, file)
            found = []
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        for secret in secret_values:
                            if secret in line:
                                found.append(secret)
            except Exception:
                continue
            if found:
                artifacts.append(Artifact(path=path, secrets=found))
    return artifacts
