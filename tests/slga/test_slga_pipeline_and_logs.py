import os
import tempfile
import shutil
import pytest
from engines.slga import run, detector, pipeline_scanner

def make_file(path, content):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)

def test_detect_secrets_in_pipeline_config():
    with tempfile.TemporaryDirectory() as tmpdir:
        ci_path = os.path.join(tmpdir, 'ci.yaml')
        make_file(ci_path, 'stages:\n  - build\n  - deploy\n  - test\n  password: "supersecret123"\n')
        secrets = detector.detect_secrets(tmpdir, ci_config_path=ci_path)
        assert any('supersecret123' in s.value for s in secrets)

def test_scan_logs_for_secrets():
    with tempfile.TemporaryDirectory() as tmpdir:
        log_dir = os.path.join(tmpdir, 'logs')
        os.makedirs(log_dir)
        log_path = os.path.join(log_dir, 'build.log')
        make_file(log_path, 'INFO: Build started\nAPI_KEY=abcd1234superkey\n')
        secrets = [detector.Secret(value='abcd1234superkey', secret_type='api_key', entropy=4.0)]
        logs = pipeline_scanner.scan_logs_for_secrets(log_dir, [s.value for s in secrets])
        assert any('abcd1234superkey' in l.secrets for l in logs)

def test_scan_artifacts_for_secrets():
    with tempfile.TemporaryDirectory() as tmpdir:
        artifact_dir = os.path.join(tmpdir, 'artifacts')
        os.makedirs(artifact_dir)
        artifact_path = os.path.join(artifact_dir, 'output.txt')
        make_file(artifact_path, 'Sensitive: ghp_abcdefghijklmnopqrstuvwxyz1234567890abcd\n')
        secrets = [detector.Secret(value='ghp_abcdefghijklmnopqrstuvwxyz1234567890abcd', secret_type='github', entropy=4.5)]
        artifacts = pipeline_scanner.scan_artifacts_for_secrets(artifact_dir, [s.value for s in secrets])
        assert any('ghp_abcdefghijklmnopqrstuvwxyz1234567890abcd' in a.secrets for a in artifacts)

def test_scan_pipeline_stages():
    with tempfile.TemporaryDirectory() as tmpdir:
        ci_path = os.path.join(tmpdir, 'ci.yaml')
        make_file(ci_path, 'stages:\n  - build\n  - test\n')
        stages = pipeline_scanner.scan_pipeline_stages(ci_path)
        assert any(s.name == 'build' or s.name == 'test' for s in stages)
