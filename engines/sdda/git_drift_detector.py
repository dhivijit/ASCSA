"""
Git-diff–based drift detector for SDDA.

Compares two SLGA secret snapshots (current HEAD vs HEAD~1) to identify
stateless drift signals without requiring a persistent historical database.

Drift types:
  ADDED   — new secret appeared at HEAD that was absent at HEAD~1  (CRITICAL)
  REMOVED — secret present at HEAD~1 is gone at HEAD               (LOW)
  MOVED   — same secret value exists at both, but in different files (MEDIUM)

This module is designed for CI/CD pipelines where sdda.db does not persist
between runs. All detection is derived purely from the git tree.
"""

import hashlib
import logging
from dataclasses import dataclass, field
from typing import List, Dict
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class GitDriftDetection:
    """Drift detection result from a git-snapshot comparison."""
    secret_id: str
    run_id: str
    timestamp: datetime
    drift_type: str             # ADDED | REMOVED | MOVED
    severity: str               # CRITICAL | MEDIUM | LOW
    is_drifted: bool = True
    total_drift_score: float = 1.0
    files_added_in: List[str] = field(default_factory=list)
    files_removed_from: List[str] = field(default_factory=list)
    secret_type: str = ""
    anomaly_details: Dict = field(default_factory=dict)
    recommendation: str = ""


def _sid(value: str) -> str:
    """Stable identity hash for a secret value."""
    return "secret_" + hashlib.sha256(value.encode()).hexdigest()[:16]


def scan_tree_for_secrets(repo, commit) -> list:
    """
    Scan the git tree at *commit* for secrets using SLGA detector patterns.

    Reads file blobs directly from the git object store — no filesystem
    checkout required. Returns a List[Secret] (file-based only).

    Args:
        repo: GitPython Repo object.
        commit: GitPython Commit object to scan (e.g. HEAD~1).
    """
    from engines.slga.models import Secret
    from engines.slga.detector import (
        SECRET_REGEXES,
        shannon_entropy,
        _should_scan_file,
        _get_file_extension,
        _is_false_positive,
    )

    secrets: list = []

    try:
        tree = commit.tree
    except Exception as exc:
        logger.warning(f"Could not read tree for commit {commit.hexsha[:8]}: {exc}")
        return secrets

    def _walk(tree_obj, prefix=""):
        for item in tree_obj:
            if item.type == "tree":
                _walk(item, prefix + item.name + "/")
            elif item.type == "blob":
                filepath = prefix + item.name
                if not _should_scan_file(item.name):
                    continue
                file_ext = _get_file_extension(item.name)
                try:
                    content = item.data_stream.read().decode("utf-8", errors="ignore")
                except Exception:
                    continue
                for i, line in enumerate(content.splitlines(), 1):
                    for regex in SECRET_REGEXES:
                        for match in regex.finditer(line):
                            value = (
                                match.group(2)
                                if match.lastindex and match.lastindex >= 2
                                else match.group(0)
                            )
                            if shannon_entropy(value) > 3.5 or len(value) > 12:
                                if not _is_false_positive(value, line, file_ext):
                                    secrets.append(
                                        Secret(
                                            value=value,
                                            secret_type=regex.pattern,
                                            entropy=shannon_entropy(value),
                                            files=[filepath],
                                            lines=[i],
                                            commits=[],
                                        )
                                    )

    _walk(tree)
    return secrets


def diff_snapshots(
    current_secrets,   # List[Secret] — HEAD
    previous_secrets,  # List[Secret] — HEAD~1
    run_id: str,
    timestamp: datetime,
) -> List[GitDriftDetection]:
    """
    Diff two SLGA secret snapshots and return GitDriftDetection events.

    File-based secrets only; commit_history type is excluded to prevent
    noise from historical commit scanning.
    """
    # Build id → Secret maps, file-based secrets only
    curr = {
        _sid(s.value): s
        for s in current_secrets
        if s.files and s.secret_type != "commit_history"
    }
    prev = {
        _sid(s.value): s
        for s in previous_secrets
        if s.files and s.secret_type != "commit_history"
    }

    detections: List[GitDriftDetection] = []

    # ── ADDED ────────────────────────────────────────────────────────────────
    for sid in set(curr) - set(prev):
        s = curr[sid]
        detections.append(
            GitDriftDetection(
                secret_id=sid,
                run_id=run_id,
                timestamp=timestamp,
                drift_type="ADDED",
                severity="CRITICAL",
                total_drift_score=1.0,
                files_added_in=list(s.files)[:5],
                secret_type=s.secret_type,
                anomaly_details={
                    "type": "ADDED",
                    "files": list(s.files)[:5],
                    "lines": list(s.lines)[:5],
                },
                recommendation=(
                    f"New secret detected in {', '.join(list(s.files)[:3])}. "
                    "Remove immediately and rotate the credential."
                ),
            )
        )

    # ── REMOVED ──────────────────────────────────────────────────────────────
    for sid in set(prev) - set(curr):
        s = prev[sid]
        detections.append(
            GitDriftDetection(
                secret_id=sid,
                run_id=run_id,
                timestamp=timestamp,
                drift_type="REMOVED",
                severity="LOW",
                total_drift_score=0.3,
                files_removed_from=list(s.files)[:5],
                secret_type=s.secret_type,
                anomaly_details={
                    "type": "REMOVED",
                    "previous_files": list(s.files)[:5],
                },
                recommendation=(
                    f"Secret removed from {', '.join(list(s.files)[:3])}. "
                    "Verify it was rotated — deletion alone does not revoke access."
                ),
            )
        )

    # ── MOVED ─────────────────────────────────────────────────────────────────
    for sid in set(curr) & set(prev):
        c, p = curr[sid], prev[sid]
        if set(c.files) != set(p.files):
            new_locs = list(set(c.files) - set(p.files))
            old_locs = list(set(p.files) - set(c.files))
            detections.append(
                GitDriftDetection(
                    secret_id=sid,
                    run_id=run_id,
                    timestamp=timestamp,
                    drift_type="MOVED",
                    severity="MEDIUM",
                    total_drift_score=0.6,
                    files_added_in=new_locs[:5],
                    files_removed_from=old_locs[:5],
                    secret_type=c.secret_type,
                    anomaly_details={
                        "type": "MOVED",
                        "new_locations": new_locs[:5],
                        "old_locations": old_locs[:5],
                    },
                    recommendation=(
                        f"Secret moved from {old_locs[0] if old_locs else '?'} "
                        f"to {new_locs[0] if new_locs else '?'}. "
                        "Ensure it is not duplicated and is absent from git history."
                    ),
                )
            )

    return detections
