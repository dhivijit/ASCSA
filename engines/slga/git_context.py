"""
SLGA Git Context — GitPython enrichment for code-level authorship & hotspots.

Uses GitPython APIs (blame, iter_commits, commit.stats) that are already
available in the project but previously unused, to provide:
  - Per-file blame summaries (author -> line count)
  - Change-frequency tracking (how often a file is modified)
  - Contributor aggregation (name, email, commit count, date range)
  - File hotspot detection (high churn + multiple contributors)

All methods degrade gracefully when the repository is not a git repo
or a file is untracked.
"""

import os
import logging
from collections import defaultdict
from typing import List, Dict, Optional

from git import Repo, InvalidGitRepositoryError, GitCommandError

from .models import Contributor, FileGitContext

logger = logging.getLogger(__name__)


class GitContextAnalyzer:
    """Extracts git-level context for files and the overall repository."""

    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self._repo: Optional[Repo] = None
        try:
            self._repo = Repo(repo_path)
        except (InvalidGitRepositoryError, Exception) as e:
            logger.warning(f"GitContextAnalyzer: not a git repository ({e})")

    # -- file-level ---------------------------------------------------------

    def analyze_file(self, file_path: str) -> Optional[FileGitContext]:
        """Return git context for a single file (blame, frequency, contributors)."""
        if self._repo is None:
            return None

        rel_path = os.path.relpath(file_path, self.repo_path).replace("\\", "/")

        # Change frequency: number of commits touching this file
        change_frequency = 0
        last_modified: Optional[str] = None
        file_contributors: Dict[str, Contributor] = {}

        try:
            for commit in self._repo.iter_commits(paths=rel_path, max_count=500):
                change_frequency += 1
                author_name = str(commit.author)
                author_email = str(commit.author.email) if commit.author.email else ""
                commit_date = str(commit.committed_datetime)

                if author_name not in file_contributors:
                    file_contributors[author_name] = Contributor(
                        name=author_name,
                        email=author_email,
                        commits_count=0,
                        files_touched=[rel_path],
                        first_seen=commit_date,
                        last_seen=commit_date,
                    )

                file_contributors[author_name].commits_count += 1
                # Update date range
                if commit_date < (file_contributors[author_name].first_seen or commit_date):
                    file_contributors[author_name].first_seen = commit_date
                if commit_date > (file_contributors[author_name].last_seen or ""):
                    file_contributors[author_name].last_seen = commit_date

                if last_modified is None:
                    last_modified = commit_date
        except GitCommandError:
            logger.debug(f"Could not get commit history for {rel_path}")

        # Blame summary: author -> line count
        blame_summary: Dict[str, int] = {}
        try:
            blame_data = self._repo.blame("HEAD", rel_path)
            for commit, lines in blame_data:
                author = str(commit.author)
                blame_summary[author] = blame_summary.get(author, 0) + len(lines)
        except (GitCommandError, Exception):
            logger.debug(f"Could not get blame for {rel_path}")

        # Hotspot: high churn + multiple contributors
        is_hotspot = change_frequency >= 20 and len(file_contributors) >= 3

        return FileGitContext(
            file_path=rel_path,
            contributors=list(file_contributors.values()),
            change_frequency=change_frequency,
            last_modified=last_modified,
            blame_summary=blame_summary,
            is_hotspot=is_hotspot,
        )

    # -- repository-level ---------------------------------------------------

    def analyze_repository(
        self, max_files: int = 200, max_commits: int = 500
    ) -> Dict:
        """Analyze git context across the repository.

        Returns a dict with:
          - ``contributors``: aggregated Contributor list
          - ``file_contexts``: list of FileGitContext for analysed files
          - ``hotspots``: files flagged as hotspots
          - ``total_commits``: total commits examined
          - ``total_files_analyzed``: number of files with context
        """
        if self._repo is None:
            return {
                "contributors": [], "file_contexts": [], "hotspots": [],
                "total_commits": 0, "total_files_analyzed": 0,
            }

        # Gather per-file change counts via commit iteration
        file_commit_count: Dict[str, int] = defaultdict(int)
        contributor_map: Dict[str, Contributor] = {}
        total_commits = 0

        try:
            for commit in self._repo.iter_commits(max_count=max_commits):
                total_commits += 1
                author_name = str(commit.author)
                author_email = str(commit.author.email) if commit.author.email else ""
                commit_date = str(commit.committed_datetime)

                if author_name not in contributor_map:
                    contributor_map[author_name] = Contributor(
                        name=author_name,
                        email=author_email,
                        commits_count=0,
                        files_touched=[],
                        first_seen=commit_date,
                        last_seen=commit_date,
                    )

                contrib = contributor_map[author_name]
                contrib.commits_count += 1
                if commit_date < (contrib.first_seen or commit_date):
                    contrib.first_seen = commit_date
                if commit_date > (contrib.last_seen or ""):
                    contrib.last_seen = commit_date

                # Use commit.stats.files to track file-level churn
                try:
                    for fpath in commit.stats.files:
                        file_commit_count[fpath] += 1
                        if fpath not in contrib.files_touched:
                            contrib.files_touched.append(fpath)
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"Error iterating commits: {e}")

        # Build file contexts for the top-N most-changed files
        sorted_files = sorted(file_commit_count.items(), key=lambda x: -x[1])[:max_files]

        file_contexts: List[FileGitContext] = []
        hotspots: List[FileGitContext] = []

        for fpath, freq in sorted_files:
            # Find contributors who touched this file
            file_contribs = [
                c for c in contributor_map.values()
                if fpath in c.files_touched
            ]
            is_hotspot = freq >= 20 and len(file_contribs) >= 3

            ctx = FileGitContext(
                file_path=fpath,
                contributors=file_contribs,
                change_frequency=freq,
                is_hotspot=is_hotspot,
            )
            file_contexts.append(ctx)
            if is_hotspot:
                hotspots.append(ctx)

        return {
            "contributors": list(contributor_map.values()),
            "file_contexts": file_contexts,
            "hotspots": hotspots,
            "total_commits": total_commits,
            "total_files_analyzed": len(file_contexts),
        }

    # -- helpers ------------------------------------------------------------

    def get_contributors(self, max_commits: int = 500) -> List[Contributor]:
        """Return aggregated contributor statistics."""
        result = self.analyze_repository(max_files=0, max_commits=max_commits)
        return result["contributors"]

    def get_file_hotspots(self, top_n: int = 10, max_commits: int = 500) -> List[FileGitContext]:
        """Return the *top_n* most frequently changed files."""
        result = self.analyze_repository(max_files=top_n, max_commits=max_commits)
        return result["file_contexts"][:top_n]
