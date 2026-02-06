"""
Tests for SLGA git commit content scanning
"""

import pytest
import os
import tempfile
import git
from engines.slga.git_parser import get_all_commits, get_commits_for_file, _scan_diff_for_secrets
from engines.slga.run import run_slga


class TestCommitContentScanning:
    """Test git commit content scanning functionality"""
    
    @pytest.fixture
    def temp_repo(self):
        """Create a temporary git repository with test commits"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Initialize repo
            repo = git.Repo.init(tmpdir)
            
            # Create first commit with a secret
            test_file = os.path.join(tmpdir, 'config.py')
            with open(test_file, 'w') as f:
                f.write('# Configuration\n')
                f.write('API_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
                f.write('DATABASE_URL = "postgresql://localhost/db"\n')
            
            repo.index.add(['config.py'])
            repo.index.commit('Add configuration with API key')
            
            # Create second commit modifying the file
            with open(test_file, 'a') as f:
                f.write('SECRET_TOKEN = "sk_live_1234567890abcdefghij"\n')
            
            repo.index.add(['config.py'])
            repo.index.commit('Add secret token')
            
            # Create third commit removing secrets
            with open(test_file, 'w') as f:
                f.write('# Configuration\n')
                f.write('# Secrets moved to environment variables\n')
            
            repo.index.add(['config.py'])
            repo.index.commit('Remove hardcoded secrets')
            
            yield tmpdir
    
    def test_get_all_commits_without_content(self, temp_repo):
        """Test fetching commits without content"""
        commits = get_all_commits(temp_repo, fetch_content=False)
        
        assert len(commits) == 3
        assert all(c.hash for c in commits)
        assert all(c.message for c in commits)
        # Diff should not be fetched
        assert all(c.diff is None for c in commits)
        assert all(not c.secrets_found for c in commits)
    
    def test_get_all_commits_with_content(self, temp_repo):
        """Test fetching commits with content and secret scanning"""
        commits = get_all_commits(temp_repo, fetch_content=True)
        
        assert len(commits) == 3
        
        # All commits should have diffs
        assert all(c.diff is not None for c in commits)
        
        # Check that secrets were found in commits
        secrets_found = sum(len(c.secrets_found) for c in commits)
        assert secrets_found >= 2  # At least the AWS key and Stripe key
    
    def test_get_commits_for_file_with_content(self, temp_repo):
        """Test fetching commits for specific file with content"""
        config_file = os.path.join(temp_repo, 'config.py')
        commits = get_commits_for_file(temp_repo, config_file, fetch_content=True)
        
        assert len(commits) == 3  # All commits modified config.py
        
        # Check that commits have content
        assert all(c.diff is not None for c in commits)
        assert all(c.changed_files for c in commits)
    
    def test_scan_diff_for_secrets(self):
        """Test secret detection in diff text"""
        diff_text = """
diff --git a/config.py b/config.py
index abc123..def456 100644
--- a/config.py
+++ b/config.py
@@ -1,3 +1,4 @@
 # Configuration
 DATABASE_URL = "postgresql://localhost/db"
+API_KEY = "AKIAIOSFODNN7EXAMPLE"
+SECRET_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
"""
        
        secrets = _scan_diff_for_secrets(diff_text)
        
        # Should find at least the AWS key and GitHub token
        assert len(secrets) >= 2
        assert any('AKIA' in s for s in secrets)
        assert any('ghp_' in s for s in secrets)
    
    def test_scan_diff_ignores_removed_lines(self):
        """Test that removed lines (starting with -) are ignored"""
        diff_text = """
diff --git a/config.py b/config.py
index abc123..def456 100644
--- a/config.py
+++ b/config.py
@@ -1,3 +1,2 @@
 # Configuration
-API_KEY = "AKIAIOSFODNN7EXAMPLE"
 # Use environment variables
"""
        
        secrets = _scan_diff_for_secrets(diff_text)
        
        # Should not find secrets in removed lines
        assert len(secrets) == 0
    
    def test_run_slga_with_commit_scanning(self, temp_repo):
        """Test full SLGA run with commit scanning enabled"""
        graph, secrets, db_path, propagation = run_slga(
            repo_path=temp_repo,
            scan_commits=True,
            max_commits=10,
            store_to_db=False  # Don't create DB in tests
        )
        
        # Should find secrets (both from files and commits)
        assert len(secrets) >= 0  # May be 0 if secrets were all removed
        
        # Check for commit-based secrets
        commit_secrets = [s for s in secrets if s.secret_type == "commit_history"]
        assert len(commit_secrets) >= 2  # Should find the historical secrets
    
    def test_run_slga_without_commit_scanning(self, temp_repo):
        """Test SLGA run with commit scanning disabled"""
        graph, secrets, db_path, propagation = run_slga(
            repo_path=temp_repo,
            scan_commits=False,
            store_to_db=False
        )
        
        # Should only find secrets in current files (none after removal commit)
        commit_secrets = [s for s in secrets if s.secret_type == "commit_history"]
        assert len(commit_secrets) == 0  # No commit scanning
    
    def test_max_commits_limit(self, temp_repo):
        """Test that max_commits parameter limits the scan"""
        # Create more commits
        repo = git.Repo(temp_repo)
        test_file = os.path.join(temp_repo, 'test.txt')
        
        for i in range(10):
            with open(test_file, 'w') as f:
                f.write(f'Test content {i}\n')
            repo.index.add(['test.txt'])
            repo.index.commit(f'Commit {i}')
        
        # Scan with limit
        commits = get_all_commits(temp_repo, max_count=5, fetch_content=True)
        
        assert len(commits) == 5
    
    def test_commit_model_fields(self, temp_repo):
        """Test that Commit model has all expected fields"""
        commits = get_all_commits(temp_repo, max_count=1, fetch_content=True)
        
        assert len(commits) > 0
        commit = commits[0]
        
        # Check all fields exist
        assert hasattr(commit, 'hash')
        assert hasattr(commit, 'message')
        assert hasattr(commit, 'author')
        assert hasattr(commit, 'date')
        assert hasattr(commit, 'diff')
        assert hasattr(commit, 'changed_files')
        assert hasattr(commit, 'secrets_found')
        assert hasattr(commit, 'files')
        assert hasattr(commit, 'commits')


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
