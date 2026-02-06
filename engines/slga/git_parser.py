# SLGA git parser
import os
import re
from git import Repo
from .models import Commit
from .detector import SECRET_REGEXES, shannon_entropy

def get_commits_for_file(repo_path, file_path, fetch_content=False):
	"""Get commits for a specific file.
	
	Args:
		repo_path: Path to git repository
		file_path: Path to file to get commits for
		fetch_content: If True, fetch commit diffs and scan for secrets
		
	Returns:
		List of Commit objects
	"""
	repo = Repo(repo_path)
	rel_path = os.path.relpath(file_path, repo_path)
	commits = []
	for commit in repo.iter_commits(paths=rel_path):
		commit_obj = Commit(
			hash=commit.hexsha,
			files=[rel_path],
			message=commit.message.strip(),
			author=str(commit.author),
			date=str(commit.committed_datetime)
		)
		
		if fetch_content:
			# Get diff for this commit
			try:
				if commit.parents:
					diff = commit.parents[0].diff(commit, create_patch=True)
				else:
					# First commit has no parent
					diff = commit.diff(None, create_patch=True)
				
				commit_obj.diff = _extract_diff_text(diff)
				commit_obj.changed_files = [d.a_path or d.b_path for d in diff]
				commit_obj.secrets_found = _scan_diff_for_secrets(commit_obj.diff)
			except Exception as e:
				# Handle errors gracefully
				pass
		
		commits.append(commit_obj)
	return commits

def get_all_commits(repo_path, max_count=None, fetch_content=False):
	"""Get all commits in repository.
	
	Args:
		repo_path: Path to git repository
		max_count: Maximum number of commits to fetch (optional)
		fetch_content: If True, fetch commit diffs and scan for secrets
		
	Returns:
		List of Commit objects
	"""
	repo = Repo(repo_path)
	commits = []
	
	for i, commit in enumerate(repo.iter_commits()):
		if max_count and i >= max_count:
			break
			
		commit_obj = Commit(
			hash=commit.hexsha,
			files=[],
			message=commit.message.strip(),
			author=str(commit.author),
			date=str(commit.committed_datetime)
		)
		
		if fetch_content:
			# Get diff for this commit
			try:
				if commit.parents:
					diff = commit.parents[0].diff(commit, create_patch=True)
				else:
					# First commit has no parent
					diff = commit.diff(None, create_patch=True)
				
				commit_obj.diff = _extract_diff_text(diff)
				commit_obj.changed_files = [d.a_path or d.b_path for d in diff]
				commit_obj.files = commit_obj.changed_files  # Update files list
				commit_obj.secrets_found = _scan_diff_for_secrets(commit_obj.diff)
			except Exception as e:
				# Handle errors gracefully
				pass
		
		commits.append(commit_obj)
		
	return commits

def _extract_diff_text(diff):
	"""Extract text content from git diff objects."""
	diff_text = []
	for item in diff:
		try:
			if item.diff:
				diff_text.append(item.diff.decode('utf-8', errors='ignore'))
		except Exception:
			pass
	return '\n'.join(diff_text)

def _scan_diff_for_secrets(diff_text):
	"""Scan diff text for secrets using SECRET_REGEXES."""
	if not diff_text:
		return []
		
	secrets_found = []
	for line in diff_text.split('\n'):
		# Only scan added lines (starting with +)
		if not line.startswith('+'):
			continue
			
		for regex in SECRET_REGEXES:
			for match in regex.finditer(line):
				value = match.group(2) if match.lastindex and match.lastindex >= 2 else match.group(0)
				entropy = shannon_entropy(value)
				if entropy > 3.5 or len(value) > 12:
					secrets_found.append(value)
					
	return list(set(secrets_found))  # Remove duplicates
