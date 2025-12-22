# SLGA git parser
import os
from git import Repo
from .models import Commit

def get_commits_for_file(repo_path, file_path):
	repo = Repo(repo_path)
	rel_path = os.path.relpath(file_path, repo_path)
	commits = []
	for commit in repo.iter_commits(paths=rel_path):
		commits.append(Commit(
			hash=commit.hexsha,
			files=[rel_path],
			message=commit.message.strip(),
			author=str(commit.author),
			date=str(commit.committed_datetime)
		))
	return commits
