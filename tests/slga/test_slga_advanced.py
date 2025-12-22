import os
import tempfile
import shutil
from engines.slga.run import run_slga

def create_multifile_repo(tmpdir):
    # Multiple files, multiple secrets, JS and Python
    pyfile = os.path.join(tmpdir, 'a.py')
    jsfile = os.path.join(tmpdir, 'b.js')
    with open(pyfile, 'w') as f:
        f.write('DB_PASSWORD = "supersecretpass123"\n')
    with open(jsfile, 'w') as f:
        f.write('const token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";\n')
    import git
    repo = git.Repo.init(tmpdir)
    repo.index.add(['a.py', 'b.js'])
    repo.index.commit('Add secrets in multiple files')
    repo.close()
    return tmpdir

def test_multiple_secrets_and_files():
    tmpdir = tempfile.mkdtemp()
    try:
        repo_path = create_multifile_repo(tmpdir)
        graph = run_slga(repo_path)
        with graph.driver.session() as session:
            result = session.run(
                "MATCH (s:Secret) RETURN count(s) as count"
            )
            count = result.single()["count"]
            print(f"[DEBUG] Number of secrets detected in Neo4j: {count}")
            assert count >= 2, f"Should detect multiple secrets in different files, found {count}"
        graph.close()
    finally:
        import gc
        gc.collect()
        shutil.rmtree(tmpdir, ignore_errors=True)
