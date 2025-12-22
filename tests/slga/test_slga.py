import os
import tempfile
import shutil
import pytest
from engines.slga.run import run_slga
from engines.slga.graph import LineageGraph
from engines.slga.models import Secret

TEST_NEO4J_URI = os.environ.get('NEO4J_URI', 'bolt://localhost:7687')
TEST_NEO4J_USER = os.environ.get('NEO4J_USER', 'neo4j')
TEST_NEO4J_PASS = os.environ.get('NEO4J_PASS', 'testtest')

def create_sample_repo(tmpdir):
    # Create a sample Python file with a secret
    pyfile = os.path.join(tmpdir, 'test.py')
    with open(pyfile, 'w') as f:
        f.write('API_KEY = "sk_live_1234567890abcdef1234567890abcdef"\n')
    # Initialize git repo
    import git
    repo = git.Repo.init(tmpdir)
    repo.index.add(['test.py'])
    repo.index.commit('Add test secret')
    repo.close()
    return tmpdir

def test_secret_detection_and_graph():
    tmpdir = tempfile.mkdtemp()
    try:
        repo_path = create_sample_repo(tmpdir)
        graph = run_slga(repo_path)
        # Check if secret node exists in Neo4j
        with graph.driver.session() as session:
            result = session.run(
                "MATCH (s:Secret) WHERE s.value CONTAINS 'sk_live_' RETURN s"
            )
            records = list(result)
            assert len(records) > 0, "Secret node not created in Neo4j"
        graph.close()
    finally:
        import gc
        gc.collect()
        shutil.rmtree(tmpdir, ignore_errors=True)

def test_secret_propagation_query():
    tmpdir = tempfile.mkdtemp()
    try:
        repo_path = create_sample_repo(tmpdir)
        graph = run_slga(repo_path)
        # Query propagation
        results = graph.query_secret_propagation('sk_live_1234567890abcdef1234567890abcdef')
        assert results, "Propagation query returned no results"
        graph.close()
    finally:
        import gc
        gc.collect()
        shutil.rmtree(tmpdir, ignore_errors=True)
