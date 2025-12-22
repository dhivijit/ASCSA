# SLGA graph logic
from neo4j import GraphDatabase
from .models import Secret, Commit, Stage, Log, Artifact

class LineageGraph:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def create_stage_nodes(self, stages):
        with self.driver.session() as session:
            for stage in stages:
                session.execute_write(self._create_stage_node, stage)

    @staticmethod
    def _create_stage_node(tx, stage: Stage):
        tx.run(
            """
            MERGE (st:Stage {name: $name})
            """,
            name=stage.name
        )
        for secret in getattr(stage, 'secrets', []):
            tx.run(
                """
                MERGE (s:Secret {value: $secret})
                MERGE (st:Stage {name: $name})
                MERGE (s)-[:USED_IN]->(st)
                """,
                secret=secret, name=stage.name
            )

    def create_log_nodes(self, logs):
        with self.driver.session() as session:
            for log in logs:
                session.execute_write(self._create_log_node, log)

    @staticmethod
    def _create_log_node(tx, log: Log):
        tx.run(
            """
            MERGE (l:Log {path: $path})
            """,
            path=log.path
        )
        for secret in getattr(log, 'secrets', []):
            tx.run(
                """
                MERGE (s:Secret {value: $secret})
                MERGE (l:Log {path: $path})
                MERGE (s)-[:APPEARS_IN_LOG]->(l)
                """,
                secret=secret, path=log.path
            )

    def create_artifact_nodes(self, artifacts):
        with self.driver.session() as session:
            for artifact in artifacts:
                session.execute_write(self._create_artifact_node, artifact)

    @staticmethod
    def _create_artifact_node(tx, artifact: Artifact):
        tx.run(
            """
            MERGE (a:Artifact {path: $path})
            """,
            path=artifact.path
        )
        for secret in getattr(artifact, 'secrets', []):
            tx.run(
                """
                MERGE (s:Secret {value: $secret})
                MERGE (a:Artifact {path: $path})
                MERGE (s)-[:APPEARS_IN_ARTIFACT]->(a)
                """,
                secret=secret, path=artifact.path
            )

    def create_secret_nodes(self, secrets):
        with self.driver.session() as session:
            for secret in secrets:
                session.execute_write(self._create_secret_node, secret)

    @staticmethod
    def _create_secret_node(tx, secret: Secret):
        tx.run(
            """
            MERGE (s:Secret {value: $value})
            SET s.type = $type, s.entropy = $entropy
            """,
            value=secret.value, type=secret.secret_type, entropy=secret.entropy
        )
        for file, line in zip(secret.files, secret.lines):
            tx.run(
                """
                MERGE (f:File {path: $file})
                MERGE (s:Secret {value: $value})
                MERGE (s)-[:APPEARS_IN {line: $line}]->(f)
                """,
                file=file, value=secret.value, line=line
            )

    def create_commit_nodes(self, commits):
        with self.driver.session() as session:
            for commit in commits:
                session.execute_write(self._create_commit_node, commit)

    @staticmethod
    def _create_commit_node(tx, commit: Commit):
        tx.run(
            """
            MERGE (c:Commit {hash: $hash})
            SET c.message = $message, c.author = $author, c.date = $date
            """,
            hash=commit.hash, message=commit.message, author=commit.author, date=commit.date
        )
        for file in commit.files:
            tx.run(
                """
                MERGE (f:File {path: $file})
                MERGE (c:Commit {hash: $hash})
                MERGE (f)-[:IN_COMMIT]->(c)
                """,
                file=file, hash=commit.hash
            )

    def query_secret_propagation(self, secret_value):
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (s:Secret {value: $value})-[r*1..3]-(n)
                RETURN s, r, n
                """,
                value=secret_value
            )
            return [record for record in result]

def build_lineage_graph(secrets, file_to_commits, neo4j_uri, neo4j_user, neo4j_pass, stages=None, logs=None, artifacts=None):
    graph = LineageGraph(neo4j_uri, neo4j_user, neo4j_pass)
    graph.create_secret_nodes(secrets)
    all_commits = []
    for commits in file_to_commits.values():
        all_commits.extend(commits)
    graph.create_commit_nodes(all_commits)
    if stages:
        graph.create_stage_nodes(stages)
    if logs:
        graph.create_log_nodes(logs)
    if artifacts:
        graph.create_artifact_nodes(artifacts)
    return graph
