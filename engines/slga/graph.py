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
        """Query propagation paths for a secret (up to 3 hops)"""
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH path = (s:Secret {value: $value})-[r*1..3]-(n)
                RETURN path, nodes(path) as nodes, relationships(path) as rels
                LIMIT 100
                """,
                value=secret_value
            )
            return [record for record in result]
    
    def analyze_secret_propagation(self, secret_value):
        """Comprehensive propagation analysis for a secret"""
        with self.driver.session() as session:
            # Get propagation scope
            scope_result = session.run(
                """
                MATCH (s:Secret {value: $value})
                OPTIONAL MATCH (s)-[:APPEARS_IN]->(f:File)
                OPTIONAL MATCH (f)-[:IN_COMMIT]->(c:Commit)
                OPTIONAL MATCH (s)-[:USED_IN]->(st:Stage)
                OPTIONAL MATCH (s)-[:APPEARS_IN_LOG]->(l:Log)
                OPTIONAL MATCH (s)-[:APPEARS_IN_ARTIFACT]->(a:Artifact)
                RETURN 
                    count(DISTINCT f) as file_count,
                    count(DISTINCT c) as commit_count,
                    count(DISTINCT st) as stage_count,
                    count(DISTINCT l) as log_count,
                    count(DISTINCT a) as artifact_count,
                    collect(DISTINCT f.path) as files,
                    collect(DISTINCT st.name) as stages,
                    collect(DISTINCT l.path) as logs,
                    collect(DISTINCT a.path) as artifacts
                """,
                value=secret_value
            )
            
            scope = scope_result.single()
            if not scope:
                return None
            
            # Calculate propagation risk score
            risk_score = 0
            risk_factors = []
            
            file_count = scope['file_count']
            commit_count = scope['commit_count']
            stage_count = scope['stage_count']
            log_count = scope['log_count']
            artifact_count = scope['artifact_count']
            
            # File spread risk
            if file_count > 5:
                risk_score += 30
                risk_factors.append(f"High file spread: {file_count} files")
            elif file_count > 2:
                risk_score += 15
                risk_factors.append(f"Moderate file spread: {file_count} files")
            
            # Commit history risk
            if commit_count > 10:
                risk_score += 20
                risk_factors.append(f"Extensive commit history: {commit_count} commits")
            elif commit_count > 5:
                risk_score += 10
                risk_factors.append(f"Multiple commits: {commit_count} commits")
            
            # CI/CD stage usage risk (HIGH RISK)
            if stage_count > 0:
                risk_score += 25
                risk_factors.append(f"Used in CI/CD pipeline: {stage_count} stage(s)")
            
            # Log exposure risk (CRITICAL)
            if log_count > 0:
                risk_score += 20
                risk_factors.append(f"EXPOSED in logs: {log_count} log file(s)")
            
            # Artifact containment risk (HIGH RISK)
            if artifact_count > 0:
                risk_score += 15
                risk_factors.append(f"Found in artifacts: {artifact_count} artifact(s)")
            
            # Determine severity
            if risk_score >= 70:
                severity = "CRITICAL"
            elif risk_score >= 50:
                severity = "HIGH"
            elif risk_score >= 30:
                severity = "MEDIUM"
            else:
                severity = "LOW"
            
            return {
                'secret_value': secret_value,
                'propagation_scope': {
                    'files': file_count,
                    'commits': commit_count,
                    'stages': stage_count,
                    'logs': log_count,
                    'artifacts': artifact_count
                },
                'file_paths': scope['files'],
                'stage_names': scope['stages'],
                'log_paths': scope['logs'],
                'artifact_paths': scope['artifacts'],
                'risk_score': risk_score,
                'severity': severity,
                'risk_factors': risk_factors
            }
    
    def get_all_secrets_propagation_summary(self):
        """Get propagation summary for all secrets in the graph"""
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (s:Secret)
                OPTIONAL MATCH (s)-[:APPEARS_IN]->(f:File)
                OPTIONAL MATCH (s)-[:USED_IN]->(st:Stage)
                OPTIONAL MATCH (s)-[:APPEARS_IN_LOG]->(l:Log)
                OPTIONAL MATCH (s)-[:APPEARS_IN_ARTIFACT]->(a:Artifact)
                RETURN 
                    s.value as secret_value,
                    s.type as secret_type,
                    count(DISTINCT f) as file_count,
                    count(DISTINCT st) as stage_count,
                    count(DISTINCT l) as log_count,
                    count(DISTINCT a) as artifact_count
                ORDER BY (count(DISTINCT f) + count(DISTINCT st) + count(DISTINCT l) + count(DISTINCT a)) DESC
                LIMIT 50
                """
            )
            return [dict(record) for record in result]
    
    def find_critical_propagation_chains(self):
        """Find secrets with critical propagation patterns (code -> pipeline -> logs/artifacts)"""
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (s:Secret)-[:APPEARS_IN]->(f:File)
                MATCH (s)-[:USED_IN]->(st:Stage)
                MATCH (s)-[:APPEARS_IN_LOG|APPEARS_IN_ARTIFACT]->(exposure)
                RETURN DISTINCT
                    s.value as secret_value,
                    s.type as secret_type,
                    collect(DISTINCT f.path) as files,
                    collect(DISTINCT st.name) as stages,
                    collect(DISTINCT labels(exposure)[0] + ':' + coalesce(exposure.path, '')) as exposures
                """
            )
            return [dict(record) for record in result]

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
