# SLGA graph logic
import logging
from neo4j import GraphDatabase

logger = logging.getLogger(__name__)
from .models import (
    Secret, Commit, Stage, Log, Artifact,
    CodeFunction, CodeClass, CodeImport, CallEdge,
    Contributor, FileSymbolSummary, FileGitContext,
)

class LineageGraph:
    def __init__(self, uri, user, password, connection_timeout=10):
        self.driver = GraphDatabase.driver(
            uri, auth=(user, password),
            connection_timeout=connection_timeout,
            connection_acquisition_timeout=connection_timeout,
        )
        # Fail fast if Neo4j is unreachable rather than hanging silently
        self.driver.verify_connectivity()
        # Counters populated by _refresh_counts() after all writes complete.
        self.node_count = 0
        self.edge_count = 0

    def _refresh_counts(self):
        """Query Neo4j for actual node and relationship counts after writes.

        Called once at the end of build_lineage_graph() so that the orchestrator
        sees correct values from getattr(graph, 'node_count', 0).
        """
        try:
            with self.driver.session() as session:
                n = session.run("MATCH (n) RETURN count(n) AS cnt").single()
                r = session.run("MATCH ()-[rel]->() RETURN count(rel) AS cnt").single()
                self.node_count = n["cnt"] if n else 0
                self.edge_count = r["cnt"] if r else 0
            logger.info(
                f"Neo4j graph summary: {self.node_count} nodes, {self.edge_count} relationships"
            )
        except Exception as exc:
            logger.warning(f"Neo4j count refresh failed (non-fatal): {exc}")

    def get_driver(self):
        """Expose the Neo4j driver for shared access by other components."""
        return self.driver

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
            session.execute_write(
                lambda tx: tx.run(
                    """
                    UNWIND $rows AS row
                    MERGE (s:Secret {value: row.value})
                    SET s.type = row.type, s.entropy = row.entropy
                    """,
                    rows=[{'value': s.value, 'type': s.secret_type, 'entropy': s.entropy}
                          for s in secrets],
                )
            )
            # File appearance links
            rows = [
                {'value': s.value, 'file': f, 'line': l}
                for s in secrets
                for f, l in zip(s.files, s.lines)
            ]
            if rows:
                session.execute_write(
                    lambda tx: tx.run(
                        """
                        UNWIND $rows AS row
                        MERGE (f:File {path: row.file})
                        MERGE (s:Secret {value: row.value})
                        MERGE (s)-[:APPEARS_IN {line: row.line}]->(f)
                        """,
                        rows=rows,
                    )
                )

    def create_commit_nodes(self, commits):
        if not commits:
            return
        with self.driver.session() as session:
            session.execute_write(
                lambda tx: tx.run(
                    """
                    UNWIND $rows AS row
                    MERGE (c:Commit {hash: row.hash})
                    SET c.message = row.message, c.author = row.author, c.date = row.date
                    """,
                    rows=[{'hash': c.hash, 'message': c.message,
                           'author': c.author, 'date': c.date}
                          for c in commits],
                )
            )
            file_rows = [
                {'file': f, 'hash': c.hash}
                for c in commits
                for f in c.files
            ]
            if file_rows:
                session.execute_write(
                    lambda tx: tx.run(
                        """
                        UNWIND $rows AS row
                        MERGE (f:File {path: row.file})
                        MERGE (c:Commit {hash: row.hash})
                        MERGE (f)-[:IN_COMMIT]->(c)
                        """,
                        rows=file_rows,
                    )
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
            # Check what relationships exist in the graph
            rel_check = session.run("""
                MATCH ()-[r]->()
                RETURN DISTINCT type(r) as rel_type
            """)
            existing_rels = {rec['rel_type'] for rec in rel_check}
            
            # Build conditional query
            query_parts = ["MATCH (s:Secret {value: $value})"]
            query_parts.append("OPTIONAL MATCH (s)-[:APPEARS_IN]->(f:File)")
            query_parts.append("OPTIONAL MATCH (f)-[:IN_COMMIT]->(c:Commit)")
            
            if 'USED_IN' in existing_rels:
                query_parts.append("OPTIONAL MATCH (s)-[:USED_IN]->(st:Stage)")
            if 'APPEARS_IN_LOG' in existing_rels:
                query_parts.append("OPTIONAL MATCH (s)-[:APPEARS_IN_LOG]->(l:Log)")
            if 'APPEARS_IN_ARTIFACT' in existing_rels:
                query_parts.append("OPTIONAL MATCH (s)-[:APPEARS_IN_ARTIFACT]->(a:Artifact)")
            
            # Build RETURN clause with safe conditional expressions
            stage_count = "count(DISTINCT st)" if 'USED_IN' in existing_rels else "0"
            log_count = "count(DISTINCT l)" if 'APPEARS_IN_LOG' in existing_rels else "0"
            artifact_count = "count(DISTINCT a)" if 'APPEARS_IN_ARTIFACT' in existing_rels else "0"
            stages_collect = "collect(DISTINCT st.name)" if 'USED_IN' in existing_rels else "[]"
            logs_collect = "collect(DISTINCT l.path)" if 'APPEARS_IN_LOG' in existing_rels else "[]"
            artifacts_collect = "collect(DISTINCT a.path)" if 'APPEARS_IN_ARTIFACT' in existing_rels else "[]"
            
            return_clause = (
                "RETURN \n"
                "    count(DISTINCT f) as file_count,\n"
                "    count(DISTINCT c) as commit_count,\n"
                f"    {stage_count} as stage_count,\n"
                f"    {log_count} as log_count,\n"
                f"    {artifact_count} as artifact_count,\n"
                "    collect(DISTINCT f.path) as files,\n"
                f"    {stages_collect} as stages,\n"
                f"    {logs_collect} as logs,\n"
                f"    {artifacts_collect} as artifacts"
            )
            query_parts.append(return_clause)
            
            # Get propagation scope
            scope_result = session.run("\n".join(query_parts), value=secret_value)
            
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
            # First check what relationship types exist
            rel_check = session.run("""
                MATCH ()-[r]->()
                RETURN DISTINCT type(r) as rel_type
            """)
            existing_rels = {rec['rel_type'] for rec in rel_check}
            
            # Build query based on existing relationships
            query_parts = ["MATCH (s:Secret)"]
            query_parts.append("OPTIONAL MATCH (s)-[:APPEARS_IN]->(f:File)")
            
            if 'USED_IN' in existing_rels:
                query_parts.append("OPTIONAL MATCH (s)-[:USED_IN]->(st:Stage)")
            if 'APPEARS_IN_LOG' in existing_rels:
                query_parts.append("OPTIONAL MATCH (s)-[:APPEARS_IN_LOG]->(l:Log)")
            if 'APPEARS_IN_ARTIFACT' in existing_rels:
                query_parts.append("OPTIONAL MATCH (s)-[:APPEARS_IN_ARTIFACT]->(a:Artifact)")
            
            query_parts.append("""
                RETURN 
                    s.value as secret_value,
                    s.type as secret_type,
                    count(DISTINCT f) as file_count,
                    {} as stage_count,
                    {} as log_count,
                    {} as artifact_count
                ORDER BY count(DISTINCT f) DESC
                LIMIT 50
            """.format(
                "count(DISTINCT st)" if 'USED_IN' in existing_rels else "0",
                "count(DISTINCT l)" if 'APPEARS_IN_LOG' in existing_rels else "0",
                "count(DISTINCT a)" if 'APPEARS_IN_ARTIFACT' in existing_rels else "0"
            ))
            
            result = session.run("\n".join(query_parts))
            return [dict(record) for record in result]
    
    def find_critical_propagation_chains(self):
        """Find secrets with critical propagation patterns (code -> pipeline -> logs/artifacts)"""
        with self.driver.session() as session:
            # Check if required relationships exist for critical chains
            rel_check = session.run("""
                MATCH ()-[r]->()
                RETURN DISTINCT type(r) as rel_type
            """)
            existing_rels = {rec['rel_type'] for rec in rel_check}
            
            # Only query if we have the necessary relationships for critical chains
            if not ({'USED_IN', 'APPEARS_IN_LOG'}.issubset(existing_rels) or 
                    {'USED_IN', 'APPEARS_IN_ARTIFACT'}.issubset(existing_rels)):
                return []  # No critical chains possible without these relationships
            
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

    # ------------------------------------------------------------------
    # Code Symbol Analysis — Neo4j node & relationship creation
    # ------------------------------------------------------------------

    def ensure_indexes(self):
        """Create indexes needed for fast MERGE/MATCH lookups."""
        with self.driver.session() as session:
            for stmt in [
                "CREATE INDEX code_function_name IF NOT EXISTS FOR (n:CodeFunction) ON (n.name)",
                "CREATE INDEX file_path IF NOT EXISTS FOR (n:File) ON (n.path)",
                "CREATE INDEX secret_value IF NOT EXISTS FOR (n:Secret) ON (n.value)",
                "CREATE INDEX commit_hash IF NOT EXISTS FOR (n:Commit) ON (n.hash)",
            ]:
                session.run(stmt)
        logger.info("Neo4j: indexes ensured")

    _BATCH_SIZE = 500

    def create_code_function_nodes(self, functions):
        """Create CodeFunction nodes linked to their File via DEFINED_IN."""
        total = len(functions)
        logger.info(f"Neo4j: writing {total} code function nodes (batched)...")
        with self.driver.session() as session:
            for start in range(0, total, self._BATCH_SIZE):
                batch = functions[start:start + self._BATCH_SIZE]
                rows = [
                    {'name': f.name, 'file_path': f.file_path,
                     'line_start': f.line_start, 'line_end': f.line_end,
                     'params': f.params, 'is_method': f.is_method,
                     'parent_class': f.parent_class or '',
                     'return_type': f.return_type or ''}
                    for f in batch
                ]
                session.execute_write(
                    lambda tx, r=rows: tx.run(
                        """
                        UNWIND $rows AS row
                        MERGE (fn:CodeFunction {name: row.name, file_path: row.file_path,
                                                line_start: row.line_start})
                        SET fn.line_end = row.line_end,
                            fn.params = row.params,
                            fn.is_method = row.is_method,
                            fn.parent_class = row.parent_class,
                            fn.return_type = row.return_type
                        MERGE (f:File {path: row.file_path})
                        MERGE (fn)-[:DEFINED_IN]->(f)
                        """,
                        rows=r,
                    )
                )
                # Method → class links for methods that have a parent
                method_rows = [r for r in rows if r['parent_class']]
                if method_rows:
                    session.execute_write(
                        lambda tx, mr=method_rows: tx.run(
                            """
                            UNWIND $rows AS row
                            MATCH (fn:CodeFunction {name: row.name, file_path: row.file_path,
                                                    line_start: row.line_start})
                            MERGE (cls:CodeClass {name: row.parent_class,
                                                  file_path: row.file_path})
                            MERGE (fn)-[:METHOD_OF]->(cls)
                            """,
                            rows=mr,
                        )
                    )
                logger.info(f"Neo4j: code functions {min(start + self._BATCH_SIZE, total)}/{total}")

    def create_code_class_nodes(self, classes):
        """Create CodeClass nodes linked to their File via DEFINED_IN."""
        with self.driver.session() as session:
            for cls in classes:
                session.execute_write(self._create_code_class_node, cls)

    @staticmethod
    def _create_code_class_node(tx, cls: CodeClass):
        tx.run(
            """
            MERGE (c:CodeClass {name: $name, file_path: $file_path})
            SET c.line_start = $line_start,
                c.line_end = $line_end,
                c.methods = $methods,
                c.bases = $bases
            MERGE (f:File {path: $file_path})
            MERGE (c)-[:DEFINED_IN]->(f)
            """,
            name=cls.name,
            file_path=cls.file_path,
            line_start=cls.line_start,
            line_end=cls.line_end,
            methods=cls.methods,
            bases=cls.bases,
        )
        # Create INHERITS relationships for base classes
        for base in cls.bases:
            tx.run(
                """
                MERGE (child:CodeClass {name: $child_name, file_path: $file_path})
                MERGE (parent:CodeClass {name: $base_name})
                MERGE (child)-[:INHERITS]->(parent)
                """,
                child_name=cls.name,
                file_path=cls.file_path,
                base_name=base,
            )

    def create_code_import_nodes(self, imports):
        """Create CodeImport nodes linked to their File via IMPORTS_FROM."""
        total = len(imports)
        logger.info(f"Neo4j: writing {total} import nodes (batched)...")
        with self.driver.session() as session:
            for start in range(0, total, self._BATCH_SIZE):
                batch = imports[start:start + self._BATCH_SIZE]
                rows = [
                    {'module': i.module, 'file_path': i.file_path,
                     'line': i.line, 'names': i.names, 'alias': i.alias or ''}
                    for i in batch
                ]
                session.execute_write(
                    lambda tx, r=rows: tx.run(
                        """
                        UNWIND $rows AS row
                        MERGE (i:CodeImport {module: row.module, file_path: row.file_path,
                                             line: row.line})
                        SET i.names = row.names, i.alias = row.alias
                        MERGE (f:File {path: row.file_path})
                        MERGE (i)-[:IMPORTS_FROM]->(f)
                        """,
                        rows=r,
                    )
                )
                logger.info(f"Neo4j: imports {min(start + self._BATCH_SIZE, total)}/{total}")

    def create_call_edges(self, edges):
        """Create CALLS relationships between CodeFunction nodes."""
        total = len(edges)
        logger.info(f"Neo4j: writing {total} call edges (batched)...")
        with self.driver.session() as session:
            for start in range(0, total, self._BATCH_SIZE):
                batch = edges[start:start + self._BATCH_SIZE]
                rows = [
                    {'caller': e.caller, 'callee': e.callee,
                     'file_path': e.file_path, 'line': e.line}
                    for e in batch
                ]
                session.execute_write(
                    lambda tx, r=rows: tx.run(
                        """
                        UNWIND $rows AS row
                        MATCH (caller:CodeFunction {name: row.caller})
                        MATCH (callee:CodeFunction {name: row.callee})
                        MERGE (caller)-[:CALLS]->(callee)
                        """,
                        rows=r,
                    )
                )
                logger.info(f"Neo4j: call edges {min(start + self._BATCH_SIZE, total)}/{total}")

    def create_contributor_nodes(self, contributors):
        """Create Contributor nodes linked to Files via AUTHORED_BY."""
        logger.info(f"Neo4j: creating {len(contributors)} contributor nodes...")
        with self.driver.session() as session:
            for contrib in contributors:
                session.execute_write(self._create_contributor_node, contrib)

    @staticmethod
    def _create_contributor_node(tx, contrib: Contributor):
        tx.run(
            """
            MERGE (ct:Contributor {name: $name})
            SET ct.email = $email,
                ct.commits_count = $commits_count,
                ct.first_seen = $first_seen,
                ct.last_seen = $last_seen
            """,
            name=contrib.name,
            email=contrib.email,
            commits_count=contrib.commits_count,
            first_seen=contrib.first_seen or "",
            last_seen=contrib.last_seen or "",
        )
        for fpath in contrib.files_touched:
            tx.run(
                """
                MERGE (ct:Contributor {name: $name})
                MERGE (f:File {path: $fpath})
                MERGE (ct)-[:AUTHORED_BY]->(f)
                """,
                name=contrib.name,
                fpath=fpath,
            )

    # ------------------------------------------------------------------
    # Code Symbol Queries
    # ------------------------------------------------------------------

    def query_call_chain(self, function_name, depth=3):
        """Traverse CALLS relationships outward from *function_name*."""
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH path = (f:CodeFunction {name: $name})-[:CALLS*1..""" + str(int(depth)) + """]->(callee:CodeFunction)
                RETURN [n IN nodes(path) | n.name] AS chain,
                       length(path) AS depth
                ORDER BY depth
                LIMIT 50
                """,
                name=function_name,
            )
            return [dict(record) for record in result]

    def query_class_hierarchy(self, class_name):
        """Traverse INHERITS relationships from *class_name*."""
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH path = (c:CodeClass {name: $name})-[:INHERITS*1..5]->(parent:CodeClass)
                RETURN [n IN nodes(path) | n.name] AS hierarchy,
                       length(path) AS depth
                ORDER BY depth
                LIMIT 20
                """,
                name=class_name,
            )
            return [dict(record) for record in result]

    def find_functions_with_secrets(self):
        """Find functions defined in files that contain secrets."""
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (fn:CodeFunction)-[:DEFINED_IN]->(f:File)<-[:APPEARS_IN]-(s:Secret)
                RETURN fn.name AS function_name,
                       fn.file_path AS file_path,
                       fn.line_start AS line_start,
                       fn.line_end AS line_end,
                       collect(DISTINCT s.type) AS secret_types,
                       count(DISTINCT s) AS secret_count
                ORDER BY secret_count DESC
                LIMIT 50
                """
            )
            return [dict(record) for record in result]

    def find_dead_code(self):
        """Find CodeFunction nodes with no incoming CALLS edges (potential dead code)."""
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (fn:CodeFunction)
                WHERE NOT ()-[:CALLS]->(fn)
                  AND NOT fn.name IN ['main', '__init__', '__main__', 'setup', 'teardown']
                  AND NOT fn.name STARTS WITH 'test_'
                RETURN fn.name AS function_name,
                       fn.file_path AS file_path,
                       fn.line_start AS line_start
                ORDER BY fn.file_path
                LIMIT 100
                """
            )
            return [dict(record) for record in result]

    def get_contributor_risk(self, file_path):
        """Assess contributor risk for a file (bus-factor analysis)."""
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (ct:Contributor)-[:AUTHORED_BY]->(f:File {path: $file_path})
                RETURN count(ct) AS contributor_count,
                       collect(ct.name) AS contributors,
                       collect(ct.commits_count) AS commit_counts
                """,
                file_path=file_path,
            )
            record = result.single()
            if not record:
                return None
            return {
                "file_path": file_path,
                "contributor_count": record["contributor_count"],
                "contributors": record["contributors"],
                "commit_counts": record["commit_counts"],
                "bus_factor_risk": "HIGH" if record["contributor_count"] <= 1 else (
                    "MEDIUM" if record["contributor_count"] <= 2 else "LOW"
                ),
            }

def build_lineage_graph(secrets, file_to_commits, neo4j_uri, neo4j_user, neo4j_pass,
                        stages=None, logs=None, artifacts=None,
                        code_analysis=None, git_context=None):
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

    # Code symbol analysis nodes
    if code_analysis:
        all_functions = []
        all_classes = []
        all_imports = []
        all_call_edges = []
        for summary in code_analysis:
            all_functions.extend(summary.functions)
            all_classes.extend(summary.classes)
            all_imports.extend(summary.imports)
            all_call_edges.extend(summary.call_edges)
        if all_functions:
            graph.create_code_function_nodes(all_functions)
        if all_classes:
            graph.create_code_class_nodes(all_classes)
        if all_imports:
            graph.create_code_import_nodes(all_imports)
        if all_call_edges:
            graph.ensure_indexes()  # must exist before MATCH lookups in call edges
            graph.create_call_edges(all_call_edges)

    # Git contributor nodes
    if git_context:
        contributors = git_context.get("contributors", [])
        if contributors:
            graph.create_contributor_nodes(contributors)

    # Populate node_count / edge_count so the orchestrator reports real numbers.
    graph._refresh_counts()

    return graph
