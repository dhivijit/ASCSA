# SLGA engine package

"""
Secret Lineage Graph Construction Algorithm (SLGA)
--------------------------------------------------
Usage:

from engines.slga.run import run_slga

# Set Neo4j connection via environment variables:
#   NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD

graph, secrets, db_path, propagation_analysis = run_slga('/path/to/repo')

# Graph analysis methods (when Neo4j is available):
# - graph.analyze_secret_propagation(secret_value)
# - graph.get_all_secrets_propagation_summary()
# - graph.find_critical_propagation_chains()
# - graph.query_secret_propagation(secret_value)

# Propagation analysis results include:
# - Risk scores and severity levels
# - Propagation scope (files, commits, stages, logs, artifacts)
# - Critical propagation chains (code -> pipeline -> logs/artifacts)
"""
