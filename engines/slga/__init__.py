# SLGA engine package

"""
Secret Lineage Graph Construction Algorithm (SLGA)
--------------------------------------------------
Usage:

from engines.slga.run import run_slga

# Set Neo4j connection via environment variables:
#   NEO4J_URI, NEO4J_USER, NEO4J_PASS

graph = run_slga('/path/to/repo')

# Query propagation for a secret:
# result = graph.query_secret_propagation(secret_value)
"""
