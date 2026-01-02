# CLI exit codes
"""Exit codes for ASCSA-CI application."""

SUCCESS = 0                    # No issues found, all checks passed
WARN = 1                       # Low/Medium risks found, warning level
RISK_HIGH = 2                  # High risks found, should block in strict mode
RISK_CRITICAL = 3              # Critical risks found, should always block
CONFIG_ERROR = 10              # Configuration error
REPO_ERROR = 11                # Repository access error
ENGINE_ERROR = 12              # Engine execution error
DEPENDENCY_ERROR = 13          # Missing dependencies (e.g., Neo4j)
INVALID_ARGS = 14              # Invalid command-line arguments
