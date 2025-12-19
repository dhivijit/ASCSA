# Entry point for CLI
import sys
from cli.context import build_context
from core.orchestrator import run_pipeline

def main():
    context = build_context()
    result = run_pipeline(context)

    if result["recommendation"] == "BLOCK":
        sys.exit(1)
    elif result["recommendation"] == "WARN":
        sys.exit(2)
    sys.exit(0)
