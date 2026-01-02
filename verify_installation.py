#!/usr/bin/env python3
"""
Quick verification script for ASCSA-CI installation.
Run this to verify that all components are properly installed.
"""

import sys
import importlib

def check_import(module_name):
    """Check if a module can be imported."""
    try:
        importlib.import_module(module_name)
        print(f"✓ {module_name}")
        return True
    except ImportError as e:
        print(f"✗ {module_name}: {e}")
        return False

def main():
    print("=" * 60)
    print("ASCSA-CI Installation Verification")
    print("=" * 60)
    
    print("\nChecking core modules...")
    core_modules = [
        'cli.main',
        'cli.context',
        'cli.exit_codes',
        'core.orchestrator',
        'core.emitter',
        'core.contracts',
    ]
    
    core_ok = all(check_import(m) for m in core_modules)
    
    print("\nChecking engine modules...")
    engine_modules = [
        'engines.slga.run',
        'engines.sdda.run',
        'engines.hcrs.run',
    ]
    
    engines_ok = all(check_import(m) for m in engine_modules)
    
    print("\nChecking dependencies...")
    dependencies = [
        'yaml',
        'git',
        'colorama',
        'cryptography',
        'requests',
        'neo4j',
    ]
    
    deps_ok = all(check_import(m) for m in dependencies)
    
    print("\n" + "=" * 60)
    if core_ok and engines_ok and deps_ok:
        print("✓ All checks passed! ASCSA-CI is ready to use.")
        print("\nTry running: ascsa --help")
        return 0
    else:
        print("✗ Some checks failed. Please install missing dependencies:")
        print("  pip install -r requirements.txt")
        print("  pip install -e .")
        return 1

if __name__ == '__main__':
    sys.exit(main())
