# ASCSA-CI Quick Reference Guide

## Command to Run

```bash
python -m cli.main <path-to-repository> [options]
```

## Quick Examples

### Scan current directory (HCRS only, no Neo4j needed)
```bash
python -m cli.main . --skip-slga --skip-sdda
```

### Scan with verbose output
```bash
python -m cli.main . --skip-slga --skip-sdda --verbose
```

### Export to JSON
```bash
python -m cli.main . --skip-slga --skip-sdda --format json --output scan-results.json
```

### Scan another repository
```bash
python -m cli.main /path/to/other/repo --skip-slga --skip-sdda
```

### Scan only changed files (PR mode)
```bash
python -m cli.main . --skip-slga --skip-sdda --changed-files file1.py file2.py
```

## Common Options

| Option | Description |
|--------|-------------|
| `--skip-slga` | Skip Secret Lineage Graph (use when Neo4j not available) |
| `--skip-sdda` | Skip Drift Detection (use when Neo4j not available) |
| `--skip-hcrs` | Skip Code Risk Scoring |
| `--verbose`, `-v` | Enable detailed logging |
| `--format {console,json,yaml}` | Output format |
| `--output FILE` | Write results to file |
| `--help` | Show all options |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | ✅ PASS - No critical issues |
| 1 | ⚠️ WARN - Low/Medium risks |
| 2 | 🔴 HIGH - High risks found |
| 3 | 🔴 CRITICAL - Critical risks found |
| 10+ | ❌ Configuration/execution error |

## What It Detects

- Hardcoded secrets (passwords, API keys, tokens)
- AWS/Azure/GCP credentials
- Command injection
- SQL injection
- Path traversal
- Weak cryptography
- Sensitive logging
- Dependency vulnerabilities
- And 10+ more security patterns

## Output Example

```
================================================================================
ASCSA-CI Security Scan Results
================================================================================

Run ID: b5e05581-6df5-47e2-80a7-a15fae7d2f4c
Repository: C:\Users\dhivi\Experiments\ASCSA
Branch: main

Overall Risk: BLOCK - CRITICAL

Security Violations:
  CRITICAL: 127
  HIGH: 17
  MEDIUM: 3
  LOW: 0

Top Violations:
  1. [CRITICAL] hardcoded_secret in file.py:40
     Hardcoded password detected
```

## Tips

1. **Start simple**: Use `--skip-slga --skip-sdda` initially
2. **Check exit code**: Use `echo $?` (Linux) or `echo %ERRORLEVEL%` (Windows)
3. **Export results**: Use `--format json` for CI/CD integration
4. **Verbose mode**: Use `-v` to see what's happening
5. **Help**: Always available with `--help`

## Next Steps

1. Try scanning your own projects
2. Set up Neo4j for full functionality
3. Integrate with your CI/CD pipeline
4. Customize rules in `config/rules.yaml`

## Need Help?

- See [INSTALLATION.md](INSTALLATION.md) for detailed setup
- See [README.md](README.md) for project overview
- Run `python verify_installation.py` to check installation
- Use `--help` to see all options
