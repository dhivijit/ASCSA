# ASCSA-CI
**Autonomous Secret & Code Security Agent for CI/CD**

An Intelligent Platform for Secret Drift Detection, Secure Code Enforcement, and Context-Aware Remediation in CI Pipelines

---

## Overview

**ASCSA-CI** is an autonomous CI security agent that combines graph modeling, behavior analysis, static analysis, risk correlation, and automated remediation to address modern CI/CD security challenges. It:

- 🔍 **Detects insecure code changes** using structural & semantic analysis (HCRS)
- 🗺️ **Builds a Secret Lineage Graph** to track secrets across code and CI (SLGA)
- 📊 **Detects secret drift** using behavioral analysis (SDDA)
- 🔗 **Correlates code risks** with secret behavior for high-confidence alerts
- 💡 **Generates developer-friendly** remediation suggestions

This project fills major gaps in existing DevSecOps tools by providing actionable, context-aware security for CI pipelines.

## Quick Start

### Installation

```bash
# Clone or navigate to the repository
cd ASCSA

# Install dependencies
pip install -r requirements.txt

# Install ASCSA-CI in development mode
pip install -e .

# Verify installation
python verify_installation.py
```

### Running ASCSA-CI

#### Method 1: Using the installed command (recommended)
```bash
# Scan current directory
ascsa .

# Scan another repository
ascsa /path/to/your/repository

# Scan with verbose output
ascsa . --verbose

# Get help
ascsa --help
```

#### Method 2: Running as Python module (if not installed)
```bash
# Scan current directory
python -m cli.main .

# Scan with specific options
python -m cli.main . --skip-slga --skip-sdda --verbose
```

#### Method 3: Quick scan scripts (HCRS only, no Neo4j required)
```bash
# Using bash (Git Bash on Windows, or Linux/Mac)
./scan.sh

# Using Windows batch
scan.bat

# Scan specific directory
./scan.sh /path/to/repo
```

### Common Usage Patterns

```bash
# Quick scan without Neo4j (HCRS code analysis only)
ascsa . --skip-slga --skip-sdda

# Quiet mode (minimal output)
ascsa . --skip-slga --skip-sdda --quiet

# Export results to JSON
ascsa . --skip-slga --skip-sdda --format json --output results.json

# Scan only changed files (PR mode)
ascsa . --changed-files src/app.py src/utils.py

# Verbose debugging
ascsa . --skip-slga --skip-sdda --verbose
```

## Features

### 🔐 Three Intelligent Engines

1. **SLGA** - Secret Lineage Graph Analysis
   - Maps secret propagation across files, commits, CI stages, logs, and artifacts
   - Uses Neo4j for graph modeling
   - Tracks complete secret lifecycle

2. **SDDA** - Secret Drift Detection Analysis
   - Behavioral anomaly detection for secrets
   - Statistical baseline modeling
   - Time-series drift analysis

3. **HCRS** - Hybrid Code Risk Scoring
   - AST-based static analysis
   - Multi-language support (Python, JavaScript)
   - Pattern-based vulnerability detection
   - OSV integration for dependency scanning

### 🎯 Key Capabilities

- ✅ Hardcoded secret detection
- ✅ Command injection detection
- ✅ SQL injection detection
- ✅ Unsafe API usage detection
- ✅ Weak cryptography detection
- ✅ Sensitive logging detection
- ✅ Secret usage drift detection
- ✅ Multi-signal risk correlation
- ✅ Actionable remediation suggestions

## Architecture

```
Repository → ASCSA-CI Agent → [SLGA + SDDA + HCRS] → Correlation → Remediation → Report
```

## Advanced Usage Examples

### Full Scan with All Engines (requires Neo4j)

```bash
# First, start Neo4j
docker run -p 7687:7687 -p 7474:7474 -e NEO4J_AUTH=neo4j/password neo4j:latest

# Set environment variables
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASS="password"

# Run full scan
ascsa /path/to/repo --verbose
```

### Quick Scan (No Neo4j Required)

```bash
# Skip SLGA and SDDA engines (only run HCRS code analysis)
ascsa . --skip-slga --skip-sdda

# Same with quiet output
ascsa . --skip-slga --skip-sdda --quiet
```

### PR/Diff Mode (scan only changed files)

```bash
# Scan specific files
ascsa . --skip-slga --skip-sdda --changed-files src/app.py src/config.py

# In CI, with git diff
CHANGED_FILES=$(git diff --name-only HEAD~1)
ascsa . --skip-slga --skip-sdda --changed-files $CHANGED_FILES
```

### CI/CD Integration

```bash
# GitHub Actions / GitLab CI
ascsa . \
  --skip-slga \
  --skip-sdda \
  --environment ci \
  --format json \
  --output security-report.json

# Check exit code
if [ $? -eq 3 ]; then
  echo "Critical security issues found!"
  exit 1
fi
```

### Different Output Formats

```bash
# Console output (default, colored)
ascsa . --skip-slga --skip-sdda

# JSON output
ascsa . --skip-slga --skip-sdda --format json --output results.json

# YAML output
ascsa . --skip-slga --skip-sdda --format yaml --output results.yaml
```

## Command-Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--skip-slga` | | Skip Secret Lineage Graph Analysis (use when Neo4j not available) |
| `--skip-sdda` | | Skip Secret Drift Detection Analysis (use when Neo4j not available) |
| `--skip-hcrs` | | Skip Hybrid Code Risk Scoring |
| `--verbose` | `-v` | Enable detailed logging |
| `--quiet` | `-q` | Suppress all output except errors |
| `--format` | `-f` | Output format: `console`, `json`, `yaml` |
| `--output` | `-o` | Write results to file |
| `--changed-files` | | List of changed files (for PR/diff mode) |
| `--branch` | `-b` | Git branch name (auto-detected if not provided) |
| `--environment` | `-e` | Environment: `development`, `staging`, `production`, `ci` |
| `--config` | | Path to custom configuration file |
| `--help` | `-h` | Show all options |

## Exit Codes

| Code | Meaning | Description |
|------|---------|-------------|
| `0` | ✅ **PASS** | No critical issues found |
| `1` | ⚠️ **WARN** | Low or Medium risks detected |
| `2` | 🔴 **HIGH** | High risks found, should block in strict mode |
| `3` | 🔴 **CRITICAL** | Critical risks found, should always block |
| `10` | ❌ **CONFIG_ERROR** | Configuration error |
| `11` | ❌ **REPO_ERROR** | Repository access error |
| `12` | ❌ **ENGINE_ERROR** | Engine execution error |
| `13` | ❌ **DEPENDENCY_ERROR** | Missing dependencies |
| `14` | ❌ **INVALID_ARGS** | Invalid command-line arguments |

### Using Exit Codes in CI/CD

```bash
# Bash script
ascsa . --skip-slga --skip-sdda --quiet
EXIT_CODE=$?

if [ $EXIT_CODE -eq 3 ]; then
  echo "CRITICAL: Security scan failed with critical issues"
  exit 1
elif [ $EXIT_CODE -eq 2 ]; then
  echo "HIGH: Security scan found high-risk issues"
  exit 1
elif [ $EXIT_CODE -eq 1 ]; then
  echo "WARN: Security scan found warnings"
  # Continue but notify
fi
```

## Configuration

### Environment Variables

```bash
# Neo4j (required for SLGA)
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASS="password"
```

### Config Files

- `config/thresholds.yaml` - Risk thresholds and scoring weights
- `config/rules.yaml` - Custom security rules
- `config/policies.yaml` - Enforcement policies

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run HCRS tests
pytest tests/hcrs/

# Run SDDA tests
pytest tests/sdda/

# Run SLGA tests
pytest tests/slga/

# Run with coverage
pytest --cov=. --cov-report=html
```

### Project Structure

```
ASCSA/
├── cli/                 # Command-line interface
├── core/                # Core orchestration
├── engines/             # Security engines
│   ├── hcrs/           # Hybrid Code Risk Scoring
│   ├── sdda/           # Secret Drift Detection
│   └── slga/           # Secret Lineage Graph
├── config/              # Configuration files
├── tests/               # Test suite
└── output/              # Output formatters
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Acknowledgments

This project was developed as part of research into autonomous CI/CD security and DevSecOps automation.

## Contact

For questions, issues, or suggestions, please open an issue on GitHub.

---

**ASCSA-CI** - Making CI/CD pipelines secure by design.
