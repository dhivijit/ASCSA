# ASCSA-CI Installation & Usage Guide

## Installation

### Method 1: Development Installation (Recommended for development)

```bash
# Clone the repository
cd C:\Users\dhivi\Experiments\ASCSA

# Install in editable mode
pip install -e .
```

### Method 2: Production Installation

```bash
# Install from directory
pip install .
```

### Method 3: Install with optional dependencies

```bash
# Install with AST analysis support
pip install -e ".[ast]"

# Install with development tools
pip install -e ".[dev]"

# Install everything
pip install -e ".[dev,ast]"
```

## Prerequisites

### Required

- Python 3.8 or higher
- Git (for repository analysis)

### Optional (but recommended)

- **Neo4j** (for Secret Lineage Graph Analysis - SLGA)
  - Download from: https://neo4j.com/download/
  - Or use Docker: `docker run -p 7687:7687 -p 7474:7474 -e NEO4J_AUTH=neo4j/password neo4j:latest`
  - Set environment variables:
    ```bash
    export NEO4J_URI="bolt://localhost:7687"
    export NEO4J_USER="neo4j"
    export NEO4J_PASS="password"
    ```

## Usage

### Basic Usage

Scan a repository:

```bash
ascsa /path/to/repository
```

### Advanced Usage Examples

#### 1. Scan with verbose output

```bash
ascsa /path/to/repository --verbose
```

#### 2. Scan specific branch

```bash
ascsa /path/to/repository --branch main
```

#### 3. Scan only changed files (PR mode)

```bash
ascsa /path/to/repository --changed-files src/app.py src/config.py
```

#### 4. Skip specific engines

```bash
# Skip SLGA if Neo4j is not available
ascsa /path/to/repository --skip-slga

# Skip SDDA
ascsa /path/to/repository --skip-sdda

# Skip HCRS
ascsa /path/to/repository --skip-hcrs
```

#### 5. Custom configuration

```bash
ascsa /path/to/repository --config custom-config.yaml --rules custom-rules.yaml
```

#### 6. Output to JSON file

```bash
ascsa /path/to/repository --format json --output results.json
```

#### 7. Scan with CI/CD context

```bash
ascsa /path/to/repository \
  --ci-config .github/workflows/main.yml \
  --log-dir ./logs \
  --artifact-dir ./artifacts \
  --environment production
```

#### 8. Specify Neo4j connection

```bash
ascsa /path/to/repository \
  --neo4j-uri bolt://localhost:7687 \
  --neo4j-user neo4j \
  --neo4j-pass password
```

## Command-Line Options

### Required Arguments

- `repo_path` - Path to the repository to scan

### Optional Arguments

#### Scan Configuration

- `--branch`, `-b` - Git branch name (auto-detected if not provided)
- `--environment`, `-e` - Environment type: development, staging, production, ci
- `--actor`, `-a` - Actor/user triggering the scan (default: current user)

#### CI/CD Options

- `--ci-config` - Path to CI configuration file
- `--log-dir` - Path to CI logs directory for secret scanning
- `--artifact-dir` - Path to CI artifacts directory for secret scanning
- `--changed-files` - List of changed files (for PR/diff mode)

#### Engine Control

- `--skip-slga` - Skip Secret Lineage Graph Analysis
- `--skip-sdda` - Skip Secret Drift Detection Analysis
- `--skip-hcrs` - Skip Hybrid Code Risk Scoring

#### Configuration

- `--config` - Path to configuration file (default: config/thresholds.yaml)
- `--rules` - Path to custom rules file

#### Database

- `--sdda-db` - Path to SDDA SQLite database (default: sdda.db)
- `--neo4j-uri` - Neo4j URI (default: from NEO4J_URI env var)
- `--neo4j-user` - Neo4j username (default: from NEO4J_USER env var)
- `--neo4j-pass` - Neo4j password (default: from NEO4J_PASS env var)

#### Output

- `--format`, `-f` - Output format: console, json, yaml (default: console)
- `--output`, `-o` - Output file path (default: stdout)
- `--verbose`, `-v` - Enable verbose logging
- `--quiet`, `-q` - Suppress all output except errors

## Exit Codes

- `0` - Success: No issues found, all checks passed
- `1` - Warning: Low/Medium risks found
- `2` - High Risk: High risks found, should block in strict mode
- `3` - Critical Risk: Critical risks found, should always block
- `10` - Configuration Error
- `11` - Repository Error
- `12` - Engine Execution Error
- `13` - Dependency Error
- `14` - Invalid Arguments

## CI/CD Integration

### GitHub Actions

```yaml
name: ASCSA Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.10'
      
      - name: Install ASCSA-CI
        run: |
          pip install -r requirements.txt
          pip install -e .
      
      - name: Run Security Scan
        run: ascsa . --format json --output results.json
        env:
          NEO4J_URI: ${{ secrets.NEO4J_URI }}
          NEO4J_USER: ${{ secrets.NEO4J_USER }}
          NEO4J_PASS: ${{ secrets.NEO4J_PASS }}
      
      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: security-scan-results
          path: results.json
```

### GitLab CI

```yaml
security-scan:
  stage: test
  image: python:3.10
  script:
    - pip install -r requirements.txt
    - pip install .
    - ascsa . --format json --output results.json
  artifacts:
    reports:
      security: results.json
  variables:
    NEO4J_URI: $NEO4J_URI
    NEO4J_USER: $NEO4J_USER
    NEO4J_PASS: $NEO4J_PASS
```

## Troubleshooting

### "Neo4j credentials not configured"

If you see this warning and want to use SLGA:

1. Install Neo4j (see Prerequisites)
2. Set environment variables:
   ```bash
   export NEO4J_URI="bolt://localhost:7687"
   export NEO4J_USER="neo4j"
   export NEO4J_PASS="your-password"
   ```
3. Or use command-line options:
   ```bash
   ascsa /path/to/repo --neo4j-uri bolt://localhost:7687 --neo4j-user neo4j --neo4j-pass password
   ```

### "Missing dependency" errors

Install all dependencies:
```bash
pip install -r requirements.txt
```

### Module import errors

Make sure you installed the package:
```bash
pip install -e .
```

## Next Steps

- Review the [documentation](documentation.md) for detailed information about the algorithms
- Check the [test summaries](tests/hcrs/TEST_SUMMARY.md) to see examples
- Customize thresholds in [config/thresholds.yaml](config/thresholds.yaml)
- Add custom rules in [config/rules.yaml](config/rules.yaml)
