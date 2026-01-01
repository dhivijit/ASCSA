# HCRS - Hybrid Code Risk Scoring Engine

## Overview

The Hybrid Code Risk Scoring (HCRS) engine is a sophisticated static analysis tool that detects security vulnerabilities in Python and JavaScript code. It uses a combination of:

- **Regex-based pattern matching** for quick detection of common issues
- **AST-based analysis** (optional tree-sitter support) for deeper code understanding
- **Configurable rules** that can be customized per project
- **Weighted risk scoring** to prioritize critical issues

## Features

### Supported Languages
- **Python** (.py files)
- **JavaScript/TypeScript** (.js, .jsx, .ts, .tsx, .mjs files)

### Detected Vulnerabilities

#### Critical Severity
- Hardcoded secrets (API keys, passwords, AWS keys, tokens)
- Command injection vulnerabilities
- Unsafe deserialization (pickle, yaml.load)
- Eval/exec usage
- SQL injection via string formatting

#### High Severity
- SQL injection patterns
- Path traversal vulnerabilities
- Sensitive data exposure in logs
- XSS vulnerabilities (JavaScript)
- Unsafe API usage

#### Medium Severity
- Weak cryptographic algorithms (MD5, SHA1)
- Insecure random number generation
- CORS misconfiguration

### Customizable Rules

All detection rules are defined in `config/rules.yaml` and can be:
- Enabled/disabled per rule
- Customized with different severity levels
- Extended with new patterns
- Weighted differently for risk scoring

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Optional: Install tree-sitter for advanced AST analysis
pip install tree-sitter tree-sitter-python tree-sitter-javascript
```

## Usage

### Command Line Interface

```bash
# Scan entire repository
python -m engines.hcrs.cli scan /path/to/repo

# Scan with output to file
python -m engines.hcrs.cli scan /path/to/repo --output report.json --format json

# Scan specific files only
python -m engines.hcrs.cli scan /path/to/repo --files app.py utils.js

# Use custom rules
python -m engines.hcrs.cli scan /path/to/repo --rules custom_rules.yaml
```

### Python API

```python
from engines.hcrs import HCRSScanner, HCRSReporter

# Initialize scanner
scanner = HCRSScanner()

# Scan repository
repo_score = scanner.scan_repository('/path/to/repo')

# Generate reports
text_report = HCRSReporter.generate_text_report(repo_score)
json_report = HCRSReporter.generate_json_report(repo_score)

# Save to file
HCRSReporter.save_report(repo_score, 'report.json', format='json')

# Access results programmatically
print(f"Total violations: {repo_score.summary['total_violations']}")
print(f"Critical issues: {repo_score.critical_count}")
print(f"Risk score: {repo_score.total_score}")
```

### Scan Specific Files (PR Mode)

```python
# Scan only changed files in a PR
changed_files = ['src/app.py', 'src/utils.js']
repo_score = scanner.scan_diff('/path/to/repo', changed_files)
```

## Demo

Run the included demo to see HCRS in action:

```bash
python examples/hcrs_demo.py
```

This will:
1. Create a temporary repository with intentionally vulnerable code
2. Scan it with HCRS
3. Display a detailed report
4. Generate JSON output

## Configuration

### Thresholds Configuration (`config/thresholds.yaml`)

```yaml
hcrs:
  # Risk weights for violation types
  risk_weights:
    hardcoded_secret: 100
    command_injection: 90
    sql_injection: 85
    # ... more weights
  
  # Severity thresholds (per file)
  severity_thresholds:
    critical: 200  # >= 200 points = CRITICAL
    high: 100
    medium: 50
    low: 10
  
  # Analysis limits
  max_file_size_kb: 500
  max_files: 10000
```

### Rules Configuration (`config/rules.yaml`)

```yaml
python_rules:
  - rule_id: PY-SEC-001
    name: Hardcoded Password
    violation_type: hardcoded_secret
    severity: CRITICAL
    pattern_type: regex
    pattern: '(?i)(password|passwd)\\s*=\\s*["\'][^"\']{8,}["\']'
    message: "Hardcoded password detected"
    cwe_id: "CWE-798"
    recommendation: "Use environment variables"
    weight: 100
    enabled: true
    confidence: 0.9
```

## Report Output

### Text Report
```
================================================================================
HCRS - Hybrid Code Risk Scoring Report
================================================================================
Repository: /path/to/repo
Scan Time: 2026-01-01 12:00:00
Total Risk Score: 450.00

SUMMARY
--------------------------------------------------------------------------------
Files Analyzed: 15
Total Violations: 23

Severity Breakdown:
  🚨 Critical: 5
  ⚠️  High:     8
  📋 Medium:   7
  ℹ️  Low:      3

RECOMMENDATION
--------------------------------------------------------------------------------
🚨 CRITICAL: 5 critical security issue(s) detected...
```

### JSON Report
```json
{
  "repo_path": "/path/to/repo",
  "timestamp": "2026-01-01T12:00:00",
  "total_score": 450.0,
  "summary": {
    "total_violations": 23,
    "severity_counts": {
      "CRITICAL": 5,
      "HIGH": 8
    }
  },
  "files": [...]
}
```

## Architecture

```
engines/hcrs/
├── __init__.py           # Package exports
├── models.py             # Data models
├── scanner.py            # Main scanning orchestrator
├── rule_loader.py        # Load rules from YAML
├── config_loader.py      # Load configuration
├── python_analyzer.py    # Python code analyzer
├── javascript_analyzer.py # JavaScript analyzer
├── risk_engine.py        # Risk scoring logic
├── reporter.py           # Report generation
├── osv_scanner.py        # Dependency vulnerability scanning
├── cli.py                # Command-line interface
└── run.py                # Main entry point
```

## Integration with ASCSA-CI

HCRS integrates with other ASCSA engines:

```python
from engines.hcrs import run_hcrs
from engines.slga import run_slga
from engines.sdda import run_sdda

# Run HCRS code analysis
code_risks = run_hcrs(repo_path)

# Run secret lineage analysis
lineage = run_slga(repo_path)

# Run drift detection
drift_report = run_sdda(pipeline_run, secret_usages)

# Correlate results (CSCE)
# High-risk code + secret drift = Critical alert
```

## Customization

### Adding New Rules

1. Edit `config/rules.yaml`
2. Add rule under `python_rules` or `javascript_rules`:

```yaml
- rule_id: PY-SEC-999
  name: Custom Security Check
  violation_type: unsafe_api
  severity: HIGH
  pattern_type: regex
  pattern: 'dangerous_function\\('
  message: "Usage of dangerous_function detected"
  recommendation: "Use safe_alternative instead"
  weight: 75
  enabled: true
```

### Adjusting Risk Weights

Edit `config/thresholds.yaml`:

```yaml
hcrs:
  risk_weights:
    hardcoded_secret: 150  # Increase importance
    weak_crypto: 30        # Decrease importance
```

## Exit Codes

- `0`: No critical or high-severity issues
- `1`: High-severity issues detected
- `2`: Critical issues detected

Useful for CI/CD pipelines:

```bash
python -m engines.hcrs.cli scan . || exit $?
```

## Performance

- Typical scan speed: ~100-500 files/second
- Memory usage: ~50-200MB for medium repositories
- Configurable limits prevent resource exhaustion

## Limitations

- Currently uses regex + simple pattern matching (tree-sitter support is optional)
- Does not perform data flow analysis
- May have false positives (check confidence scores)
- Cannot detect runtime-only vulnerabilities

## Future Enhancements

- [ ] Full tree-sitter AST integration
- [ ] Data flow analysis
- [ ] Machine learning-based anomaly detection
- [ ] Support for more languages (Go, Java, etc.)
- [ ] IDE integration (VS Code extension)
- [ ] Auto-fix suggestions with patches

## Contributing

To add support for a new language:

1. Create `{language}_analyzer.py` in `engines/hcrs/`
2. Add rules to `config/rules.yaml`
3. Update `config_loader.py` with file extensions
4. Register analyzer in `scanner.py`

## License

Part of ASCSA-CI project.

## See Also

- [SLGA](../slga/README.md) - Secret Lineage Graph Algorithm
- [SDDA](../sdda/README.md) - Secret Drift Detection Algorithm
- [Project Documentation](../../documentation.md)
