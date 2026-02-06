# CSCE - Code-Secret Correlation Engine

## Overview

The **Code-Secret Correlation Engine (CSCE)** is the intelligence layer of ASCSA-CI that correlates findings from three different security analysis engines to identify high-confidence security risks.

### Why CSCE?

Individual security tools often generate false positives or miss context. CSCE combines multiple signals to:

- **Reduce false positives** - Cross-validation between engines
- **Increase confidence** - Multiple detection methods confirm findings
- **Identify critical risks** - Secret drift + risky code = urgent alert
- **Provide context** - Understand relationships between issues

## How It Works

CSCE performs **multi-signal fusion** by correlating:

1. **HCRS** - Code vulnerabilities and security violations
2. **SLGA** - Secret locations and lineage tracking
3. **SDDA** - Behavioral drift in secret usage

### Correlation Types

#### 1. **Spatial Correlation**
Finds secrets and code violations in the same file.

**Example:**
```
File: src/api/auth.py
- SLGA detected: DB_PASSWORD secret
- HCRS detected: Sensitive logging violation
→ CSCE: SECRET + LOGGING = HIGH severity correlation
```

#### 2. **Secret Match Correlation**
Both HCRS and SLGA independently detect the same hardcoded secret.

**Example:**
```
File: config/settings.py:42
- HCRS: Hardcoded secret detected (pattern match)
- SLGA: API key detected (entropy analysis)
→ CSCE: CRITICAL - confirmed by multiple methods
```

#### 3. **Behavioral Correlation**
Secret drift (SDDA) occurs in files with code violations (HCRS).

**Example:**
```
Secret: AWS_ACCESS_KEY
- SDDA: First time used in production environment
- HCRS: Command injection vulnerability in same file
- SLGA: Secret found in that file
→ CSCE: CRITICAL - drift + vulnerability = immediate risk
```

#### 4. **Propagation Correlation**
Secret propagated through risky code paths (requires Neo4j).

**Example:**
```
Secret: DB_PASSWORD
- SLGA: Propagated through 5 stages
- HCRS: SQL injection in propagation path
→ CSCE: HIGH - secret exposed via vulnerable code
```

## Installation

CSCE is part of ASCSA-CI. No separate installation needed.

```bash
pip install -r requirements.txt
```

## Usage

### Python API

```python
from engines.hcrs import HCRSScanner
from engines.slga import detect_secrets
from engines.sdda import run_sdda
from engines.csce import run_csce

# Step 1: Run individual engines
scanner = HCRSScanner()
repo_score = scanner.scan_repository('/path/to/repo')
secrets = detect_secrets('/path/to/repo')

# Step 2: Run correlation
violations = repo_score.get_all_violations()
report = run_csce(
    hcrs_violations=violations,
    slga_secrets=secrets
)

# Step 3: Check results
print(f"Total correlations: {report.total_correlations}")
print(f"Critical: {report.critical_count}")

for corr in report.get_critical_alerts():
    print(f"🚨 {corr.description}")
    print(f"   {corr.recommendation}")
```

### With SDDA Integration

```python
from engines.sdda import run_sdda, PipelineRun, SecretUsage
from datetime import datetime

# Run SDDA
run = PipelineRun(
    run_id="current",
    timestamp=datetime.now(),
    branch="main",
    environment="production",
    actor="github-actions",
    secrets_used=["DB_PASSWORD"],
    stages=["build", "test"]
)

usage = SecretUsage(
    secret_id="DB_PASSWORD",
    run_id="current",
    timestamp=datetime.now(),
    stages={"build", "test"},
    access_count=2
)

drift_report = run_sdda(run, [usage])

# Correlate with HCRS and SLGA
report = run_csce(
    hcrs_violations=violations,
    sdda_drifts=drift_report.drifted_secrets,
    slga_secrets=secrets
)
```

### With Neo4j Graph

```python
from engines.slga import build_lineage_graph

# Build Neo4j graph
graph = build_lineage_graph(
    secrets, 
    file_to_commits, 
    neo4j_uri, 
    neo4j_user, 
    neo4j_pass
)

# Run CSCE with graph
report = run_csce(
    hcrs_violations=violations,
    slga_secrets=secrets,
    neo4j_graph=graph
)
```

## Report Output

### Text Report

```
================================================================================
CSCE - Code-Secret Correlation Report
================================================================================
Generated: 2026-01-19 14:30:00

SUMMARY
--------------------------------------------------------------------------------
Total Correlations: 8
High Confidence: 6 (87.5% avg)

Severity Breakdown:
  🚨 Critical: 2
  ⚠️  High:     3
  📋 Medium:   2
  ℹ️  Low:      1

TOP PRIORITIES
--------------------------------------------------------------------------------
1. 🚨 [CRITICAL] Hardcoded secret confirmed by multiple detection methods
   Type: SECRET_MATCH
   Confidence: 95.0%
   Recommendation: 🚨 IMMEDIATE ACTION: Rotate this secret and remove from code

2. ⚠️ [HIGH] Secret drift detected with 1 code violation(s)
   Type: BEHAVIORAL
   Confidence: 85.0%
   Recommendation: ⚠️ URGENT: Review secret usage AND code violations
```

### JSON Report

```json
{
  "timestamp": "2026-01-19T14:30:00",
  "summary": {
    "total_correlations": 8,
    "critical_count": 2,
    "high_count": 3,
    "avg_confidence": 0.87
  },
  "correlations": [
    {
      "id": "SECRET_MATCH_0",
      "type": "secret_match",
      "severity": "CRITICAL",
      "confidence": 0.95,
      "description": "Hardcoded secret confirmed by multiple methods",
      "recommendation": "Rotate and remove",
      "evidence": {
        "file": "src/config.py",
        "hcrs_line": 42,
        "slga_lines": [42],
        "entropy": 4.2
      }
    }
  ]
}
```

## Integration with CI/CD

### GitHub Actions

```yaml
- name: Run ASCSA-CI with Correlation
  run: |
    python -c "
    from engines.hcrs import HCRSScanner
    from engines.slga import detect_secrets
    from engines.csce import run_csce
    
    scanner = HCRSScanner()
    repo_score = scanner.scan_repository('.')
    secrets = detect_secrets('.')
    
    violations = repo_score.get_all_violations()
    report = run_csce(violations, slga_secrets=secrets)
    
    if report.critical_count > 0:
        exit(1)  # Fail build on critical correlations
    "
```

## API Reference

### `run_csce()`

```python
def run_csce(
    hcrs_violations: List[SecurityViolation],
    sdda_drifts: Optional[List[DriftDetection]] = None,
    slga_secrets: Optional[List[Secret]] = None,
    neo4j_graph = None
) -> CorrelationReport
```

**Parameters:**
- `hcrs_violations`: List of code violations from HCRS (required)
- `sdda_drifts`: List of secret drift detections from SDDA (optional)
- `slga_secrets`: List of detected secrets from SLGA (optional)
- `neo4j_graph`: Neo4j graph instance for propagation analysis (optional)

**Returns:** `CorrelationReport` with all correlations

### `CorrelationReport`

**Properties:**
- `total_correlations` - Total number of correlations found
- `critical_count` - Number of critical severity correlations
- `high_count` - Number of high severity correlations
- `avg_confidence` - Average confidence score
- `correlations` - List of all correlations

**Methods:**
- `get_by_severity(severity)` - Filter by severity
- `get_high_confidence()` - Get high-confidence correlations only
- `get_critical_alerts()` - Get critical correlations only
- `to_dict()` - Convert to dictionary for JSON

### `Correlation`

**Properties:**
- `correlation_id` - Unique identifier
- `correlation_type` - Type of correlation
- `severity` - Severity level
- `confidence` - Confidence score (0.0-1.0)
- `description` - Human-readable description
- `recommendation` - Actionable recommendation
- `evidence` - Supporting evidence dictionary

## Confidence Scoring

CSCE assigns confidence scores based on correlation type:

| Correlation Type | Confidence | Reason |
|------------------|------------|--------|
| SECRET_MATCH | 95% | Both engines detected same secret |
| PROPAGATION | 90% | Graph confirms propagation |
| BEHAVIORAL | 85% | Drift + code risk correlation |
| SPATIAL (sensitive) | 80% | Secret + sensitive operation |
| SPATIAL (normal) | 60% | Secret + regular code |

## Severity Calculation

CSCE amplifies severity when multiple signals combine:

```
HCRS: HIGH + SLGA: SECRET → CRITICAL
SDDA: PRODUCTION DRIFT + HCRS: CRITICAL → CRITICAL
HCRS: MEDIUM + SLGA: SECRET → HIGH
```

## Examples

### Example 1: Critical Secret Detection

```python
# Both engines detect hardcoded password
report = run_csce(violations, slga_secrets=secrets)

for corr in report.get_critical_alerts():
    # Correlation ID: SECRET_MATCH_0
    # Severity: CRITICAL
    # Confidence: 95%
    # Description: Hardcoded secret confirmed by multiple methods
```

### Example 2: Drift with Code Risk

```python
# Secret drifted to production + logging violation
report = run_csce(violations, sdda_drifts, secrets)

# Correlation Type: BEHAVIORAL
# Severity: CRITICAL (production + critical code)
# Recommendation: Rotate secret AND fix logging
```

### Example 3: No Correlations

```python
# No significant correlations
report = run_csce(violations, slga_secrets=[])

# total_correlations: 0
# This could mean:
# - No secrets found by SLGA
# - Secrets not in files with violations
# - Good separation of concerns
```

## Performance

- **Spatial correlation:** O(n × m) where n=violations, m=secrets
- **Secret match:** O(n × m) filtered subset
- **Behavioral:** O(d × m × n) where d=drifts
- **Propagation:** O(m) graph queries

Typical performance:
- 100 violations × 50 secrets: <1 second
- 1000 violations × 200 secrets: ~2-3 seconds

## Troubleshooting

### No correlations found

**Possible reasons:**
1. No secrets detected by SLGA
2. HCRS violations in different files than secrets
3. No drift detected by SDDA

**Solution:** Run engines individually to verify outputs

### Low confidence scores

**Possible reasons:**
1. Only spatial correlation (normal code)
2. No cross-validation between engines

**Solution:** Enable SDDA for behavioral correlation

### Too many correlations

**Possible reasons:**
1. Many secrets in codebase
2. Widespread code violations

**Solution:** Focus on high-confidence or critical severity

## Future Enhancements

- [ ] Temporal correlation (same time window)
- [ ] Machine learning confidence adjustment
- [ ] Historical correlation tracking
- [ ] Auto-prioritization based on impact
- [ ] Integration with RRE for auto-remediation

## Contributing

See main project CONTRIBUTING.md

## License

Part of ASCSA-CI project. See LICENSE.
