# SLGA - Shift Left Git Analysis

## Overview

SLGA (Shift Left Git Analysis) is a comprehensive secret detection and lineage tracking engine. It scans repositories for secrets (API keys, tokens, passwords) and tracks their propagation through:

- Source code files
- **Git commit history** (NEW!)
- CI/CD pipeline configurations  
- Build logs
- Deployment artifacts

## Key Features

### 🆕 Git Commit Content Scanning
- **Scans commit diffs**: Analyzes actual changes in each commit
- **Historical secret detection**: Finds secrets that were added/removed in commits
- **Complete git history**: Tracks secrets even if removed from current codebase
- **Configurable depth**: Control how many commits to scan

### Secret Detection
- API keys (AWS, Stripe, GitHub, etc.)
- Authentication tokens
- Passwords and credentials
- High-entropy strings
- Custom regex patterns

### Lineage Tracking
- File-to-commit relationships
- Commit-to-secret relationships (NEW!)
- Secret propagation through CI/CD
- Multi-hop propagation analysis

## Usage

### Basic Usage

```python
from engines.slga.run import run_slga

# Run SLGA with commit scanning enabled
graph, secrets, db_path, propagation = run_slga(
    repo_path="/path/to/repo",
    scan_commits=True,      # Enable git history scanning
    max_commits=100,        # Scan last 100 commits
    store_to_db=True
)

print(f"Found {len(secrets)} secrets")
```

### Git Commit Scanning

```python
from engines.slga.git_parser import get_all_commits

# Get commits with content and secret analysis
commits = get_all_commits(
    repo_path="/path/to/repo",
    max_count=50,
    fetch_content=True      # Fetch and analyze commit diffs
)

for commit in commits:
    if commit.secrets_found:
        print(f"Commit {commit.hash[:8]} contains secrets!")
        print(f"  Changed files: {commit.changed_files}")
        print(f"  Secrets: {commit.secrets_found}")
```

### Advanced Configuration

```python
graph, secrets, db_path, propagation = run_slga(
    repo_path="/path/to/repo",
    ci_config_path="/path/to/.github/workflows/ci.yml",
    log_dir="/path/to/logs",
    artifact_dir="/path/to/artifacts",
    db_path="custom_slga.db",
    scan_id="my_scan_001",
    scan_commits=True,      # Enable commit scanning
    max_commits=200,        # Scan more commits
    store_to_db=True
)
```

## Parameters

### `run_slga()`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `repo_path` | str | *required* | Path to git repository |
| `ci_config_path` | str | None | Path to CI/CD config file |
| `log_dir` | str | None | Directory containing logs |
| `artifact_dir` | str | None | Directory containing artifacts |
| `db_path` | str | "slga.db" | SQLite database path |
| `scan_id` | str | auto | Unique scan identifier |
| `store_to_db` | bool | True | Store results in database |
| **`scan_commits`** | **bool** | **True** | **Scan git commit history** |
| **`max_commits`** | **int** | **100** | **Max commits to scan** |

### `get_all_commits()`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `repo_path` | str | *required* | Path to git repository |
| `max_count` | int | None | Maximum commits to fetch |
| **`fetch_content`** | **bool** | **False** | **Fetch commit diffs and scan for secrets** |

## Output

### Secrets Object

```python
@dataclass
class Secret:
    value: str                    # The secret value
    secret_type: str             # Type/pattern that matched
    entropy: float               # Shannon entropy score
    files: List[str]             # Files containing the secret
    lines: List[int]             # Line numbers in files
    commits: List[str]           # Commit hashes (NEW!)
```

### Commit Object (Enhanced)

```python
@dataclass
class Commit:
    hash: str                    # Commit hash
    files: List[str]             # Files in commit
    message: str                 # Commit message
    author: str                  # Author name
    date: str                    # Commit timestamp
    diff: str                    # Commit diff content (NEW!)
    changed_files: List[str]     # Files changed (NEW!)
    secrets_found: List[str]     # Secrets in diff (NEW!)
```

## Examples

See:
- [`examples/slga_demo.py`](../../examples/slga_demo.py) - Basic usage
- [`examples/slga_commit_scan_demo.py`](../../examples/slga_commit_scan_demo.py) - Commit scanning demo

## How It Works

### 1. File Scanning
- Scans all code files (`.py`, `.js`, `.ts`, etc.)
- Applies regex patterns for known secret types
- Calculates entropy scores
- Records file locations and line numbers

### 2. Commit History Scanning (NEW!)
When `scan_commits=True`:

1. **Fetch commits**: Gets last N commits from repository
2. **Extract diffs**: Gets actual changes for each commit
3. **Scan added lines**: Analyzes lines starting with `+`
4. **Pattern matching**: Applies same regex patterns as file scanning
5. **Link to commits**: Associates secrets with commit hashes

This helps find:
- Secrets that were committed then removed
- Secrets in old versions of files
- Complete secret lifecycle in git history

### 3. Propagation Analysis
- Builds Neo4j graph of relationships
- Tracks secret flow through:
  - Files → Commits
  - Commits → Secrets (NEW!)
  - Secrets → CI/CD Stages
  - Secrets → Logs/Artifacts
- Calculates risk scores based on propagation

### 4. Storage
- **SQLite**: All secrets, files, commits, relationships
- **Neo4j** (optional): Graph visualization and queries

## Performance Considerations

### Commit Scanning Performance

- **Default**: Scans last 100 commits (~10-30 seconds)
- **Large repos**: Use `max_commits` to limit scope
- **Deep history**: Increase `max_commits` for thorough analysis

```python
# Fast scan (recent commits only)
run_slga(repo_path, scan_commits=True, max_commits=50)

# Thorough scan (more history)
run_slga(repo_path, scan_commits=True, max_commits=500)

# Disable commit scanning (fastest)
run_slga(repo_path, scan_commits=False)
```

## Database Schema

The SQLite database includes these relationships:

```
secrets → files (via line numbers)
files → commits (via git history)
secrets → commits (direct link for commit-based secrets) [NEW!]
secrets → stages
secrets → logs  
secrets → artifacts
```

Query example:
```python
from engines.slga.database import SLGADatabase

db = SLGADatabase("slga.db")
secrets = db.get_all_secrets()
for secret in secrets:
    print(f"Secret: {secret['value'][:30]}...")
    print(f"  Type: {secret['secret_type']}")
    if secret['commits']:
        print(f"  Found in commits: {secret['commits']}")
```

## Secret Types Detected

- **AWS Access Keys**: `AKIA[0-9A-Z]{16}`
- **Stripe Keys**: `sk_live_[0-9a-zA-Z]{24,}`
- **GitHub Tokens**: `ghp_[0-9a-zA-Z]{36,}`
- **Generic patterns**: `api_key`, `secret`, `token`, `password`, etc.
- **High entropy strings**: Shannon entropy > 3.5

## Risk Scoring

Propagation analysis assigns risk scores based on:

| Factor | Points | Severity |
|--------|--------|----------|
| File spread (>5 files) | +30 | High |
| Commit history (>10) | +20 | Medium |
| CI/CD usage | +25 | High |
| Log exposure | +20 | **Critical** |
| Artifact containment | +15 | High |

**Severity Levels**:
- 70+: CRITICAL
- 50-69: HIGH
- 30-49: MEDIUM
- <30: LOW

## Neo4j Integration

Set these environment variables for graph visualization:

```bash
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASSWORD="your_password"
```

Then query the graph:

```python
# Analyze secret propagation
analysis = graph.analyze_secret_propagation("AKIAIOSFODNN7EXAMPLE")
print(f"Risk: {analysis['severity']}")
print(f"Scope: {analysis['propagation_scope']}")

# Find critical chains
chains = graph.find_critical_propagation_chains()
```

## Integration

SLGA integrates with the main orchestrator:

```python
from core.orchestrator import Orchestrator

orch = Orchestrator(repo_path="/path/to/repo")
results = orch.run_full_scan(
    enable_slga=True,
    slga_scan_commits=True,    # Enable commit scanning
    slga_max_commits=100
)
```

## Future Enhancements

- [ ] Scan pull request diffs
- [ ] Secret rotation detection
- [ ] False positive filtering
- [ ] Remediation suggestions
- [ ] Commit author notification
- [ ] Pre-commit hook integration

## Contributing

When adding new secret patterns, update `detector.py`:

```python
SECRET_REGEXES = [
    re.compile(r'your_pattern_here'),
    # existing patterns...
]
```

## License

See LICENSE file in repository root.
