"""
HCRS Scanner — Main analysis orchestrator for Hybrid Code Risk Scoring.

Discovers files in a repository, dispatches to language-specific analyzers
(Python, JavaScript), runs OSV dependency vulnerability checks, and
aggregates results into a RepositoryRiskScore.

Tracks scan coverage metadata so reports are meaningful even when no
violations are found.
"""
import os
from typing import List, Tuple, Dict
from .models import FileRiskScore, RepositoryRiskScore
from .config_loader import load_hcrs_config, should_analyze_file
from .rule_loader import RuleLoader
from .python_analyzer import PythonSimpleAnalyzer
from .javascript_analyzer import JavaScriptAnalyzer
from .risk_engine import compute_file_risk_score, compute_repository_risk_score
from .osv_scanner import scan_dep_vulns


class HCRSScanner:
    """Main scanner for Hybrid Code Risk Scoring.

    Coordinates file discovery, language analysis, dependency scanning,
    and risk score computation for an entire repository.
    """

    def __init__(self, config_path: str = None, rules_path: str = None):
        self.config = load_hcrs_config(config_path)
        self.rule_loader = RuleLoader(rules_path)

        python_rules = self.rule_loader.get_rules_for_language('python')
        javascript_rules = self.rule_loader.get_rules_for_language('javascript')

        self.python_analyzer = PythonSimpleAnalyzer(python_rules)
        self.javascript_analyzer = JavaScriptAnalyzer(javascript_rules)

    def scan_repository(self, repo_path: str) -> RepositoryRiskScore:
        """Scan entire repository for security vulnerabilities.

        Args:
            repo_path: Path to repository root.

        Returns:
            RepositoryRiskScore with complete analysis and scan coverage.
        """
        print(f"Starting HCRS scan of repository: {repo_path}")

        files_to_scan = self._discover_files(repo_path)
        print(f"Found {len(files_to_scan)} files to analyze")

        # Track scan coverage by language
        language_counts = {}
        for _, lang in files_to_scan:
            language_counts[lang] = language_counts.get(lang, 0) + 1

        file_scores = []
        skipped_count = 0
        for i, (file_path, language) in enumerate(files_to_scan, 1):
            if i % 10 == 0:
                print(f"Progress: {i}/{len(files_to_scan)} files analyzed")

            file_score = self.scan_file(file_path, language)
            if file_score:
                file_scores.append(file_score)
            else:
                skipped_count += 1

        # Scan dependencies for vulnerabilities (OSV)
        dependency_vulns = self._scan_dependencies(repo_path)

        # Compute repository-level risk
        repo_score = compute_repository_risk_score(repo_path, file_scores)
        repo_score.dependency_vulnerabilities = dependency_vulns
        repo_score.summary['dependency_vulnerability_count'] = len(dependency_vulns)

        # Enrich summary with scan coverage metadata
        repo_score.summary['scan_coverage'] = {
            'total_files_discovered': len(files_to_scan),
            'total_files_analyzed': len(file_scores),
            'files_skipped': skipped_count,
            'files_by_language': language_counts,
            'rules_loaded': {
                'python': len(self.rule_loader.get_rules_for_language('python')),
                'javascript': len(self.rule_loader.get_rules_for_language('javascript')),
            },
            'dependency_files_checked': self._count_dep_files(repo_path),
            'dependency_vulnerabilities_found': len(dependency_vulns),
        }

        print(f"\nScan complete!")
        print(f"Total violations: {repo_score.summary['total_violations']}")
        print(f"  Critical: {repo_score.critical_count}")
        print(f"  High: {repo_score.high_count}")
        print(f"  Medium: {repo_score.medium_count}")
        print(f"  Low: {repo_score.low_count}")
        print(f"Total risk score: {repo_score.total_score:.2f}")

        return repo_score
    
    def scan_file(self, file_path: str, language: str = None) -> FileRiskScore:
        """
        Scan a single file for vulnerabilities.
        
        Args:
            file_path: Path to file
            language: Language override (auto-detected if None)
        
        Returns:
            FileRiskScore for the file
        """
        # Auto-detect language if not provided
        if language is None:
            should_scan, language = should_analyze_file(file_path, self.config)
            if not should_scan:
                return None
        
        # Read file content
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return None
        
        # Check file size limit
        max_size_kb = self.config.get('max_file_size_kb', 500)
        if len(content) > max_size_kb * 1024:
            print(f"Skipping {file_path}: exceeds size limit")
            return None
        
        # Analyze with appropriate analyzer
        violations = []
        if language == 'python':
            violations = self.python_analyzer.analyze(file_path, content)
        elif language == 'javascript':
            violations = self.javascript_analyzer.analyze(file_path, content)
        
        # Compute risk score
        file_score = compute_file_risk_score(file_path, language, violations)
        
        return file_score
    
    def _discover_files(self, repo_path: str) -> List[Tuple[str, str]]:
        """
        Discover all files in repository that should be analyzed.
        
        Returns:
            List of (file_path, language) tuples
        """
        files = []
        max_files = self.config.get('max_files', 10000)
        
        # Directories to skip
        skip_dirs = {
            '.git', '.svn', '.hg',
            'node_modules', '__pycache__', '.pytest_cache',
            'venv', 'env', '.venv', '.env',
            'build', 'dist', '.next', '.nuxt',
            'coverage', '.coverage', 'htmlcov'
        }
        
        for root, dirs, filenames in os.walk(repo_path):
            # Remove skip directories from traversal
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            
            for filename in filenames:
                file_path = os.path.join(root, filename)
                should_scan, language = should_analyze_file(file_path, self.config)
                
                if should_scan:
                    files.append((file_path, language))
                
                # Respect max files limit
                if len(files) >= max_files:
                    print(f"Warning: Reached max file limit ({max_files})")
                    return files
        
        return files
    
    def scan_diff(self, repo_path: str, changed_files: List[str]) -> RepositoryRiskScore:
        """
        Scan only specific changed files (useful for PR analysis).
        
        Args:
            repo_path: Repository root path
            changed_files: List of file paths that changed
        
        Returns:
            RepositoryRiskScore for changed files only
        """
        print(f"Scanning {len(changed_files)} changed files...")
        
        file_scores = []
        for file_path in changed_files:
            full_path = os.path.join(repo_path, file_path) if not os.path.isabs(file_path) else file_path
            
            should_scan, language = should_analyze_file(full_path, self.config)
            if should_scan and os.path.exists(full_path):
                file_score = self.scan_file(full_path, language)
                if file_score:
                    file_scores.append(file_score)
        
        repo_score = compute_repository_risk_score(repo_path, file_scores)
        
        print(f"Found {repo_score.summary['total_violations']} violations in changed files")
        
        return repo_score
    
    def _scan_dependencies(self, repo_path: str) -> List[Dict]:
        """Scan dependency files for known vulnerabilities using OSV.

        The list of files to check is read from
        ``hcrs.dependency_files`` in the config.

        Returns:
            List of vulnerability dictionaries from OSV.
        """
        all_vulns = []
        dep_files = self.config.get('dependency_files', [
            'requirements.txt', 'package.json',
            'package-lock.json', 'pyproject.toml',
        ])

        for filename in dep_files:
            file_path = os.path.join(repo_path, filename)
            if os.path.exists(file_path):
                try:
                    print(f"Scanning dependencies in {filename}...")
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()

                    vulns = scan_dep_vulns(content, filename)
                    all_vulns.extend(vulns)

                except Exception as e:
                    print(f"Warning: Could not scan {filename}: {e}")

        if all_vulns:
            print(f"Found {len(all_vulns)} dependency vulnerabilities")
        else:
            print("No dependency vulnerabilities found")

        return all_vulns

    def _count_dep_files(self, repo_path: str) -> int:
        """Count how many dependency manifest files exist in the repo."""
        dep_files = self.config.get('dependency_files', [
            'requirements.txt', 'package.json',
            'package-lock.json', 'pyproject.toml',
        ])
        return sum(1 for f in dep_files if os.path.exists(os.path.join(repo_path, f)))
