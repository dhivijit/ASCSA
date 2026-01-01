# HCRS Python analyzer using tree-sitter
import re
from typing import List, Optional
from .models import SecurityViolation, CodeLocation, ViolationType, Severity, SecurityRule

try:
    from tree_sitter import Language, Parser
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    print("Warning: tree-sitter not available. Install with: pip install tree-sitter")

class PythonAnalyzer:
    """Analyzes Python code for security vulnerabilities using tree-sitter"""
    
    def __init__(self, rules: List[SecurityRule]):
        self.rules = rules
        self.parser = None
        
        if TREE_SITTER_AVAILABLE:
            try:
                # Note: Users will need to build tree-sitter languages
                # This is a placeholder - actual implementation needs language builds
                # Language.build_library('build/languages.so', ['vendor/tree-sitter-python'])
                # PY_LANGUAGE = Language('build/languages.so', 'python')
                # self.parser = Parser()
                # self.parser.set_language(PY_LANGUAGE)
                pass
            except Exception as e:
                print(f"Warning: Could not initialize tree-sitter parser: {e}")
    
    def analyze(self, file_path: str, content: str) -> List[SecurityViolation]:
        """Analyze Python file for security violations"""
        violations = []
        
        # For now, use regex-based analysis as fallback
        # Tree-sitter AST analysis can be added when languages are built
        violations.extend(self._regex_analysis(file_path, content))
        
        # If tree-sitter is available, add AST analysis
        if self.parser:
            violations.extend(self._ast_analysis(file_path, content))
        
        return violations
    
    def _regex_analysis(self, file_path: str, content: str) -> List[SecurityViolation]:
        """Regex-based security scanning"""
        violations = []
        lines = content.split('\n')
        
        for rule in self.rules:
            if rule.pattern_type != 'regex':
                continue
            
            try:
                pattern = re.compile(rule.pattern)
                
                for line_num, line in enumerate(lines, 1):
                    matches = pattern.finditer(line)
                    for match in matches:
                        location = CodeLocation(
                            file_path=file_path,
                            line_start=line_num,
                            line_end=line_num,
                            column_start=match.start(),
                            column_end=match.end(),
                            snippet=line.strip()
                        )
                        
                        violation = SecurityViolation(
                            violation_type=rule.violation_type,
                            severity=rule.severity,
                            location=location,
                            message=rule.message,
                            description=rule.description,
                            cwe_id=rule.cwe_id,
                            recommendation=rule.recommendation,
                            confidence=rule.confidence
                        )
                        violations.append(violation)
            
            except re.error as e:
                print(f"Invalid regex in rule {rule.rule_id}: {e}")
        
        return violations
    
    def _ast_analysis(self, file_path: str, content: str) -> List[SecurityViolation]:
        """AST-based security scanning using tree-sitter"""
        violations = []
        
        # Parse content into AST
        tree = self.parser.parse(bytes(content, 'utf8'))
        root_node = tree.root_node
        
        for rule in self.rules:
            if rule.pattern_type != 'ast':
                continue
            
            # Find matching nodes based on rule pattern
            matches = self._find_ast_patterns(root_node, rule.pattern, content)
            
            for node in matches:
                location = CodeLocation(
                    file_path=file_path,
                    line_start=node.start_point[0] + 1,
                    line_end=node.end_point[0] + 1,
                    column_start=node.start_point[1],
                    column_end=node.end_point[1],
                    snippet=content[node.start_byte:node.end_byte][:100]
                )
                
                violation = SecurityViolation(
                    violation_type=rule.violation_type,
                    severity=rule.severity,
                    location=location,
                    message=rule.message,
                    description=rule.description,
                    cwe_id=rule.cwe_id,
                    recommendation=rule.recommendation,
                    confidence=rule.confidence
                )
                violations.append(violation)
        
        return violations
    
    def _find_ast_patterns(self, node, pattern: str, source: str) -> List:
        """Find AST nodes matching the pattern"""
        matches = []
        
        # Pattern can be node types like: "call|os.system|subprocess.call"
        patterns = pattern.split('|')
        
        def traverse(n):
            # Check if node matches any pattern
            node_text = source[n.start_byte:n.end_byte] if n.start_byte < len(source) else ""
            
            for pat in patterns:
                if pat in node_text or n.type == pat:
                    matches.append(n)
                    break
            
            # Recursively check children
            for child in n.children:
                traverse(child)
        
        traverse(node)
        return matches


class PythonSimpleAnalyzer:
    """Simplified Python analyzer using built-in ast module"""
    
    def __init__(self, rules: List[SecurityRule]):
        self.rules = rules
    
    def analyze(self, file_path: str, content: str) -> List[SecurityViolation]:
        """Analyze Python file using regex and simple pattern matching"""
        violations = []
        lines = content.split('\n')
        
        for rule in self.rules:
            violations.extend(self._apply_rule(file_path, content, lines, rule))
        
        return violations
    
    def _apply_rule(self, file_path: str, content: str, lines: List[str], rule: SecurityRule) -> List[SecurityViolation]:
        """Apply a single rule to the content"""
        violations = []
        
        if rule.pattern_type == 'regex':
            try:
                pattern = re.compile(rule.pattern, re.MULTILINE | re.IGNORECASE)
                
                for line_num, line in enumerate(lines, 1):
                    matches = pattern.finditer(line)
                    for match in matches:
                        location = CodeLocation(
                            file_path=file_path,
                            line_start=line_num,
                            line_end=line_num,
                            column_start=match.start(),
                            column_end=match.end(),
                            snippet=line.strip()
                        )
                        
                        violation = SecurityViolation(
                            violation_type=rule.violation_type,
                            severity=rule.severity,
                            location=location,
                            message=rule.message,
                            description=rule.description,
                            cwe_id=rule.cwe_id,
                            recommendation=rule.recommendation,
                            confidence=rule.confidence
                        )
                        violations.append(violation)
            
            except re.error as e:
                print(f"Invalid regex in rule {rule.rule_id}: {e}")
        
        elif rule.pattern_type == 'ast':
            # Simple pattern matching for common dangerous calls
            patterns = rule.pattern.split('|')
            
            for line_num, line in enumerate(lines, 1):
                for pattern in patterns:
                    if pattern in line:
                        # Additional context checks
                        if self._is_likely_vulnerable(line, pattern, rule):
                            location = CodeLocation(
                                file_path=file_path,
                                line_start=line_num,
                                line_end=line_num,
                                snippet=line.strip()
                            )
                            
                            violation = SecurityViolation(
                                violation_type=rule.violation_type,
                                severity=rule.severity,
                                location=location,
                                message=rule.message,
                                description=rule.description,
                                cwe_id=rule.cwe_id,
                                recommendation=rule.recommendation,
                                confidence=rule.confidence * 0.8  # Lower confidence for simple matching
                            )
                            violations.append(violation)
                            break
        
        return violations
    
    def _is_likely_vulnerable(self, line: str, pattern: str, rule: SecurityRule) -> bool:
        """Check if the pattern match is likely a real vulnerability"""
        line = line.strip()
        
        # Skip comments
        if line.startswith('#'):
            return False
        
        # Context-specific checks
        if rule.violation_type == ViolationType.COMMAND_INJECTION:
            # Check if user input is involved
            user_input_indicators = ['input(', 'request.', 'args.', 'argv', 'get(', 'post(']
            has_user_input = any(indicator in line for indicator in user_input_indicators)
            
            # Check for string concatenation or formatting
            has_formatting = any(op in line for op in ['+', '%', '.format', 'f"', "f'"])
            
            return has_user_input or has_formatting
        
        elif rule.violation_type == ViolationType.SQL_INJECTION:
            # Check for string concatenation/formatting with execute
            if 'execute' in line:
                return any(op in line for op in ['+', '%', '.format', 'f"', "f'"])
        
        # For most other rules, presence is enough
        return True
