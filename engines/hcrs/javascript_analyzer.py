# HCRS JavaScript analyzer
import re
from typing import List, Tuple
from .models import SecurityViolation, CodeLocation, ViolationType, Severity, SecurityRule

try:
    from tree_sitter import Language, Parser
    _TS_AVAILABLE = True
except ImportError:
    _TS_AVAILABLE = False

# JavaScript/TypeScript AST node types that are safe (non-injectable) literals.
_JS_LITERAL_TYPES = frozenset({
    'string', 'number', 'true', 'false', 'null', 'undefined',
})


def _init_javascript_parser() -> Tuple:
    """Initialize a tree-sitter parser for JavaScript.

    Supports tree-sitter 0.20.x and 0.21+ APIs.  Returns ``(None, None)``
    on any failure so callers can fall back gracefully.
    """
    if not _TS_AVAILABLE:
        return None, None
    try:
        import tree_sitter_javascript as tsjavascript
        language = Language(tsjavascript.language())
        try:
            parser = Parser(language)       # tree-sitter >= 0.21
        except TypeError:
            parser = Parser()               # tree-sitter 0.20.x
            parser.set_language(language)
        return parser, language
    except Exception as e:
        print(f"Warning: Could not initialize tree-sitter JavaScript parser: {e}")
        return None, None

class JavaScriptAnalyzer:
    """Analyzes JavaScript/TypeScript code for security vulnerabilities"""
    
    def __init__(self, rules: List[SecurityRule]):
        self.rules = rules
    
    def analyze(self, file_path: str, content: str) -> List[SecurityViolation]:
        """Analyze JavaScript file for security violations"""
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
                pattern = re.compile(rule.pattern, re.MULTILINE)
                
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
            # Pattern matching for common dangerous constructs
            patterns = rule.pattern.split('|')
            
            for line_num, line in enumerate(lines, 1):
                for pattern in patterns:
                    if pattern in line:
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
                                confidence=rule.confidence * 0.8
                            )
                            violations.append(violation)
                            break
        
        return violations
    
    def _is_likely_vulnerable(self, line: str, pattern: str, rule: SecurityRule) -> bool:
        """Check if the pattern match is likely a real vulnerability"""
        line = line.strip()
        
        # Skip comments
        if line.startswith('//') or line.startswith('/*') or line.startswith('*'):
            return False
        
        # Context-specific checks
        if rule.violation_type == ViolationType.COMMAND_INJECTION:
            # Check for user input or variables
            user_input_indicators = ['req.', 'request.', 'params.', 'query.', 'body.', 'input', 'process.argv']
            has_user_input = any(indicator in line for indicator in user_input_indicators)
            
            # Check for string concatenation
            has_concat = '+' in line or '${' in line
            
            return has_user_input or has_concat
        
        elif rule.violation_type == ViolationType.XSS_VULNERABILITY:
            # innerHTML/outerHTML with variables or concatenation
            if 'innerHTML' in line or 'outerHTML' in line or 'document.write' in line:
                return '+' in line or '${' in line or '=' in line
        
        elif rule.violation_type == ViolationType.EVAL_USAGE:
            # eval is almost always dangerous
            return 'eval(' in line or 'Function(' in line
        
        # For most other rules, presence is enough
        return True


class JavaScriptTreeSitterAnalyzer:
    """Analyzes JavaScript/TypeScript using tree-sitter for semantic accuracy.

    Regex rules always run.  AST-type rules use the tree-sitter parse tree
    when available, so matching is restricted to actual ``call_expression``
    nodes (comments and string literals are ignored) and injection rules are
    only flagged when arguments are non-literal expressions.  Falls back to
    substring matching transparently when tree-sitter is unavailable.
    """

    def __init__(self, rules: List[SecurityRule]):
        self.rules = rules
        self.parser, self.language = _init_javascript_parser()
        status = "enabled" if self.parser else "unavailable — AST rules will use substring fallback"
        print(f"[JavaScriptTreeSitterAnalyzer] tree-sitter: {status}")

    def analyze(self, file_path: str, content: str) -> List[SecurityViolation]:
        """Analyze JavaScript/TypeScript file for security violations."""
        violations = []
        violations.extend(self._regex_analysis(file_path, content))
        if self.parser:
            violations.extend(self._ast_analysis(file_path, content))
        else:
            violations.extend(self._ast_fallback_analysis(file_path, content))
        return violations

    # ------------------------------------------------------------------
    # Regex rules
    # ------------------------------------------------------------------

    def _regex_analysis(self, file_path: str, content: str) -> List[SecurityViolation]:
        """Apply all regex-type rules line-by-line."""
        violations = []
        lines = content.split('\n')
        for rule in self.rules:
            if rule.pattern_type != 'regex':
                continue
            try:
                pattern = re.compile(rule.pattern, re.MULTILINE)
                for line_num, line in enumerate(lines, 1):
                    for match in pattern.finditer(line):
                        location = CodeLocation(
                            file_path=file_path,
                            line_start=line_num,
                            line_end=line_num,
                            column_start=match.start(),
                            column_end=match.end(),
                            snippet=line.strip(),
                        )
                        violations.append(SecurityViolation(
                            violation_type=rule.violation_type,
                            severity=rule.severity,
                            location=location,
                            message=rule.message,
                            description=rule.description,
                            cwe_id=rule.cwe_id,
                            recommendation=rule.recommendation,
                            confidence=rule.confidence,
                        ))
            except re.error as e:
                print(f"Invalid regex in rule {rule.rule_id}: {e}")
        return violations

    # ------------------------------------------------------------------
    # Tree-sitter AST rules
    # ------------------------------------------------------------------

    def _ast_analysis(self, file_path: str, content: str) -> List[SecurityViolation]:
        """Apply AST-type rules using the tree-sitter parse tree."""
        violations = []
        try:
            tree = self.parser.parse(bytes(content, 'utf-8'))
        except Exception as e:
            print(f"tree-sitter JS parse error for {file_path}: {e}")
            return self._ast_fallback_analysis(file_path, content)

        root_node = tree.root_node
        for rule in self.rules:
            if rule.pattern_type != 'ast':
                continue
            nodes = self._find_call_nodes(root_node, rule.pattern, content)
            for node in nodes:
                if not self._is_node_dangerous(node, rule, content):
                    continue
                location = CodeLocation(
                    file_path=file_path,
                    line_start=node.start_point[0] + 1,
                    line_end=node.end_point[0] + 1,
                    column_start=node.start_point[1],
                    column_end=node.end_point[1],
                    snippet=content[node.start_byte:node.end_byte][:100],
                )
                violations.append(SecurityViolation(
                    violation_type=rule.violation_type,
                    severity=rule.severity,
                    location=location,
                    message=rule.message,
                    description=rule.description,
                    cwe_id=rule.cwe_id,
                    recommendation=rule.recommendation,
                    confidence=rule.confidence,
                ))
        return violations

    def _find_call_nodes(self, root_node, pattern: str, source: str) -> List:
        """Find JS ``call_expression`` (and ``new_expression``) nodes whose
        callee matches any pipe-separated pattern.

        Trailing ``(`` is stripped from sub-patterns before comparison so that
        patterns like ``eval(`` correctly match the callee ``eval``.

        Matching is performed against the callee text only, so comments and
        string literals that happen to contain the same keyword are ignored.
        """
        matches = []
        patterns = pattern.split('|')
        src_bytes = source.encode('utf-8')

        def get_callee_text(node) -> str:
            if node.type == 'new_expression':
                # `new Foo(...)` — skip the 'new' keyword, take the constructor name
                for child in node.children:
                    if child.type not in ('new', 'arguments', '(', ')', 'comment'):
                        return src_bytes[child.start_byte:child.end_byte].decode('utf-8', errors='ignore')
            elif node.child_count > 0:
                func_node = node.children[0]
                return src_bytes[func_node.start_byte:func_node.end_byte].decode('utf-8', errors='ignore')
            return ''

        def traverse(node):
            if node.type in ('call_expression', 'new_expression'):
                callee = get_callee_text(node)
                for pat in patterns:
                    # Strip trailing '(' that some rule patterns include (e.g. "eval(")
                    clean_pat = pat.rstrip('(')
                    if clean_pat and clean_pat in callee:
                        matches.append(node)
                        break
            for child in node.children:
                traverse(child)

        traverse(root_node)
        return matches

    def _is_node_dangerous(self, call_node, rule: SecurityRule, source: str) -> bool:
        """Return True when the call node represents an actual risk.

        Injection rules are only flagged when at least one argument is a
        non-literal expression.  Eval usage is always dangerous.
        """
        if rule.violation_type in (ViolationType.COMMAND_INJECTION, ViolationType.SQL_INJECTION):
            return self._has_non_literal_arg(call_node, source)
        if rule.violation_type == ViolationType.EVAL_USAGE:
            return True
        return True

    def _has_non_literal_arg(self, call_node, source: str) -> bool:
        """Return True when the call has at least one non-literal argument.

        Template literals with ``${...}`` substitutions are treated as
        non-literal because they can embed user-controlled expressions.
        """
        src_bytes = source.encode('utf-8')
        for child in call_node.children:
            if child.type == 'arguments':
                for arg in child.children:
                    if arg.type in ('(', ')', ','):
                        continue
                    if arg.type == 'template_string':
                        text = src_bytes[arg.start_byte:arg.end_byte].decode('utf-8', errors='ignore')
                        if '${' in text:
                            return True
                        continue
                    if arg.type not in _JS_LITERAL_TYPES:
                        return True
        return False

    # ------------------------------------------------------------------
    # Substring fallback (used when tree-sitter is unavailable)
    # ------------------------------------------------------------------

    def _ast_fallback_analysis(self, file_path: str, content: str) -> List[SecurityViolation]:
        """Substring-based fallback for AST rules when tree-sitter is absent."""
        violations = []
        lines = content.split('\n')
        for rule in self.rules:
            if rule.pattern_type != 'ast':
                continue
            patterns = rule.pattern.split('|')
            for line_num, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                    continue
                for pat in patterns:
                    if pat in line:
                        location = CodeLocation(
                            file_path=file_path,
                            line_start=line_num,
                            line_end=line_num,
                            snippet=stripped,
                        )
                        violations.append(SecurityViolation(
                            violation_type=rule.violation_type,
                            severity=rule.severity,
                            location=location,
                            message=rule.message,
                            description=rule.description,
                            cwe_id=rule.cwe_id,
                            recommendation=rule.recommendation,
                            confidence=rule.confidence * 0.8,
                        ))
                        break
        return violations
