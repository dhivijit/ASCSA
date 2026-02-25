# HCRS Python analyzer using tree-sitter
import re
from typing import List, Tuple
from .models import SecurityViolation, CodeLocation, ViolationType, Severity, SecurityRule

try:
    from tree_sitter import Language, Parser
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    print("Warning: tree-sitter not available. Install with: pip install tree-sitter")

# Python AST node types that are safe (non-injectable) literals.
_PYTHON_LITERAL_TYPES = frozenset({
    'string', 'concatenated_string', 'integer', 'float', 'true', 'false', 'none',
})


def _init_python_parser() -> Tuple:
    """Initialize a tree-sitter parser for Python.

    Handles both tree-sitter 0.20.x (``Parser().set_language()``) and
    the 0.21+ constructor ``Parser(language)``.

    Returns:
        ``(parser, language)`` on success, ``(None, None)`` on failure so
        callers can fall back to regex/substring analysis gracefully.
    """
    if not TREE_SITTER_AVAILABLE:
        return None, None
    try:
        import tree_sitter_python as tspython
        language = Language(tspython.language())
        try:
            parser = Parser(language)       # tree-sitter >= 0.21
        except TypeError:
            parser = Parser()               # tree-sitter 0.20.x
            parser.set_language(language)
        return parser, language
    except Exception as e:
        print(f"Warning: Could not initialize tree-sitter Python parser: {e}")
        return None, None


class PythonAnalyzer:
    """Analyzes Python code for security vulnerabilities using tree-sitter.

    Regex-type rules always run regardless of tree-sitter availability.
    When the parser is successfully initialised, AST-type rules are resolved
    against the real syntax tree, which:
      - restricts matching to actual ``call`` nodes (ignores comments/strings)
      - checks whether arguments are non-literal expressions (injection risk)
        rather than simple string literals (safe), replacing the previous
        line-level heuristic of looking for ``+`` anywhere on the same line.

    When tree-sitter is unavailable the AST rules fall back to the same
    substring-matching logic used by ``PythonSimpleAnalyzer``, so nothing
    is silently skipped.
    """

    def __init__(self, rules: List[SecurityRule]):
        self.rules = rules
        self.parser, self.language = _init_python_parser()
        status = "enabled" if self.parser else "unavailable — AST rules will use substring fallback"
        print(f"[PythonAnalyzer] tree-sitter: {status}")

    def analyze(self, file_path: str, content: str) -> List[SecurityViolation]:
        """Analyze Python file for security violations."""
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
                pattern = re.compile(rule.pattern, re.MULTILINE | re.IGNORECASE)
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
        """Apply AST-type rules using the real tree-sitter parse tree."""
        violations = []
        try:
            tree = self.parser.parse(bytes(content, 'utf-8'))
        except Exception as e:
            print(f"tree-sitter parse error for {file_path}: {e}")
            return self._ast_fallback_analysis(file_path, content)

        root_node = tree.root_node
        for rule in self.rules:
            if rule.pattern_type != 'ast':
                continue
            nodes = self._find_ast_patterns(root_node, rule.pattern, content)
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

    def _find_ast_patterns(self, root_node, pattern: str, source: str) -> List:
        """Find ``call`` nodes whose callee (or argument list) matches any
        pipe-separated pattern.

        Two matching modes are applied per sub-pattern:
        - **Callee match**: if the sub-pattern does not contain ``=``, it is
          compared against the callee (function expression) text.  Only actual
          call sites are inspected — comments and string literals that happen
          to contain the keyword are ignored.
        - **Argument match**: if the sub-pattern contains ``=`` (e.g.
          ``shell=True``), the full call-node text is searched instead, so
          keyword arguments are detected correctly.
        """
        matches = []
        patterns = pattern.split('|')
        src_bytes = source.encode('utf-8')

        def get_callee_text(call_node) -> str:
            # tree-sitter Python: call → [function_expr, argument_list]
            # function_expr is identifier  (e.g. eval)  or
            #                   attribute  (e.g. os.system)
            for child in call_node.children:
                if child.type in ('identifier', 'attribute'):
                    return src_bytes[child.start_byte:child.end_byte].decode('utf-8', errors='ignore')
            # Fallback: first non-punctuation child
            for child in call_node.children:
                if child.type not in ('argument_list', '(', ')', ','):
                    return src_bytes[child.start_byte:child.end_byte].decode('utf-8', errors='ignore')
            return ''

        def traverse(node):
            if node.type == 'call':
                callee = get_callee_text(node)
                call_text = src_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='ignore')
                for pat in patterns:
                    if '=' in pat:
                        # Keyword argument pattern (e.g. shell=True) — search full call text
                        if pat in call_text:
                            matches.append(node)
                            break
                    else:
                        # Function name pattern — restrict to callee only
                        if pat in callee:
                            matches.append(node)
                            break
            for child in node.children:
                traverse(child)

        traverse(root_node)
        return matches

    def _is_node_dangerous(self, call_node, rule: SecurityRule, source: str) -> bool:
        """Return True when the matched call node represents an actual risk.

        Injection rules (command / SQL) are only flagged when at least one
        argument is a non-literal expression such as a variable, f-string, or
        binary operation.  All other rule types (eval, deserialization, weak
        crypto, etc.) are flagged purely on presence.
        """
        if rule.violation_type in (ViolationType.COMMAND_INJECTION, ViolationType.SQL_INJECTION):
            return self._has_non_literal_arg(call_node, source)
        return True

    def _has_non_literal_arg(self, call_node, source: str) -> bool:
        """Return True when the call has at least one non-string-literal argument.

        Keyword arguments such as ``shell=True`` are excluded from the literal
        check — they are not injection vectors themselves.

        Special case: f-strings (``f"...{var}..."``) have node type ``string``
        in tree-sitter Python but contain ``interpolation`` child nodes.  They
        are treated as non-literal because they embed user-controlled expressions.
        """
        for child in call_node.children:
            if child.type == 'argument_list':
                for arg in child.children:
                    if arg.type in ('(', ')', ','):
                        continue
                    if arg.type == 'keyword_argument':
                        continue    # e.g. shell=True — not an injection vector
                    if arg.type == 'string':
                        # Plain string literal is safe; f-string with interpolation is not
                        if any(c.type == 'interpolation' for c in arg.children):
                            return True
                        continue
                    if arg.type not in _PYTHON_LITERAL_TYPES:
                        return True  # variable, binary_operator, call, etc.
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
                if line.strip().startswith('#'):
                    continue
                for pat in patterns:
                    if pat in line and self._fallback_is_vulnerable(line, rule):
                        location = CodeLocation(
                            file_path=file_path,
                            line_start=line_num,
                            line_end=line_num,
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
                            confidence=rule.confidence * 0.8,
                        ))
                        break
        return violations

    def _fallback_is_vulnerable(self, line: str, rule: SecurityRule) -> bool:
        """Context heuristic used by the substring fallback path."""
        if rule.violation_type == ViolationType.COMMAND_INJECTION:
            user_input = ['input(', 'request.', 'args.', 'argv', 'get(', 'post(']
            formatting = ['+', '%', '.format', 'f"', "f'"]
            return any(i in line for i in user_input) or any(f in line for f in formatting)
        if rule.violation_type == ViolationType.SQL_INJECTION:
            if 'execute' in line:
                return any(op in line for op in ['+', '%', '.format', 'f"', "f'"])
        return True


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
