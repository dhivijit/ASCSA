# HCRS JavaScript analyzer
import re
from typing import List
from .models import SecurityViolation, CodeLocation, ViolationType, Severity, SecurityRule

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
