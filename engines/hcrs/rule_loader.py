# HCRS rule loader
import os
import yaml
from typing import List, Dict
from .models import SecurityRule, ViolationType, Severity

class RuleLoader:
    """Loads and manages security rules from configuration"""
    
    def __init__(self, rules_path: str = None):
        if rules_path is None:
            rules_path = os.path.join(
                os.path.dirname(__file__), '..', '..', 'config', 'rules.yaml'
            )
        self.rules_path = rules_path
        self.rules: Dict[str, List[SecurityRule]] = {
            'python': [],
            'javascript': []
        }
        self.load_rules()
    
    def load_rules(self):
        """Load rules from YAML configuration"""
        if not os.path.exists(self.rules_path):
            print(f"Warning: Rules file not found at {self.rules_path}")
            return
        
        with open(self.rules_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        # Load Python rules
        if 'python_rules' in config:
            for rule_data in config['python_rules']:
                rule = self._parse_rule(rule_data, 'python')
                if rule and rule.enabled:
                    self.rules['python'].append(rule)
        
        # Load JavaScript rules
        if 'javascript_rules' in config:
            for rule_data in config['javascript_rules']:
                rule = self._parse_rule(rule_data, 'javascript')
                if rule and rule.enabled:
                    self.rules['javascript'].append(rule)
    
    def _parse_rule(self, rule_data: dict, language: str) -> SecurityRule:
        """Parse a single rule from dictionary"""
        try:
            return SecurityRule(
                rule_id=rule_data['rule_id'],
                name=rule_data['name'],
                violation_type=ViolationType(rule_data['violation_type']),
                severity=Severity(rule_data['severity']),
                language=language,
                pattern_type=rule_data['pattern_type'],
                pattern=rule_data['pattern'],
                message=rule_data['message'],
                description=rule_data.get('description', ''),
                cwe_id=rule_data.get('cwe_id'),
                recommendation=rule_data.get('recommendation', ''),
                weight=rule_data.get('weight', 1.0),
                enabled=rule_data.get('enabled', True),
                confidence=rule_data.get('confidence', 1.0)
            )
        except Exception as e:
            print(f"Error parsing rule {rule_data.get('rule_id', 'unknown')}: {e}")
            return None
    
    def get_rules_for_language(self, language: str) -> List[SecurityRule]:
        """Get all enabled rules for a specific language"""
        return self.rules.get(language, [])
    
    def get_rule_by_id(self, rule_id: str) -> SecurityRule:
        """Get a specific rule by ID"""
        for language_rules in self.rules.values():
            for rule in language_rules:
                if rule.rule_id == rule_id:
                    return rule
        return None
