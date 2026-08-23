"""
Custom Rule Engine for Gədr.
Allows users to define custom vulnerability patterns using YAML.
"""
import yaml
import re
from pathlib import Path

class CustomRuleEngine:
    def __init__(self, rules_dir: Path = Path("custom_rules")):
        self.rules_dir = rules_dir
        self.rules_dir.mkdir(exist_ok=True)
        self.rules = self._load_rules()

    def _load_rules(self) -> list:
        all_rules = []
        for rule_file in self.rules_dir.glob("*.yaml"):
            try:
                with open(rule_file, 'r') as f:
                    rule_data = yaml.safe_load(f)
                    if rule_data:
                        all_rules.append(rule_data)
            except Exception as e:
                print(f"Error loading rule {rule_file}: {e}")
        return all_rules

    def scan_file(self, file_path: Path, content: str) -> list:
        findings = []
        for rule in self.rules:
            # Check if rule applies to this file extension
            if "extensions" in rule and file_path.suffix not in rule["extensions"]:
                continue
            
            pattern = rule.get("pattern")
            if not pattern:
                continue

            # Search for the pattern in the content
            for i, line in enumerate(content.splitlines(), 1):
                if re.search(pattern, line):
                    findings.append({
                        "file": str(file_path),
                        "line": i,
                        "code": line.strip(),
                        "scanner": "CustomRuleEngine",
                        "rule_id": rule.get("id", "custom-rule"),
                        "title": rule.get("title", "Custom Vulnerability Detected"),
                        "severity": rule.get("severity", "Medium"),
                        "severity_score": rule.get("severity_score", 5),
                        "cwe": rule.get("cwe", "CWE-Misc"),
                        "owasp": rule.get("owasp", "Other"),
                        "description": rule.get("description", "Detected by custom user rule."),
                    })
        return findings

    def add_rule(self, rule_id: str, title: str, pattern: str, severity: str = "Medium", **kwargs):
        rule_data = {
            "id": rule_id,
            "title": title,
            "pattern": pattern,
            "severity": severity,
            **kwargs
        }
        rule_file = self.rules_dir / f"{rule_id}.yaml"
        with open(rule_file, 'w') as f:
            yaml.dump(rule_data, f)
        self.rules.append(rule_data)
