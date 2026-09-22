"""
Custom Rule Engine for Gədr.
Allows users to define custom vulnerability patterns using YAML.
"""
import logging
import re
import yaml
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from pathlib import Path

logger = logging.getLogger(__name__)

_REGEX_TIMEOUT = 2  # seconds per regex execution
_REGEX_COMPLEXITY_LIMIT = 500  # max characters in a pattern


class CustomRuleEngine:
    def __init__(self, rules_dir: Path = Path("custom_rules")):
        self.rules_dir = rules_dir
        self.rules_dir.mkdir(exist_ok=True)
        self.rules = self._load_rules()
        self._pool = ThreadPoolExecutor(max_workers=1)

    def _load_rules(self) -> list:
        all_rules = []
        for rule_file in self.rules_dir.glob("*.yaml"):
            try:
                with open(rule_file, 'r') as f:
                    rule_data = yaml.safe_load(f)
                    if rule_data:
                        all_rules.append(rule_data)
            except Exception as e:
                logger.warning("Error loading rule %s: %s", rule_file, e)
        return all_rules

    def _safe_search(self, pattern: str, line: str, rule_id: str) -> bool:
        """Run regex with timeout and complexity check."""
        if len(pattern) > _REGEX_COMPLEXITY_LIMIT:
            logger.warning("Rule %s: pattern too long (%d chars), skipping", rule_id, len(pattern))
            return False
        try:
            compiled = re.compile(pattern)
        except re.error:
            logger.warning("Rule %s: invalid regex pattern, skipping", rule_id)
            return False
        try:
            future = self._pool.submit(compiled.search, line)
            return future.result(timeout=_REGEX_TIMEOUT)
        except FuturesTimeoutError:
            logger.warning("Rule %s: regex timed out, skipping", rule_id)
            return False

    def scan_file(self, file_path: Path, content: str) -> list:
        findings = []
        for rule in self.rules:
            if "extensions" in rule and file_path.suffix not in rule["extensions"]:
                continue

            pattern = rule.get("pattern")
            if not pattern:
                continue

            rule_id = rule.get("id", "custom-rule")
            for i, line in enumerate(content.splitlines(), 1):
                if self._safe_search(pattern, line, rule_id):
                    findings.append({
                        "file": str(file_path),
                        "line": i,
                        "code": line.strip(),
                        "scanner": "CustomRuleEngine",
                        "rule_id": rule_id,
                        "title": rule.get("title", "Custom Vulnerability Detected"),
                        "severity": rule.get("severity", "Medium"),
                        "severity_score": rule.get("severity_score", 5),
                        "cwe": rule.get("cwe", "CWE-Misc"),
                        "owasp": rule.get("owasp", "Other"),
                        "description": rule.get("description", "Detected by custom user rule."),
                    })
        return findings

    def add_rule(self, rule_id: str, title: str, pattern: str, severity: str = "Medium", **kwargs):
        # Validate regex before saving
        try:
            re.compile(pattern)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}")

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
