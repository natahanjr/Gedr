"""
Taint Analysis Engine for Gədr.
Tracks user-controlled input (sources) to dangerous functions (sinks).
"""
import re
from pathlib import Path

class TaintAnalyzer:
    def __init__(self):
        # Sources: Where user input enters the system
        self.sources = {
            "python": [r"request\.", r"input\(", r"sys\.argv"],
            "php": [r"\$_GET", r"\$_POST", r"\$_REQUEST", r"\$_COOKIE"],
            "java": [r"getParameter", r"getHeader", r"readLine"],
            "js": [r"location\.search", r"document\.cookie", r"req\.body"],
        }
        
        # Sinks: Where untrusted data causes a vulnerability
        self.sinks = {
            "sql": [r"execute\(", r"query\(", r"mysqli_query"],
            "cmd": [r"system\(", r"popen\(", r"subprocess\.run", r"exec\("],
            "xss": [r"innerHTML", r"document\.write", r"echo", r"print\("],
            "file": [r"open\(", r"file_get_contents", r"read_file"],
        }

    def analyze_file(self, file_path: Path, content: str, language: str) -> list:
        """
        Performs basic data-flow taint analysis.
        Returns a list of potential taint-flow findings.
        """
        findings = []
        lang_sources = self.sources.get(language, [])
        if not lang_sources:
            return []

        lines = content.splitlines()
        tainted_vars = set()

        for i, line in enumerate(lines, 1):
            # 1. Track Taint Sources: Find where variables are assigned from a source
            for source_pattern in lang_sources:
                if re.search(source_pattern, line):
                    # Simple regex to find variable assignments like 'x = request.args...'
                    match = re.search(r"(\w+)\s*=", line)
                    if match:
                        tainted_vars.add(match.group(1))
                        # We mark the line as a source
                        # (handled by heuristic, but we track it for flow)

            # 2. Track Taint Propagation: x = y (if y is tainted, x becomes tainted)
            for var in list(tainted_vars):
                if re.search(rf"(\w+)\s*=\s*.*{var}.*", line):
                    new_var_match = re.search(r"(\w+)\s*=", line)
                    if new_var_match:
                        tainted_vars.add(new_var_match.group(1))

            # 3. Check for Taint Sinks: Is a tainted variable used in a dangerous function?
            for sink_type, sink_patterns in self.sinks.items():
                for sink_pattern in sink_patterns:
                    if re.search(sink_pattern, line):
                        # Check if any currently tainted variable is used in this line
                        for var in tainted_vars:
                            if re.search(rf"\b{var}\b", line):
                                findings.append({
                                    "file": str(file_path),
                                    "line": i,
                                    "code": line.strip(),
                                    "scanner": "TaintAnalyzer",
                                    "rule_id": f"TAINT-{sink_type.upper()}",
                                    "title": f"Unsanitized User Input flowing to {sink_type} sink",
                                    "severity": "Critical",
                                    "severity_score": 9,
                                    "cwe": "CWE-20", # Improper Input Validation
                                    "owasp": "A03:2021-Injection",
                                    "description": f"User-controlled data flows directly into a {sink_type} sink without visible sanitization.",
                                })
                                break
        return findings
