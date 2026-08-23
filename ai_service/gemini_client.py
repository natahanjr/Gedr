"""
Gemini client for the AI microservice.

Reads config from environment:
  GEMINI_API_KEY   — required for AI mode
  GEMINI_MODEL     — model name (default: gemini-3.6-flash)
  GEMINI_BASE_URL  — optional API endpoint override
"""
import json
import os
import time
from pathlib import Path

from dotenv import load_dotenv

_env = Path(__file__).resolve().parent.parent / ".env"
if _env.exists():
    load_dotenv(_env)

import google.generativeai as genai  # noqa: E402

# --- Config ---
_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")
_BASE_URL = os.getenv("GEMINI_BASE_URL", "").rstrip("/")

_RETRIES = 3
_BACKOFF_INIT = 2.0
_BACKOFF_MAX = 30.0
_TIMEOUT = 60.0

_PROMPT_TEMPLATE = """You are a senior application security engineer.

Analyze the finding below and respond with STRICT JSON (no markdown fences, no extra text) using exactly these keys:
{{"explanation": "...", "impact": "...", "attack_scenario": "...", "root_cause": "...", "recommended_fix": "...", "secure_code": "...", "owasp": "...", "cwe": "...", "severity": "...", "severity_score": 0}}

Finding:
Language: {language}
File: {file}
Line: {line}
Code:
```
{code}
```
Issue: {title}
Scanner: {scanner}
CWE: {cwe}
Reported Severity: {severity}

Rules:
- explanation: 2-3 plain-language sentences.
- impact: what an attacker could achieve.
- attack_scenario: one concrete step-by-step attack.
- root_cause: why the vulnerability exists.
- recommended_fix: concrete remediation steps.
- secure_code: corrected code snippet in the same language.
- owasp: OWASP Top 10 (2021) category name only.
- cwe: CWE id only.
- severity: Critical, High, Medium, or Low.
- severity_score: 1-10 integer.
"""


# ------------------------------------------------------------------
# Offline fallback
# ------------------------------------------------------------------
def get_fallback(finding: dict) -> dict:
    cwe = finding.get("cwe", "CWE-20")
    title = finding.get("title", "Security issue")
    sev = finding.get("severity", "Low")

    guidance = {
        "CWE-89": ("Injection", "parameterized queries / prepared statements", "read or modify database data", "inject SQL through input fields"),
        "CWE-79": ("Cross-Site Scripting", "encode output for the correct context and use CSP", "steal cookies/session tokens", "inject script via unsanitized input"),
        "CWE-78": ("Injection", "avoid shell=True, use argument lists", "execute arbitrary OS commands", "append shell metacharacters to command input"),
        "CWE-120": ("Memory Safety", "use bounds-checked functions", "overwrite memory and gain code execution", "supply oversized input to overflow buffer"),
        "CWE-502": ("Software and Data Integrity Failures", "never deserialize untrusted data", "achieve remote code execution", "craft malicious serialized payload"),
        "CWE-798": ("Identification and Authentication Failures", "move secrets to env vars or vault", "impersonate the application", "extract credential from codebase"),
        "CWE-434": ("Software and Data Integrity Failures", "validate file extension, MIME, content", "upload webshell and take over server", "upload malicious executable file"),
    }
    owasp, fix, impact, scenario = guidance.get(cwe, ("Security Misconfiguration", "validate and sanitize inputs", "exploit the weakness", "craft input triggering the vulnerable path"))

    return {
        "explanation": f"{title} in {finding.get('file', '?')} (line {finding.get('line', 0)}). Matches {cwe}. Severity: {sev}.",
        "impact": f"Potentially {impact}.",
        "attack_scenario": f"1) Find the input entry point. 2) {scenario}. 3) escalate access.",
        "root_cause": "Untrusted data is handled without validation, encoding, or bounds checking.",
        "recommended_fix": fix,
        "secure_code": _examples.get(cwe, "# Apply context-appropriate input validation and least privilege."),
        "owasp": owasp,
        "cwe": cwe,
        "severity": sev,
        "severity_score": {"Critical": 9, "High": 7, "Medium": 5, "Low": 2}.get(sev, 3),
        "model": "offline fallback",
    }


_examples = {
    "CWE-89": "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))",
    "CWE-79": "import html; page += html.escape(user_input)",
    "CWE-78": "subprocess.run([cmd, arg], shell=False)",
    "CWE-120": "snprintf(dst, sizeof(dst), \"%s\", src);",
    "CWE-502": "data = json.loads(payload)",
    "CWE-798": "password = os.environ[\"DB_PASSWORD\"]",
    "CWE-434": "if ext in {\"png\", \"jpg\"} and max_size < 5_000_000: save_file(f)",
}


# ------------------------------------------------------------------
# Client
# ------------------------------------------------------------------
class GeminiClient:
    def __init__(self):
        self.api_key = _API_KEY
        self.model_name = _MODEL
        self.provider = "gemini" if _API_KEY else "offline"
        self.available = bool(_API_KEY)
        self._model = None

        if self.available:
            try:
                genai.configure(api_key=self.api_key)
                if _BASE_URL:
                    from google.generativeai import client as gc
                    gc.default_options.api_endpoint = _BASE_URL
                self._model = genai.GenerativeModel(self.model_name)
            except Exception:
                self.available = False

    def analyze_finding(self, finding: dict, language: str = "unknown") -> dict | None:
        if not self.available or self._model is None:
            return None

        prompt = _PROMPT_TEMPLATE.format(
            language=language,
            file=finding.get("file", ""),
            line=finding.get("line", 0),
            code=(finding.get("code") or "")[:1500],
            title=finding.get("title", ""),
            scanner=finding.get("scanner", ""),
            cwe=finding.get("cwe", "CWE-20"),
            severity=finding.get("severity", "Low"),
        )
        try:
            raw = self._generate(prompt)
            return _parse_json(raw)
        except Exception:
            return None

    def generate_text(self, prompt: str) -> str:
        """Free-form text generation (for summaries)."""
        if not self.available or self._model is None:
            raise RuntimeError("AI not available")
        return self._generate(prompt)

    # ------------------------------------------------------------------
    def _generate(self, prompt: str, retries: int = _RETRIES) -> str:
        backoff = _BACKOFF_INIT
        for attempt in range(retries):
            try:
                resp = self._model.generate_content(
                    prompt,
                    generation_config=genai.GenerationConfig(
                        temperature=0.2,
                        max_output_tokens=4096,
                    ),
                )
                text = resp.text.strip()
                if text:
                    return text
                raise ValueError("empty response")
            except Exception as e:
                name = type(e).__name__.lower()
                retryable = any(k in name for k in ("resourceexhausted", "serviceunavailable", "timeout"))
                if retryable and attempt < retries - 1:
                    time.sleep(backoff)
                    backoff = min(backoff * 2, _BACKOFF_MAX)
                    continue
                if attempt < retries - 1 and not retryable:
                    time.sleep(backoff)
                    backoff = min(backoff * 2, _BACKOFF_MAX)
                    continue
                raise
        raise RuntimeError("Gemini call failed after retries")


# ------------------------------------------------------------------
# JSON helper
# ------------------------------------------------------------------
def _parse_json(text: str) -> dict:
    cleaned = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    if cleaned.startswith("{"):
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            start, end = cleaned.find("{"), cleaned.rfind("}")
            if start != -1 and end > start:
                return json.loads(cleaned[start : end + 1])
    raise ValueError("No JSON found")
