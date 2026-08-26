"""
AI security reasoning agent for Gədr.

Supports two backends, selected by CCI_AI_PROVIDER:
  "native"   (default) — primary provider SDK
  "opencode"         — OpenAI-compatible HTTP API endpoint

Graceful fallback:
  - If no API key is configured, returns a rule-based local explanation
    so the platform still works fully offline.
  - If the configured backend fails at runtime, falls back to offline mode.

Environment variables:
  CCI_AI_PROVIDER   — "native" (default) or "opencode"
  CCI_AI_API_KEY    — API key
  CCI_AI_BASE_URL   — base URL for opencode provider (no trailing slash)
  CCI_AI_MODEL      — model id
"""
import json
import os
import time
from pathlib import Path

import requests


# ------------------------------------------------------------------
# Dotenv loader
# ------------------------------------------------------------------
def _load_dotenv() -> None:
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv()

# ------------------------------------------------------------------
# Configuration (new names + legacy aliases)
# ------------------------------------------------------------------
_PROVIDER = os.getenv("CCI_AI_PROVIDER", "native").lower()

_API_KEY = os.getenv("CCI_AI_API_KEY", os.getenv("AI_PRIMARY_KEY", "")).strip()
_BASE_URL = os.getenv("CCI_AI_BASE_URL", os.getenv("AI_PRIMARY_URL", "")).rstrip("/")
_MODEL = os.getenv("CCI_AI_MODEL", os.getenv("AI_PRIMARY_MODEL", ""))

# Cloud fallback (OpenAI-compatible) — used when the primary
# backend fails (quota exhausted, rate limits, outages, ...).
AI_FALLBACK_KEY = os.getenv("AI_FALLBACK_KEY", "").strip()
AI_FALLBACK_URL = os.getenv("AI_FALLBACK_URL", "").rstrip("/")
AI_FALLBACK_MODEL = os.getenv("AI_FALLBACK_MODEL", "")

# Third-tier fallback
AI_REASONING_KEY = os.getenv("AI_REASONING_KEY", "").strip()
AI_REASONING_URL = os.getenv("AI_REASONING_URL", "").rstrip("/")
REASONING_MODEL = os.getenv("AI_REASONING_MODEL", "")

# Fourth-tier fallback
AI_TIER4_KEY = os.getenv("AI_TIER4_KEY", "").strip()
AI_TIER4_URL = os.getenv("AI_TIER4_URL", "").rstrip("/")
AI_TIER4_MODEL = os.getenv("AI_TIER4_MODEL", "")

# Fifth-tier fallback
AI_TIER5_KEY = os.getenv("AI_TIER5_KEY", "").strip()
AI_TIER5_URL = os.getenv("AI_TIER5_URL", "").rstrip("/")
AI_TIER5_MODEL = os.getenv("AI_TIER5_MODEL", "")

# Sixth-tier fallback
AI_TIER6_KEY = os.getenv("AI_TIER6_KEY", "").strip()
AI_TIER6_URL = os.getenv("AI_TIER6_URL", "").rstrip("/")
AI_TIER6_MODEL = os.getenv("AI_TIER6_MODEL", "")

# Retry / timeout
MAX_RETRIES = 2
INITIAL_BACKOFF = 1.0
MAX_BACKOFF = 8.0
REQUEST_TIMEOUT = 60.0

# ------------------------------------------------------------------
# Prompt
# ------------------------------------------------------------------
PROMPT_TEMPLATE = """You are a senior application security engineer reviewing findings from a Static Application Security Testing (SAST) platform.

Analyze the finding below and respond with STRICT JSON (no markdown fences, no extra text) using exactly these keys:
{{"explanation": "...", "impact": "...", "attack_scenario": "...", "root_cause": "...", "recommended_fix": "...", "secure_code": "...", "owasp": "...", "cwe": "..."}}

Finding:
Programming Language: {language}
File: {file}
Line Number: {line}
Code:
```
{code}
```
Detected Issue: {title}
Scanner: {scanner}
CWE: {cwe}
Severity: {severity}

Rules:
- explanation: 2-3 sentences in plain language.
- impact: what could an attacker achieve.
- attack_scenario: one concrete step-by-step attack.
- root_cause: why the vulnerability exists (not what it is).
- recommended_fix: concrete remediation steps.
- secure_code: a corrected code snippet relevant to the language.
- owasp: OWASP Top 10 (2021) category name only.
- cwe: the CWE id only (keep provided or nearest equivalent).
"""


# ------------------------------------------------------------------
# Secure code examples
# ------------------------------------------------------------------
def _secure_example(cwe: str) -> str:
    examples = {
        "CWE-89": "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))",
        "CWE-79": "import html; page += html.escape(user_input)",
        "CWE-78": "subprocess.run([cmd, arg], shell=False)",
        "CWE-120": "snprintf(dst, sizeof(dst), \"%s\", src);",
        "CWE-502": "data = json.loads(payload)  # instead of pickle.loads()",
        "CWE-798": "password = os.environ[\"DB_PASSWORD\"]",
        "CWE-434": "if ext in {\"png\", \"jpg\"} and max_size < 5_000_000: save_file(f)",
    }
    return examples.get(cwe, "# Apply context-appropriate input validation, encoding, and least privilege.")


# ------------------------------------------------------------------
# Offline fallback
# ------------------------------------------------------------------
def _local_fallback(finding: dict) -> dict:
    cwe = finding.get("cwe", "CWE-20")
    title = finding.get("title", "Security issue")
    sev = finding.get("severity", "Low")

    guidance = {
        "CWE-89": ("Injection",
                   "parameterized queries / prepared statements; never concatenate input into SQL",
                   "an attacker can read, modify, or delete database data", "inject SQL through input fields"),
        "CWE-79": ("Cross-Site Scripting",
                   "encode output for the correct context (HTML, JS, URL) and use a CSP",
                   "an attacker can steal cookies/session tokens or execute actions as the victim", "inject a script via an unsanitized input that is reflected or stored"),
        "CWE-78": ("Injection",
                   "avoid shell=True / use argument lists and allowlists for commands",
                   "an attacker can execute arbitrary OS commands on the server", "append shell metacharacters to a value passed to the command"),
        "CWE-120": ("Security Misconfiguration",
                    "use bounds-checked functions (strncpy_s, snprintf) and size checks",
                    "an attacker can overwrite memory and gain code execution", "supply an oversized input that overflows a fixed buffer"),
        "CWE-502": ("Software and Data Integrity Failures",
                    "never deserialize untrusted data; validate class allowlists / use safe formats (JSON)",
                    "an attacker can achieve remote code execution", "craft a malicious serialized payload"),
        "CWE-798": ("Identification and Authentication Failures",
                    "move secrets to environment variables or a vault; rotate the exposed credential",
                    "an attacker can impersonate the application or access protected services", "extract the credential from the public codebase"),
        "CWE-434": ("Software and Data Integrity Failures",
                    "validate file extension, MIME type and content; store uploads outside the web root",
                    "an attacker can upload a webshell and take over the server", "upload a malicious executable file"),
    }
    owasp, fix, impact, scenario = guidance.get(
        cwe, ("Security Misconfiguration", "validate and sanitize inputs; apply least privilege",
              "an attacker can exploit the weakness for the shown impact", "craft input that triggers the vulnerable code path")
    )

    return {
        "explanation": (
            f"{title} was reported in {finding.get('file', '?')} (line {finding.get('line', 0)}) by "
            f"{finding.get('scanner', 'heuristic scanner')}. Severity: {sev}. This matches {cwe}."
        ),
        "impact": f"Potentially {impact}.",
        "attack_scenario": f"1) Identify the entry point for this input; 2) {scenario}; 3) escalate privileges or data access.",
        "root_cause": "The code does not enforce safe handling of untrusted data at this location (missing validation, encoding, or bounds checking).",
        "recommended_fix": fix,
        "secure_code": _secure_example(cwe),
        "owasp": owasp,
        "cwe": cwe,
        "model": "offline fallback",
    }


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
            raise
    raise ValueError("No JSON object found in model response")


# ------------------------------------------------------------------
# OpenAI-compatible backend
# ------------------------------------------------------------------
class _OpenAIBackend:
    """Thin wrapper around an OpenAI-compatible /chat/completions endpoint."""

    def __init__(self, api_key: str, base_url: str, model: str, timeout: float = REQUEST_TIMEOUT):
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.timeout = timeout

    def generate(self, prompt: str) -> str:
        backoff = INITIAL_BACKOFF
        last_err = None

        for attempt in range(MAX_RETRIES):
            try:
                resp = requests.post(
                    f"{self.base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": "You are a defensive security analysis assistant. Output only valid JSON."},
                            {"role": "user", "content": prompt},
                        ],
                        "temperature": 0.2,
                        "max_tokens": 4096,
                        "stream": False,
                    },
                    timeout=self.timeout,
                )
            except (requests.Timeout, requests.ConnectionError) as e:
                last_err = e
                if attempt < MAX_RETRIES - 1:
                    time.sleep(backoff)
                    backoff = min(backoff * 2, MAX_BACKOFF)
                    continue
                raise RuntimeError(f"AI API unreachable after {MAX_RETRIES} attempts: {e}")

            if resp.status_code in (429, 500, 502, 503, 504):
                last_err = RuntimeError(f"HTTP {resp.status_code}")
                if attempt < MAX_RETRIES - 1:
                    time.sleep(backoff)
                    backoff = min(backoff * 2, MAX_BACKOFF)
                    continue
                raise RuntimeError(f"AI API error after retries: {resp.status_code}")

            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"].get("content", "")
            if not content:
                raise ValueError("Empty response from model")
            return content

        raise RuntimeError(f"AI API call failed: {last_err}")


# ------------------------------------------------------------------
# Native SDK backend (primary)
# ------------------------------------------------------------------
class _NativeBackend:
    """Primary provider native SDK backend."""

    def __init__(self, api_key: str, model: str):
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            self._model = genai.GenerativeModel(model)
            self._genai = genai
        except Exception as e:
            raise RuntimeError(f"Cannot initialise native AI SDK: {e}")

    def generate(self, prompt: str) -> str:
        backoff = INITIAL_BACKOFF
        last_err = None

        for attempt in range(MAX_RETRIES):
            try:
                response = self._model.generate_content(
                    prompt,
                    generation_config=self._genai.GenerationConfig(
                        temperature=0.2,
                        max_output_tokens=4096,
                    ),
                )
                text = response.text.strip()
                if not text:
                    raise ValueError("Empty response from model")
                return text

            except Exception as e:
                last_err = e
                is_retryable = _is_retryable_native_error(e)
                if is_retryable and attempt < MAX_RETRIES - 1:
                    time.sleep(backoff)
                    backoff = min(backoff * 2, MAX_BACKOFF)
                    continue
                if is_retryable:
                    raise RuntimeError(f"Gədr AI failed after {MAX_RETRIES} retries: {e}")
                raise RuntimeError(f"Gədr AI error: {e}")

        raise RuntimeError(f"Gədr AI call failed: {last_err}")


def _is_retryable_native_error(exc: Exception) -> bool:
    name = type(exc).__name__.lower()
    return any(k in name for k in ("resourceexhausted", "serviceunavailable",
                                    "timeout", "connection", "internalservererror"))


# ------------------------------------------------------------------
# Main agent class
# ------------------------------------------------------------------
class GedrAgent:
    """
    AI security reasoning agent.

    Selects backend from CCI_AI_PROVIDER:
      "opencode" (default) → OpenAI-compatible HTTP (OpenCode Zen)
      "native"            → native provider SDK
    """

    def __init__(self, api_key: str = _API_KEY, model: str = _MODEL):
        self.api_key = api_key
        self.model_name = model
        self.provider = _PROVIDER
        self.enabled = False
        self._backends: list = []

        if self.enabled is False:
            pass

        # Primary backend
        if api_key:
            try:
                if self.provider == "native":
                    self._backends.append(_NativeBackend(api_key, model))
                    self.enabled = True
                else:
                    if not _BASE_URL:
                        raise ValueError("CCI_AI_BASE_URL is required for opencode provider")
                    self._backends.append(_OpenAIBackend(api_key, _BASE_URL, model))
                    self.enabled = True
            except Exception as e:
                print(f"[AI] Primary backend unavailable: {e}")

        # Secondary backend: cloud fallback (skip if primary already uses it)
        primary_is_fallback = (
            self.provider != "native"
            and _BASE_URL and AI_FALLBACK_URL and _BASE_URL.rstrip("/") == AI_FALLBACK_URL
        )
        if AI_FALLBACK_KEY and not primary_is_fallback:
            try:
                self._backends.append(_OpenAIBackend(AI_FALLBACK_KEY, AI_FALLBACK_URL, AI_FALLBACK_MODEL))
                if not self.enabled:
                    self.enabled = True
                    self.model_name = AI_FALLBACK_MODEL
            except Exception as e:
                print(f"[AI] Cloud fallback unavailable: {e}")

        # Third-tier backend: extra NVIDIA NIM free models
        if AI_REASONING_KEY:
            try:
                reasoning_url = AI_REASONING_URL or AI_FALLBACK_URL
                self._backends.append(
                    _OpenAIBackend(AI_REASONING_KEY, reasoning_url, REASONING_MODEL, timeout=120.0)
                )
                if not self.enabled:
                    self.enabled = True
                    self.model_name = REASONING_MODEL
            except Exception as e:
                print(f"[AI] Tier 3 fallback unavailable: {e}")

        # Fourth-tier backend
        if AI_TIER4_KEY:
            try:
                self._backends.append(
                    _OpenAIBackend(AI_TIER4_KEY, AI_TIER4_URL or AI_FALLBACK_URL, AI_TIER4_MODEL, timeout=120.0)
                )
                if not self.enabled:
                    self.enabled = True
                    self.model_name = AI_TIER4_MODEL
            except Exception as e:
                print(f"[AI] Tier 4 fallback unavailable: {e}")

        # Fifth-tier backend
        if AI_TIER5_KEY:
            try:
                self._backends.append(
                    _OpenAIBackend(AI_TIER5_KEY, AI_TIER5_URL or AI_FALLBACK_URL, AI_TIER5_MODEL, timeout=120.0)
                )
                if not self.enabled:
                    self.enabled = True
                    self.model_name = AI_TIER5_MODEL
            except Exception as e:
                print(f"[AI] Tier 5 fallback unavailable: {e}")

    @property
    def available(self) -> bool:
        return self.enabled

    @property
    def model(self) -> str:
        return self.model_name

    # ------------------------------------------------------------------
    def generate(self, prompt: str) -> str:
        """Generate text trying each backend in order (primary -> fallbacks)."""
        last_err = None
        for i, backend in enumerate(self._backends):
            try:
                text = backend.generate(prompt)
                if i > 0:
                    print(f"[AI] Served by fallback backend #{i}")
                return text
            except Exception as e:
                last_err = e
                print(f"[AI] Backend #{i} failed ({type(e).__name__}: {e}), trying next...")
        raise RuntimeError(f"All AI backends failed: {last_err}")

    # ------------------------------------------------------------------
    def analyze_finding(self, finding: dict) -> dict:
        if not self.enabled or not self._backends:
            return _local_fallback(finding)

        prompt = PROMPT_TEMPLATE.format(
            language=finding.get("language", "unknown"),
            file=finding.get("file", ""),
            line=finding.get("line", 0),
            code=(finding.get("code") or "")[:1500],
            title=finding.get("title", ""),
            scanner=finding.get("scanner", ""),
            cwe=finding.get("cwe", "CWE-20"),
            severity=finding.get("severity", "Low"),
        )

        try:
            text = self.generate(prompt)
            return _parse_json(text)
        except Exception:
            return _local_fallback(finding)

    def analyze_many(self, findings: list[dict], db, max_items: int = 20) -> int:
        if not self.enabled:
            return 0

        todo = []
        for finding in findings:
            finding_id = finding.get("finding_id") or finding.get("id")
            if not finding_id or db.get_recommendation(finding_id):
                continue
            todo.append((finding_id, finding))
        todo = todo[:max_items]

        done = 0
        for finding_id, finding in todo:
            try:
                rec = self.analyze_finding(finding)
            except Exception:
                continue
            if not rec.get("explanation") or rec.get("model") == "offline fallback":
                continue
            try:
                db.save_ai_recommendation(finding_id, {**rec, "model": self.model_name})
                done += 1
            except Exception:
                continue
            time.sleep(0.5)
        return done


# Backwards-compat alias
get_fallback = _local_fallback
