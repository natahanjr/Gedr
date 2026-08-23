"""Shared security metadata for Gədr scanners.

Central mapping of rules to CVSS-style severity scores, CWE IDs and
OWASP Top 10 categories. Keeps scanners consistent with the risk engine.
"""

SEVERITY_SCORES = {
    "Critical": 10,
    "High": 7,
    "Medium": 5,
    "Low": 2,
}

# CWE / OWASP reference catalog used across all language scanners
CWE_CATALOG = {
    "CWE-89": ("SQL Injection", "Injection"),
    "CWE-79": ("Cross-Site Scripting (XSS)", "Injection"),
    "CWE-78": ("OS Command Injection", "Injection"),
    "CWE-94": ("Code Injection", "Injection"),
    "CWE-95": ("Eval-based Code Injection", "Injection"),
    "CWE-798": ("Hardcoded Credentials", "Identification and Authentication Failures"),
    "CWE-521": ("Weak Password Requirements", "Identification and Authentication Failures"),
    "CWE-287": ("Improper Authentication", "Identification and Authentication Failures"),
    "CWE-306": ("Missing Authentication for Critical Function", "Broken Access Control"),
    "CWE-862": ("Missing Authorization", "Broken Access Control"),
    "CWE-352": ("Cross-Site Request Forgery (CSRF)", "Broken Access Control"),
    "CWE-22": ("Path Traversal", "Broken Access Control"),
    "CWE-434": ("Unrestricted File Upload", "Security Misconfiguration"),
    "CWE-502": ("Deserialization of Untrusted Data", "Injection"),
    "CWE-120": ("Buffer Overflow", "Memory Safety"),
    "CWE-121": ("Stack-based Buffer Overflow", "Memory Safety"),
    "CWE-122": ("Heap-based Buffer Overflow", "Memory Safety"),
    "CWE-787": ("Out-of-bounds Write", "Memory Safety"),
    "CWE-119": ("Improper Restriction of Operations in Memory", "Memory Safety"),
    "CWE-476": ("NULL Pointer Dereference", "Memory Safety"),
    "CWE-416": ("Use After Free", "Memory Safety"),
    "CWE-311": ("Missing Encryption of Sensitive Data", "Sensitive Data Exposure"),
    "CWE-312": ("Cleartext Storage of Sensitive Data", "Sensitive Data Exposure"),
    "CWE-319": ("Cleartext Transmission of Sensitive Data", "Sensitive Data Exposure"),
    "CWE-295": ("Improper Certificate Validation", "Cryptographic Failures"),
    "CWE-326": ("Inadequate Encryption Strength", "Cryptographic Failures"),
    "CWE-327": ("Broken or Risky Crypto Algorithm", "Cryptographic Failures"),
    "CWE-614": ("Sensitive Cookie Without HttpOnly", "Identification and Authentication Failures"),
    "CWE-79:DOM": ("DOM-based XSS", "Injection"),
    "CWE-400": ("Uncontrolled Resource Consumption", "Security Misconfiguration"),
    "CWE-259": ("Hardcoded Password", "Identification and Authentication Failures"),
    "CWE-20": ("Improper Input Validation", "Injection"),
    "CWE-749": ("Exposed Dangerous Method", "Security Misconfiguration"),
    "CWE-98": ("Include Injection", "Injection"),
    "CWE-918": ("Server-Side Request Forgery (SSRF)", "Security Misconfiguration"),
}


def resolve_cwe(cwe_id: str) -> dict:
    """Return CWE description + OWASP category for a CWE id (fallback safe)."""
    name, owasp = CWE_CATALOG.get(cwe_id, ("Security Issue", "Security Misconfiguration"))
    return {"cwe": cwe_id, "name": name, "owasp": owasp}


def score_to_severity(score: int) -> str:
    """Map a CVSS-style score to a severity label per the risk engine spec."""
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    return "Low"
