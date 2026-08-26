"""
Gədr Reporting Engine - evidence sanitisation.

Generated reports are sensitive documents that are frequently shared beyond
the team that produced them. Before any scanner output, code snippet or
description reaches the PDF it passes through `sanitize()`, which:

1. normalises unicode to a PDF-safe subset,
2. strips control characters,
3. redacts credential-looking material (API keys, tokens, passwords,
   private keys, JWTs, basic-auth URLs) while preserving enough context
   for the reader to understand what was found.

Redaction is conservative: anything that *looks* like a secret is masked
even if the pattern might occasionally match benign text. Over-redaction in
a report is preferable to credential leakage.
"""
from __future__ import annotations

import re
import unicodedata

# --------------------------------------------------------------------------- #
# Credential patterns - each entry: (compiled regex, group index of the secret)
# --------------------------------------------------------------------------- #

_SECRET_PATTERNS: list[tuple[re.Pattern, int]] = [
    # AWS access key id + generic cloud key ids
    (re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), 1),
    # AWS secret access key
    (re.compile(r"\b([A-Za-z0-9/+=]{40})\b"), 1),
    # GitLab personal access tokens
    (re.compile(r"\b(glpat-[0-9A-Za-z_\-]{8,})\b"), 1),
    # OpenAI-style keys and other vendor sk- keys
    (re.compile(r"\b(sk-[A-Za-z0-9_-]{12,})\b"), 1),
    # GitHub tokens
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,})\b"), 1),
    # GitLab deploy tokens
    (re.compile(r"\b(gldt-[0-9A-Za-z_\-]{8,})\b"), 1),
    # Slack tokens
    (re.compile(r"\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b"), 1),
    # Slack webhooks
    (re.compile(r"\b(T[a-zA-Z0-9_\-]{10,})\b"), 1),
    # JWTs
    (re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})\b"), 1),
    # PEM private key blocks
    (re.compile(
        r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----)"), 0),
    # Basic-auth style URLs: scheme://user:secret@host
    (re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://[^\s/:@]+:)([^\s/@]{3,})(@)"), 2),
    # key = "value" assignments for credential-ish key names
    (re.compile(
        r"((?:api[_-]?key|apikey|access[_-]?key|secret[_-]?(?:key)?|auth[_-]?token|"
        r"token|passwd|password|pwd|client[_-]?secret)\s*[:=]\s*[\"']?)"
        r"([^\s\"',;)]{6,})", re.IGNORECASE), 2),
    # Authorization: Bearer <token>
    (re.compile(r"(?i)\b(bearer\s+)([A-Za-z0-9._+\-/]{10,})"), 2),
]

_REDACT_CHAR = "\u2588"  # full block


def _mask(secret: str) -> str:
    """Mask a secret but keep a short prefix/suffix so context survives."""
    if len(secret) <= 8:
        return _REDACT_CHAR * max(len(secret), 4)
    head, tail = secret[:4], secret[-2:]
    body = _REDACT_CHAR * min(max(len(secret) - 6, 4), 24)
    return f"{head}{body}{tail}"


def _redact(text: str) -> str:
    for pattern, group in _SECRET_PATTERNS:
        def _sub(match: re.Match, _g: int = group) -> str:
            try:
                secret = match.group(_g)
            except IndexError:
                return match.group(0)
            if not secret:
                return match.group(0)
            start, end = match.span(_g)
            prefix = match.group(0)[: start - match.start()]
            suffix = match.group(0)[end - match.start():]
            return prefix + _mask(secret) + suffix

        text = pattern.sub(_sub, text)
    return text


def clean(text: object, max_length: int | None = None) -> str:
    """Normalise arbitrary input text for safe embedding in the report."""
    if text is None:
        return ""
    s = str(text)
    s = unicodedata.normalize("NFKC", s)
    s = "".join(ch for ch in s if ch == "\n" or ch == "\t" or ord(ch) >= 32)
    s = _redact(s)
    s = re.sub(r"[ \t]+\n", "\n", s)
    s = re.sub(r"\n{4,}", "\n\n\n", s)
    if max_length is not None and len(s) > max_length:
        s = s[:max_length].rstrip() + " \u2026"
    return s.strip()


_HEADING_LINE = re.compile(r"^\s*(?:#{1,4}\s*)?(\S[^:\n]{1,79}):?\s*:?\s*$")


def strip_ai_headings(text: object) -> str:
    """
    Remove heading-like lines the AI reasoning layer emits inside prose
    (e.g. "WHAT IS THIS VULNERABILITY?", "## Vulnerable Code", "ROOT CAUSE:").
    The report supplies its own styled labels for these sections, so raw
    headings would only duplicate them and break the layout.
    """
    if not text:
        return ""
    kept: list[str] = []
    for line in str(text).split("\n"):
        m = _HEADING_LINE.match(line)
        if m:
            words = m.group(1).strip().strip("*`_ ").rstrip(":")
            letters = [ch for ch in words if ch.isalpha()]
            # heading-like: short, and essentially ALL CAPS (allowing for
            # markdown emphasis and stray lowercase in e.g. "PoC")
            if len(words) <= 60 and len(letters) >= 2 and sum(
                    ch.isupper() for ch in letters) / len(letters) >= 0.8:
                continue
        kept.append(line)
    out = "\n".join(kept)
    out = re.sub(r"\n{3,}", "\n\n", out)
    return out.strip()


def sanitize_code(code: object, max_lines: int = 14, max_line_chars: int = 110) -> tuple[list[str], int]:
    """
    Prepare a code/evidence snippet for rendering.

    Returns (lines, omitted_count). Long snippets are truncated with an
    explicit note so the reader always knows when evidence was shortened.
    """
    if not code:
        return [], 0
    raw_lines = clean(code).splitlines() or [""]
    rendered: list[str] = []
    for line in raw_lines[:max_lines]:
        line = line.replace("\t", "    ")
        if len(line) > max_line_chars:
            line = line[: max_line_chars - 1] + "\u2026"
        rendered.append(line)
    omitted = max(0, len(raw_lines) - max_lines)
    return rendered, omitted
