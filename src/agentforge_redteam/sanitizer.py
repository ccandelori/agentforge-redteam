"""Deterministic PHI and secret sanitizer.

This module is the platform's last line of defense against leaking real PHI,
API keys, or JWTs into committed vulnerability reports or GitLab issues. The
Documentation Agent calls :func:`sanitize_evidence` on every piece of evidence
before writing a report.

Design constraints (these are load-bearing — do not relax without review):

- **Deterministic & regex-based.** No LLM call, no network, no I/O.
  The function is pure so that redactions are auditable and reproducible.
- **Fail-closed via truncation.** Suspiciously long evidence is truncated
  even if it contains no recognised secret pattern, forcing a reviewer to
  ask for it explicitly.
- **Compile once.** All patterns are compiled at module load so that the
  hot path (called per-evidence in the Documentation Agent) is allocation-free.
"""

from __future__ import annotations

import re
from typing import Final

DOCUMENT_TRUNCATION_THRESHOLD: Final[int] = 1000
DOCUMENT_TRUNCATION_KEEP: Final[int] = 200

# --- Compiled patterns (module-load time) -----------------------------------
#
# JWT: three base64url segments, header must start with the canonical
# ``eyJ`` prefix (which is ``{"alg`` / ``{"typ`` base64url-encoded).
_JWT_RE: Final[re.Pattern[str]] = re.compile(
    r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
    re.MULTILINE,
)

# API keys: ``sk-``/``pk-`` style (Anthropic, OpenAI projects, Langfuse public,
# OpenRouter, etc.). The ``[A-Za-z0-9]`` anchor + ``{16,}`` tail guards against
# stomping prose like "sk-i-dunno" — real keys are long.
_API_KEY_SK_RE: Final[re.Pattern[str]] = re.compile(
    r"\bsk-[A-Za-z0-9][A-Za-z0-9_-]{16,}\b",
    re.MULTILINE,
)
_API_KEY_PK_RE: Final[re.Pattern[str]] = re.compile(
    r"\bpk-[A-Za-z0-9][A-Za-z0-9_-]{16,}\b",
    re.MULTILINE,
)

# GitLab personal access tokens.
_GITLAB_PAT_RE: Final[re.Pattern[str]] = re.compile(
    r"\bglpat-[A-Za-z0-9_-]{20,}\b",
    re.MULTILINE,
)

# US Social Security Number (###-##-####). ``\b`` handles whitespace/punctuation
# boundaries; the negative lookbehind/lookahead for ``\d-`` / ``-\d`` keeps us
# from matching the middle of a longer hyphenated numeric string like a
# phone number (e.g. ``1-234-56-7890``).
_SSN_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<!\d-)\b\d{3}-\d{2}-\d{4}\b(?!-\d)",
    re.MULTILINE,
)

# Medical Record Number — Synthea emits UUID v4 patient IDs. We accept any
# canonical UUID since synthetic data also uses v3/v5 occasionally.
_MRN_RE: Final[re.Pattern[str]] = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
    re.MULTILINE,
)

_TRUNCATION_SUFFIX: Final[str] = "...[TRUNCATED]"


def sanitize_evidence(text: str) -> str:
    """Redact PHI, secrets, and truncate long document bodies. Pure function.

    Redaction patterns applied in this order:
      1. JWT tokens         -> ``[JWT_REDACTED]``
      2. API keys           -> ``[API_KEY_REDACTED]``   (``sk-...``, ``pk-...``, ``glpat-...``)
      3. SSN (###-##-####)  -> ``[SSN_REDACTED]``
      4. MRN (UUID-like)    -> ``[MRN_REDACTED]``
      5. Long bodies        -> first ``DOCUMENT_TRUNCATION_KEEP`` chars + ``...[TRUNCATED]``
                              (only if final length > ``DOCUMENT_TRUNCATION_THRESHOLD``)
    """
    # Order matters: JWTs first because their base64url segments could
    # otherwise be mis-classified by a greedy follow-on rule. API keys are
    # next because ``sk-``/``pk-`` patterns are more specific than the
    # generic SSN/MRN shapes that follow.
    result = _JWT_RE.sub("[JWT_REDACTED]", text)
    result = _API_KEY_SK_RE.sub("[API_KEY_REDACTED]", result)
    result = _API_KEY_PK_RE.sub("[API_KEY_REDACTED]", result)
    result = _GITLAB_PAT_RE.sub("[API_KEY_REDACTED]", result)
    result = _SSN_RE.sub("[SSN_REDACTED]", result)
    result = _MRN_RE.sub("[MRN_REDACTED]", result)

    if len(result) > DOCUMENT_TRUNCATION_THRESHOLD:
        result = result[:DOCUMENT_TRUNCATION_KEEP] + _TRUNCATION_SUFFIX

    return result
