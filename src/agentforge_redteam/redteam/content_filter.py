"""Deterministic content filter — last line of defense before a payload reaches the target.

The Red Team agent is authorized to probe the in-scope healthcare assistant, but
it is NOT authorized to deliver real-exploit, CBRN, child-safety, or working-
malware content to *anything*. This module enforces that boundary by refusing
matching payloads BEFORE they ever hit the wire.

Design choices
--------------
* **Loud fail, not silent redaction.** :class:`PayloadRefused` propagates out of
  the Red Team node so the orchestrator notices the configuration drift. A
  payload that trips the filter is treated as a programming error, not as
  attack traffic to be munged.
* **Compile patterns at import.** The patterns are cheap to author and the
  module is imported once at boot, so we accept the trivially-larger import
  cost to avoid per-call recompilation.
* **Distinct from the sanitizer.** :mod:`agentforge_redteam.sanitizer` redacts
  PHI from observed traffic AFTER the fact (for HIPAA-evidentiary logs). This
  module refuses BEFORE the fact and never modifies the payload.
"""

from __future__ import annotations

import re
from typing import Final


class PayloadRefused(Exception):
    """Raised when a payload trips the content filter.

    The first positional argument names the category that matched
    (e.g. ``"cbrn"`` or ``"exploit_code"``). Callers should NOT catch this and
    retry — a tripped filter means the seed library or the LLM mutation is
    producing out-of-scope content and the engagement owner needs to know.
    """


OUT_OF_SCOPE_PATTERNS: Final[dict[str, re.Pattern[str]]] = {
    "cbrn": re.compile(
        r"\b(anthrax|sarin|VX nerve|enriched uranium|plutonium-239|botulinum toxin|smallpox)\b",
        re.IGNORECASE,
    ),
    "exploit_code": re.compile(
        r"\b(metasploit|/etc/passwd|nc -lvnp|reverse shell|RCE payload|0day exploit)\b",
        re.IGNORECASE,
    ),
    "child_safety": re.compile(
        r"\b(CSAM|child sexual|underage)\b",
        re.IGNORECASE,
    ),
    "malware": re.compile(
        r"\b(WannaCry|Emotet|ransomware payload|keylogger source)\b",
        re.IGNORECASE,
    ),
}


def filter_payload(payload: str) -> str:
    """Return ``payload`` unchanged if it is in-scope; raise otherwise.

    The patterns are scanned in insertion order. The first match wins and its
    category name is passed as the exception's first positional argument so
    the audit log records *why* a payload was refused, not just *that* it was.
    """
    for category, pattern in OUT_OF_SCOPE_PATTERNS.items():
        if pattern.search(payload):
            raise PayloadRefused(category)
    return payload
