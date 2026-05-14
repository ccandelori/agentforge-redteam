"""SHA-keyed rubric bytes cache for true historical regression replay.

Why this exists
---------------
Promoted regression cases (``evals/regressions/<finding_id>.json``) carry
the SHA-256 of the rubric YAML the Judge used at promotion time. If
someone edits a rubric after a case is promoted, the on-disk rubric SHA
no longer matches the recorded SHA. Without this cache the harness was
forced to either:

* Replay against the current rubric (with a drift warning) — silently
  scoring against a different rubric than the one the case was anchored
  to. The audit specifically called this out.
* Hard-fail the replay with "rubric drift, cannot continue" — too rigid
  for real workflows where rubrics evolve.

This module gives us a third option: cache the rubric bytes by SHA when
a case is promoted, then load by SHA at replay time. The cache lives at
``evals/regressions/.rubric_cache/<sha256>.yaml`` and IS committed to
the repo (NOT gitignored) — a fresh checkout has everything it needs to
replay every promoted case against the rubric that originally judged it.

Cache shape
-----------
* Filename: ``<sha256>.yaml`` where the SHA is the SHA-256 of the
  raw bytes (the same SHA recorded on the verdict and the case).
* Content: the verbatim bytes of the rubric YAML at promotion time.
* Verification: at read time we recompute the SHA from the bytes and
  reject any mismatch (a corrupted cache file would otherwise silently
  produce a different rubric than the case promised).

The cache is content-addressable so the operator can ``ls`` the
directory to see every historical rubric version anchored to a
promoted case. No category-name coupling — two categories that happen
to have the same rubric YAML bytes share one cache entry.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Final

from agentforge_redteam.regression.case import REGRESSIONS_DIR
from agentforge_redteam.rubrics.loader import Rubric, _build_rubric

DEFAULT_CACHE_DIR: Final[Path] = REGRESSIONS_DIR / ".rubric_cache"


def cache_path(sha: str, root: Path | str = DEFAULT_CACHE_DIR) -> Path:
    """Where ``sha``'s bytes live (or would live) in the cache."""
    return Path(root) / f"{sha}.yaml"


def cache_rubric_bytes(raw_bytes: bytes, root: Path | str = DEFAULT_CACHE_DIR) -> str:
    """Write ``raw_bytes`` to ``<root>/<sha256>.yaml`` and return the SHA.

    Idempotent: if the file already exists with the same content, we
    leave it alone. If it exists with DIFFERENT content (cache corruption
    / hash collision — astronomically improbable for SHA-256, but loud
    is better than silent), we raise ``ValueError`` rather than overwrite.
    """
    sha = hashlib.sha256(raw_bytes).hexdigest()
    path = cache_path(sha, root)
    if path.exists():
        existing = path.read_bytes()
        if existing != raw_bytes:
            raise ValueError(
                f"rubric cache collision at {path}: existing bytes "
                f"({len(existing)}) differ from new bytes ({len(raw_bytes)}); "
                f"refusing to overwrite. Investigate manually — SHA-256 "
                f"collision is astronomically improbable, more likely a "
                f"corrupted cache file."
            )
        return sha
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw_bytes)
    return sha


def load_cached_rubric(sha: str, root: Path | str = DEFAULT_CACHE_DIR) -> Rubric | None:
    """Load and validate the cached rubric for ``sha``. ``None`` on cache miss.

    Verifies the on-disk bytes hash to ``sha`` before returning. A
    mismatch (corrupted cache file, manual edit, unrelated bytes pasted
    in) raises ``ValueError`` — silently returning the wrong rubric
    would defeat the purpose of the SHA anchor.
    """
    path = cache_path(sha, root)
    if not path.is_file():
        return None
    raw = path.read_bytes()
    actual_sha = hashlib.sha256(raw).hexdigest()
    if actual_sha != sha:
        raise ValueError(
            f"rubric cache integrity error at {path}: file's actual SHA "
            f"is {actual_sha} but it lives at {sha}.yaml. Refusing to "
            f"return the bytes — this would silently swap the rubric on "
            f"the harness."
        )
    # ``_build_rubric`` is the same parser ``load_rubric`` uses; we hit
    # it directly so the resulting Rubric carries the cached SHA in its
    # ``sha`` field (rather than re-hashing from disk).
    return _build_rubric(raw, sha)
