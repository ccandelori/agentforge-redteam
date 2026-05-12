"""Loader for the hand-crafted seed payloads in ``attack_library.json``.

The Red Team agent reads this file at boot to seed its first wave of mutations.
Downstream code must never trust the raw JSON: we validate it through
:class:`AttackLibrary` (Pydantic v2) and only hand out frozen models.

The SHA-256 of the on-disk bytes is recorded in ``run_manifests.attack_library_sha``
so a campaign can be tied back to the exact seed set it was launched from.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Final

from pydantic import BaseModel, Field

ATTACK_LIBRARY_PATH: Final[Path] = Path("attack_library.json")


class AttackSeed(BaseModel):
    """One hand-crafted seed payload from attack_library.json."""

    model_config = {"frozen": True, "extra": "forbid"}

    category: str = Field(min_length=1)
    sub_attack: str = Field(min_length=1)
    payload: str = Field(min_length=1, max_length=4000)
    notes: str = Field(min_length=1)


class AttackLibrary(BaseModel):
    """The validated, in-memory view of ``attack_library.json``.

    The schema does not pin the number of seeds: the "exactly 9" property is
    enforced by tests against the committed file, not by the loader, so that
    we can grow the library without changing this module.
    """

    model_config = {"frozen": True, "extra": "forbid"}

    version: int = Field(ge=1)
    attacks: list[AttackSeed] = Field(min_length=1)


def load_attack_library(path: Path | str = ATTACK_LIBRARY_PATH) -> AttackLibrary:
    """Read, JSON-decode, and validate the attack library at ``path``.

    A missing file raises :class:`FileNotFoundError`; a malformed payload
    propagates :class:`pydantic.ValidationError`. Callers should *not* catch
    these — a broken library is a deploy-time bug, not a runtime branch.
    """
    raw = Path(path).read_text(encoding="utf-8")
    data = json.loads(raw)
    return AttackLibrary.model_validate(data)


def seeds_for_category(category: str, path: Path | str = ATTACK_LIBRARY_PATH) -> list[AttackSeed]:
    """Return all seeds in ``category``; an unknown category yields ``[]``."""
    library = load_attack_library(path)
    return [seed for seed in library.attacks if seed.category == category]


def attack_library_sha(path: Path | str = ATTACK_LIBRARY_PATH) -> str:
    """SHA-256 of the file's bytes. Stored in run_manifests.attack_library_sha for reproducibility."""
    raw_bytes = Path(path).read_bytes()
    return hashlib.sha256(raw_bytes).hexdigest()
