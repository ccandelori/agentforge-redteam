"""YAML rubric loader for the Judge agent.

A rubric file declares the **shape** of a Judge verdict for a given attack
category: which sub-attacks the rubric covers, what individual checks to run,
and how check outcomes map to severities. Every rubric's bytes are SHA-256
hashed and the hash is recorded on every :class:`~agentforge_redteam.state.VerdictRecord`
it produced; the combined set hash lands on ``run_manifests.rubric_set_sha``
so an entire run can be tied to the exact rubric revision that scored it.

This module validates the **structure** of rubric YAML. Semantic checks
(e.g. that ``severity_map`` keys match the four canonical outcome keys in
``agentforge_redteam.severity``) belong in the severity module, not here —
the loader stays narrow so it can be reused unchanged when new outcome keys
are introduced.

The loader reads from disk on every call. A higher-level cache may be added
in a future task without changing this contract.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Final, Literal

import yaml
from pydantic import BaseModel, Field

CheckType = Literal["deterministic", "llm"]
Severity = Literal["P0", "P1", "P2", "P3"]

DEFAULT_RUBRICS_DIR: Final[Path] = Path("rubrics")


class RubricCheck(BaseModel):
    """One named check applied by the Judge as part of a rubric."""

    model_config = {"frozen": True, "extra": "forbid"}

    name: str = Field(min_length=1)
    type: CheckType
    criteria: str = Field(min_length=1)
    severity_contribution: str = Field(min_length=1)


class VerdictSchemaShape(BaseModel):
    """The shape Judge output must match.

    The loader validates the SHAPE here; Pydantic's
    :class:`~agentforge_redteam.state.VerdictRecord` validates the Judge's
    actual fill at runtime. ``verdict`` is the list of accepted verdict
    strings; the other fields are type tags (e.g. ``"float"``,
    ``"list[str]"``) describing the expected Python type.
    """

    model_config = {"frozen": True, "extra": "forbid"}

    verdict: list[str] = Field(min_length=1)
    confidence: str = Field(min_length=1)
    evidence_refs: str = Field(min_length=1)
    notes: str = Field(min_length=1)


class Rubric(BaseModel):
    """A validated rubric, anchored by the SHA-256 of its on-disk bytes."""

    model_config = {"frozen": True, "extra": "forbid"}

    version: str = Field(min_length=1)
    category: str = Field(min_length=1)
    sub_attacks: list[str] = Field(min_length=1)
    verdict_schema: VerdictSchemaShape
    checks: list[RubricCheck] = Field(min_length=1)
    severity_map: dict[str, Severity] = Field(min_length=1)
    # Not in YAML — attached by the loader after reading the file.
    sha: str = Field(min_length=64, max_length=64)


class RubricNotFoundError(FileNotFoundError):
    """Raised when :func:`load_rubric` is called for a category with no YAML.

    Subclasses :class:`FileNotFoundError` so existing
    ``except FileNotFoundError`` handlers still catch it.
    """


def _read_and_hash(path: Path) -> tuple[bytes, str]:
    """Return (raw_bytes, sha256_hex_digest) for ``path``."""
    raw = path.read_bytes()
    return raw, hashlib.sha256(raw).hexdigest()


def _build_rubric(raw_bytes: bytes, sha: str) -> Rubric:
    """Parse YAML bytes into a :class:`Rubric`, attaching ``sha``."""
    # ``yaml.safe_load`` only — never ``yaml.load``. Untrusted YAML must not be
    # able to instantiate arbitrary Python objects.
    data = yaml.safe_load(raw_bytes)
    if not isinstance(data, dict):
        # Force a clean ValidationError rather than a TypeError from
        # model_validate on a non-dict.
        data = {"__root__": data}
    data["sha"] = sha
    return Rubric.model_validate(data)


def load_rubric(category: str, rubrics_dir: Path | str = DEFAULT_RUBRICS_DIR) -> Rubric:
    """Read ``rubrics_dir/{category}.yaml``, validate, and attach its SHA.

    The filename convention is ``<category>.yaml``. For the canonical example
    rubric the file is named ``example.yaml`` rather than its category —
    callers looking up ``prompt-injection-indirect`` should rely on
    :func:`load_all_rubrics` (which keys by the file's ``category`` field) or
    ensure a category-named file exists. To keep ``load_rubric`` predictable,
    we first try ``{category}.yaml``; if missing, we fall back to scanning
    every YAML in the directory for a matching ``category`` field.
    """
    directory = Path(rubrics_dir)
    direct = directory / f"{category}.yaml"
    if direct.is_file():
        raw, sha = _read_and_hash(direct)
        return _build_rubric(raw, sha)

    # Fall back to a directory scan keyed by the YAML's ``category`` field.
    # This is what lets ``rubrics/example.yaml`` answer to category
    # ``prompt-injection-indirect``.
    for candidate in sorted(directory.glob("*.yaml")):
        raw, sha = _read_and_hash(candidate)
        rubric = _build_rubric(raw, sha)
        if rubric.category == category:
            return rubric

    raise RubricNotFoundError(f"No rubric for category {category!r} in {directory}")


def load_all_rubrics(
    rubrics_dir: Path | str = DEFAULT_RUBRICS_DIR,
) -> dict[str, Rubric]:
    """Load every ``*.yaml`` in ``rubrics_dir``, keyed by ``category`` field.

    Non-YAML files (e.g. ``SCHEMA.md``, stray ``notes.md``) are silently
    skipped. Malformed YAML or schema-violating content raises
    :class:`pydantic.ValidationError`.
    """
    directory = Path(rubrics_dir)
    out: dict[str, Rubric] = {}
    for path in sorted(directory.glob("*.yaml")):
        raw, sha = _read_and_hash(path)
        rubric = _build_rubric(raw, sha)
        out[rubric.category] = rubric
    return out


def rubric_set_sha(rubrics_dir: Path | str = DEFAULT_RUBRICS_DIR) -> str:
    """SHA-256 of the concatenation of every rubric's SHA, sorted by category.

    Stored in ``run_manifests.rubric_set_sha`` so a run can be replayed
    against the exact rubric set that scored it.
    """
    rubrics = load_all_rubrics(rubrics_dir)
    joined = "".join(rubrics[cat].sha for cat in sorted(rubrics))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()
