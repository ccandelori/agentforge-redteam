"""Regression test-case shape and Git-trackable JSON serialization.

A :class:`RegressionTestCase` is the harness's source of truth: one JSON file
per confirmed finding under ``evals/regressions/<finding_id>.json``. The file
is small, diffable, and Git-trackable so reviewers can see exactly which
findings have been promoted and what each one expects on replay.

The case captures three load-bearing anchors:

* ``original_target_sha`` — the build SHA the original finding was filed
  against. Replays compare a *new* target_sha to this one; matching SHAs
  imply the harness is replaying against the same build (useful for
  determinism checks but not regression detection).
* ``rubric_sha`` — the SHA-256 of the rubric bytes that *originally* judged
  the finding. The harness re-runs the SAME rubric SHA on replay, not the
  latest rubric on disk. If the rubric file has drifted, the harness logs a
  warning but proceeds with the recorded SHA so old findings remain valid
  under the rubric that produced them.
* ``expected_verdict`` / ``expected_confidence`` — the original Judge ruling.
  The replay compares its new ruling against these.

The JSON layout is deliberately flat. Pydantic's ``model_dump_json`` is used
so datetimes serialize to ISO-8601 with the ``Z`` suffix and UUIDs serialize
to their canonical 36-character string form — keeping the on-disk format
stable across Python versions.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Final, Literal
from uuid import UUID

from pydantic import BaseModel, Field

REGRESSIONS_DIR: Final[Path] = Path("evals/regressions")

Verdict = Literal["pass", "fail", "partial", "inconclusive"]
# Status taxonomy for a regression replay outcome. The literal values are the
# CONTRACT the harness produces and the runner aggregates; downstream consumers
# (CLI summary print, CI gate) pattern-match on these strings.
#
# Semantics — anchored to the platform's verdict convention where
# ``verdict='pass'`` means "the attack SUCCEEDED" (a vulnerability was
# confirmed) and ``verdict='fail'`` means "the attack FAILED" (defense held):
#
# * ``held``           — the original attack no longer succeeds (or its outcome
#                        is materially the same and the fix has not slipped).
#                        The good outcome.
# * ``regressed``      — the original attack still succeeds, OR a previously-
#                        defended attack now succeeds. A CI gate fails on this.
# * ``weakly_passing`` — the original attack still succeeds but the Judge is
#                        meaningfully less confident, OR the new verdict is
#                        ``partial`` (the fix is incomplete). Warning, not
#                        a hard fail.
# * ``inconclusive``   — the Judge couldn't classify the replay outcome.
#                        Surfaced as its own bucket so operators don't confuse
#                        a Judge ambiguity for a real regression.
RegressionStatus = Literal["held", "regressed", "weakly_passing", "inconclusive"]


class RegressionTestCase(BaseModel):
    """A finding promoted to a deterministic regression test.

    The fields below are enough to replay the attack and re-judge it against
    the ORIGINAL rubric — independent of any later platform evolution. The
    model is ``frozen`` so a loaded case can be safely shared across the
    harness's replay logic without copy-on-mutate concerns.
    """

    model_config = {"frozen": True, "extra": "forbid"}

    finding_id: UUID
    attack_id: UUID
    payload: str = Field(min_length=1)
    target_url: str = Field(min_length=1)
    original_target_sha: str = Field(min_length=1)
    rubric_sha: str = Field(min_length=64, max_length=64)
    rubric_category: str = Field(min_length=1)
    expected_verdict: Verdict
    expected_confidence: float = Field(ge=0.0, le=1.0)
    promoted_at: datetime


def case_path(finding_id: UUID, root: Path | str = REGRESSIONS_DIR) -> Path:
    """Return the on-disk path for ``finding_id``'s test-case JSON.

    The filename is the canonical 36-character UUID string with a ``.json``
    suffix — directly addressable from a ``finding_id`` without a directory
    scan.
    """
    return Path(root) / f"{finding_id}.json"


def write_case(case: RegressionTestCase, root: Path | str = REGRESSIONS_DIR) -> Path:
    """Write ``case`` to ``<root>/<finding_id>.json`` and return the path.

    Refuses to overwrite an existing file (raises :class:`FileExistsError`).
    The ``finding_id`` is the unique key for a promoted finding; overwriting
    silently would erase the original-finding anchor a regression is meant to
    detect against. Callers that genuinely want to re-promote a finding must
    delete the file (and audit-trail it) first.

    Parent directories are created on demand so the very first promotion in
    a fresh checkout works without a separate ``mkdir`` step.
    """
    path = case_path(case.finding_id, root)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(
            f"regression test case already exists at {path}; "
            "delete it explicitly before re-promoting"
        )
    # ``indent=2`` keeps the file diff-friendly for code review; Pydantic's
    # serializer handles UUID -> str and datetime -> ISO-8601 automatically.
    path.write_text(case.model_dump_json(indent=2), encoding="utf-8")
    return path


def read_case(path: Path | str) -> RegressionTestCase:
    """Read and validate a test-case JSON file from disk."""
    text = Path(path).read_text(encoding="utf-8")
    return RegressionTestCase.model_validate_json(text)
