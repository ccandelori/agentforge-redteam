"""Durable canary-failure event recorder.

When the Judge raises :class:`CanaryMismatch` (Task 26), we want a structured
row in the audit log so a human (or a monitoring query) can answer "how often
has the Judge drifted in the last 7d?" without scraping logs. This module
writes that row to ``agent_steps`` under a stable, queryable
``tool='canary_failed'`` marker.

We piggy-back on ``agent_steps`` rather than introducing a new table because:

* The schema is already migrated and indexed by ``session_id + timestamp``.
* Coverage / drift queries already join through ``agent_steps``; adding the
  canary marker there means they pick it up for free.
* The row carries an ``args`` JSON blob — perfect for the
  (expected, actual, confidence_delta) tuple without a schema migration.

Design choices:

* **No dedup.** A repeat ``record_canary_failure`` call writes a second row.
  Canary failures are cheap to over-record and under-recording would silently
  lose audit value. If the same mismatch fires twice in a session that's a
  meaningful signal in itself.
* **Synchronous, single-statement INSERT.** No ``call_tool`` wrapping — the
  wrapper exists to instrument *active* tool calls (open-row / close-row);
  this is a passive event record. A single INSERT keeps the latency cost of
  a canary trip negligible.
* **No cost / latency.** The fields default to ``0`` in the schema; we leave
  them there. A canary record is not a billable LLM call.
"""

from __future__ import annotations

import json
from typing import Final
from uuid import UUID, uuid4

from sqlalchemy import text as sql_text
from sqlalchemy.engine import Engine

CANARY_FAILED_TOOL_NAME: Final[str] = "canary_failed"
CANARY_FAILED_AGENT: Final[str] = "judge"


def record_canary_failure(
    engine: Engine,
    *,
    session_id: str,
    case_id: UUID,
    expected_verdict: str,
    actual_verdict: str,
    confidence_delta: float,
) -> None:
    """INSERT a synthetic ``agent_steps`` row marking a canary-Judge mismatch.

    The ``args`` and ``result`` JSON columns both carry the
    (case_id, expected, actual, confidence_delta) tuple. We mirror the same
    payload into both columns so downstream queries can read whichever they
    prefer; the wrapper convention has the args being request-side and the
    result being response-side, and a canary failure is conceptually both.

    Parameters
    ----------
    engine:
        Engine pointed at the migrated platform DB. Caller owns the engine
        lifecycle.
    session_id:
        The active session — matches ``run_manifests.session_id`` and the
        rest of the audit log written in this run.
    case_id:
        UUID of the :class:`GroundTruthCase` that was injected.
    expected_verdict:
        The verdict the canary case declared.
    actual_verdict:
        The verdict the Judge actually returned.
    confidence_delta:
        Numeric drift signal — typically ``judge_confidence - expected_conf``
        (sign-preserving), or ``0.0`` when the caller has no confidence
        signal to compare against.

    Notes
    -----
    Idempotency: this function is **not** idempotent. Two calls produce two
    rows. See module docstring for the rationale.
    """
    payload = {
        "case_id": str(case_id),
        "expected_verdict": expected_verdict,
        "actual_verdict": actual_verdict,
        "confidence_delta": confidence_delta,
    }
    payload_json = json.dumps(payload)
    step_id = str(uuid4())
    with engine.begin() as conn:
        conn.execute(
            sql_text(
                "INSERT INTO agent_steps "
                "(step_id, agent, tool, args, result, cost_cents, latency_ms, "
                "session_id) "
                "VALUES (:step_id, :agent, :tool, :args, :result, 0, 0, "
                ":session_id)"
            ),
            {
                "step_id": step_id,
                "agent": CANARY_FAILED_AGENT,
                "tool": CANARY_FAILED_TOOL_NAME,
                "args": payload_json,
                "result": payload_json,
                "session_id": session_id,
            },
        )
