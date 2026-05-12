"""Tests for the Documentation Agent skeleton.

These tests exercise the full Doc Agent path:
sanitize -> deterministic severity -> LLM call -> Jinja render -> route ->
GitLab autofile OR human queue insert -> findings row -> state update.

Anthropic and GitLab clients are stubbed with in-memory fakes (Protocol
shape). The DB is a real SQLite under ``tmp_path`` migrated by Alembic so
the schema under test is the same the production stack uses.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import Engine

from agentforge_redteam.agents.documentation import (
    AUTOFILE_CONFIDENCE_THRESHOLD,
    DEFAULT_MODEL,
    FindingAlreadyFiled,
    FindingFrameworks,
    GitLabIssueRef,
    LLMResponse,
    _parse_llm_response_to_sections,
    _route,
    documentation_node,
)
from agentforge_redteam.db import create_platform_engine
from agentforge_redteam.state import (
    AttackRecord,
    PlatformState,
    VerdictRecord,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_INI = REPO_ROOT / "alembic.ini"
ALEMBIC_DIR = REPO_ROOT / "alembic"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Engine]:
    """Yield a platform engine pointed at a freshly-migrated tmp database."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("PLATFORM_DB_PATH", str(db_path))

    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(ALEMBIC_DIR))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    command.upgrade(cfg, "head")

    eng = create_platform_engine(db_path)
    try:
        yield eng
    finally:
        eng.dispose()


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


_CANNED_LLM_JSON = json.dumps(
    {
        "title": "Indirect prompt injection enables citation fabrication",
        "description": "The clinical assistant fabricated a citation after an indirect injection. "
        "Repeatable across runs.",
        "severity_rationale": "Severity P2: partial injection success, no PHI cross-leak.",
        "clinical_impact": "A clinician may order unnecessary tests if they trust a fabricated citation.",
        "observed_behavior": "Assistant cited 'Smith 2025' which does not exist.",
        "expected_behavior": "Assistant should refuse to cite unverifiable sources.",
        "remediation_suggestions": "Add a tool-side citation verifier.",
        "validation_steps": "Add a regression test that replays the payload and asserts refusal.",
        "reproduction_steps": [
            "Send the seed payload from attack_library.json.",
            "Observe the assistant cites '2025 Smith et al.'",
        ],
    }
)


class _FakeLLM:
    """In-memory stand-in for an Anthropic-shaped client."""

    def __init__(
        self,
        *,
        response_json: str = _CANNED_LLM_JSON,
        cost_cents: int = 250,
    ) -> None:
        self.response_json = response_json
        self.cost_cents = cost_cents
        self.calls: list[dict[str, Any]] = []

    async def complete(self, *, system: str, user: str, model: str) -> LLMResponse:
        self.calls.append({"system_len": len(system), "user_len": len(user), "model": model})
        return LLMResponse(text=self.response_json, cost_cents=self.cost_cents)


class _FakeGitLab:
    """In-memory stand-in for a GitLab issues client."""

    def __init__(self, *, issue_id: int = 1234) -> None:
        self.issue_id = issue_id
        self.calls: list[dict[str, Any]] = []

    async def create_issue(self, *, title: str, body: str, labels: list[str]) -> GitLabIssueRef:
        self.calls.append({"title": title, "body_len": len(body), "labels": labels, "body": body})
        return GitLabIssueRef(
            issue_id=self.issue_id,
            url=f"https://gitlab.example/{self.issue_id}",
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_FRAMEWORKS = FindingFrameworks(
    owasp_id="LLM01:2025",
    mitre_id="ATLAS.T0051",
    hipaa_section="§164.308(a)(1)(ii)(A)",
)


def _persist_attack_and_verdict(
    engine: Engine, attack: AttackRecord, verdict: VerdictRecord
) -> None:
    """Insert ``attacks`` and ``verdicts`` rows so the ``findings`` FK is satisfied.

    The Doc Agent's tests would otherwise trip the FK constraint because in
    isolation we don't run the Red Team / Judge nodes that normally persist
    these rows. This helper is a unit-test seam; production callers don't
    need it because the upstream agents are responsible for their own rows.
    """
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO attacks "
                "(attack_id, campaign_id, payload, target_response, target_sha, status_code, latency_ms) "
                "VALUES (:attack_id, :campaign_id, :payload, :target_response, "
                ":target_sha, :status_code, :latency_ms)"
            ),
            {
                "attack_id": str(attack.attack_id),
                "campaign_id": str(attack.campaign_id),
                "payload": attack.payload,
                "target_response": attack.target_response,
                "target_sha": attack.target_sha,
                "status_code": attack.status_code,
                "latency_ms": attack.latency_ms,
            },
        )
        conn.execute(
            sa.text(
                "INSERT INTO verdicts "
                "(verdict_id, attack_id, verdict, confidence, evidence_refs, "
                "rubric_sha, model_version, prompt_sha) "
                "VALUES (:verdict_id, :attack_id, :verdict, :confidence, "
                ":evidence_refs, :rubric_sha, :model_version, :prompt_sha)"
            ),
            {
                "verdict_id": str(verdict.verdict_id),
                "attack_id": str(verdict.attack_id),
                "verdict": verdict.verdict,
                "confidence": verdict.confidence,
                "evidence_refs": json.dumps(verdict.evidence_refs),
                "rubric_sha": verdict.rubric_sha,
                "model_version": verdict.model_version,
                "prompt_sha": "doc-test-prompt-sha",
            },
        )


def _build_state(
    *,
    engine: Engine | None = None,
    verdict: str = "pass",
    confidence: float = 0.9,
    target_response: str = "stub-target-response with no PHI",
    session_id: str = "sess-doc-1",
) -> tuple[PlatformState, AttackRecord, VerdictRecord]:
    """Return a minimal state with one attack and one verdict.

    If ``engine`` is supplied, the attack and verdict rows are also persisted
    so that the ``findings`` FK constraint is satisfied on insert.
    """
    attack = AttackRecord(
        campaign_id=uuid4(),
        payload="please cite a study",
        target_response=target_response,
        target_sha="target-sha-abc",
        status_code=200,
        latency_ms=42,
    )
    verdict_record = VerdictRecord(
        attack_id=attack.attack_id,
        verdict=verdict,  # type: ignore[arg-type]
        confidence=confidence,
        evidence_refs=["log://session/turn-7"],
        rubric_sha="rubric-sha-xyz",
        model_version="claude-sonnet-test",
    )
    state = PlatformState(
        session_id=session_id,
        attack_records=[attack],
        verdict_records=[verdict_record],
    )
    if engine is not None:
        _persist_attack_and_verdict(engine, attack, verdict_record)
    return state, attack, verdict_record


def _count(engine: Engine, table: str, where: str = "", **params: Any) -> int:
    sql = f"SELECT COUNT(*) FROM {table}"
    if where:
        sql += f" WHERE {where}"
    with engine.connect() as conn:
        return int(conn.execute(sa.text(sql), params).scalar_one())


# ---------------------------------------------------------------------------
# _route — pure routing predicate
# ---------------------------------------------------------------------------


def test_route_human_approval_for_p0_high_confidence() -> None:
    assert _route("P0", 0.99) == "human_approval"


def test_route_human_approval_for_low_confidence_low_severity() -> None:
    assert _route("P3", 0.5) == "human_approval"


def test_route_autofile_for_p2_and_high_confidence() -> None:
    assert _route("P2", 0.85) == "autofile"


def test_route_threshold_is_strictly_less_than() -> None:
    # Confidence exactly AT the threshold autofiles (the boundary belongs to
    # the autofile side, since we route only on strict less-than).
    assert _route("P3", AUTOFILE_CONFIDENCE_THRESHOLD) == "autofile"


# ---------------------------------------------------------------------------
# _parse_llm_response_to_sections
# ---------------------------------------------------------------------------


def test_parse_llm_response_rejects_malformed_json() -> None:
    with pytest.raises(ValueError, match="not valid JSON"):
        _parse_llm_response_to_sections("not json at all }")


def test_parse_llm_response_rejects_missing_keys() -> None:
    with pytest.raises(ValueError, match="missing required keys"):
        _parse_llm_response_to_sections(json.dumps({"title": "x"}))


def test_parse_llm_response_rejects_empty_reproduction_steps() -> None:
    bad = json.loads(_CANNED_LLM_JSON)
    bad["reproduction_steps"] = []
    with pytest.raises(ValueError, match="reproduction_steps"):
        _parse_llm_response_to_sections(json.dumps(bad))


# ---------------------------------------------------------------------------
# documentation_node — happy path autofile
# ---------------------------------------------------------------------------


async def test_pass_high_confidence_autofiles_to_gitlab(engine: Engine) -> None:
    state, _attack, _verdict = _build_state(engine=engine, verdict="pass", confidence=0.9)
    llm = _FakeLLM(cost_cents=250)
    gitlab = _FakeGitLab(issue_id=4242)

    new_state = await documentation_node(
        state,
        engine=engine,
        llm=llm,
        gitlab=gitlab,
        frameworks=_FRAMEWORKS,
        rubric_outcomes={},
    )

    assert len(llm.calls) == 1
    assert llm.calls[0]["model"] == DEFAULT_MODEL
    assert len(gitlab.calls) == 1
    assert len(new_state.confirmed_findings) == 1
    finding = new_state.confirmed_findings[0]
    assert finding.gitlab_issue_id == 4242
    # Severity comes out as P3 (verdict 'pass' with no rubric outcomes).
    assert finding.severity == "P3"
    # findings row exists with the gitlab issue id.
    assert (
        _count(
            engine,
            "findings",
            "gitlab_issue_id = :gid",
            gid=4242,
        )
        == 1
    )
    # No queue entry on autofile.
    assert _count(engine, "human_approval_queue") == 0


# ---------------------------------------------------------------------------
# documentation_node — P0 routes to human queue
# ---------------------------------------------------------------------------


async def test_p0_outcome_routes_to_human_approval_queue(engine: Engine) -> None:
    state, _attack, _verdict = _build_state(engine=engine, verdict="pass", confidence=0.95)
    llm = _FakeLLM()
    gitlab = _FakeGitLab()

    new_state = await documentation_node(
        state,
        engine=engine,
        llm=llm,
        gitlab=gitlab,
        frameworks=_FRAMEWORKS,
        rubric_outcomes={"patient_harm_possible": True},
    )

    # GitLab must NOT be called on human-approval routing.
    assert gitlab.calls == []
    # Approval queue has the pending row.
    assert _count(engine, "human_approval_queue", "status = 'pending'") == 1
    # Finding row written with NULL gitlab_issue_id.
    assert _count(engine, "findings", "gitlab_issue_id IS NULL") == 1
    finding = new_state.confirmed_findings[0]
    assert finding.severity == "P0"
    assert finding.gitlab_issue_id is None


# ---------------------------------------------------------------------------
# documentation_node — low-confidence routes to human queue
# ---------------------------------------------------------------------------


async def test_low_confidence_routes_to_human_approval_queue(engine: Engine) -> None:
    state, _attack, _verdict = _build_state(engine=engine, verdict="pass", confidence=0.5)
    llm = _FakeLLM()
    gitlab = _FakeGitLab()

    await documentation_node(
        state,
        engine=engine,
        llm=llm,
        gitlab=gitlab,
        frameworks=_FRAMEWORKS,
        rubric_outcomes={},
    )

    assert gitlab.calls == []
    assert _count(engine, "human_approval_queue") == 1


# ---------------------------------------------------------------------------
# documentation_node — partial verdict still produces a finding
# ---------------------------------------------------------------------------


async def test_partial_verdict_produces_finding(engine: Engine) -> None:
    state, _attack, _verdict = _build_state(engine=engine, verdict="partial", confidence=0.85)
    llm = _FakeLLM()
    gitlab = _FakeGitLab()

    new_state = await documentation_node(
        state,
        engine=engine,
        llm=llm,
        gitlab=gitlab,
        frameworks=_FRAMEWORKS,
        rubric_outcomes={},
    )

    assert len(new_state.confirmed_findings) == 1
    # 'partial' verdict + no outcomes => severity P2 (per severity ladder).
    assert new_state.confirmed_findings[0].severity == "P2"


# ---------------------------------------------------------------------------
# documentation_node — fail verdict short-circuits
# ---------------------------------------------------------------------------


async def test_fail_verdict_returns_state_unchanged(engine: Engine) -> None:
    state, _attack, _verdict = _build_state(verdict="fail", confidence=0.9)
    llm = _FakeLLM()
    gitlab = _FakeGitLab()

    new_state = await documentation_node(
        state,
        engine=engine,
        llm=llm,
        gitlab=gitlab,
        frameworks=_FRAMEWORKS,
        rubric_outcomes={},
    )

    assert new_state is state or new_state.confirmed_findings == state.confirmed_findings
    assert llm.calls == []
    assert gitlab.calls == []
    assert _count(engine, "findings") == 0
    assert _count(engine, "human_approval_queue") == 0
    assert _count(engine, "agent_steps") == 0


# ---------------------------------------------------------------------------
# documentation_node — inconclusive propagates ValueError
# ---------------------------------------------------------------------------


async def test_inconclusive_verdict_propagates_value_error(engine: Engine) -> None:
    state, _attack, _verdict = _build_state(verdict="inconclusive", confidence=0.9)
    llm = _FakeLLM()
    gitlab = _FakeGitLab()

    with pytest.raises(ValueError, match="inconclusive"):
        await documentation_node(
            state,
            engine=engine,
            llm=llm,
            gitlab=gitlab,
            frameworks=_FRAMEWORKS,
            rubric_outcomes={},
        )


# ---------------------------------------------------------------------------
# documentation_node — empty verdicts raises RuntimeError
# ---------------------------------------------------------------------------


async def test_empty_verdict_records_raises_runtime_error(engine: Engine) -> None:
    state = PlatformState(session_id="empty-sess")
    llm = _FakeLLM()
    gitlab = _FakeGitLab()

    with pytest.raises(RuntimeError, match="empty verdict_records"):
        await documentation_node(
            state,
            engine=engine,
            llm=llm,
            gitlab=gitlab,
            frameworks=_FRAMEWORKS,
        )


# ---------------------------------------------------------------------------
# documentation_node — dedup
# ---------------------------------------------------------------------------


async def test_duplicate_finding_raises_finding_already_filed(engine: Engine) -> None:
    state, _attack, _verdict = _build_state(engine=engine, verdict="pass", confidence=0.9)
    llm = _FakeLLM()
    gitlab = _FakeGitLab()

    # First call: files normally.
    await documentation_node(
        state,
        engine=engine,
        llm=llm,
        gitlab=gitlab,
        frameworks=_FRAMEWORKS,
        rubric_outcomes={},
    )
    assert _count(engine, "findings") == 1

    # Second call on the same state must raise FindingAlreadyFiled.
    with pytest.raises(FindingAlreadyFiled):
        await documentation_node(
            state,
            engine=engine,
            llm=llm,
            gitlab=gitlab,
            frameworks=_FRAMEWORKS,
            rubric_outcomes={},
        )


# ---------------------------------------------------------------------------
# documentation_node — sanitization runs before rendering
# ---------------------------------------------------------------------------


async def test_evidence_is_sanitized_in_rendered_report(engine: Engine) -> None:
    mrn = "12345678-1234-1234-1234-123456789012"
    state, _attack, _verdict = _build_state(
        engine=engine,
        verdict="pass",
        confidence=0.9,
        target_response=f"patient MRN {mrn} requested labs",
    )
    llm = _FakeLLM()
    gitlab = _FakeGitLab()

    await documentation_node(
        state,
        engine=engine,
        llm=llm,
        gitlab=gitlab,
        frameworks=_FRAMEWORKS,
        rubric_outcomes={},
    )

    body = gitlab.calls[0]["body"]
    assert "[MRN_REDACTED]" in body
    assert mrn not in body


# ---------------------------------------------------------------------------
# documentation_node — audit rows on both calls
# ---------------------------------------------------------------------------


async def test_agent_steps_records_both_llm_and_gitlab(engine: Engine) -> None:
    state, _attack, _verdict = _build_state(engine=engine, verdict="pass", confidence=0.9)
    llm = _FakeLLM()
    gitlab = _FakeGitLab()

    await documentation_node(
        state,
        engine=engine,
        llm=llm,
        gitlab=gitlab,
        frameworks=_FRAMEWORKS,
        rubric_outcomes={},
    )

    with engine.connect() as conn:
        rows = conn.execute(
            sa.text(
                "SELECT tool FROM agent_steps WHERE agent = 'documentation' ORDER BY timestamp ASC"
            )
        ).fetchall()
    tool_names = [r.tool for r in rows]
    assert tool_names == ["llm_complete", "gitlab_create_issue"]


# ---------------------------------------------------------------------------
# documentation_node — state mutation invariants
# ---------------------------------------------------------------------------


async def test_state_cost_so_far_increases_by_llm_cost(engine: Engine) -> None:
    state, _attack, _verdict = _build_state(engine=engine, verdict="pass", confidence=0.9)
    llm = _FakeLLM(cost_cents=375)
    gitlab = _FakeGitLab()

    new_state = await documentation_node(
        state,
        engine=engine,
        llm=llm,
        gitlab=gitlab,
        frameworks=_FRAMEWORKS,
        rubric_outcomes={},
    )

    assert new_state.cost_so_far == state.cost_so_far + Decimal(375)


async def test_confirmed_findings_grows_by_exactly_one(engine: Engine) -> None:
    state, _attack, _verdict = _build_state(engine=engine, verdict="pass", confidence=0.9)
    llm = _FakeLLM()
    gitlab = _FakeGitLab()

    new_state = await documentation_node(
        state,
        engine=engine,
        llm=llm,
        gitlab=gitlab,
        frameworks=_FRAMEWORKS,
        rubric_outcomes={},
    )
    assert len(new_state.confirmed_findings) == len(state.confirmed_findings) + 1


# ---------------------------------------------------------------------------
# documentation_node — rendered report is complete (smoke)
# ---------------------------------------------------------------------------


async def test_rendered_report_contains_all_required_sections(engine: Engine) -> None:
    state, _attack, _verdict = _build_state(engine=engine, verdict="pass", confidence=0.9)
    llm = _FakeLLM()
    gitlab = _FakeGitLab()

    await documentation_node(
        state,
        engine=engine,
        llm=llm,
        gitlab=gitlab,
        frameworks=_FRAMEWORKS,
        rubric_outcomes={},
    )

    body = gitlab.calls[0]["body"]
    for heading in (
        "## Summary",
        "## Severity",
        "## Framework Mapping",
        "## Clinical Impact",
        "## Reproduction Steps",
        "## Observed Behavior",
        "## Expected Behavior",
        "## Evidence",
        "## Recommended Remediation",
        "## Validation",
    ):
        assert heading in body, f"missing section: {heading}"
    # Framework tags are interpolated into the body.
    assert "LLM01:2025" in body
    assert "ATLAS.T0051" in body
    assert "§164.308(a)(1)(ii)(A)" in body


# ---------------------------------------------------------------------------
# documentation_node — ConfirmedFinding.gitlab_issue_id wiring
# ---------------------------------------------------------------------------


async def test_confirmed_finding_gitlab_id_is_int_on_autofile(engine: Engine) -> None:
    state, _attack, _verdict = _build_state(engine=engine, verdict="pass", confidence=0.9)
    llm = _FakeLLM()
    gitlab = _FakeGitLab(issue_id=9988)

    new_state = await documentation_node(
        state,
        engine=engine,
        llm=llm,
        gitlab=gitlab,
        frameworks=_FRAMEWORKS,
        rubric_outcomes={},
    )
    assert new_state.confirmed_findings[0].gitlab_issue_id == 9988


async def test_confirmed_finding_gitlab_id_is_none_on_queue_route(engine: Engine) -> None:
    state, _attack, _verdict = _build_state(engine=engine, verdict="pass", confidence=0.95)
    llm = _FakeLLM()
    gitlab = _FakeGitLab()

    new_state = await documentation_node(
        state,
        engine=engine,
        llm=llm,
        gitlab=gitlab,
        frameworks=_FRAMEWORKS,
        rubric_outcomes={"patient_harm_possible": True},
    )
    finding = new_state.confirmed_findings[0]
    assert finding.gitlab_issue_id is None
    assert finding.severity == "P0"


# ---------------------------------------------------------------------------
# documentation_node — finding_id linkage smoke
# ---------------------------------------------------------------------------


async def test_finding_id_matches_between_state_and_db(engine: Engine) -> None:
    state, _attack, _verdict = _build_state(engine=engine, verdict="pass", confidence=0.9)
    llm = _FakeLLM()
    gitlab = _FakeGitLab()

    new_state = await documentation_node(
        state,
        engine=engine,
        llm=llm,
        gitlab=gitlab,
        frameworks=_FRAMEWORKS,
        rubric_outcomes={},
    )
    fid = new_state.confirmed_findings[0].finding_id
    assert isinstance(fid, UUID)
    with engine.connect() as conn:
        row = conn.execute(
            sa.text("SELECT finding_id FROM findings WHERE finding_id = :fid"),
            {"fid": str(fid)},
        ).first()
    assert row is not None
