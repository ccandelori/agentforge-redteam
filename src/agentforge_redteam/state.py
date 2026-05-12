"""LangGraph state contract for the AgentForge red-team platform.

All four agents (Red Team, Judge, Orchestrator, Documentation) read and write
these typed records. The :class:`PlatformState` aggregate is the LangGraph
state itself; the inner records (:class:`AttackRecord`, :class:`VerdictRecord`,
:class:`ConfirmedFinding`) form the audit log we eventually persist for HIPAA
evidence.

Money is tracked as :class:`decimal.Decimal` (never ``float``) so that summed
costs are reproducible across runs.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, model_validator

Verdict = Literal["pass", "fail", "partial", "inconclusive"]


class CampaignBrief(BaseModel):
    """Orchestrator-issued plan for one attack campaign.

    A *canary* campaign is a known-answer probe injected periodically to keep
    the Judge honest: we already know what verdict it should return, and any
    deviation is a signal the Judge has drifted. The invariants below enforce
    that canary metadata is only present on canary campaigns and is always
    present when ``is_canary`` is set.
    """

    category: str
    sub_attack: str
    budget_cents: int = Field(ge=0)
    is_canary: bool = False
    canary_expected_verdict: Verdict | None = None

    @model_validator(mode="after")
    def _check_canary_invariant(self) -> CampaignBrief:
        if self.is_canary and self.canary_expected_verdict is None:
            raise ValueError("canary_expected_verdict must be set when is_canary is True")
        if not self.is_canary and self.canary_expected_verdict is not None:
            raise ValueError("canary_expected_verdict must be None when is_canary is False")
        return self


class AttackRecord(BaseModel):
    """One adversarial probe sent to the target and the response received.

    ``target_response`` may be empty because a guard-railed target sometimes
    refuses silently or 204s us. ``target_sha`` ties the record to a specific
    build of the target so a verdict isn't accidentally compared against a
    later, patched build.
    """

    attack_id: UUID = Field(default_factory=uuid4)
    campaign_id: UUID
    payload: str = Field(min_length=1)
    target_response: str
    target_sha: str = Field(min_length=1)
    status_code: int = Field(ge=100, le=599)
    latency_ms: int = Field(ge=0)


class VerdictRecord(BaseModel):
    """A Judge agent's structured ruling on a single attack.

    Reproducibility anchors
    -----------------------
    The triple ``(rubric_sha, model_version, prompt_sha)`` is what makes a
    verdict replayable: given the same target build and the same three SHAs,
    re-running the Judge must yield the same verdict (modulo LLM non-
    determinism, which the wrapper records via ``agent_steps``).

    ``prompt_sha`` is currently ``Optional[str]`` for backward compatibility
    with verdict rows produced before the field landed on this model. A
    future migration will tighten this to ``Field(min_length=1)`` once
    historic rows are backfilled. New verdicts emitted by the Judge MUST
    populate it.
    """

    verdict_id: UUID = Field(default_factory=uuid4)
    attack_id: UUID
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_refs: list[str] = Field(default_factory=list)
    rubric_sha: str = Field(min_length=1)
    model_version: str = Field(min_length=1)
    prompt_sha: str | None = None


class ConfirmedFinding(BaseModel):
    """A Judge verdict that has been triaged into a tracked finding.

    Linked back to the originating attack/verdict for audit traceability.
    ``gitlab_issue_id`` is filled in once the Documentation agent files the
    issue in GitLab; it is ``None`` until then.
    """

    finding_id: UUID = Field(default_factory=uuid4)
    severity: Literal["P0", "P1", "P2", "P3"]
    attack_id: UUID
    verdict_id: UUID
    gitlab_issue_id: int | None = None


class PlatformState(BaseModel):
    """The LangGraph state shared across all four agents.

    Money is tracked as :class:`Decimal` so that incremental cost updates
    sum cleanly without binary-float drift. ``session_id`` is supplied by the
    caller (the CLI / orchestrator entry point); we don't generate one here so
    that the same session can be resumed after a crash.
    """

    session_id: str = Field(min_length=1)
    cost_so_far: Decimal = Field(default=Decimal("0"), ge=Decimal("0"))
    campaigns_run: int = Field(default=0, ge=0)
    current_campaign: CampaignBrief | None = None
    attack_records: list[AttackRecord] = Field(default_factory=list)
    verdict_records: list[VerdictRecord] = Field(default_factory=list)
    confirmed_findings: list[ConfirmedFinding] = Field(default_factory=list)
    halt_reason: str | None = None
