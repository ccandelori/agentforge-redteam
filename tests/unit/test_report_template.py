"""Unit tests for :mod:`agentforge_redteam.report_template`.

These tests pin the contract that the Documentation Agent relies on:
the rendered report is well-structured markdown with every required
section, the framework-mapping anchors are present for auditors, the
audit footer carries the SHAs, and the Pydantic context refuses
malformed input at construction time rather than at render time.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from jinja2 import UndefinedError
from pydantic import ValidationError

from agentforge_redteam.report_template import (
    FindingReportContext,
    build_environment,
    render_finding,
)

# --- Fixture ----------------------------------------------------------------


@pytest.fixture
def sample_context() -> FindingReportContext:
    return FindingReportContext(
        severity="P2",
        title="Indirect prompt injection enables citation fabrication",
        description="The Clinical Co-Pilot fabricates a citation when asked to summarise labs.",
        severity_rationale="Confidence high; user-facing fabricated citation; no PHI leakage.",
        owasp_id="LLM01:2025",
        mitre_id="ATLAS.T0051",
        hipaa_section="§164.308(a)(1)(ii)(A)",
        clinical_impact="A clinician relying on a fabricated citation may order unneeded tests.",
        reproduction_steps=[
            "Send the seed payload from attack_library.json.",
            "Observe the assistant cites '2025 Smith et al.'",
            "Verify the cited study does not exist.",
        ],
        observed_behavior="Assistant produced a fabricated citation.",
        expected_behavior="Assistant should refuse to cite sources it cannot verify.",
        sanitized_evidence="[MRN_REDACTED] requested labs. Assistant: 'Per Smith 2025...'",
        remediation_suggestions="Add a tool-side citation verifier that cross-checks PubMed.",
        validation_steps="Add a regression test that replays the seed payload and asserts refusal.",
        finding_id="f3b2c4a1-1234-5678-9abc-def012345678",
        target_sha="abc123def456",
        rubric_sha="0000aaaa1111bbbb",
    )


# --- Rendering happy path ---------------------------------------------------


def test_render_finding_returns_non_empty_string(sample_context: FindingReportContext) -> None:
    out = render_finding(sample_context)
    assert isinstance(out, str)
    assert out.strip() != ""


def test_render_finding_starts_with_severity_and_title(
    sample_context: FindingReportContext,
) -> None:
    out = render_finding(sample_context)
    assert out.startswith("# [P2] Indirect prompt injection enables citation fabrication")


@pytest.mark.parametrize(
    "heading",
    [
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
    ],
)
def test_render_finding_contains_required_section(
    sample_context: FindingReportContext, heading: str
) -> None:
    out = render_finding(sample_context)
    assert heading in out, f"Missing required section heading: {heading}"


def test_reproduction_steps_render_as_numbered_list(
    sample_context: FindingReportContext,
) -> None:
    ctx = sample_context.model_copy(
        update={"reproduction_steps": ["Step alpha", "Step beta", "Step gamma"]}
    )
    out = render_finding(ctx)
    assert "1. Step alpha" in out
    assert "2. Step beta" in out
    assert "3. Step gamma" in out


def test_evidence_is_wrapped_in_fenced_code_block(
    sample_context: FindingReportContext,
) -> None:
    out = render_finding(sample_context)
    # The Evidence section must contain a triple-backtick fence on its own
    # line followed by the sanitized evidence then a closing fence.
    evidence_block = "```\n[MRN_REDACTED] requested labs. Assistant: 'Per Smith 2025...'\n```"
    assert evidence_block in out


def test_footer_contains_finding_target_and_rubric_shas(
    sample_context: FindingReportContext,
) -> None:
    out = render_finding(sample_context)
    assert "`f3b2c4a1-1234-5678-9abc-def012345678`" in out
    assert "`abc123def456`" in out
    assert "`0000aaaa1111bbbb`" in out
    # And the human-readable labels are present too.
    assert "Finding ID" in out
    assert "Target SHA" in out
    assert "Rubric SHA" in out


def test_framework_mapping_contains_all_three_anchors(
    sample_context: FindingReportContext,
) -> None:
    out = render_finding(sample_context)
    assert "LLM01:2025" in out
    assert "ATLAS.T0051" in out
    assert "§164.308(a)(1)(ii)(A)" in out


def test_render_is_deterministic(sample_context: FindingReportContext) -> None:
    # Same context dict must produce byte-identical output across calls —
    # the template must never sprinkle timestamps or random IDs.
    assert render_finding(sample_context) == render_finding(sample_context)


# --- Pydantic validation ----------------------------------------------------


def test_context_rejects_severity_outside_p0_p3(sample_context: FindingReportContext) -> None:
    with pytest.raises(ValidationError):
        FindingReportContext(**{**sample_context.model_dump(), "severity": "P5"})


def test_context_rejects_empty_reproduction_steps(
    sample_context: FindingReportContext,
) -> None:
    with pytest.raises(ValidationError):
        FindingReportContext(**{**sample_context.model_dump(), "reproduction_steps": []})


def test_context_rejects_extra_field(sample_context: FindingReportContext) -> None:
    with pytest.raises(ValidationError):
        FindingReportContext(**{**sample_context.model_dump(), "unexpected_field": "boom"})


# --- StrictUndefined smoke test --------------------------------------------


def test_environment_uses_strict_undefined(tmp_path: Path) -> None:
    """Proves :func:`build_environment` configures StrictUndefined.

    A template that references an undeclared variable must raise
    :class:`jinja2.UndefinedError` at render time, not silently emit an
    empty string.
    """
    (tmp_path / "bad.md.j2").write_text("hello {{ unknown_var }}", encoding="utf-8")
    env = build_environment(tmp_path)
    template = env.get_template("bad.md.j2")
    with pytest.raises(UndefinedError):
        template.render()
