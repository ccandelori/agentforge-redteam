"""Jinja2 renderer for the vulnerability-finding markdown report.

The Documentation Agent produces a dict of facts about a confirmed finding;
this module renders that dict into the canonical markdown report (the body
of a GitLab issue) using ``templates/finding.md.j2``.

Design constraints:

- **StrictUndefined.** A typo in the template (or a missing key in the
  context) raises :class:`jinja2.UndefinedError` immediately rather than
  silently producing a report with a blank field.
- **Autoescape off.** This is a markdown template, not HTML — autoescape
  would mangle markdown punctuation (``*``, `` ` ``).
- **Deterministic.** Same context dict produces byte-identical output.
  No timestamps, no random IDs, no environment lookups in the template.
- **Pydantic-validated input.** :class:`FindingReportContext` is the
  *only* supported input shape. ``extra="forbid"`` means a stale field
  name in the calling agent fails fast at construction time, not at
  template-render time.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final, Literal

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from pydantic import BaseModel, Field

TEMPLATES_DIR: Final[Path] = Path("templates")
TEMPLATE_NAME: Final[str] = "finding.md.j2"
Severity = Literal["P0", "P1", "P2", "P3"]


class FindingReportContext(BaseModel):
    """Strict shape of the data passed into ``finding.md.j2``.

    ``model_config = {"extra": "forbid"}`` is load-bearing: it means the
    Documentation Agent cannot accidentally pass an undeclared field
    (e.g. a renamed key) and silently drop it. Every field declared
    here has a corresponding ``{{ ... }}`` placeholder in the template.
    """

    model_config = {"extra": "forbid"}

    severity: Severity
    title: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1)
    severity_rationale: str = Field(min_length=1)
    owasp_id: str = Field(min_length=1)
    mitre_id: str = Field(min_length=1)
    hipaa_section: str = Field(min_length=1)
    clinical_impact: str = Field(min_length=1)
    reproduction_steps: list[str] = Field(min_length=1)
    observed_behavior: str = Field(min_length=1)
    expected_behavior: str = Field(min_length=1)
    sanitized_evidence: str
    remediation_suggestions: str = Field(min_length=1)
    validation_steps: str = Field(min_length=1)
    finding_id: str = Field(min_length=1)
    target_sha: str = Field(min_length=1)
    rubric_sha: str = Field(min_length=1)


def build_environment(templates_dir: Path = TEMPLATES_DIR) -> Environment:
    """Build a Jinja2 :class:`Environment` configured for markdown reports.

    - ``StrictUndefined`` so missing template variables raise immediately.
    - ``select_autoescape(default=False)`` so markdown punctuation isn't
      HTML-escaped.
    - ``keep_trailing_newline=True`` so the rendered output ends cleanly
      with a newline (POSIX-friendly, diff-friendly).
    """
    return Environment(
        loader=FileSystemLoader(str(templates_dir)),
        undefined=StrictUndefined,
        autoescape=select_autoescape(default=False),
        keep_trailing_newline=True,
    )


def render_finding(
    ctx: FindingReportContext,
    templates_dir: Path = TEMPLATES_DIR,
) -> str:
    """Render ``finding.md.j2`` with the given context.

    Raises :class:`jinja2.UndefinedError` if any variable referenced in
    the template is missing from the context. (Cannot happen for a
    well-formed :class:`FindingReportContext`, but the strict env is the
    backstop against a template that drifts ahead of the schema.)
    """
    env = build_environment(templates_dir)
    template = env.get_template(TEMPLATE_NAME)
    return template.render(**ctx.model_dump())
