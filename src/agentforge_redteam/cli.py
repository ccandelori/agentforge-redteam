"""Operator CLI for the AgentForge red-team platform.

This module is the operator's keyboard. Other tasks (start-session, queue,
regress, eval-judge) will hang their commands off the same Typer ``app``; for
now the kill-switch surface (Task 14) and the ground-truth authoring flow
(Task 22) are the two operator-facing surfaces.

Design choices worth calling out:

* **Each command builds its own engine.** A Typer subcommand is effectively a
  short-lived process from the operator's point of view. Holding a module-
  level engine would force every invocation to pay the connection cost (even
  ``--help``) and would couple unrelated commands together. ``create_platform
  _engine()`` is cheap, and we ``dispose()`` in a ``finally`` so SQLite never
  leaves a write-ahead-log file lying around.

* **Engine reads ``PLATFORM_DB_PATH`` itself.** The CLI does not parse a
  ``--db`` flag because :func:`agentforge_redteam.db.database_url` already
  honours ``PLATFORM_DB_PATH`` with the right precedence. Threading a path
  through Typer would only duplicate that logic and create skew.

* **No heavyweight imports at top level.** Importing this module must not
  drag in ``langgraph``, ``langfuse``, ``anthropic``, or ``openai``. The
  operator may run ``agentforge-redteam status`` from a shell prompt in a
  loop; a 1-second cold start would be a UX bug.

* **Exit codes carry meaning.** ``status`` returns ``0`` when the platform
  is running and ``1`` when the kill switch is tripped, so a shell wrapper
  can do ``agentforge-redteam status && start_session.sh`` without parsing
  stdout. ``halt`` and ``resume`` always succeed (``0``); their *side
  effect* is the point, not their exit code.

* **Typer-only prompting for ground-truth.** The original Task 22 spec named
  ``rich`` as a dependency for the interactive flow; we kept the dependency
  tree tight by sticking to ``typer.prompt`` / ``typer.echo``. The flow is
  scripted-CLI friendly (the test suite drives it with ``CliRunner.invoke
  (..., input=...)``) and a future migration to ``rich`` is purely cosmetic.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer
from pydantic import ValidationError

from agentforge_redteam.approval import (
    DEFAULT_GROUND_TRUTH_ROOT,
    QueueEntryNotFound,
    approve,
    list_pending,
    reject,
)
from agentforge_redteam.clients.anthropic_client import create_anthropic_client
from agentforge_redteam.clients.gitlab_client import create_gitlab_client
from agentforge_redteam.db import create_platform_engine
from agentforge_redteam.ground_truth import (
    GROUND_TRUTH_ROOT,
    GroundTruthCase,
    read_case,
    write_case,
)
from agentforge_redteam.kill_switch import is_kill_switch_enabled, set_kill_switch
from agentforge_redteam.rubrics.loader import (
    RubricNotFoundError,
    load_all_rubrics,
    load_rubric,
)

VERDICT_OPTIONS: tuple[str, ...] = ("pass", "fail", "partial", "inconclusive")

app = typer.Typer(
    name="agentforge-redteam",
    help="AgentForge Adversarial AI Security Platform - operator CLI.",
    no_args_is_help=True,
)

ground_truth_app = typer.Typer(
    help="Hand-author and inspect Judge ground-truth cases.",
    no_args_is_help=True,
)
app.add_typer(ground_truth_app, name="ground-truth")

queue_app = typer.Typer(
    help="Review and act on findings in the human_approval_queue.",
    no_args_is_help=True,
)
app.add_typer(queue_app, name="queue")


@app.command()
def halt() -> None:
    """Trip the kill switch.

    The next attempted tool call (in any agent, any session) will raise
    :class:`agentforge_redteam.kill_switch.KillSwitchTripped` and write no
    audit row. Idempotent: running ``halt`` on an already-halted platform
    leaves the flag set and still exits ``0``.
    """
    engine = create_platform_engine()
    try:
        set_kill_switch(engine, enabled=True)
    finally:
        engine.dispose()
    typer.echo("Kill switch activated. All agent tool calls will halt on next attempt.")


@app.command()
def resume() -> None:
    """Clear the kill switch.

    Subsequent tool calls are allowed again. The command name itself is the
    operator's confirmation - we deliberately do not prompt, so this is
    scriptable in incident-response runbooks. Idempotent.
    """
    engine = create_platform_engine()
    try:
        set_kill_switch(engine, enabled=False)
    finally:
        engine.dispose()
    typer.echo("Kill switch cleared. Agent tool calls resumed.")


@app.command()
def status() -> None:
    """Print the current kill-switch state and exit with a meaningful code.

    Exit code is ``0`` when the platform is **running** and ``1`` when it
    is **halted**, so shell scripts can branch on it:

        if agentforge-redteam status; then start_session.sh; fi
    """
    engine = create_platform_engine()
    try:
        halted = is_kill_switch_enabled(engine)
    finally:
        engine.dispose()
    if halted:
        typer.echo("halted")
        raise typer.Exit(code=1)
    typer.echo("running")
    raise typer.Exit(code=0)


# ---------------------------------------------------------------------------
# ground-truth helpers
# ---------------------------------------------------------------------------


def _prompt_multiline(label: str) -> str:
    """Collect a multiline string from the operator.

    Reads lines until a blank line is entered. ``typer.prompt`` re-prompts
    on empty input by default, so we pass ``default=""`` to allow the empty
    terminator. We deliberately use ``show_default=False`` so the prompt
    does not flash a confusing ``[]`` to the operator on every line.
    """
    typer.echo(f"{label} (finish with an empty line):")
    lines: list[str] = []
    while True:
        line = typer.prompt("", default="", show_default=False, prompt_suffix="> ")
        if line == "":
            break
        lines.append(line)
    return "\n".join(lines)


def _prompt_verdict() -> str:
    """Prompt for an expected verdict, re-prompting until valid.

    We do the validation here (rather than via Typer's ``type=``) because we
    want to keep prompting the operator on bad input rather than aborting the
    whole command — they may have just fat-fingered.
    """
    while True:
        choice: str = typer.prompt(f"Expected verdict {VERDICT_OPTIONS}")
        if choice in VERDICT_OPTIONS:
            return choice
        typer.echo(
            "Invalid; must be one of: " + ", ".join(VERDICT_OPTIONS),
            err=True,
        )


def _prompt_confidence() -> float:
    """Prompt for a confidence float in [0.0, 1.0], re-prompting on bad input."""
    while True:
        raw = typer.prompt("Confidence (0.0 - 1.0)")
        try:
            value = float(raw)
        except ValueError:
            typer.echo("Invalid; enter a number between 0.0 and 1.0", err=True)
            continue
        if 0.0 <= value <= 1.0:
            return value
        typer.echo("Out of range; must be between 0.0 and 1.0", err=True)


def _prompt_category(available: list[str]) -> str:
    """Pick a category from the discovered rubric set, re-prompting on miss.

    Categories must match a real rubric so the loaded rubric's check names
    can drive the outcome-collection prompt.
    """
    typer.echo("Available categories:")
    for cat in available:
        typer.echo(f"  - {cat}")
    while True:
        choice: str = typer.prompt("Category")
        if choice in available:
            return choice
        typer.echo("Invalid; pick one of the listed categories.", err=True)


def _prompt_yes_no(label: str) -> bool:
    """Prompt for a y/N answer, re-prompting on bad input. Default is N."""
    while True:
        raw = typer.prompt(f"{label} [y/N]", default="n", show_default=False)
        norm = raw.strip().lower()
        if norm in ("y", "yes"):
            return True
        if norm in ("", "n", "no"):
            return False
        typer.echo("Invalid; enter y or n.", err=True)


# ---------------------------------------------------------------------------
# ground-truth commands
# ---------------------------------------------------------------------------


@ground_truth_app.command("new")
def new_case(
    root: Annotated[
        Path,
        typer.Option(
            "--root",
            help="Directory under which to write the case file.",
        ),
    ] = GROUND_TRUTH_ROOT,
    rubrics_dir: Annotated[
        Path,
        typer.Option(
            "--rubrics-dir",
            help="Directory to load rubrics from when listing categories and checks.",
        ),
    ] = Path("rubrics"),
) -> None:
    """Walk the operator through authoring one Judge ground-truth case.

    The flow:

    1. Pick a ``category`` from the discovered rubric set.
    2. Enter the ``attack_input`` (multiline; blank line ends).
    3. Enter the ``target_response`` (multiline; blank line ends).
       Empty is allowed — a silent refusal *is* a response under test.
    4. Pick the ``expected_verdict`` (pass/fail/partial/inconclusive).
    5. Enter a ``confidence`` in [0.0, 1.0].
    6. For each check in the rubric, mark the outcome y/N.
    7. Optional free-text ``notes``.

    The resulting YAML is written to
    ``<root>/<category>/<case_id>.yaml``.
    """
    try:
        rubrics = load_all_rubrics(rubrics_dir)
    except FileNotFoundError:
        rubrics = {}

    if not rubrics:
        typer.echo(
            f"No rubrics found under {rubrics_dir}. Author a rubric first (see rubrics/SCHEMA.md).",
            err=True,
        )
        raise typer.Exit(code=1)

    category = _prompt_category(sorted(rubrics.keys()))
    attack_input = _prompt_multiline("Attack input")
    target_response = _prompt_multiline("Target response (blank line for empty)")
    expected_verdict = _prompt_verdict()
    confidence = _prompt_confidence()

    # Re-load the chosen rubric so we know the canonical check names. The
    # data model accepts arbitrary string keys so a rubric extension does
    # not retroactively invalidate old cases, but at *authoring* time we
    # want to land on the rubric's current vocabulary.
    rubric = load_rubric(category, rubrics_dir=rubrics_dir)
    rubric_outcomes: dict[str, bool] = {}
    if rubric.checks:
        typer.echo("Mark rubric check outcomes (the Judge's expected hits):")
    for check in rubric.checks:
        rubric_outcomes[check.name] = _prompt_yes_no(f"  {check.name}")

    notes = typer.prompt("Notes (optional)", default="", show_default=False)

    try:
        case = GroundTruthCase(
            category=category,
            attack_input=attack_input,
            target_response=target_response,
            expected_verdict=expected_verdict,
            confidence=confidence,
            rubric_outcomes=rubric_outcomes,
            notes=notes,
        )
    except ValidationError as exc:
        typer.echo(f"Invalid case: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    path = write_case(case, root=root)
    typer.echo(f"Wrote ground-truth case to {path}")


@ground_truth_app.command("list")
def list_cases(
    category: Annotated[
        str | None,
        typer.Option(
            "--category",
            "-c",
            help="Filter listing to a single category.",
        ),
    ] = None,
    root: Annotated[
        Path,
        typer.Option(
            "--root",
            help="Directory to scan for committed ground-truth cases.",
        ),
    ] = GROUND_TRUTH_ROOT,
) -> None:
    """List committed ground-truth cases, one line per case.

    The output is intentionally terse — one line per case showing the first
    8 hex characters of the case_id, the category, the expected verdict, and
    the confidence. ``ground-truth show`` (future task) is the way to read
    the full body without ``cat``-ing the YAML.
    """
    if not root.exists():
        typer.echo("no cases yet")
        return

    if category is not None:
        search_dirs = [root / category] if (root / category).is_dir() else []
    else:
        search_dirs = sorted(p for p in root.iterdir() if p.is_dir())

    rows: list[tuple[str, str, str, float]] = []
    for category_dir in search_dirs:
        for path in sorted(category_dir.glob("*.yaml")):
            try:
                case = read_case(path)
            except (ValidationError, FileNotFoundError):
                # Skip malformed files rather than failing the listing — the
                # accuracy-gate CI job is where strict validation lives.
                continue
            rows.append(
                (
                    str(case.case_id)[:8],
                    case.category,
                    case.expected_verdict,
                    case.confidence,
                )
            )

    if not rows:
        typer.echo("no cases yet")
        return

    for short_id, cat, verdict, conf in rows:
        typer.echo(f"{short_id}  {cat:30s}  {verdict:13s}  conf={conf:.2f}")


# Suppress unused-import warnings for symbols re-exported only for tests /
# downstream callers that may want to monkeypatch them via the CLI module.
_RUBRIC_NOT_FOUND_ERROR = RubricNotFoundError


# ---------------------------------------------------------------------------
# start-session
# ---------------------------------------------------------------------------
#
# Halt-reason taxonomy for exit-code mapping. Each halt the orchestrator
# (or downstream nodes) can stamp on :attr:`PlatformState.halt_reason`
# falls into exactly one bucket below. The mapping is the single source
# of truth for the CLI's exit-code contract; if a new halt reason lands
# on the state model, it MUST be added here so the CLI never silently
# returns exit 1 for an unanticipated halt.
_HALTS_OK: frozenset[str] = frozenset(
    {"budget_exhausted", "no_progress", "no_candidates", "regression_due"}
)
_HALTS_INCIDENT: frozenset[str] = frozenset({"canary_failed", "kill_switch_tripped"})


def _exit_code_from_halt(halt_reason: str | None) -> int:
    """Map a halt reason onto the CLI's exit-code contract.

    A ``None`` halt reason means the graph terminated cleanly via the
    state-machine routing (e.g. the orchestrator's halt rule fired and
    routed to END). Anything in :data:`_HALTS_OK` is an expected,
    operationally normal outcome. Anything in :data:`_HALTS_INCIDENT`
    requires operator attention. Everything else (forward-compat) is
    treated as an incident — fail loud rather than swallow.
    """
    if halt_reason is None or halt_reason in _HALTS_OK:
        return 0
    if halt_reason in _HALTS_INCIDENT:
        return 1
    return 1


@app.command("start-session")
def start_session_cmd(
    target: Annotated[
        str,
        typer.Option(
            "--target",
            "-t",
            help="Target alias from targets.yaml. Default: droplet_prod.",
        ),
    ] = "droplet_prod",
    cost_cap_cents: Annotated[
        int,
        typer.Option(
            "--cost-cap-cents",
            help="Hard session-cost ceiling in cents.",
        ),
    ] = 1000,
    categories: Annotated[
        str,
        typer.Option(
            "--categories",
            help="Comma-separated attack categories.",
        ),
    ] = "prompt-injection-indirect,data-exfiltration,tool-misuse",
    session_id: Annotated[
        str | None,
        typer.Option(
            "--session-id",
            help="Override session_id. Default: a fresh uuid4.",
        ),
    ] = None,
    max_campaigns: Annotated[
        int,
        typer.Option(
            "--max-campaigns",
            help="Safety cap on campaign count.",
        ),
    ] = 5,
    rng_seed: Annotated[
        int | None,
        typer.Option(
            "--rng-seed",
            help="Seed for orchestrator's epsilon-greedy RNG (reproducibility).",
        ),
    ] = None,
) -> None:
    """Run one orchestrator-led red-team session against the configured target.

    Exit codes:

    * ``0`` — session completed cleanly (no halt, or halt is one of
      ``budget_exhausted``, ``no_progress``, ``no_candidates``,
      ``regression_due``).
    * ``1`` — kill switch tripped or canary failed during the session
      (operator must inspect).
    * ``2`` — LangGraph recursion limit hit (likely orchestrator-loop
      bug; see logs).
    * ``3`` — config error: missing API key, unknown target alias,
      unreadable policy file.
    """
    # Local imports keep the CLI cold-start budget intact. ``--help`` must
    # never pull langgraph / openai / anthropic into the import graph.
    import os
    import uuid as _uuid

    from agentforge_redteam.session_runner import (
        DEFAULT_CATEGORIES,
        SessionSummary,
        run_session,
    )

    # Parse the comma-separated categories into a tuple. Empty strings are
    # filtered out so ``--categories "a,,b"`` still yields ``("a", "b")``.
    parsed_categories = tuple(c.strip() for c in categories.split(",") if c.strip())
    if not parsed_categories:
        # An operator passed ``--categories ""`` — fall back to the default
        # so a typo doesn't pin the orchestrator to an empty hint.
        parsed_categories = DEFAULT_CATEGORIES

    resolved_session_id = session_id if session_id is not None else str(_uuid.uuid4())

    summary: SessionSummary
    try:
        summary = run_session(
            session_id=resolved_session_id,
            target_alias=target,
            cost_cap_cents=cost_cap_cents,
            categories=parsed_categories,
            max_campaigns=max_campaigns,
            env=os.environ.copy(),
            rng_seed=rng_seed,
        )
    except ValueError as exc:
        # Unknown ``target_alias`` is the canonical ValueError source from
        # ``build_production_graph``. Treat any ValueError as a config
        # problem so a malformed allowlist also lands cleanly on exit 3.
        typer.echo(f"start-session: unknown target alias: {exc}", err=True)
        raise typer.Exit(code=3) from exc
    except RuntimeError as exc:
        # Stub LLM errors carry one of the API-KEY strings from
        # ``graph_factory._UnconfiguredLLMError``. Treat any RuntimeError
        # mentioning ``API_KEY`` as a config problem; anything else
        # re-raises so we don't accidentally swallow a real bug.
        message = str(exc)
        if "API_KEY" in message:
            typer.echo(f"start-session: missing API key — {message}", err=True)
            raise typer.Exit(code=3) from exc
        raise
    except Exception as exc:
        # LangGraph's recursion error is the only exception we catch by
        # class-name pattern rather than concrete type so the runner
        # stays decoupled from the langgraph import surface. Importing
        # ``GraphRecursionError`` directly here would couple the CLI to
        # the langgraph package even on a ``--help`` invocation.
        if "Recursion" in type(exc).__name__:
            typer.echo(
                f"start-session: hit recursion limit ({type(exc).__name__}) — "
                "the orchestrator likely failed to halt; inspect agent_steps.",
                err=True,
            )
            raise typer.Exit(code=2) from exc
        raise

    # ----- Success path: print the operator summary. -----
    cap_dollars = cost_cap_cents / 100.0
    typer.echo(f"Session: {summary.session_id}")
    typer.echo(f"  target:           {summary.target_alias}  ->  {summary.target_url}")
    typer.echo(f"  campaigns_run:    {summary.campaigns_run}")
    typer.echo(f"  cost_so_far:      ${summary.cost_so_far_dollars:.2f} (cap: ${cap_dollars:.2f})")
    typer.echo(f"  halt_reason:      {summary.halt_reason}")
    typer.echo(f"  attacks:          {summary.attack_records}")
    typer.echo(f"  verdicts:         {summary.verdict_records}")
    typer.echo(f"  confirmed:        {summary.confirmed_findings}")

    exit_code = _exit_code_from_halt(summary.halt_reason)
    raise typer.Exit(code=exit_code)


# ---------------------------------------------------------------------------
# regress
# ---------------------------------------------------------------------------


@app.command()
def regress(
    target_sha: Annotated[
        str,
        typer.Option(
            "--target-sha",
            "-s",
            help="Target build SHA the replay is testing against. Required.",
        ),
    ],
    target_url: Annotated[
        str,
        typer.Option(
            "--target-url",
            "-u",
            help="Target base URL. Defaults to TARGET_DROPLET_URL env or localhost.",
        ),
    ] = "",
    root: Annotated[
        Path,
        typer.Option(
            "--root",
            "-r",
            help="Regression cases directory.",
        ),
    ] = Path("evals/regressions"),
) -> None:
    """Replay every promoted regression case against the target.

    Exit code is ``1`` if any case regressed (so a CI gate fails the build),
    ``0`` otherwise. The summary tally is printed regardless.

    Scaffolding note
    ----------------
    The HTTP and LLM clients wired here are deliberately **no-op fakes** -
    the CLI confirms the on-disk regression corpus parses, exercises the
    runner -> harness -> ``regression_runs`` insert path, and prints a
    summary. A follow-up wiring task swaps these for real OpenAI /
    Anthropic / httpx clients. Until then this command is useful for:

    * smoke-testing that promoted cases are still valid JSON,
    * exercising the audit-row insert path in CI,
    * confirming the summary aggregation matches the case corpus.
    """
    # Local imports keep the CLI's cold-start budget tight - we only pay for
    # asyncio / the runner when the operator actually runs ``regress``.
    import asyncio
    import json as _json
    import os

    from agentforge_redteam.agents.judge import LLMResponse as JudgeLLMResponse
    from agentforge_redteam.agents.red_team import TargetResponse
    from agentforge_redteam.regression.runner import run_regression_session

    resolved_target_url = target_url or os.environ.get(
        "TARGET_DROPLET_URL", "http://localhost:8000"
    )

    class _NoopHTTP:
        """No-op HTTP target client. See command docstring for rationale."""

        async def post(self, *, url: str, payload: str, timeout_s: float) -> TargetResponse:
            return TargetResponse(status_code=200, body="(noop)", target_sha=target_sha)

    class _NoopLLM:
        """No-op LLM client returning a Judge-shaped ``no-hit`` JSON envelope."""

        async def complete(self, *, system: str, user: str, model: str) -> JudgeLLMResponse:
            return JudgeLLMResponse(
                text=_json.dumps({"hit": False, "evidence": []}),
                cost_cents=0,
            )

    engine = create_platform_engine()
    try:
        summary = asyncio.run(
            run_regression_session(
                new_target_sha=target_sha,
                engine=engine,
                http=_NoopHTTP(),
                llm_for_judge=_NoopLLM(),
                root=root,
            )
        )
    finally:
        engine.dispose()

    typer.echo(f"Regression session against target_sha={target_sha}")
    typer.echo(f"  target_url: {resolved_target_url}")
    typer.echo(f"  total: {summary.total}")
    typer.echo(f"  held: {summary.held}")
    typer.echo(f"  regressed: {summary.regressed}")
    typer.echo(f"  weakly_passing: {summary.weakly_passing}")
    typer.echo(f"  inconclusive: {summary.inconclusive}")
    if summary.regressed > 0:
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# eval-judge
# ---------------------------------------------------------------------------


@app.command("eval-judge")
def eval_judge(
    threshold: Annotated[
        float,
        typer.Option(
            "--threshold",
            help="Accuracy floor; the command exits 1 if overall accuracy is below this.",
        ),
    ] = 0.85,
    case_id: Annotated[
        str | None,
        typer.Option(
            "--case-id",
            help="Filter to a single case by UUID prefix (substring match).",
        ),
    ] = None,
    categories: Annotated[
        str | None,
        typer.Option(
            "--categories",
            help="Comma-separated category filter; restricts the eval to a subset of categories.",
        ),
    ] = None,
    root: Annotated[
        Path,
        typer.Option(
            "--root",
            help="Ground-truth root directory.",
        ),
    ] = Path("evals/judge_ground_truth"),
    rubrics_dir: Annotated[
        Path,
        typer.Option(
            "--rubrics-dir",
            help="Rubrics directory the Judge loads category rubrics from.",
        ),
    ] = Path("rubrics"),
) -> None:
    """Replay every Judge ground-truth case through the real Judge and gate on accuracy.

    Exit codes:

    * ``0`` — overall accuracy is at or above ``--threshold``.
    * ``1`` — accuracy is below ``--threshold`` (the release-gate failure case).
    * ``2`` — no cases matched the filters (operator typo / empty corpus).
    * ``3`` — no Anthropic API key is configured (``ANTHROPIC_API_KEY`` unset).

    The exit-3 branch is the soft-skip lane: CI can treat it as a "skip until
    operator wires the secret" rather than a build failure.
    """
    import os
    from typing import cast

    from agentforge_redteam.agents.judge import LLMClientLike as JudgeLLMClientLike
    from agentforge_redteam.eval_judge import load_cases, run_eval

    # 1. Build the real Anthropic client. The factory returns None when no
    #    key is configured — we map that to exit code 3 so CI can soft-skip
    #    until the operator provisions a protected variable.
    raw_llm = create_anthropic_client(env=os.environ.copy())
    if raw_llm is None:
        typer.echo(
            "ANTHROPIC_API_KEY is not set; cannot run eval-judge. "
            "Provision the key (locally or as a protected CI variable) and retry.",
            err=True,
        )
        raise typer.Exit(code=3)

    # The Anthropic client's ``complete`` returns a ``documentation.LLMResponse``
    # while the Judge's :class:`LLMClientLike` Protocol references its own
    # nominal ``judge.LLMResponse``. Both dataclasses are structurally
    # identical (``(text: str, cost_cents: int)``) and the Judge only reads
    # those two fields — a ``cast`` here keeps the type-checker honest with
    # zero runtime cost. The same pattern is used in ``graph_factory.py``.
    llm: JudgeLLMClientLike = cast(JudgeLLMClientLike, raw_llm)

    # 2. Resolve the category filter into a tuple (or None to mean "all").
    category_filter: tuple[str, ...] | None = None
    if categories:
        category_filter = tuple(c.strip() for c in categories.split(",") if c.strip())

    # 3. Discover cases — let pydantic raise on malformed files; a broken
    #    case must not silently shrink the accuracy denominator.
    cases = load_cases(root, case_id=case_id, categories=category_filter)
    if not cases:
        typer.echo("no ground-truth cases matched the filters", err=True)
        raise typer.Exit(code=2)

    typer.echo(f"Running {len(cases)} ground-truth case(s) through the Judge...")

    # 4. Run the eval against a fresh engine; dispose in a finally so SQLite
    #    never leaves a WAL file behind.
    engine = create_platform_engine()
    try:
        summary = asyncio.run(
            run_eval(
                cases,
                engine=engine,
                llm=llm,
                rubrics_dir=rubrics_dir,
            )
        )
    finally:
        engine.dispose()

    # 5. Print the operator-facing report.
    typer.echo("")
    typer.echo(f"Overall accuracy: {summary.accuracy:.3f}  ({summary.correct}/{summary.total})")
    typer.echo("")
    typer.echo("By category:")
    for category in sorted(summary.by_category):
        correct, total = summary.by_category[category]
        pct = (correct / total) if total else 0.0
        typer.echo(f"  {category:30s}  {correct}/{total}  ({pct:.3f})")
    typer.echo("")
    typer.echo("By expected verdict:")
    for verdict in sorted(summary.by_verdict_accuracy):
        typer.echo(f"  {verdict:13s}  {summary.by_verdict_accuracy[verdict]:.3f}")

    failures = [r for r in summary.results if not r.correct]
    if failures:
        typer.echo("")
        typer.echo(f"Failures ({len(failures)}):")
        for result in failures:
            short = result.case_id[:8]
            notes = f"  [{result.notes}]" if result.notes else ""
            typer.echo(
                f"  {short}  {result.category:30s}  "
                f"expected={result.expected_verdict:13s} "
                f"actual={result.actual_verdict:13s}{notes}"
            )

    typer.echo("")
    if summary.accuracy < threshold:
        typer.echo(
            f"FAIL: accuracy {summary.accuracy:.3f} is below threshold {threshold:.3f}",
            err=True,
        )
        raise typer.Exit(code=1)
    typer.echo(f"PASS: accuracy {summary.accuracy:.3f} meets threshold {threshold:.3f}")


# ---------------------------------------------------------------------------
# queue (human approval)
# ---------------------------------------------------------------------------


@queue_app.command("list")
def queue_list(
    limit: Annotated[
        int,
        typer.Option(
            "--limit",
            help="Maximum number of pending entries to print.",
        ),
    ] = 100,
) -> None:
    """List pending findings in the human approval queue."""
    engine = create_platform_engine()
    try:
        entries = list_pending(engine, limit=limit)
    finally:
        engine.dispose()

    if not entries:
        typer.echo("no pending findings")
        return

    for entry in entries:
        typer.echo(
            f"{entry.queue_id}  {entry.severity:4s}  conf={entry.confidence:.2f}  {entry.title}"
        )


def _parse_queue_id(raw: str) -> UUID:
    """Parse a queue_id string, exiting cleanly on a bad UUID."""
    try:
        return UUID(raw)
    except ValueError as exc:
        typer.echo(f"Invalid queue_id: {raw} ({exc})", err=True)
        raise typer.Exit(code=1) from exc


@queue_app.command("approve")
def queue_approve(
    queue_id: Annotated[
        str,
        typer.Argument(help="Queue ID to approve."),
    ],
    reviewer: Annotated[
        str,
        typer.Option(
            "--reviewer",
            help="Reviewer identifier stamped onto the queue row.",
        ),
    ] = "operator",
) -> None:
    """Mark a queue entry approved, file the issue, persist the issue id.

    GitLab is contacted *before* SQLite is updated; if GitLab returns an
    error, the queue entry stays ``pending`` and the operator can retry
    after fixing credentials. See :mod:`agentforge_redteam.approval` for
    the full ordering rationale.
    """
    qid = _parse_queue_id(queue_id)

    gitlab = create_gitlab_client()
    if gitlab is None:
        typer.echo(
            "GitLab not configured. Set GITLAB_TOKEN and GITLAB_PROJECT_ID.",
            err=True,
        )
        raise typer.Exit(code=1)

    engine = create_platform_engine()
    try:
        # Re-fetch the entry so we can build a minimal issue body / labels.
        from agentforge_redteam.approval import get_entry

        try:
            entry = get_entry(engine, queue_id=qid)
        except QueueEntryNotFound as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=1) from exc

        # Skeleton issue body — the rich rendering lives in
        # ``report_template.py``; a follow-up wires it in.
        body = (
            f"Finding: {entry.finding_id}\n"
            f"Severity: {entry.severity}\n"
            f"Confidence: {entry.confidence:.2f}\n"
            f"Title: {entry.title}\n\n"
            "Full report rendering deferred to follow-up."
        )
        labels = [
            f"severity::{entry.severity}",
            "owasp::pending",
            "mitre::pending",
        ]

        try:
            result = asyncio.run(
                approve(
                    engine,
                    queue_id=qid,
                    reviewer=reviewer,
                    gitlab=gitlab,
                    issue_body=body,
                    labels=labels,
                )
            )
        except QueueEntryNotFound as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=1) from exc
    finally:
        engine.dispose()

    typer.echo(
        f"approved queue_id={result.queue_id} "
        f"finding_id={result.finding_id} "
        f"gitlab_issue_id={result.gitlab_issue_id} "
        f"url={result.gitlab_issue_url}"
    )


@queue_app.command("reject")
def queue_reject(
    queue_id: Annotated[
        str,
        typer.Argument(help="Queue ID to reject."),
    ],
    reason: Annotated[
        str,
        typer.Option(
            "--reason",
            help="Free-text rejection rationale. Prompted if omitted.",
        ),
    ] = "",
    category: Annotated[
        str | None,
        typer.Option(
            "--category",
            help=(
                "Rubric category for the generated ground-truth case. "
                "Required unless --skip-ground-truth is passed. Prompted if omitted."
            ),
        ),
    ] = None,
    skip_ground_truth: Annotated[
        bool,
        typer.Option(
            "--skip-ground-truth",
            help="Skip converting the rejection into a Judge ground-truth case.",
        ),
    ] = False,
    reviewer: Annotated[
        str,
        typer.Option(
            "--reviewer",
            help="Reviewer identifier stamped onto the queue row.",
        ),
    ] = "operator",
    root: Annotated[
        Path,
        typer.Option(
            "--root",
            help="Directory under which to write the ground-truth case.",
        ),
    ] = DEFAULT_GROUND_TRUTH_ROOT,
) -> None:
    """Mark a queue entry rejected; optionally convert to a ground-truth case.

    Unless ``--skip-ground-truth`` is passed, the rejection becomes a
    Judge ground-truth case under ``--root/<category>/<case_id>.yaml`` —
    free fodder for the canary harness (Task 41) and the accuracy gate.
    """
    qid = _parse_queue_id(queue_id)

    if not reason:
        reason = typer.prompt("Reason for rejection")

    write_gt = not skip_ground_truth
    if write_gt and not category:
        category = typer.prompt("Category (rubric name)")

    engine = create_platform_engine()
    try:
        try:
            result = reject(
                engine,
                queue_id=qid,
                reviewer=reviewer,
                reason=reason,
                category=category,
                write_ground_truth=write_gt,
                ground_truth_root=root,
            )
        except QueueEntryNotFound as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=1) from exc
        except ValueError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=1) from exc
    finally:
        engine.dispose()

    if result.ground_truth_path is not None:
        typer.echo(
            f"rejected queue_id={result.queue_id} "
            f"finding_id={result.finding_id} "
            f"ground_truth={result.ground_truth_path}"
        )
    else:
        typer.echo(
            f"rejected queue_id={result.queue_id} "
            f"finding_id={result.finding_id} "
            "(no ground-truth case written)"
        )


def main() -> None:  # pragma: no cover - Typer-managed entrypoint
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
