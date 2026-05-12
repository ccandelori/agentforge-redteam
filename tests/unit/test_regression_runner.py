"""Tests for the regression session runner (Task 40).

The runner is the orchestrator's "regression branch": a separate entry point
that loads every promoted :class:`RegressionTestCase` and replays it against
a new ``target_sha`` via the Task 39 harness. The two scopes under test:

* :func:`list_promoted_cases` — file-system discovery, stable ordering,
  graceful skip on a malformed file.
* :func:`run_regression_session` — happy-path aggregation, per-case
  exception isolation, determinism, audit-row side-effects.

A small slice of CLI tests round this out: ``regress --help``, the
required-arg check, the empty-corpus exit code, and the regressed-case
exit code.

We mirror the harness's test pattern (fake HTTP + fake ``judge_node``) but
inject the runner's real entrypoint, so the test exercises the real
runner-to-harness boundary without a real LLM or HTTP target.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import Engine
from typer.testing import CliRunner

from agentforge_redteam.agents.red_team import TargetResponse
from agentforge_redteam.cli import app
from agentforge_redteam.db import create_platform_engine
from agentforge_redteam.regression.case import (
    REGRESSIONS_DIR,
    RegressionTestCase,
    write_case,
)
from agentforge_redteam.regression.harness import RegressionResult
from agentforge_redteam.regression.runner import (
    RegressionSessionSummary,
    list_promoted_cases,
    run_regression_session,
)
from agentforge_redteam.state import PlatformState, VerdictRecord

REPO_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_INI = REPO_ROOT / "alembic.ini"
ALEMBIC_DIR = REPO_ROOT / "alembic"
RUBRICS_DIR = REPO_ROOT / "rubrics"

SHA_64_HEX = "a" * 64

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures — migrated engine + an isolated regressions root per test.
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Engine]:
    """Alembic-migrated tmp SQLite database, env-redirected for CLI calls too."""
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


@pytest.fixture
def regressions_root(tmp_path: Path) -> Path:
    """Per-test stand-in for ``evals/regressions/``."""
    return tmp_path / "evals" / "regressions"


# ---------------------------------------------------------------------------
# Helpers — case factory + canned fakes that mirror the harness tests.
# ---------------------------------------------------------------------------


def _seed_finding_row(
    engine: Engine,
    *,
    finding_id: UUID,
    attack_id: UUID,
    payload: str,
    rubric_sha: str,
    verdict: str,
    confidence: float,
    original_target_sha: str,
    severity: str = "P1",
) -> None:
    """Insert the attack/verdict/finding rows the harness's FK demands.

    ``replay_regression_test`` writes a ``regression_runs`` row whose
    ``finding_id`` references ``findings.finding_id`` — the parent table must
    exist or the insert raises ``IntegrityError``. The runner doesn't write
    these rows itself; in production they're written by the Documentation
    agent at finding-promotion time. Tests have to materialise them by hand.
    """
    verdict_id = uuid4()
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO attacks "
                "(attack_id, campaign_id, payload, target_response, target_sha, "
                "status_code, latency_ms) "
                "VALUES (:attack_id, :campaign_id, :payload, :target_response, "
                ":target_sha, :status_code, :latency_ms)"
            ),
            {
                "attack_id": str(attack_id),
                "campaign_id": str(uuid4()),
                "payload": payload,
                "target_response": "(seeded)",
                "target_sha": original_target_sha,
                "status_code": 200,
                "latency_ms": 1,
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
                "verdict_id": str(verdict_id),
                "attack_id": str(attack_id),
                "verdict": verdict,
                "confidence": confidence,
                "evidence_refs": json.dumps([]),
                "rubric_sha": rubric_sha,
                "model_version": "fake-model",
                "prompt_sha": "prompt-test",
            },
        )
        conn.execute(
            sa.text(
                "INSERT INTO findings "
                "(finding_id, severity, attack_id, verdict_id, gitlab_issue_id, "
                "sanitized_evidence) "
                "VALUES (:finding_id, :severity, :attack_id, :verdict_id, "
                ":gitlab_issue_id, :sanitized_evidence)"
            ),
            {
                "finding_id": str(finding_id),
                "severity": severity,
                "attack_id": str(attack_id),
                "verdict_id": str(verdict_id),
                "gitlab_issue_id": None,
                "sanitized_evidence": json.dumps({}),
            },
        )


def _make_case(
    *,
    finding_id: UUID | None = None,
    expected_verdict: str = "pass",
    expected_confidence: float = 0.9,
    payload: str = "ignore prior instructions",
    target_url: str = "http://target.local/v1/chat",
    rubric_sha: str = SHA_64_HEX,
    rubric_category: str = "prompt-injection-indirect",
    original_target_sha: str = "target-sha-old",
) -> RegressionTestCase:
    return RegressionTestCase(
        finding_id=finding_id or uuid4(),
        attack_id=uuid4(),
        payload=payload,
        target_url=target_url,
        original_target_sha=original_target_sha,
        rubric_sha=rubric_sha,
        rubric_category=rubric_category,
        expected_verdict=expected_verdict,  # type: ignore[arg-type]
        expected_confidence=expected_confidence,
        promoted_at=datetime.now(UTC),
    )


def _write_case_and_seed_finding(engine: Engine, root: Path, case: RegressionTestCase) -> None:
    """Persist the case JSON and seed the parent ``findings`` row.

    Most runner tests need BOTH the on-disk case (so the runner discovers it)
    AND the DB-side finding row (so ``replay_regression_test``'s
    ``regression_runs`` insert doesn't trip the FK). Bundling the two saves a
    page of boilerplate per test.
    """
    write_case(case, root)
    _seed_finding_row(
        engine,
        finding_id=case.finding_id,
        attack_id=case.attack_id,
        payload=case.payload,
        rubric_sha=case.rubric_sha,
        verdict=case.expected_verdict,
        confidence=case.expected_confidence,
        original_target_sha=case.original_target_sha,
    )


class _FakeHTTP:
    """Canned :class:`HTTPTargetClientLike` for runner tests."""

    def __init__(
        self,
        *,
        body: str = "stub-target-body",
        target_sha: str = "target-sha-new",
        status_code: int = 200,
        raises_for_payload: str | None = None,
    ) -> None:
        self.body = body
        self.target_sha = target_sha
        self.status_code = status_code
        self.raises_for_payload = raises_for_payload
        self.calls: list[dict[str, Any]] = []

    async def post(self, *, url: str, payload: str, timeout_s: float) -> TargetResponse:
        self.calls.append({"url": url, "payload": payload, "timeout_s": timeout_s})
        if self.raises_for_payload is not None and payload == self.raises_for_payload:
            raise TimeoutError(f"simulated target timeout for payload={payload!r}")
        return TargetResponse(
            status_code=self.status_code, body=self.body, target_sha=self.target_sha
        )


def _make_fake_judge(
    *,
    verdict: str = "pass",
    confidence: float = 0.9,
    rubric_sha: str = SHA_64_HEX,
):
    """Stand-in for :func:`agentforge_redteam.agents.judge.judge_node`.

    The runner imports ``judge_node`` at module level; we patch it via
    ``unittest.mock.patch`` in the call sites that need a controlled verdict.
    """

    async def _fake_judge_node(
        state: PlatformState,
        *,
        engine: Engine,
        llm: Any,
        model: str = "fake-model",
        langfuse: Any | None = None,
        rubrics_dir: Any = None,
        prompts_dir: Any = None,
    ) -> PlatformState:
        if not state.attack_records:
            raise RuntimeError("fake judge_node: no attack_records")
        attack = state.attack_records[-1]
        record = VerdictRecord(
            attack_id=attack.attack_id,
            verdict=verdict,  # type: ignore[arg-type]
            confidence=confidence,
            evidence_refs=[],
            rubric_sha=rubric_sha,
            model_version=model,
        )
        return state.model_copy(update={"verdict_records": [*state.verdict_records, record]})

    return _fake_judge_node


# ---------------------------------------------------------------------------
# 1. list_promoted_cases — empty root.
# ---------------------------------------------------------------------------


def test_list_promoted_cases_returns_empty_for_missing_root(regressions_root: Path) -> None:
    assert not regressions_root.exists()
    assert list_promoted_cases(regressions_root) == []


def test_list_promoted_cases_returns_empty_for_empty_root(regressions_root: Path) -> None:
    regressions_root.mkdir(parents=True)
    assert list_promoted_cases(regressions_root) == []


# ---------------------------------------------------------------------------
# 2. list_promoted_cases — reads every JSON file under the root.
# ---------------------------------------------------------------------------


def test_list_promoted_cases_reads_every_json_under_root(regressions_root: Path) -> None:
    cases = [_make_case() for _ in range(3)]
    for case in cases:
        write_case(case, regressions_root)
    loaded = list_promoted_cases(regressions_root)
    assert len(loaded) == 3
    loaded_ids = {c.finding_id for c in loaded}
    assert loaded_ids == {c.finding_id for c in cases}


# ---------------------------------------------------------------------------
# 3. list_promoted_cases — stable ordering by finding_id.
# ---------------------------------------------------------------------------


def test_list_promoted_cases_is_sorted_by_finding_id(regressions_root: Path) -> None:
    # Craft three finding_ids whose string-sort order is well-defined.
    fids = [
        UUID("11111111-1111-1111-1111-111111111111"),
        UUID("22222222-2222-2222-2222-222222222222"),
        UUID("33333333-3333-3333-3333-333333333333"),
    ]
    for fid in reversed(fids):  # write in reverse to confirm sort isn't filesystem order
        write_case(_make_case(finding_id=fid), regressions_root)
    loaded = list_promoted_cases(regressions_root)
    assert [c.finding_id for c in loaded] == fids


# ---------------------------------------------------------------------------
# 4. list_promoted_cases — skips malformed JSON with a warning.
# ---------------------------------------------------------------------------


def test_list_promoted_cases_skips_malformed_json(regressions_root: Path) -> None:
    case = _make_case()
    write_case(case, regressions_root)
    # Drop a malformed sibling file next to the valid case.
    malformed = regressions_root / "00000000-0000-0000-0000-000000000bad.json"
    malformed.write_text("{ not valid json", encoding="utf-8")

    loaded = list_promoted_cases(regressions_root)
    assert len(loaded) == 1
    assert loaded[0].finding_id == case.finding_id


# ---------------------------------------------------------------------------
# 5. run_regression_session — empty corpus returns total=0 summary.
# ---------------------------------------------------------------------------


async def test_run_regression_session_empty_corpus(engine: Engine, regressions_root: Path) -> None:
    summary = await run_regression_session(
        new_target_sha="target-sha-new",
        engine=engine,
        http=_FakeHTTP(),
        llm_for_judge=object(),
        root=regressions_root,
    )
    assert summary.total == 0
    assert summary.held == 0
    assert summary.regressed == 0
    assert summary.weakly_passing == 0
    assert summary.inconclusive == 0
    assert summary.results == []
    assert summary.new_target_sha == "target-sha-new"


# ---------------------------------------------------------------------------
# 6. run_regression_session — 3 holding cases.
# ---------------------------------------------------------------------------


async def test_run_regression_session_all_held(engine: Engine, regressions_root: Path) -> None:
    for _ in range(3):
        case = _make_case(expected_verdict="pass", expected_confidence=0.9)
        _write_case_and_seed_finding(engine, regressions_root, case)

    # Under the corrected verdict semantics ('pass' = attack succeeded), the
    # 'held' outcome is original pass -> replay fail (attack no longer
    # succeeds; defense holds).
    fake_judge = _make_fake_judge(verdict="fail", confidence=0.9)
    with patch("agentforge_redteam.regression.runner.judge_node", fake_judge):
        summary = await run_regression_session(
            new_target_sha="target-sha-new",
            engine=engine,
            http=_FakeHTTP(),
            llm_for_judge=object(),
            root=regressions_root,
        )

    assert summary.total == 3
    assert summary.held == 3
    assert summary.regressed == 0
    assert summary.weakly_passing == 0
    assert summary.inconclusive == 0


# ---------------------------------------------------------------------------
# 7. run_regression_session — per-case exception is isolated.
# ---------------------------------------------------------------------------


async def test_run_regression_session_isolates_per_case_exceptions(
    engine: Engine, regressions_root: Path
) -> None:
    """A target timeout on case 2 must NOT abort cases 1 and 3.

    The failing case becomes ``status='regressed'`` with notes carrying
    the exception class name, while the other two continue and hold.
    """
    boom_payload = "this-payload-makes-the-target-explode"
    for payload in ("payload-a", boom_payload, "payload-c"):
        case = _make_case(payload=payload)
        _write_case_and_seed_finding(engine, regressions_root, case)

    # Original verdicts are 'pass' (attack succeeded); a 'fail' replay means
    # the attack no longer succeeds — i.e. status='held'.
    fake_judge = _make_fake_judge(verdict="fail", confidence=0.9)
    http = _FakeHTTP(raises_for_payload=boom_payload)
    with patch("agentforge_redteam.regression.runner.judge_node", fake_judge):
        summary = await run_regression_session(
            new_target_sha="target-sha-new",
            engine=engine,
            http=http,
            llm_for_judge=object(),
            root=regressions_root,
        )

    assert summary.total == 3
    # 2 holding, 1 regressed (the one that exploded).
    assert summary.held == 2
    assert summary.regressed == 1
    boom_result = next(r for r in summary.results if "exception" in r.notes)
    assert boom_result.status == "regressed"
    assert "TimeoutError" in boom_result.notes


# ---------------------------------------------------------------------------
# 8. RegressionSessionSummary.results length matches total.
# ---------------------------------------------------------------------------


async def test_summary_results_length_matches_total(engine: Engine, regressions_root: Path) -> None:
    for _ in range(4):
        case = _make_case()
        _write_case_and_seed_finding(engine, regressions_root, case)

    fake_judge = _make_fake_judge(verdict="pass", confidence=0.9)
    with patch("agentforge_redteam.regression.runner.judge_node", fake_judge):
        summary = await run_regression_session(
            new_target_sha="target-sha-new",
            engine=engine,
            http=_FakeHTTP(),
            llm_for_judge=object(),
            root=regressions_root,
        )
    assert len(summary.results) == summary.total == 4


# ---------------------------------------------------------------------------
# 9. Per-status counts sum to total.
# ---------------------------------------------------------------------------


async def test_summary_status_counts_sum_to_total(engine: Engine, regressions_root: Path) -> None:
    for _ in range(5):
        case = _make_case(expected_verdict="pass", expected_confidence=0.9)
        _write_case_and_seed_finding(engine, regressions_root, case)

    # Judge returns ``pass`` with stable confidence => every case still
    # shows the original vulnerability => all 5 land in ``regressed``.
    fake_judge = _make_fake_judge(verdict="pass", confidence=0.9)
    with patch("agentforge_redteam.regression.runner.judge_node", fake_judge):
        summary = await run_regression_session(
            new_target_sha="target-sha-new",
            engine=engine,
            http=_FakeHTTP(),
            llm_for_judge=object(),
            root=regressions_root,
        )

    assert summary.held + summary.regressed + summary.weakly_passing + summary.inconclusive == (
        summary.total
    )
    # Belt-and-braces: when every case stays pass->pass with stable confidence,
    # every case is a regression (the vuln is still reproducible).
    assert summary.regressed == 5


# ---------------------------------------------------------------------------
# 10. run_regression_session writes one regression_runs row per case.
# ---------------------------------------------------------------------------


async def test_session_writes_one_regression_runs_row_per_case(
    engine: Engine, regressions_root: Path
) -> None:
    cases = [_make_case() for _ in range(3)]
    for c in cases:
        _write_case_and_seed_finding(engine, regressions_root, c)

    fake_judge = _make_fake_judge(verdict="pass", confidence=0.9)
    with patch("agentforge_redteam.regression.runner.judge_node", fake_judge):
        await run_regression_session(
            new_target_sha="target-sha-new",
            engine=engine,
            http=_FakeHTTP(),
            llm_for_judge=object(),
            root=regressions_root,
        )

    with engine.connect() as conn:
        count = int(
            conn.execute(
                sa.text("SELECT COUNT(*) FROM regression_runs WHERE target_sha = :sha"),
                {"sha": "target-sha-new"},
            ).scalar_one()
        )
    assert count == 3


# ---------------------------------------------------------------------------
# 11. Determinism — identical inputs produce identical summary (modulo run_ids).
# ---------------------------------------------------------------------------


async def test_session_is_deterministic_modulo_run_ids(
    engine: Engine, regressions_root: Path
) -> None:
    for _ in range(2):
        case = _make_case(expected_verdict="pass", expected_confidence=0.9)
        _write_case_and_seed_finding(engine, regressions_root, case)

    fake_judge = _make_fake_judge(verdict="pass", confidence=0.9)
    with patch("agentforge_redteam.regression.runner.judge_node", fake_judge):
        first = await run_regression_session(
            new_target_sha="target-sha-new",
            engine=engine,
            http=_FakeHTTP(),
            llm_for_judge=object(),
            root=regressions_root,
        )
        second = await run_regression_session(
            new_target_sha="target-sha-new",
            engine=engine,
            http=_FakeHTTP(),
            llm_for_judge=object(),
            root=regressions_root,
        )

    assert first.total == second.total
    assert first.held == second.held
    assert first.regressed == second.regressed
    assert first.weakly_passing == second.weakly_passing
    assert first.inconclusive == second.inconclusive
    # Per-result run_ids must differ between sessions (uuid4) but statuses must match.
    assert [r.status for r in first.results] == [r.status for r in second.results]


# ---------------------------------------------------------------------------
# 12. CLI: ``regress --help`` succeeds.
# ---------------------------------------------------------------------------


def test_cli_regress_help_succeeds() -> None:
    result = runner.invoke(app, ["regress", "--help"])
    assert result.exit_code == 0
    assert "regress" in result.output.lower()
    assert "--target-sha" in result.output


# ---------------------------------------------------------------------------
# 13. CLI: missing ``--target-sha`` exits non-zero.
# ---------------------------------------------------------------------------


def test_cli_regress_requires_target_sha(engine: Engine) -> None:
    result = runner.invoke(app, ["regress"])
    assert result.exit_code != 0
    # Typer reports the missing required option on stderr; CliRunner merges
    # stderr into ``output`` for the default mix_stderr=True.
    assert "target-sha" in result.output.lower() or "missing" in result.output.lower()


# ---------------------------------------------------------------------------
# 14. CLI: empty regressions root => total=0, exit 0.
# ---------------------------------------------------------------------------


def test_cli_regress_on_empty_corpus_exits_zero(engine: Engine, tmp_path: Path) -> None:
    empty_root = tmp_path / "evals" / "empty-regressions"
    empty_root.mkdir(parents=True)

    result = runner.invoke(
        app,
        ["regress", "--target-sha", "newsha", "--root", str(empty_root)],
    )
    assert result.exit_code == 0, result.output
    assert "total: 0" in result.output
    assert "newsha" in result.output


# ---------------------------------------------------------------------------
# 15. CLI: at least one regressed case => exit 1.
# ---------------------------------------------------------------------------


def test_cli_regress_exits_one_when_a_case_regresses(engine: Engine, tmp_path: Path) -> None:
    """We monkey-patch the runner's :func:`run_regression_session` to return a
    summary with regressed > 0, since the CLI's own no-op clients always
    produce a 'fail' verdict and we want a focused contract test for the
    exit-code branch.
    """
    cli_root = tmp_path / "evals" / "regressions-cli"
    cli_root.mkdir(parents=True)

    async def _fake_session(
        *,
        new_target_sha: str,
        engine: Engine,
        http: Any,
        llm_for_judge: Any,
        langfuse: Any | None = None,
        root: Path | str = REGRESSIONS_DIR,
    ) -> RegressionSessionSummary:
        result = RegressionResult(
            run_id=uuid4(),
            test_case_path=str(Path(root) / "fake.json"),
            new_target_sha=new_target_sha,
            status="regressed",
            old_verdict="pass",
            new_verdict="fail",
            old_confidence=0.9,
            new_confidence=0.8,
            confidence_delta=-0.1,
            notes="fake regression",
        )
        return RegressionSessionSummary(
            new_target_sha=new_target_sha,
            total=1,
            held=0,
            regressed=1,
            weakly_passing=0,
            inconclusive=0,
            results=[result],
        )

    with patch("agentforge_redteam.regression.runner.run_regression_session", _fake_session):
        result = runner.invoke(
            app,
            ["regress", "--target-sha", "newsha", "--root", str(cli_root)],
        )

    assert result.exit_code == 1, result.output
    assert "regressed: 1" in result.output


# ---------------------------------------------------------------------------
# 16. JSON written by the harness round-trips through the runner.
# ---------------------------------------------------------------------------


async def test_session_consumes_real_promoted_case_json(
    engine: Engine, regressions_root: Path
) -> None:
    """Smoke test that ``write_case`` -> ``list_promoted_cases`` -> ``run_regression_session``
    is a closed loop. Catches schema drift between writer and reader.
    """
    case = _make_case(expected_verdict="pass", expected_confidence=0.9)
    _write_case_and_seed_finding(engine, regressions_root, case)

    # Independently parse the file to confirm it's valid JSON on disk.
    on_disk_path = regressions_root / f"{case.finding_id}.json"
    on_disk = json.loads(on_disk_path.read_text(encoding="utf-8"))
    assert on_disk["finding_id"] == str(case.finding_id)

    # Under the corrected verdict semantics, the 'held' status (the smoke
    # test's intent) corresponds to original pass -> replay fail.
    fake_judge = _make_fake_judge(verdict="fail", confidence=0.9)
    with patch("agentforge_redteam.regression.runner.judge_node", fake_judge):
        summary = await run_regression_session(
            new_target_sha="target-sha-new",
            engine=engine,
            http=_FakeHTTP(),
            llm_for_judge=object(),
            root=regressions_root,
        )
    assert summary.total == 1
    assert summary.results[0].status == "held"
