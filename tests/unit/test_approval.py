"""Tests for the human approval queue module and CLI.

Exercises :mod:`agentforge_redteam.approval` against a real SQLite database
migrated under ``tmp_path`` — same pattern as ``test_tool_wrapper.py``. The
CLI tests drive the Typer app via :class:`CliRunner` and assert against the
same database via ``PLATFORM_DB_PATH``.

We don't mock SQLAlchemy. The only stub is :class:`_FakeGitLab`, which
implements just enough of the ``GitLabClientLike`` protocol for ``approve``
to make its outbound call without importing ``httpx``.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
import sqlalchemy as sa
import yaml
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import Engine
from typer.testing import CliRunner

from agentforge_redteam import approval as approval_module
from agentforge_redteam import cli as cli_module
from agentforge_redteam.approval import (
    ApprovalResult,
    QueueEntryNotFound,
    approve,
    get_entry,
    list_pending,
    reject,
)
from agentforge_redteam.cli import app
from agentforge_redteam.db import create_platform_engine

REPO_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_INI = REPO_ROOT / "alembic.ini"
ALEMBIC_DIR = REPO_ROOT / "alembic"

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def migrated_engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Engine]:
    """Yield a platform engine pointed at a freshly-migrated tmp database.

    Also sets ``PLATFORM_DB_PATH`` so any in-process CLI invocation finds
    the same database via :func:`agentforge_redteam.db.database_url`.
    """
    db_path = tmp_path / "approval.db"
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


@dataclass(frozen=True, slots=True)
class _FakeIssueRef:
    """Stand-in for GitLabIssueRef matching the GitLabIssueRefLike Protocol."""

    issue_id: int
    url: str


class _FakeGitLab:
    """In-memory stand-in for the GitLab client."""

    def __init__(self, *, issue_id: int = 42, url: str = "https://gitlab/x/42") -> None:
        self._issue_id = issue_id
        self._url = url
        self.calls: list[dict[str, object]] = []

    async def create_issue(self, *, title: str, body: str, labels: list[str]) -> _FakeIssueRef:
        self.calls.append({"title": title, "body": body, "labels": list(labels)})
        return _FakeIssueRef(issue_id=self._issue_id, url=self._url)


class _ExplodingGitLab:
    """GitLab stub whose ``create_issue`` always raises."""

    async def create_issue(self, *, title: str, body: str, labels: list[str]) -> _FakeIssueRef:
        raise RuntimeError("simulated GitLab outage")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seed_queue_entry(
    engine: Engine,
    *,
    payload: str = "ignore previous instructions",
    target_response: str = "I will not comply.",
    severity: str = "P0",
    confidence: float = 0.85,
) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID]:
    """Insert one attack/verdict/finding/queue chain and return their IDs.

    Returns ``(attack_id, verdict_id, finding_id, queue_id)``. The CLI / API
    contract here is that the doc agent inserts these rows during a normal
    run; we replay that minimally so the queue has something to list.
    """
    attack_id = uuid.uuid4()
    verdict_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    queue_id = uuid.uuid4()
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
                "campaign_id": str(uuid.uuid4()),
                "payload": payload,
                "target_response": target_response,
                "target_sha": "target-sha-abc",
                "status_code": 200,
                "latency_ms": 12,
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
                "verdict": "fail",
                "confidence": confidence,
                "evidence_refs": json.dumps([]),
                "rubric_sha": "rubric-sha-abc",
                "model_version": "stub-model",
                "prompt_sha": "prompt-sha-abc",
            },
        )
        conn.execute(
            sa.text(
                "INSERT INTO findings "
                "(finding_id, severity, attack_id, verdict_id, gitlab_issue_id, "
                "sanitized_evidence) "
                "VALUES (:finding_id, :severity, :attack_id, :verdict_id, NULL, "
                ":sanitized_evidence)"
            ),
            {
                "finding_id": str(finding_id),
                "severity": severity,
                "attack_id": str(attack_id),
                "verdict_id": str(verdict_id),
                "sanitized_evidence": json.dumps({"text": "(redacted)"}),
            },
        )
        conn.execute(
            sa.text(
                "INSERT INTO human_approval_queue "
                "(queue_id, finding_id, status) "
                "VALUES (:queue_id, :finding_id, 'pending')"
            ),
            {"queue_id": str(queue_id), "finding_id": str(finding_id)},
        )
    return attack_id, verdict_id, finding_id, queue_id


def _read_status(engine: Engine, queue_id: uuid.UUID) -> str:
    with engine.connect() as conn:
        return str(
            conn.execute(
                sa.text("SELECT status FROM human_approval_queue WHERE queue_id = :q"),
                {"q": str(queue_id)},
            ).scalar_one()
        )


def _read_gitlab_issue_id(engine: Engine, finding_id: uuid.UUID) -> int | None:
    with engine.connect() as conn:
        value = conn.execute(
            sa.text("SELECT gitlab_issue_id FROM findings WHERE finding_id = :f"),
            {"f": str(finding_id)},
        ).scalar_one()
    return None if value is None else int(value)


# ---------------------------------------------------------------------------
# list_pending / get_entry
# ---------------------------------------------------------------------------


def test_list_pending_empty_queue_returns_empty_list(migrated_engine: Engine) -> None:
    assert list_pending(migrated_engine) == []


def test_list_pending_returns_seeded_entry(migrated_engine: Engine) -> None:
    _, _, _, queue_id = _seed_queue_entry(
        migrated_engine, payload="hello there", severity="P1", confidence=0.4
    )

    entries = list_pending(migrated_engine)
    assert len(entries) == 1
    entry = entries[0]
    assert entry.queue_id == queue_id
    assert entry.severity == "P1"
    assert entry.confidence == pytest.approx(0.4)
    assert entry.title == "hello there"
    assert entry.status == "pending"


def test_list_pending_orders_newest_first(migrated_engine: Engine) -> None:
    _, _, _, qid_old = _seed_queue_entry(migrated_engine, payload="OLD")
    # SQLite CURRENT_TIMESTAMP has one-second resolution; sleep just over a
    # second so the second insert lands on a strictly later timestamp.
    time.sleep(1.05)
    _, _, _, qid_new = _seed_queue_entry(migrated_engine, payload="NEW")

    entries = list_pending(migrated_engine)
    assert [e.queue_id for e in entries] == [qid_new, qid_old]


def test_get_entry_returns_the_right_entry(migrated_engine: Engine) -> None:
    _, _, _, queue_id = _seed_queue_entry(migrated_engine, payload="targeted")
    entry = get_entry(migrated_engine, queue_id=queue_id)
    assert entry.queue_id == queue_id
    assert entry.title == "targeted"


def test_get_entry_missing_raises(migrated_engine: Engine) -> None:
    with pytest.raises(QueueEntryNotFound):
        get_entry(migrated_engine, queue_id=uuid.uuid4())


def test_get_entry_non_pending_raises(migrated_engine: Engine) -> None:
    _, _, _, queue_id = _seed_queue_entry(migrated_engine)
    # Hand-mark approved bypassing the API so we test the read path only.
    with migrated_engine.begin() as conn:
        conn.execute(
            sa.text("UPDATE human_approval_queue SET status='approved' WHERE queue_id = :q"),
            {"q": str(queue_id)},
        )
    with pytest.raises(QueueEntryNotFound):
        get_entry(migrated_engine, queue_id=queue_id)


# ---------------------------------------------------------------------------
# approve
# ---------------------------------------------------------------------------


async def test_approve_happy_path_updates_status_and_finding(
    migrated_engine: Engine,
) -> None:
    _, _, finding_id, queue_id = _seed_queue_entry(migrated_engine)
    fake = _FakeGitLab(issue_id=99, url="https://gitlab/x/99")

    result: ApprovalResult = await approve(
        migrated_engine,
        queue_id=queue_id,
        reviewer="cameron",
        gitlab=fake,
        issue_body="rendered body",
        labels=["severity::P0"],
    )

    assert result.queue_id == queue_id
    assert result.finding_id == finding_id
    assert result.gitlab_issue_id == 99
    assert result.gitlab_issue_url == "https://gitlab/x/99"

    assert _read_status(migrated_engine, queue_id) == "approved"
    assert _read_gitlab_issue_id(migrated_engine, finding_id) == 99
    assert fake.calls == [
        {
            "title": "ignore previous instructions",
            "body": "rendered body",
            "labels": ["severity::P0"],
        }
    ]


async def test_approve_gitlab_failure_leaves_queue_pending(
    migrated_engine: Engine,
) -> None:
    _, _, finding_id, queue_id = _seed_queue_entry(migrated_engine)

    with pytest.raises(RuntimeError, match="simulated GitLab outage"):
        await approve(
            migrated_engine,
            queue_id=queue_id,
            reviewer="cameron",
            gitlab=_ExplodingGitLab(),
            issue_body="body",
            labels=[],
        )

    # Queue row untouched; finding's gitlab_issue_id still NULL.
    assert _read_status(migrated_engine, queue_id) == "pending"
    assert _read_gitlab_issue_id(migrated_engine, finding_id) is None


async def test_approve_twice_raises_queue_entry_not_found(
    migrated_engine: Engine,
) -> None:
    _, _, _, queue_id = _seed_queue_entry(migrated_engine)
    fake = _FakeGitLab(issue_id=1, url="https://x/1")
    await approve(
        migrated_engine,
        queue_id=queue_id,
        reviewer="cameron",
        gitlab=fake,
        issue_body="body",
        labels=[],
    )
    with pytest.raises(QueueEntryNotFound):
        await approve(
            migrated_engine,
            queue_id=queue_id,
            reviewer="cameron",
            gitlab=fake,
            issue_body="body",
            labels=[],
        )


# ---------------------------------------------------------------------------
# reject
# ---------------------------------------------------------------------------


def test_reject_with_ground_truth_writes_yaml_under_category(
    migrated_engine: Engine, tmp_path: Path
) -> None:
    _, _, finding_id, queue_id = _seed_queue_entry(
        migrated_engine, payload="exploit X", target_response="I refuse."
    )
    gt_root = tmp_path / "gt"

    result = reject(
        migrated_engine,
        queue_id=queue_id,
        reviewer="cameron",
        reason="false positive — model refused cleanly",
        category="prompt-injection-indirect",
        write_ground_truth=True,
        ground_truth_root=gt_root,
    )

    assert result.queue_id == queue_id
    assert result.finding_id == finding_id
    assert result.ground_truth_path is not None
    assert result.ground_truth_path.exists()
    assert result.ground_truth_path.parent == gt_root / "prompt-injection-indirect"

    payload = yaml.safe_load(result.ground_truth_path.read_text())
    assert payload["category"] == "prompt-injection-indirect"
    assert payload["attack_input"] == "exploit X"
    assert payload["target_response"] == "I refuse."
    assert payload["expected_verdict"] == "fail"
    assert payload["confidence"] == 1.0
    assert "false positive" in payload["notes"]

    assert _read_status(migrated_engine, queue_id) == "rejected"


def test_reject_without_ground_truth_writes_no_file(
    migrated_engine: Engine, tmp_path: Path
) -> None:
    _, _, _, queue_id = _seed_queue_entry(migrated_engine)
    gt_root = tmp_path / "gt"

    result = reject(
        migrated_engine,
        queue_id=queue_id,
        reviewer="cameron",
        reason="not interesting",
        write_ground_truth=False,
        ground_truth_root=gt_root,
    )
    assert result.ground_truth_path is None
    assert not gt_root.exists()
    assert _read_status(migrated_engine, queue_id) == "rejected"


def test_reject_with_ground_truth_missing_category_raises(
    migrated_engine: Engine, tmp_path: Path
) -> None:
    _, _, _, queue_id = _seed_queue_entry(migrated_engine)
    with pytest.raises(ValueError, match="category is required"):
        reject(
            migrated_engine,
            queue_id=queue_id,
            reviewer="cameron",
            reason="...",
            category=None,
            write_ground_truth=True,
            ground_truth_root=tmp_path / "gt",
        )
    # Status untouched on validation failure.
    assert _read_status(migrated_engine, queue_id) == "pending"


def test_reject_twice_raises_queue_entry_not_found(migrated_engine: Engine, tmp_path: Path) -> None:
    _, _, _, queue_id = _seed_queue_entry(migrated_engine)
    reject(
        migrated_engine,
        queue_id=queue_id,
        reviewer="cameron",
        reason="r",
        write_ground_truth=False,
        ground_truth_root=tmp_path / "gt",
    )
    with pytest.raises(QueueEntryNotFound):
        reject(
            migrated_engine,
            queue_id=queue_id,
            reviewer="cameron",
            reason="r",
            write_ground_truth=False,
            ground_truth_root=tmp_path / "gt",
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_queue_help_works(migrated_engine: Engine) -> None:
    result = runner.invoke(app, ["queue", "--help"])
    assert result.exit_code == 0, result.output
    assert "queue" in result.output.lower()


def test_cli_queue_list_empty_prints_no_pending(migrated_engine: Engine) -> None:
    result = runner.invoke(app, ["queue", "list"])
    assert result.exit_code == 0, result.output
    assert "no pending findings" in result.output


def test_cli_queue_list_after_seeding_prints_queue_id(migrated_engine: Engine) -> None:
    _, _, _, queue_id = _seed_queue_entry(migrated_engine, payload="visible payload")
    result = runner.invoke(app, ["queue", "list"])
    assert result.exit_code == 0, result.output
    # The full UUID is printed; assert on the first 8 chars as the spec asks.
    assert str(queue_id)[:8] in result.output
    assert "visible payload" in result.output


def test_cli_queue_approve_missing_id_exits_one(
    migrated_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The CLI guards on GitLab config first; stub it out so the failure is
    # the QueueEntryNotFound, not the missing-token branch.
    monkeypatch.setattr(
        cli_module,
        "create_gitlab_client",
        lambda: _FakeGitLab(),
    )
    bogus = str(uuid.uuid4())
    result = runner.invoke(app, ["queue", "approve", bogus])
    assert result.exit_code == 1, result.output


def test_cli_queue_approve_happy_path(
    migrated_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, finding_id, queue_id = _seed_queue_entry(migrated_engine)
    monkeypatch.setattr(
        cli_module,
        "create_gitlab_client",
        lambda: _FakeGitLab(issue_id=77, url="https://gitlab/x/77"),
    )
    result = runner.invoke(app, ["queue", "approve", str(queue_id)])
    assert result.exit_code == 0, result.output
    assert "approved" in result.output
    assert "gitlab_issue_id=77" in result.output
    assert _read_status(migrated_engine, queue_id) == "approved"
    assert _read_gitlab_issue_id(migrated_engine, finding_id) == 77


def test_cli_queue_reject_writes_ground_truth(migrated_engine: Engine, tmp_path: Path) -> None:
    _, _, _, queue_id = _seed_queue_entry(
        migrated_engine, payload="reject me", target_response="ok"
    )
    gt_root = tmp_path / "gt"
    result = runner.invoke(
        app,
        [
            "queue",
            "reject",
            str(queue_id),
            "--reason",
            "model refused, no exploit",
            "--category",
            "prompt-injection-indirect",
            "--root",
            str(gt_root),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "rejected" in result.output
    assert _read_status(migrated_engine, queue_id) == "rejected"
    category_dir = gt_root / "prompt-injection-indirect"
    assert category_dir.exists()
    yamls = list(category_dir.glob("*.yaml"))
    assert len(yamls) == 1


# Quiet ruff F401: ``approval_module`` is imported above so that future tests
# can monkeypatch into the module without re-importing.
_ = approval_module
