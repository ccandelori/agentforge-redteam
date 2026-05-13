"""Tests for the operator FastAPI app.

Drives :mod:`agentforge_redteam.web.app` via :class:`fastapi.testclient.TestClient`
against a real SQLite database migrated under ``tmp_path``. No real network:
the GitLab sink is monkeypatched to a fake at the factory site.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine

from agentforge_redteam.db import create_platform_engine
from agentforge_redteam.web import app as app_module
from agentforge_redteam.web.app import app
from agentforge_redteam.web.auth import (
    WEB_UI_PASSWORD_ENV,
    WEB_UI_USER_ENV,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_INI = REPO_ROOT / "alembic.ini"
ALEMBIC_DIR = REPO_ROOT / "alembic"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def migrated_engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Engine]:
    """Fresh DB with ``alembic upgrade head``. ``PLATFORM_DB_PATH`` is set so
    the app's per-request engine binds to the same SQLite file."""
    db_path = tmp_path / "web.db"
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
def client(migrated_engine: Engine) -> Iterator[TestClient]:
    """TestClient bound to the migrated DB."""
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _FakeIssueRef:
    issue_id: int
    url: str


class _FakeGitLab:
    """In-memory stand-in for the GitLab client used by ``approve``."""

    def __init__(self, *, issue_id: int = 4242, url: str = "https://gl/test/4242") -> None:
        self._issue_id = issue_id
        self._url = url
        self.calls: list[dict[str, object]] = []

    async def create_issue(self, *, title: str, body: str, labels: list[str]) -> _FakeIssueRef:
        self.calls.append({"title": title, "body": body, "labels": list(labels)})
        return _FakeIssueRef(issue_id=self._issue_id, url=self._url)


# ---------------------------------------------------------------------------
# Seed helpers
# ---------------------------------------------------------------------------


def _seed_queue_entry(
    engine: Engine,
    *,
    payload: str = "ignore previous instructions",
    target_response: str = "I refuse to comply.",
    severity: str = "P0",
    confidence: float = 0.85,
) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID]:
    """Insert one attack/verdict/finding/queue chain. Returns the four UUIDs."""
    attack_id = uuid.uuid4()
    verdict_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    queue_id = uuid.uuid4()
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO attacks "
                "(attack_id, campaign_id, payload, target_response, target_sha, "
                "status_code, latency_ms) VALUES "
                "(:a, :c, :p, :tr, :tsha, 200, 10)"
            ),
            {
                "a": str(attack_id),
                "c": str(uuid.uuid4()),
                "p": payload,
                "tr": target_response,
                "tsha": "sha-test",
            },
        )
        conn.execute(
            sa.text(
                "INSERT INTO verdicts "
                "(verdict_id, attack_id, verdict, confidence, evidence_refs, "
                "rubric_sha, model_version, prompt_sha) VALUES "
                "(:v, :a, 'fail', :conf, :refs, 'r', 'm', 'p')"
            ),
            {
                "v": str(verdict_id),
                "a": str(attack_id),
                "conf": confidence,
                "refs": json.dumps([]),
            },
        )
        conn.execute(
            sa.text(
                "INSERT INTO findings "
                "(finding_id, severity, attack_id, verdict_id, gitlab_issue_id, "
                "sanitized_evidence) VALUES "
                "(:f, :sev, :a, :v, NULL, :se)"
            ),
            {
                "f": str(finding_id),
                "sev": severity,
                "a": str(attack_id),
                "v": str(verdict_id),
                "se": json.dumps({}),
            },
        )
        conn.execute(
            sa.text(
                "INSERT INTO human_approval_queue "
                "(queue_id, finding_id, status) VALUES (:q, :f, 'pending')"
            ),
            {"q": str(queue_id), "f": str(finding_id)},
        )
    return attack_id, verdict_id, finding_id, queue_id


def _seed_coverage_row(
    engine: Engine,
    *,
    category: str = "prompt-injection-direct",
    sub_attack: str = "system-override",
) -> None:
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO coverage_matrix "
                "(category, sub_attack, runs_last_7d, runs_lifetime, "
                "findings_by_severity, last_run_at, avg_cost_cents, coverage_score) "
                "VALUES (:c, :s, 3, 9, :fbs, NULL, 12, 0.5)"
            ),
            {
                "c": category,
                "s": sub_attack,
                "fbs": json.dumps({"P0": 1, "P2": 2}),
            },
        )


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


def test_auth_disabled_when_password_unset(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(WEB_UI_PASSWORD_ENV, raising=False)
    resp = client.get("/coverage")
    assert resp.status_code == 200


def test_auth_required_when_password_set(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(WEB_UI_PASSWORD_ENV, "s3cret")
    resp = client.get("/coverage")
    assert resp.status_code == 401
    assert resp.headers.get("www-authenticate") == "Basic"


def test_auth_accepts_valid_credentials(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(WEB_UI_USER_ENV, "alice")
    monkeypatch.setenv(WEB_UI_PASSWORD_ENV, "s3cret")
    resp = client.get("/coverage", auth=("alice", "s3cret"))
    assert resp.status_code == 200


def test_auth_rejects_wrong_credentials(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(WEB_UI_PASSWORD_ENV, "s3cret")
    resp = client.get("/coverage", auth=("operator", "wrong"))
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Root / health
# ---------------------------------------------------------------------------


def test_root_returns_name_and_version(client: TestClient) -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "AgentForge web UI"
    assert body["version"] == "0.1.0"


def test_healthz_returns_ok(client: TestClient) -> None:
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


def test_start_session_happy_path(
    client: TestClient,
    migrated_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # POST /sessions/start schedules ``_dispatch_session`` as a FastAPI
    # BackgroundTask. The real dispatcher invokes ``run_session`` which
    # spins up the LangGraph + LLM stack — far out of scope for a web-layer
    # test. We stub it to just write a placeholder manifest row so the
    # post-condition (operator can GET the session afterward) still holds.
    captured: list[tuple[str, str, int, tuple[str, ...]]] = []

    def fake_dispatch(
        session_id: str,
        target_alias: str,
        cost_cap_cents: int,
        categories: tuple[str, ...],
    ) -> None:
        captured.append((session_id, target_alias, cost_cap_cents, categories))
        with migrated_engine.begin() as conn:
            conn.execute(
                sa.text(
                    "INSERT INTO run_manifests "
                    "(session_id, target_sha, prompt_set_sha, rubric_set_sha, "
                    "attack_library_sha, policy_sha, cost_cap_cents) "
                    "VALUES (:sid, 'pending', 'pending', 'pending', 'pending', 'pending', :cap)"
                ),
                {"sid": session_id, "cap": cost_cap_cents},
            )

    monkeypatch.setattr(
        "agentforge_redteam.web.app._dispatch_session",
        fake_dispatch,
    )

    resp = client.post(
        "/sessions/start",
        json={
            "cost_cap_cents": 5000,
            "target": "clinical-copilot",
            "categories": ["prompt-injection-direct"],
        },
    )
    assert resp.status_code == 200, resp.text
    session_id = resp.json()["session_id"]
    assert uuid.UUID(session_id)

    # The bg task ran (TestClient drains BackgroundTasks before returning).
    assert captured == [(session_id, "clinical-copilot", 5000, ("prompt-injection-direct",))]

    with migrated_engine.connect() as conn:
        row = conn.execute(
            sa.text("SELECT cost_cap_cents FROM run_manifests WHERE session_id = :s"),
            {"s": session_id},
        ).first()
    assert row is not None
    assert row[0] == 5000


def test_start_session_rejects_invalid_body(client: TestClient) -> None:
    resp = client.post(
        "/sessions/start",
        json={
            "cost_cap_cents": -10,
            "target": "clinical-copilot",
            "categories": ["x"],
        },
    )
    assert resp.status_code == 422


def test_get_session_existing(
    client: TestClient,
    migrated_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Same fake-dispatch trick — write a placeholder manifest row so the
    # follow-up GET has something to return.
    def fake_dispatch(
        session_id: str,
        target_alias: str,
        cost_cap_cents: int,
        categories: tuple[str, ...],
    ) -> None:
        with migrated_engine.begin() as conn:
            conn.execute(
                sa.text(
                    "INSERT INTO run_manifests "
                    "(session_id, target_sha, prompt_set_sha, rubric_set_sha, "
                    "attack_library_sha, policy_sha, cost_cap_cents) "
                    "VALUES (:sid, 'pending', 'pending', 'pending', 'pending', 'pending', :cap)"
                ),
                {"sid": session_id, "cap": cost_cap_cents},
            )

    monkeypatch.setattr(
        "agentforge_redteam.web.app._dispatch_session",
        fake_dispatch,
    )

    created = client.post(
        "/sessions/start",
        json={
            "cost_cap_cents": 5000,
            "target": "clinical-copilot",
            "categories": ["prompt-injection-direct"],
        },
    ).json()
    sid = created["session_id"]

    resp = client.get(f"/sessions/{sid}")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["session_id"] == sid
    assert body["campaigns_run"] == 0
    # cost_so_far is JSON-serialised by Pydantic as a string for Decimals.
    assert body["cost_so_far"] in ("0.00", "0", 0, 0.0)
    assert body["halt_reason"] is None
    assert "started_at" in body


def test_get_session_missing_returns_404(client: TestClient) -> None:
    resp = client.get(f"/sessions/{uuid.uuid4()}")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------


def test_coverage_empty(client: TestClient) -> None:
    resp = client.get("/coverage")
    assert resp.status_code == 200
    assert resp.json() == {"rows": []}


def test_coverage_with_rows(client: TestClient, migrated_engine: Engine) -> None:
    _seed_coverage_row(migrated_engine)
    resp = client.get("/coverage")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["rows"]) == 1
    row = body["rows"][0]
    assert row["category"] == "prompt-injection-direct"
    assert row["sub_attack"] == "system-override"
    assert row["runs_last_7d"] == 3
    assert row["runs_lifetime"] == 9
    assert row["findings_by_severity"] == {"P0": 1, "P2": 2}
    assert row["avg_cost_cents"] == 12


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


def test_findings_list_empty(client: TestClient) -> None:
    resp = client.get("/findings")
    assert resp.status_code == 200
    assert resp.json() == {"findings": []}


def test_findings_list_returns_seeded(client: TestClient, migrated_engine: Engine) -> None:
    _, _, finding_id, _ = _seed_queue_entry(migrated_engine, payload="exfil PHI", severity="P1")
    resp = client.get("/findings")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["findings"]) == 1
    f = body["findings"][0]
    assert f["finding_id"] == str(finding_id)
    assert f["severity"] == "P1"
    assert f["title"] == "exfil PHI"
    assert f["gitlab_issue_id"] is None


def test_finding_detail_404_on_missing(client: TestClient) -> None:
    resp = client.get(f"/findings/{uuid.uuid4()}")
    assert resp.status_code == 404


def test_finding_detail_returns_full_payload(client: TestClient, migrated_engine: Engine) -> None:
    _, _, finding_id, _ = _seed_queue_entry(
        migrated_engine,
        payload="exfil PHI long payload",
        target_response="I will not comply.",
        severity="P0",
    )
    resp = client.get(f"/findings/{finding_id}")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["finding_id"] == str(finding_id)
    assert body["attack_payload"] == "exfil PHI long payload"
    assert body["target_response"] == "I will not comply."
    assert body["severity"] == "P0"
    assert body["rendered_markdown"] == ""


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


def test_halt_trips_switch(client: TestClient, migrated_engine: Engine) -> None:
    resp = client.post("/halt")
    assert resp.status_code == 200
    assert resp.json() == {"status": "halted"}
    with migrated_engine.connect() as conn:
        row = conn.execute(sa.text("SELECT enabled FROM kill_switch WHERE id = 1")).first()
    assert row is not None
    assert bool(row[0]) is True


def test_halt_is_idempotent(client: TestClient) -> None:
    first = client.post("/halt")
    second = client.post("/halt")
    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json() == {"status": "halted"}


def test_resume_clears_switch(client: TestClient, migrated_engine: Engine) -> None:
    client.post("/halt")
    resp = client.post("/resume")
    assert resp.status_code == 200
    assert resp.json() == {"status": "running"}
    with migrated_engine.connect() as conn:
        row = conn.execute(sa.text("SELECT enabled FROM kill_switch WHERE id = 1")).first()
    assert row is not None
    assert bool(row[0]) is False


def _insert_manifest_row(engine: Engine, session_id: str) -> None:
    """Helper: insert a placeholder manifest row matching production shape."""
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO run_manifests "
                "(session_id, target_sha, prompt_set_sha, rubric_set_sha, "
                "attack_library_sha, policy_sha, cost_cap_cents) "
                "VALUES (:sid, 'pending', 'pending', 'pending', 'pending', 'pending', 100)"
            ),
            {"sid": session_id},
        )


def test_halt_marks_active_sessions_with_operator_halt(
    client: TestClient, migrated_engine: Engine
) -> None:
    """The /halt endpoint must write halt_reason='operator_halt' on every
    in-flight session so post-mortem state is informative. Surfaced when
    session 29488fc5 wedged: /halt returned 200 but the manifest's
    halt_reason was never populated, so the operator-visible state stayed
    NULL forever."""
    from agentforge_redteam.web import app as web_app

    sid = str(uuid.uuid4())
    _insert_manifest_row(migrated_engine, sid)
    web_app._active_sessions.add(sid)
    try:
        resp = client.post("/halt")
        assert resp.status_code == 200
        with migrated_engine.connect() as conn:
            row = conn.execute(
                sa.text("SELECT halt_reason, ended_at FROM run_manifests WHERE session_id = :sid"),
                {"sid": sid},
            ).first()
        assert row is not None
        assert row[0] == "operator_halt"
        assert row[1] is not None
    finally:
        web_app._active_sessions.discard(sid)


def test_halt_does_not_clobber_existing_halt_reason(
    client: TestClient, migrated_engine: Engine
) -> None:
    """If a session already has halt_reason set (e.g. dispatcher_crash from
    an earlier exception path), a subsequent /halt must leave it alone —
    the more specific reason wins over the generic operator_halt."""
    from agentforge_redteam.web import app as web_app

    sid = str(uuid.uuid4())
    _insert_manifest_row(migrated_engine, sid)
    with migrated_engine.begin() as conn:
        conn.execute(
            sa.text(
                "UPDATE run_manifests SET halt_reason = 'dispatcher_crash:RuntimeError' "
                "WHERE session_id = :sid"
            ),
            {"sid": sid},
        )
    web_app._active_sessions.add(sid)
    try:
        client.post("/halt")
        with migrated_engine.connect() as conn:
            row = conn.execute(
                sa.text("SELECT halt_reason FROM run_manifests WHERE session_id = :sid"),
                {"sid": sid},
            ).first()
        assert row is not None
        assert row[0] == "dispatcher_crash:RuntimeError"
    finally:
        web_app._active_sessions.discard(sid)


def test_get_session_returns_persisted_halt_reason(
    client: TestClient, migrated_engine: Engine
) -> None:
    """GET /sessions/{id} must read halt_reason from the manifest column
    (added in migration 0003), not return hardcoded None."""
    sid = str(uuid.uuid4())
    _insert_manifest_row(migrated_engine, sid)
    with migrated_engine.begin() as conn:
        conn.execute(
            sa.text(
                "UPDATE run_manifests SET halt_reason = 'budget_exhausted' WHERE session_id = :sid"
            ),
            {"sid": sid},
        )
    resp = client.get(f"/sessions/{sid}")
    assert resp.status_code == 200
    assert resp.json()["halt_reason"] == "budget_exhausted"


# ---------------------------------------------------------------------------
# Queue
# ---------------------------------------------------------------------------


def test_queue_list_empty(client: TestClient) -> None:
    resp = client.get("/queue")
    assert resp.status_code == 200
    assert resp.json() == {"entries": []}


def test_queue_list_returns_entries(client: TestClient, migrated_engine: Engine) -> None:
    _, _, finding_id, queue_id = _seed_queue_entry(
        migrated_engine, payload="leak system prompt", severity="P0", confidence=0.9
    )
    resp = client.get("/queue")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["entries"]) == 1
    e = body["entries"][0]
    assert e["queue_id"] == str(queue_id)
    assert e["finding_id"] == str(finding_id)
    assert e["severity"] == "P0"
    assert e["title"] == "leak system prompt"
    assert e["confidence"] == pytest.approx(0.9)


def test_queue_approve_happy_path(
    client: TestClient,
    migrated_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, finding_id, queue_id = _seed_queue_entry(migrated_engine)
    fake = _FakeGitLab(issue_id=777, url="https://gl/test/777")
    # The app's documentation-client resolver imports inside the function;
    # patch the resolver directly to keep the test hermetic.
    monkeypatch.setattr(app_module, "_documentation_client", lambda: fake)

    resp = client.post(
        f"/queue/{queue_id}/approve",
        json={"reviewer": "cameron"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["queue_id"] == str(queue_id)
    assert body["finding_id"] == str(finding_id)
    assert body["gitlab_issue_id"] == 777
    assert body["gitlab_issue_url"] == "https://gl/test/777"

    with migrated_engine.connect() as conn:
        status_val = conn.execute(
            sa.text("SELECT status FROM human_approval_queue WHERE queue_id = :q"),
            {"q": str(queue_id)},
        ).scalar_one()
    assert status_val == "approved"
    assert fake.calls and fake.calls[0]["labels"] == [
        "severity::P0",
        "source::web-ui",
    ]


def test_queue_approve_404_when_not_pending(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "_documentation_client", lambda: _FakeGitLab())
    bogus = uuid.uuid4()
    resp = client.post(
        f"/queue/{bogus}/approve",
        json={"reviewer": "cameron"},
    )
    assert resp.status_code == 404


def test_queue_approve_503_when_no_sink(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "_documentation_client", lambda: None)
    resp = client.post(
        f"/queue/{uuid.uuid4()}/approve",
        json={"reviewer": "cameron"},
    )
    assert resp.status_code == 503


def test_queue_reject_with_ground_truth(
    client: TestClient,
    migrated_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _, _, _, queue_id = _seed_queue_entry(
        migrated_engine, payload="reject me", target_response="I won't"
    )
    # Redirect the ground-truth root so we don't write into the repo.
    monkeypatch.chdir(tmp_path)

    resp = client.post(
        f"/queue/{queue_id}/reject",
        json={
            "reviewer": "cameron",
            "reason": "model refused cleanly",
            "category": "prompt-injection-indirect",
            "write_ground_truth": True,
        },
    )
    assert resp.status_code == 204, resp.text
    with migrated_engine.connect() as conn:
        status_val = conn.execute(
            sa.text("SELECT status FROM human_approval_queue WHERE queue_id = :q"),
            {"q": str(queue_id)},
        ).scalar_one()
    assert status_val == "rejected"


def test_queue_reject_without_ground_truth(client: TestClient, migrated_engine: Engine) -> None:
    _, _, _, queue_id = _seed_queue_entry(migrated_engine)
    resp = client.post(
        f"/queue/{queue_id}/reject",
        json={
            "reviewer": "cameron",
            "reason": "not interesting",
            "write_ground_truth": False,
        },
    )
    assert resp.status_code == 204
    with migrated_engine.connect() as conn:
        status_val = conn.execute(
            sa.text("SELECT status FROM human_approval_queue WHERE queue_id = :q"),
            {"q": str(queue_id)},
        ).scalar_one()
    assert status_val == "rejected"


def test_queue_reject_missing_reason_returns_422(
    client: TestClient, migrated_engine: Engine
) -> None:
    _, _, _, queue_id = _seed_queue_entry(migrated_engine)
    resp = client.post(
        f"/queue/{queue_id}/reject",
        json={"reviewer": "cameron"},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------


def test_cors_preflight_succeeds(client: TestClient) -> None:
    resp = client.options(
        "/coverage",
        headers={
            "Origin": "https://operator.example",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization",
        },
    )
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == "*"
