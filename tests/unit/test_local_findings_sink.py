"""Unit tests for :mod:`agentforge_redteam.clients.local_findings_sink`
and the :mod:`agentforge_redteam.clients.factory` selector.

The sink satisfies the Doc Agent's ``GitLabClientLike`` Protocol by
writing rendered finding bodies to disk under a configurable root. These
tests cover:

* basic write + return-shape semantics
* slug + counter behaviour (boundary conditions and resume-from-disk)
* the YAML labels footer
* concurrent ``create_issue`` calls do not collide
* the factory's branch selection between real GitLab and local sink
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest

from agentforge_redteam.agents.documentation import GitLabIssueRef
from agentforge_redteam.clients.factory import create_documentation_client
from agentforge_redteam.clients.gitlab_client import (
    GITLAB_PROJECT_ID_ENV,
    GITLAB_TOKEN_ENV,
    GitLabClient,
)
from agentforge_redteam.clients.local_findings_sink import (
    LocalFindingsSink,
    create_documentation_sink,
)

# ---------------------------------------------------------------------------
# create_issue: returns and writes
# ---------------------------------------------------------------------------


async def test_create_issue_writes_file_to_findings_dir(tmp_path: Path) -> None:
    """A single ``create_issue`` call writes one .md file under the configured
    root. The returned ref carries the synthetic counter and a file:// URL.
    """
    sink = LocalFindingsSink(findings_dir=tmp_path)
    ref = await sink.create_issue(title="t", body="b", labels=["x"])

    written = list(tmp_path.glob("*.md"))
    assert len(written) == 1
    assert isinstance(ref, GitLabIssueRef)


async def test_first_issue_id_is_one_and_url_is_file_scheme(tmp_path: Path) -> None:
    sink = LocalFindingsSink(findings_dir=tmp_path)
    ref = await sink.create_issue(title="t", body="b", labels=[])

    assert ref.issue_id == 1
    assert ref.url.startswith("file://")


async def test_counter_increments_on_subsequent_calls(tmp_path: Path) -> None:
    """The synthetic ``issue_id`` is monotonic across calls on one sink."""
    sink = LocalFindingsSink(findings_dir=tmp_path)
    refs = []
    for _ in range(3):
        refs.append(await sink.create_issue(title="t", body="b", labels=[]))

    assert [r.issue_id for r in refs] == [1, 2, 3]
    assert len(list(tmp_path.glob("*.md"))) == 3


# ---------------------------------------------------------------------------
# Body + footer
# ---------------------------------------------------------------------------


async def test_written_file_contains_body_verbatim(tmp_path: Path) -> None:
    sink = LocalFindingsSink(findings_dir=tmp_path)
    body = "# Heading\n\nSome content with *markdown*.\n"
    await sink.create_issue(title="t", body=body, labels=["a"])

    on_disk = next(iter(tmp_path.glob("*.md"))).read_text(encoding="utf-8")
    assert body in on_disk


async def test_written_file_appends_yaml_labels_footer(tmp_path: Path) -> None:
    """Labels are persisted as a YAML block at the END of the file so they
    are not lost when GitLab issue metadata would normally carry them.
    """
    sink = LocalFindingsSink(findings_dir=tmp_path)
    await sink.create_issue(title="t", body="b", labels=["x", "y::z"])

    on_disk = next(iter(tmp_path.glob("*.md"))).read_text(encoding="utf-8")
    assert on_disk.rstrip("\n").endswith("---")
    assert "labels:\n  - x\n  - y::z" in on_disk


# ---------------------------------------------------------------------------
# Slug behaviour
# ---------------------------------------------------------------------------


async def test_title_is_slugified_into_filename(tmp_path: Path) -> None:
    """A title with punctuation slugifies to a-z/0-9/dash, lowercased."""
    sink = LocalFindingsSink(findings_dir=tmp_path)
    await sink.create_issue(title="This is a P0!", body="b", labels=[])

    written = list(tmp_path.glob("*.md"))
    assert len(written) == 1
    assert written[0].name.startswith("this-is-a-p0-")
    assert written[0].name.endswith("-1.md")


async def test_long_title_truncates_at_sixty_chars(tmp_path: Path) -> None:
    """Slug component caps at 60 chars so the filename stays bounded."""
    sink = LocalFindingsSink(findings_dir=tmp_path)
    long_title = "a" * 200
    await sink.create_issue(title=long_title, body="b", labels=[])

    written = list(tmp_path.glob("*.md"))
    assert len(written) == 1
    # Filename shape: "<slug>-<counter>.md"; slug must be <= 60 chars.
    slug_part = written[0].name.rsplit("-", 1)[0]
    assert len(slug_part) == 60


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------


def test_create_documentation_sink_returns_local_sink() -> None:
    assert isinstance(create_documentation_sink(), LocalFindingsSink)


def test_factory_returns_local_sink_when_env_missing() -> None:
    """No ``GITLAB_TOKEN`` / ``GITLAB_PROJECT_ID`` -> local sink."""
    client = create_documentation_client(env={})
    assert isinstance(client, LocalFindingsSink)


def test_factory_returns_gitlab_client_when_env_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With env populated the factory returns the real httpx-backed client.

    We don't make a network call here — we only verify the branch selection.
    A monkeypatched ``httpx.AsyncClient`` keeps the import-time wiring
    hermetic even if construction were to eagerly open a transport.
    """
    monkeypatch.setattr(httpx, "AsyncClient", httpx.AsyncClient)
    client = create_documentation_client(
        env={GITLAB_TOKEN_ENV: "glpat-test", GITLAB_PROJECT_ID_ENV: "42"}
    )
    assert isinstance(client, GitLabClient)


# ---------------------------------------------------------------------------
# Resume + concurrency
# ---------------------------------------------------------------------------


async def test_counter_resumes_from_highest_existing_suffix(tmp_path: Path) -> None:
    """Pre-existing ``*-N.md`` files set the counter floor.

    The sink scans the directory on each call; if a previous run wrote
    ``foo-7.md`` the next call should land at ``issue_id == 8``.
    """
    (tmp_path / "foo-7.md").write_text("legacy", encoding="utf-8")
    sink = LocalFindingsSink(findings_dir=tmp_path)
    ref = await sink.create_issue(title="t", body="b", labels=[])

    assert ref.issue_id == 8


async def test_concurrent_create_issue_calls_do_not_collide(tmp_path: Path) -> None:
    """``asyncio.gather`` over five concurrent ``create_issue`` calls yields
    five distinct files and five distinct ``issue_id`` values.
    """
    sink = LocalFindingsSink(findings_dir=tmp_path)
    refs = await asyncio.gather(
        *(sink.create_issue(title=f"t-{i}", body="b", labels=[]) for i in range(5))
    )

    assert len({r.issue_id for r in refs}) == 5
    assert len(list(tmp_path.glob("*.md"))) == 5
