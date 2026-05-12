"""Unit tests for :mod:`agentforge_redteam.findings_store`.

The store is a pure I/O leaf with four functions; these tests cover
path construction, the refuse-to-overwrite guarantee, the
parent-directory-on-demand behaviour, the round-trip property, and
the listing sort order. The store has no Doc-Agent dependency so these
tests do not import anything from ``agentforge_redteam.agents``.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid4

import pytest

from agentforge_redteam.findings_store import (
    FINDINGS_DIR,
    finding_path,
    list_findings,
    read_finding,
    write_finding,
)

# ---------------------------------------------------------------------------
# finding_path
# ---------------------------------------------------------------------------


def test_finding_path_returns_expected_layout(tmp_path: Path) -> None:
    uid = UUID("00000000-0000-0000-0000-000000000001")
    assert finding_path(uid, tmp_path) == tmp_path / f"{uid}.md"


def test_finding_path_default_root_is_findings_dir() -> None:
    """With no ``root`` argument, the path resolves under the package
    default ``findings/`` directory. This is the documented zero-arg
    behaviour the local fallback relies on.
    """
    uid = UUID("00000000-0000-0000-0000-000000000002")
    assert finding_path(uid).parent == FINDINGS_DIR


# ---------------------------------------------------------------------------
# write_finding
# ---------------------------------------------------------------------------


def test_write_finding_creates_parent_directory(tmp_path: Path) -> None:
    """A nested ``root`` that doesn't yet exist is created automatically."""
    nested = tmp_path / "deeply" / "nested" / "findings"
    uid = uuid4()
    path = write_finding(uid, "# body", root=nested)
    assert path.exists()
    assert path.parent == nested


def test_write_finding_refuses_to_overwrite(tmp_path: Path) -> None:
    """Calling ``write_finding`` twice with the same id raises ``FileExistsError``.

    This is the load-bearing refuse-to-overwrite guarantee documented in
    the module docstring — finding IDs are uuid4 so the only way to land
    here is a wiring bug, and silent overwrite would destroy evidence.
    """
    uid = uuid4()
    write_finding(uid, "first", root=tmp_path)
    with pytest.raises(FileExistsError):
        write_finding(uid, "second", root=tmp_path)


def test_write_finding_returns_target_path(tmp_path: Path) -> None:
    uid = uuid4()
    path = write_finding(uid, "# body", root=tmp_path)
    assert path == tmp_path / f"{uid}.md"


# ---------------------------------------------------------------------------
# read_finding
# ---------------------------------------------------------------------------


def test_read_finding_raises_when_missing(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        read_finding(uuid4(), root=tmp_path)


def test_write_then_read_round_trip(tmp_path: Path) -> None:
    """The exact bytes written come back from ``read_finding``."""
    uid = uuid4()
    body = "## hello\n\nbody text\n"
    write_finding(uid, body, root=tmp_path)
    assert read_finding(uid, root=tmp_path) == body


# ---------------------------------------------------------------------------
# list_findings
# ---------------------------------------------------------------------------


def test_list_findings_on_missing_root_returns_empty(tmp_path: Path) -> None:
    """A non-existent ``root`` yields ``[]`` rather than raising.

    Callers iterating "all findings" on a fresh checkout should not have
    to special-case bootstrap; the store smooths that over.
    """
    nonexistent = tmp_path / "does-not-exist"
    assert list_findings(root=nonexistent) == []


def test_list_findings_on_empty_root_returns_empty(tmp_path: Path) -> None:
    assert list_findings(root=tmp_path) == []


def test_list_findings_returns_sorted_paths(tmp_path: Path) -> None:
    """After writing three findings, ``list_findings`` returns them sorted
    lexicographically by filename — stable across runs so callers can
    depend on the order for diffing or pagination.
    """
    uids = [
        UUID("11111111-1111-1111-1111-111111111111"),
        UUID("22222222-2222-2222-2222-222222222222"),
        UUID("00000000-0000-0000-0000-000000000000"),
    ]
    for uid in uids:
        write_finding(uid, f"# {uid}", root=tmp_path)
    listing = list_findings(root=tmp_path)
    assert listing == sorted(listing)
    assert [p.stem for p in listing] == [
        "00000000-0000-0000-0000-000000000000",
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
    ]
