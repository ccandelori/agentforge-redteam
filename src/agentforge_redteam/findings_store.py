"""Local-filesystem store for rendered finding markdown bodies.

The Documentation Agent's primary filing path is GitLab (see
:mod:`agentforge_redteam.clients.gitlab_client`). When GitLab credentials
are absent — dev laptops, offline CI lanes, and pre-submission rehearsal —
the canonical fallback writes findings via
:class:`agentforge_redteam.clients.local_findings_sink.LocalFindingsSink`
(slug+counter filenames, YAML labels footer).

This module owns standalone read/write/list primitives over a
``findings/`` tree keyed by ``finding_id``. It is deliberately a pure I/O
leaf — no Doc-Agent imports, no GitLab imports — so unit tests exercise
it in isolation and downstream tooling (a future "list local findings"
CLI command, for example) can iterate ``findings/`` without pulling in
the agent stack.

Design constraints (load-bearing — keep stable):

* **Refuse-to-overwrite.** ``write_finding`` raises ``FileExistsError``
  on collision. The Doc Agent assigns ``finding_id`` from ``uuid.uuid4``,
  so a collision indicates either a real bug (the same ``finding_id``
  flowing through twice) or a caller hand-crafting a UUID; in either
  case silent overwrite would destroy evidence.

* **Parent directories created on demand.** ``write_finding`` runs
  ``parent.mkdir(parents=True, exist_ok=True)`` so first-run callers
  on a clean checkout don't need to remember to create ``findings/``.
  This is the only mutation we perform outside the target file itself.

* **Default root is repo-relative.** ``FINDINGS_DIR = Path("findings")``
  resolves against the current working directory. The CLI and tests
  almost always pass an explicit ``root`` argument; the default exists
  so the local-fallback can be invoked with zero arguments in a
  notebook or one-shot script.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final
from uuid import UUID

__all__ = [
    "FINDINGS_DIR",
    "finding_path",
    "list_findings",
    "read_finding",
    "write_finding",
]


FINDINGS_DIR: Final[Path] = Path("findings")
"""Default root directory for local finding markdown files.

Resolves against the current working directory. Callers that need a
deterministic location (tests, CLI) pass an explicit ``root`` argument.
"""


def finding_path(finding_id: UUID, root: Path | str = FINDINGS_DIR) -> Path:
    """Return the canonical on-disk path for ``finding_id`` under ``root``.

    The filename is ``<finding_id>.md`` (no subdirectories). UUIDs render
    as 36-char hyphenated strings so collisions across the filesystem are
    not a concern; this is the entire reason we use uuid4 for finding_id
    in the first place.
    """
    return Path(root) / f"{finding_id}.md"


def write_finding(
    finding_id: UUID,
    rendered_markdown: str,
    *,
    root: Path | str = FINDINGS_DIR,
) -> Path:
    """Persist ``rendered_markdown`` to ``<root>/<finding_id>.md``.

    Creates the parent directory if needed. Refuses to overwrite an
    existing file (``FileExistsError``) — see the module docstring for
    the rationale. Writes use UTF-8 with a single trailing newline left
    intact; the caller is responsible for whatever final-newline policy
    the rendered template established.

    Returns the absolute path the bytes were written to.
    """
    path = finding_path(finding_id, root)
    path.parent.mkdir(parents=True, exist_ok=True)
    # ``x`` mode (exclusive create) raises FileExistsError if the target
    # exists. This is the load-bearing refuse-to-overwrite guarantee.
    with path.open("x", encoding="utf-8") as fh:
        fh.write(rendered_markdown)
    return path


def read_finding(finding_id: UUID, *, root: Path | str = FINDINGS_DIR) -> str:
    """Return the markdown text previously written for ``finding_id``.

    Raises ``FileNotFoundError`` when no file exists — callers that
    expect "may or may not be present" semantics should catch that
    explicitly rather than asking us to return ``None``; an Optional
    return type would obscure the legitimate case where a caller wants
    to fail loudly on a missing finding (e.g. the approval CLI).
    """
    path = finding_path(finding_id, root)
    return path.read_text(encoding="utf-8")


def list_findings(*, root: Path | str = FINDINGS_DIR) -> list[Path]:
    """Return every ``<root>/*.md`` path sorted by filename.

    A missing root yields ``[]`` — callers iterating "all findings" on
    a fresh checkout should not have to special-case the bootstrap.
    The sort is by filename (so UUID lexicographic, not by mtime); this
    is stable across runs which is what the tests rely on.
    """
    root_path = Path(root)
    if not root_path.exists():
        return []
    return sorted(root_path.glob("*.md"))
