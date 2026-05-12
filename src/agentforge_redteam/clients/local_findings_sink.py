"""Filesystem-backed implementation of the Doc Agent's GitLab Protocol.

The Documentation Agent depends on the Protocol
:class:`agentforge_redteam.agents.documentation.GitLabClientLike`. Its single
method, ``create_issue``, is the only seam the agent uses to route a
confirmed finding onto the autofile path.

In production that Protocol is satisfied by
:class:`agentforge_redteam.clients.gitlab_client.GitLabClient`. In dev,
test, and pre-submission rehearsal — anywhere the environment does not
carry ``GITLAB_TOKEN``/``GITLAB_PROJECT_ID`` — we substitute
:class:`LocalFindingsSink` from this module. It writes the rendered issue
body to ``findings/<slug>-<n>.md`` on the local filesystem and returns a
:class:`GitLabIssueRef` whose ``issue_id`` is a synthetic monotonic
counter and whose ``url`` is the ``file://`` URI of the written file.

Design constraints (load-bearing — keep stable):

* **Same return type as the real client.** The Doc Agent's downstream code
  (the ``findings`` table INSERT) reads ``issue_id`` off the returned ref;
  re-using :class:`GitLabIssueRef` keeps that path untouched.
* **Counter rooted in existing on-disk state.** The synthetic ``issue_id``
  starts at the highest existing ``*-<n>.md`` suffix + 1. Reruns of the
  Doc Agent on the same dev box therefore do not collide on filenames or
  on ``gitlab_issue_id``.
* **Labels as YAML footer.** GitLab labels carry signal (severity, OWASP
  ID, MITRE ID) that would be lost if the body were written verbatim. We
  append a fenced ``---\\nlabels:\\n  - ...\\n`` block at the END of the
  body so the file is round-trippable and grep-friendly without
  rearranging the rendered template.
* **Counter increments are protected by a lock.** ``create_issue`` is
  declared ``async`` to match the Protocol; the implementation acquires a
  per-instance :class:`asyncio.Lock` so concurrent ``gather`` callers do
  not race on the counter or the directory scan.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Final

from agentforge_redteam.agents.documentation import GitLabIssueRef

__all__ = [
    "DEFAULT_FINDINGS_DIR",
    "LocalFindingsSink",
    "create_documentation_sink",
]


DEFAULT_FINDINGS_DIR: Final[Path] = Path("findings")
"""Default on-disk root for written finding markdown. Relative to CWD."""

_MAX_SLUG_LEN: Final[int] = 60
_COUNTER_SUFFIX_RE: Final[re.Pattern[str]] = re.compile(r"-(\d+)\.md$")


def _slugify(title: str) -> str:
    """Return a filesystem-safe slug derived from ``title``.

    Lowercases, replaces non-alphanumerics with a single ``-``, strips
    leading/trailing dashes, and truncates to :data:`_MAX_SLUG_LEN` chars.
    Empty or all-symbol titles fall back to ``"finding"`` so the
    resulting filename is never just ``-1.md``.
    """
    lowered = title.lower()
    slug = re.sub(r"[^a-z0-9]+", "-", lowered).strip("-")
    if not slug:
        return "finding"
    return slug[:_MAX_SLUG_LEN]


def _next_counter(findings_dir: Path) -> int:
    """Return ``max(existing-numeric-suffix) + 1`` (or 1 if no files exist).

    We scan ``findings_dir`` for ``*-<digits>.md`` files and pick the
    highest numeric suffix. A missing directory yields 1 — the directory
    is created on the first write.
    """
    if not findings_dir.exists():
        return 1
    highest = 0
    for path in findings_dir.glob("*.md"):
        match = _COUNTER_SUFFIX_RE.search(path.name)
        if match is None:
            continue
        try:
            n = int(match.group(1))
        except ValueError:  # pragma: no cover - regex guarantees digits
            continue
        if n > highest:
            highest = n
    return highest + 1


def _labels_yaml_block(labels: list[str]) -> str:
    """Render a YAML labels block to append at the END of the body.

    Format::

        ---
        labels:
          - severity::P2
          - owasp::LLM01:2025
        ---

    Empty labels list renders an empty YAML sequence so the block is
    always structurally valid.
    """
    if not labels:
        body = "---\nlabels: []\n---\n"
    else:
        items = "\n".join(f"  - {label}" for label in labels)
        body = f"---\nlabels:\n{items}\n---\n"
    return body


class LocalFindingsSink:
    """Filesystem-backed :class:`GitLabClientLike`.

    Writes rendered finding reports to ``<findings_dir>/<slug>-<n>.md``
    instead of POSTing to GitLab. The synthetic ``issue_id`` is a
    monotonic counter rooted in the highest existing numeric suffix; the
    ``url`` field carries a ``file://`` URI of the written path.

    The instance owns an :class:`asyncio.Lock` so concurrent callers in
    the same event loop do not race on counter assignment.
    """

    __slots__ = ("_dir", "_lock")

    def __init__(self, *, findings_dir: Path | str = DEFAULT_FINDINGS_DIR) -> None:
        self._dir = Path(findings_dir)
        self._lock = asyncio.Lock()

    async def create_issue(self, *, title: str, body: str, labels: list[str]) -> GitLabIssueRef:
        """Write ``body`` (with a YAML labels footer) to disk and return a ref.

        The filename is ``<slug>-<counter>.md`` where ``slug`` is the
        slugified ``title`` and ``counter`` is the monotonic
        ``issue_id``. Returns a :class:`GitLabIssueRef` carrying the
        counter as ``issue_id`` and a ``file://`` URI as ``url``.

        Concurrent callers within one event loop are serialised on a
        per-instance lock so no two writes share the same counter.
        """
        slug = _slugify(title)
        async with self._lock:
            self._dir.mkdir(parents=True, exist_ok=True)
            counter = _next_counter(self._dir)
            filename = f"{slug}-{counter}.md"
            path = self._dir / filename
            footer = _labels_yaml_block(labels)
            # Single trailing newline between rendered body and the YAML
            # footer so the file reads cleanly regardless of whether the
            # body ends with one.
            separator = "" if body.endswith("\n") else "\n"
            path.write_text(f"{body}{separator}\n{footer}", encoding="utf-8")
        return GitLabIssueRef(issue_id=counter, url=path.resolve().as_uri())


def create_documentation_sink() -> LocalFindingsSink:
    """Factory for the local sink — always succeeds, no env required.

    Returns a :class:`LocalFindingsSink` rooted at
    :data:`DEFAULT_FINDINGS_DIR`. Callers that need a deterministic
    location (tests, CLI under ``XDG_STATE_HOME``) construct
    :class:`LocalFindingsSink` directly with an explicit ``findings_dir``.
    """
    return LocalFindingsSink()
