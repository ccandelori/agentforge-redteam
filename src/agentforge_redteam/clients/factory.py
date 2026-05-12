"""Single import point for the Documentation Agent's filing client.

The Documentation Agent accepts a Protocol-typed
:class:`agentforge_redteam.agents.documentation.GitLabClientLike` and does
not care which concrete implementation it sees. Production runs want the
real GitLab REST client; dev, offline CI, and pre-submission rehearsal
want the local-filesystem fallback.

:func:`create_documentation_client` is the policy seam that decides
between them. It always returns a sink — never ``None`` — so the Doc
Agent's autofile path is wired regardless of whether GitLab credentials
are present. Test code can call this with an explicit ``env`` argument to
force either branch deterministically.
"""

from __future__ import annotations

from agentforge_redteam.agents.documentation import GitLabClientLike
from agentforge_redteam.clients.gitlab_client import create_gitlab_client
from agentforge_redteam.clients.local_findings_sink import (
    LocalFindingsSink,
    create_documentation_sink,
)

__all__ = [
    "LocalFindingsSink",
    "create_documentation_client",
    "create_documentation_sink",
]


def create_documentation_client(
    env: dict[str, str] | None = None,
) -> GitLabClientLike:
    """Return the real :class:`GitLabClient` if GitLab env is configured;
    else the :class:`LocalFindingsSink`.

    Never returns ``None``: the Documentation Agent always receives a
    sink, so the autofile path is wired even on developer laptops with no
    GitLab token. The env-detection contract matches
    :func:`agentforge_redteam.clients.gitlab_client.create_gitlab_client`:
    both ``GITLAB_TOKEN`` and ``GITLAB_PROJECT_ID`` must be set for the
    real client to be selected.
    """
    real = create_gitlab_client(env=env)
    if real is not None:
        return real
    return create_documentation_sink()
