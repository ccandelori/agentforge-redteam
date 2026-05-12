"""Target URL allowlist — the platform's primary safety boundary.

Every HTTP call the Red Team agent issues against a target *must* first pass
through :func:`validate_target_url`. If the URL does not appear (after trailing
slash normalization) in ``targets.yaml``, we raise :class:`TargetNotAllowed`
and refuse the call. The YAML file is the single source of truth and can only
be changed by a human commit — no agent has write access to it at runtime.

The module is intentionally side-effect free at import time: ``targets.yaml``
is only read when :func:`load_targets` is called. That keeps tests fast and
lets callers point at alternate paths (e.g. ``tmp_path`` fixtures).
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import yaml

DEFAULT_TARGETS_PATH: Final[Path] = Path("targets.yaml")


class TargetNotAllowed(Exception):
    """Raised when a URL is not on the configured target allowlist.

    The message embeds both the rejected URL and the full allowed-set so that
    a human scanning the audit log immediately sees what *is* permitted —
    no need to grep the repo for the YAML file mid-incident.
    """

    def __init__(self, url: str, allowed: list[str] | None = None) -> None:
        self.url = url
        self.allowed = list(allowed) if allowed is not None else []
        allowed_repr = ", ".join(self.allowed) if self.allowed else "<none>"
        super().__init__(f"URL not in target allowlist: {url!r}. Allowed targets: [{allowed_repr}]")


def _normalize(url: str) -> str:
    """Strip a single trailing slash for comparison purposes.

    URLs are case-sensitive in path components, so we deliberately do *not*
    lowercase. ``"https://x.com"`` and ``"https://x.com/"`` should match;
    ``"https://x.com/Admin"`` and ``"https://x.com/admin"`` should not.
    """
    return url.rstrip("/")


def load_targets(path: Path | str = DEFAULT_TARGETS_PATH) -> dict[str, str]:
    """Return ``{name: url}`` from ``targets.yaml``.

    Raises
    ------
    FileNotFoundError
        If ``path`` does not exist.
    ValueError
        If the file is malformed: missing/wrong ``version``, missing
        ``targets`` mapping, empty mapping, or a value that is not a string.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"targets allowlist not found: {path}")

    with path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    if not isinstance(raw, dict):
        raise ValueError(
            f"targets file must be a YAML mapping at top level, got {type(raw).__name__}"
        )

    version = raw.get("version")
    if version != 1:
        raise ValueError(f"targets file version must be 1, got {version!r}")

    targets = raw.get("targets")
    if targets is None:
        raise ValueError("targets file is missing required 'targets' key")
    if not isinstance(targets, dict):
        raise ValueError(f"'targets' must be a mapping of str -> str, got {type(targets).__name__}")
    if not targets:
        raise ValueError("'targets' mapping must be non-empty")

    normalized: dict[str, str] = {}
    for name, url in targets.items():
        if not isinstance(name, str):
            raise ValueError(f"target name must be a string, got {type(name).__name__}: {name!r}")
        if not isinstance(url, str):
            raise ValueError(
                f"target {name!r} must map to a string URL, got {type(url).__name__}: {url!r}"
            )
        normalized[name] = url

    return normalized


def validate_target_url(url: str, path: Path | str = DEFAULT_TARGETS_PATH) -> str:
    """Return ``url`` if it is on the allowlist; otherwise raise.

    Both sides of the comparison have any trailing ``/`` stripped, so
    ``"https://example.com"`` and ``"https://example.com/"`` are treated as
    equivalent. The original (un-normalized) ``url`` is returned on success
    so callers don't accidentally lose a path they intended.
    """
    targets = load_targets(path)
    allowed_urls = list(targets.values())
    normalized_allowed = {_normalize(allowed) for allowed in allowed_urls}
    if _normalize(url) in normalized_allowed:
        return url
    raise TargetNotAllowed(url, allowed=allowed_urls)
