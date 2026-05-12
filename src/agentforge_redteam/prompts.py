"""System-prompt loader with content-addressed hashing.

Every agent in AgentForge runs against a versioned system prompt stored as a
markdown file in :data:`PROMPTS_DIR`. This module is the *only* path through
which agents load their prompt text at runtime, which gives us two
properties downstream code relies on:

* **Reproducibility.** :func:`load_prompt` returns the prompt text alongside
  the SHA-256 of its bytes. That digest is stamped into
  ``run_manifests.prompt_set_sha`` so a verdict is verifiably anchored to
  the exact prompt that produced it.
* **Determinism.** :func:`prompt_set_sha` is the SHA-256 of the four
  individual digests concatenated in a fixed agent order
  (``redteam``, ``judge``, ``orchestrator``, ``doc``). Same prompt files
  → same digest, byte-for-byte, across runs and machines.

The module is intentionally tiny and dependency-free (stdlib only) so it
can be imported from hot paths without pulling LangGraph / Anthropic SDKs
into a loader cycle.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, get_args

PROMPTS_DIR: Final[Path] = Path("prompts")

AgentName = Literal["redteam", "judge", "orchestrator", "doc"]

# Fixed iteration order. ``prompt_set_sha`` concatenates per-agent digests
# in this order, so reordering this tuple is a breaking change to the
# manifest digest and MUST be matched by an Alembic migration.
AGENT_ORDER: Final[tuple[AgentName, ...]] = ("redteam", "judge", "orchestrator", "doc")

_VALID_NAMES: Final[frozenset[str]] = frozenset(get_args(AgentName))


@dataclass(frozen=True, slots=True)
class LoadedPrompt:
    """A loaded system prompt plus the SHA-256 of its on-disk bytes.

    ``sha256`` is the hex digest of ``text.encode("utf-8")`` — i.e. the
    same bytes that were read from disk. Callers MUST NOT re-hash a
    modified copy of ``text`` and expect equality; the whole point is to
    bind a verdict to the literal file content.
    """

    name: AgentName
    text: str
    sha256: str
    path: Path


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_prompt(name: AgentName, prompts_dir: Path = PROMPTS_DIR) -> LoadedPrompt:
    """Load ``{prompts_dir}/{name}.md`` and return its text plus digest.

    Raises
    ------
    FileNotFoundError
        If the prompt file does not exist. We do NOT silently fall back to
        an empty prompt — a missing prompt is a configuration error that
        should surface loudly before any agent runs.
    """
    if name not in _VALID_NAMES:
        # Defense in depth: the ``Literal`` already constrains static
        # callers, but the runtime check catches dynamic dispatch (e.g. a
        # CLI arg fed straight in) before we touch the filesystem.
        raise FileNotFoundError(
            f"unknown agent prompt name: {name!r}; expected one of {sorted(_VALID_NAMES)}"
        )

    path = prompts_dir / f"{name}.md"
    if not path.is_file():
        raise FileNotFoundError(f"prompt file not found: {path}")

    data = path.read_bytes()
    text = data.decode("utf-8")
    return LoadedPrompt(name=name, text=text, sha256=_sha256_hex(data), path=path)


def load_all_prompts(prompts_dir: Path = PROMPTS_DIR) -> dict[AgentName, LoadedPrompt]:
    """Load every agent prompt, keyed by agent name, in :data:`AGENT_ORDER`.

    The returned ``dict`` preserves insertion order (Python 3.7+), so
    callers that iterate it get the same order :func:`prompt_set_sha`
    uses — handy when surfacing per-prompt digests in logs.
    """
    return {name: load_prompt(name, prompts_dir) for name in AGENT_ORDER}


def prompt_set_sha(prompts_dir: Path = PROMPTS_DIR) -> str:
    """Return the SHA-256 of the concatenated per-agent digests.

    The digests are joined with no separator in :data:`AGENT_ORDER`. This
    value lands in ``run_manifests.prompt_set_sha`` so any later attempt
    to reproduce a verdict can confirm the prompt set was identical.
    """
    prompts = load_all_prompts(prompts_dir)
    joined = "".join(prompts[name].sha256 for name in AGENT_ORDER)
    return _sha256_hex(joined.encode("utf-8"))
