"""Unit tests for ``agentforge_redteam.prompts``.

The prompt loader is the binding between an agent's behavior and the
``run_manifests.prompt_set_sha`` value that future auditors will use to
prove a verdict was generated against a specific prompt set. These tests
pin three properties:

1. Every shipped prompt is present and parseable from disk.
2. The per-prompt SHA-256 matches the file bytes byte-for-byte.
3. The aggregate ``prompt_set_sha`` is deterministic and changes the
   instant any single prompt changes.

We also assert anchor phrases inside each prompt — these catch a
regression where someone deletes a critical safety clause (CBRN refusal,
PHI sanitization, epsilon exploration) without anyone noticing in review.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import cast

import pytest

from agentforge_redteam.prompts import (
    AGENT_ORDER,
    AgentName,
    LoadedPrompt,
    load_all_prompts,
    load_prompt,
    prompt_set_sha,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
REAL_PROMPTS_DIR = REPO_ROOT / "prompts"


def _copy_real_prompts(dst: Path) -> Path:
    """Mirror the real prompts dir into ``dst`` so tests can mutate one file
    without touching the checked-in originals."""
    dst.mkdir(parents=True, exist_ok=True)
    for name in AGENT_ORDER:
        src = REAL_PROMPTS_DIR / f"{name}.md"
        (dst / f"{name}.md").write_bytes(src.read_bytes())
    return dst


@pytest.mark.parametrize("name", list(AGENT_ORDER))
def test_every_agent_prompt_file_exists_on_disk(name: AgentName) -> None:
    path = REAL_PROMPTS_DIR / f"{name}.md"
    assert path.is_file(), f"missing prompt: {path}"
    assert path.read_text(encoding="utf-8").strip(), f"empty prompt: {path}"


def test_load_prompt_returns_loaded_prompt_with_hex_sha256() -> None:
    loaded = load_prompt("redteam", prompts_dir=REAL_PROMPTS_DIR)
    assert isinstance(loaded, LoadedPrompt)
    assert loaded.name == "redteam"
    assert loaded.text.strip(), "loaded prompt text must be non-empty"
    assert len(loaded.sha256) == 64
    assert all(c in "0123456789abcdef" for c in loaded.sha256)
    assert loaded.path == REAL_PROMPTS_DIR / "redteam.md"


def test_loaded_prompt_sha256_matches_manual_digest_of_file_bytes() -> None:
    path = REAL_PROMPTS_DIR / "judge.md"
    expected = hashlib.sha256(path.read_bytes()).hexdigest()
    loaded = load_prompt("judge", prompts_dir=REAL_PROMPTS_DIR)
    assert loaded.sha256 == expected


def test_load_all_prompts_returns_exactly_four_known_agents() -> None:
    prompts = load_all_prompts(prompts_dir=REAL_PROMPTS_DIR)
    assert set(prompts.keys()) == {"redteam", "judge", "orchestrator", "doc"}
    assert list(prompts.keys()) == list(AGENT_ORDER)
    for name, loaded in prompts.items():
        assert loaded.name == name
        assert loaded.text.strip()


def test_prompt_set_sha_is_64_char_hex() -> None:
    digest = prompt_set_sha(prompts_dir=REAL_PROMPTS_DIR)
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


def test_prompt_set_sha_is_deterministic_across_calls() -> None:
    a = prompt_set_sha(prompts_dir=REAL_PROMPTS_DIR)
    b = prompt_set_sha(prompts_dir=REAL_PROMPTS_DIR)
    assert a == b


def test_prompt_set_sha_changes_when_any_single_prompt_changes(tmp_path: Path) -> None:
    mirror = _copy_real_prompts(tmp_path / "prompts")
    baseline = prompt_set_sha(prompts_dir=mirror)

    # Mutate one file by appending a single byte — this is the smallest
    # change that could plausibly slip through code review unnoticed, and
    # it MUST flip the aggregate digest.
    redteam = mirror / "redteam.md"
    redteam.write_bytes(redteam.read_bytes() + b"\n# tweak\n")

    mutated = prompt_set_sha(prompts_dir=mirror)
    assert mutated != baseline


@pytest.mark.parametrize(
    ("name", "anchors"),
    [
        ("redteam", ("OWASP", "CBRN")),
        ("judge", ("verdict_schema", "inconclusive")),
        ("orchestrator", ("coverage", "epsilon")),
        ("doc", ("severity", "sanitized")),
    ],
)
def test_each_prompt_contains_required_anchor_phrases(
    name: AgentName, anchors: tuple[str, ...]
) -> None:
    loaded = load_prompt(name, prompts_dir=REAL_PROMPTS_DIR)
    for anchor in anchors:
        assert anchor in loaded.text, f"{name}.md is missing anchor phrase: {anchor!r}"


def test_load_prompt_raises_file_not_found_for_unknown_agent(tmp_path: Path) -> None:
    # ``cast`` bypasses the Literal so we can exercise the runtime guard.
    bogus = cast(AgentName, "missing")
    with pytest.raises(FileNotFoundError):
        load_prompt(bogus, prompts_dir=tmp_path)


def test_load_prompt_raises_file_not_found_when_dir_is_empty(tmp_path: Path) -> None:
    # Even for a known agent name, an empty prompts dir must fail loudly
    # rather than silently fall back to an empty prompt.
    with pytest.raises(FileNotFoundError):
        load_prompt("redteam", prompts_dir=tmp_path)
