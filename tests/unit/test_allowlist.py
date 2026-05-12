"""Unit tests for the target URL allowlist in ``agentforge_redteam.allowlist``.

The allowlist is the platform's primary safety boundary — these tests pin
the loader's failure modes (each catches a distinct way an operator could
mis-edit ``targets.yaml``) and the validator's normalization rules.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentforge_redteam.allowlist import (
    TargetNotAllowed,
    load_targets,
    validate_target_url,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
REAL_TARGETS_PATH = REPO_ROOT / "targets.yaml"


def _write_yaml(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "targets.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_load_targets_returns_two_named_entries_from_real_file() -> None:
    targets = load_targets(REAL_TARGETS_PATH)
    assert set(targets.keys()) == {"localhost_dev_easy", "droplet_prod"}
    assert targets["localhost_dev_easy"] == "http://localhost:8000"
    assert targets["droplet_prod"] == "https://143.244.157.90"


def test_load_targets_returns_custom_mapping_verbatim(tmp_path: Path) -> None:
    path = _write_yaml(
        tmp_path,
        'version: 1\ntargets:\n  alpha: "https://a.example.com"\n  beta: "https://b.example.com/api"\n',
    )
    assert load_targets(path) == {
        "alpha": "https://a.example.com",
        "beta": "https://b.example.com/api",
    }


def test_load_targets_raises_filenotfound_for_missing_path(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.yaml"
    with pytest.raises(FileNotFoundError):
        load_targets(missing)


def test_load_targets_raises_value_error_when_targets_key_missing(tmp_path: Path) -> None:
    path = _write_yaml(tmp_path, "version: 1\n")
    with pytest.raises(ValueError, match="missing required 'targets' key"):
        load_targets(path)


def test_load_targets_raises_value_error_when_targets_empty(tmp_path: Path) -> None:
    path = _write_yaml(tmp_path, "version: 1\ntargets: {}\n")
    with pytest.raises(ValueError, match="non-empty"):
        load_targets(path)


def test_load_targets_raises_value_error_for_non_string_target_value(tmp_path: Path) -> None:
    path = _write_yaml(tmp_path, "version: 1\ntargets:\n  bad: 12345\n")
    with pytest.raises(ValueError, match="must map to a string URL"):
        load_targets(path)


def test_load_targets_raises_value_error_for_wrong_version(tmp_path: Path) -> None:
    path = _write_yaml(
        tmp_path,
        'version: 2\ntargets:\n  alpha: "https://a.example.com"\n',
    )
    with pytest.raises(ValueError, match="version must be 1"):
        load_targets(path)


def test_validate_target_url_returns_url_for_allowlisted_entry() -> None:
    assert (
        validate_target_url("http://localhost:8000", REAL_TARGETS_PATH) == "http://localhost:8000"
    )


def test_validate_target_url_raises_for_arbitrary_url() -> None:
    with pytest.raises(TargetNotAllowed):
        validate_target_url("https://evil.example.com", REAL_TARGETS_PATH)


@pytest.mark.parametrize(
    "candidate",
    ["https://143.244.157.90", "https://143.244.157.90/"],
)
def test_validate_target_url_matches_with_or_without_trailing_slash(candidate: str) -> None:
    assert validate_target_url(candidate, REAL_TARGETS_PATH) == candidate


def test_target_not_allowed_message_carries_url_and_allowed_set() -> None:
    with pytest.raises(TargetNotAllowed) as excinfo:
        validate_target_url("https://evil.example.com", REAL_TARGETS_PATH)
    err = excinfo.value
    assert err.url == "https://evil.example.com"
    assert "http://localhost:8000" in err.allowed
    assert "https://143.244.157.90" in err.allowed
    message = str(err)
    assert "https://evil.example.com" in message
    assert "http://localhost:8000" in message
    assert "https://143.244.157.90" in message
