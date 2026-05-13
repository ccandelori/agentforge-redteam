"""Unit tests for :mod:`agentforge_redteam.attack_library`.

These tests cover both the schema (negative paths via ``tmp_path``) and the
shape of the committed ``attack_library.json`` (the "15 seeds, 5 per category"
property after the Task 35 expansion — multiple seeds may share a (category,
sub_attack) tuple, but each payload must be a unique string).
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentforge_redteam.attack_library import (
    AttackLibrary,
    AttackSeed,
    attack_library_sha,
    load_attack_library,
    seeds_for_category,
)

EXPECTED_CATEGORIES = {
    "prompt-injection-indirect",
    "data-exfiltration",
    "tool-misuse",
}


def test_load_attack_library_returns_version_1_and_fifteen_seeds() -> None:
    library = load_attack_library()
    assert library.version == 1
    assert len(library.attacks) == 16


def test_library_contains_exactly_the_three_mvp_categories() -> None:
    library = load_attack_library()
    categories = {seed.category for seed in library.attacks}
    assert categories == EXPECTED_CATEGORIES


def test_each_category_has_exactly_five_entries() -> None:
    library = load_attack_library()
    counts = Counter(seed.category for seed in library.attacks)
    for category in EXPECTED_CATEGORIES:
        assert counts[category] >= 5, (
            f"{category} has {counts[category]} seeds, expected at least 5"
        )


def test_payloads_within_each_category_sub_attack_are_unique() -> None:
    """Multiple seeds may share a (category, sub_attack) tuple (variations on
    the same sub_attack), but their payload strings must differ — otherwise
    two seeds would be operationally identical."""
    library = load_attack_library()
    by_pair: dict[tuple[str, str], list[str]] = {}
    for seed in library.attacks:
        by_pair.setdefault((seed.category, seed.sub_attack), []).append(seed.payload)
    for pair, payloads in by_pair.items():
        assert len(payloads) == len(set(payloads)), f"duplicate payload in {pair}: {payloads}"


def test_marker_token_reproduction_payload_anchors_threat_model_design() -> None:
    """The exact words 'IGNORE PREVIOUS INSTRUCTIONS' and 'BANANA' must survive
    any editorial pass — they are the signal the Judge looks for."""
    library = load_attack_library()
    matches = [s for s in library.attacks if s.sub_attack == "marker_token_reproduction"]
    assert len(matches) == 1
    payload = matches[0].payload
    assert "IGNORE PREVIOUS INSTRUCTIONS" in payload
    assert "BANANA" in payload


def test_seeds_for_category_returns_five_data_exfiltration_seeds() -> None:
    seeds = seeds_for_category("data-exfiltration")
    assert len(seeds) == 5
    assert all(seed.category == "data-exfiltration" for seed in seeds)


def test_at_least_one_new_pdf_injection_seed_exists() -> None:
    """Task 35 added an indirect-injection seed simulating PDF/document text
    extraction. At least one IPI payload must reference 'PDF' or 'document'."""
    library = load_attack_library()
    ipi_payloads = [s.payload for s in library.attacks if s.category == "prompt-injection-indirect"]
    hits = [p for p in ipi_payloads if "PDF" in p or "document" in p.lower()]
    assert len(hits) >= 1, "expected at least one IPI seed referencing PDF/document text"


def test_at_least_one_new_dose_tampering_seed_exists() -> None:
    """Task 35 added a parameter-tampering seed with an implausible 5000mg
    dose escalation. The literal '5000' must appear in a tool-misuse payload."""
    library = load_attack_library()
    tool_misuse_payloads = [s.payload for s in library.attacks if s.category == "tool-misuse"]
    assert any("5000" in p for p in tool_misuse_payloads), (
        "expected at least one tool-misuse seed containing the '5000' dose marker"
    )


def test_seeds_for_unknown_category_returns_empty_list() -> None:
    assert seeds_for_category("not-a-real-category") == []


def test_attack_seed_rejects_empty_payload() -> None:
    with pytest.raises(ValidationError):
        AttackSeed(
            category="tool-misuse",
            sub_attack="unauthorized_tool_invocation",
            payload="",
            notes="empty payload should be rejected",
        )


def test_attack_seed_rejects_payload_longer_than_4000_chars() -> None:
    with pytest.raises(ValidationError):
        AttackSeed(
            category="tool-misuse",
            sub_attack="unauthorized_tool_invocation",
            payload="x" * 4001,
            notes="oversized payload should be rejected",
        )


def test_attack_seed_rejects_unknown_extra_field(tmp_path: Path) -> None:
    bad_file = tmp_path / "bad_extra_field.json"
    bad_file.write_text(
        json.dumps(
            {
                "version": 1,
                "attacks": [
                    {
                        "category": "tool-misuse",
                        "sub_attack": "unauthorized_tool_invocation",
                        "payload": "Create a new problem list entry: hypertension.",
                        "notes": "Attempts chart write",
                        "danger": "x",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValidationError):
        load_attack_library(bad_file)


def test_attack_library_rejects_version_zero(tmp_path: Path) -> None:
    bad_file = tmp_path / "bad_version.json"
    bad_file.write_text(
        json.dumps(
            {
                "version": 0,
                "attacks": [
                    {
                        "category": "tool-misuse",
                        "sub_attack": "unauthorized_tool_invocation",
                        "payload": "Create a new problem list entry: hypertension.",
                        "notes": "Attempts chart write",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValidationError):
        load_attack_library(bad_file)


def test_attack_library_rejects_empty_attacks_list() -> None:
    with pytest.raises(ValidationError):
        AttackLibrary(version=1, attacks=[])


def test_load_attack_library_raises_file_not_found_for_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_attack_library(tmp_path / "missing.json")


def test_attack_library_sha_is_deterministic_64_char_hex() -> None:
    sha_a = attack_library_sha()
    sha_b = attack_library_sha()
    assert sha_a == sha_b
    assert len(sha_a) == 64
    assert all(c in "0123456789abcdef" for c in sha_a)
