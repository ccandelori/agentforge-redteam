"""Unit tests for :mod:`agentforge_redteam.sanitizer`.

The sanitizer is the last line of defense between agent-collected evidence
and a committed vulnerability report. Tests are written vertical-slice TDD:
each name reads like a spec line that an auditor could match against the
threat model.
"""

from __future__ import annotations

from agentforge_redteam.sanitizer import (
    DOCUMENT_TRUNCATION_KEEP,
    DOCUMENT_TRUNCATION_THRESHOLD,
    sanitize_evidence,
)

_TRUNCATION_SUFFIX = "...[TRUNCATED]"


# --- Trivial / clean-input invariants ---------------------------------------


def test_empty_input_returns_empty_string() -> None:
    assert sanitize_evidence("") == ""


def test_clean_prose_is_returned_unchanged() -> None:
    text = "The patient is doing well."
    assert sanitize_evidence(text) == text


# --- JWT redaction ----------------------------------------------------------


def test_jwt_token_is_redacted() -> None:
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abc123"
    result = sanitize_evidence(jwt)
    assert "[JWT_REDACTED]" in result
    assert "eyJ" not in result


def test_jwt_in_the_middle_of_a_sentence_preserves_surrounding_text() -> None:
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abc123"
    text = f"Auth header was {jwt} and the request succeeded."
    result = sanitize_evidence(text)
    assert result == "Auth header was [JWT_REDACTED] and the request succeeded."


def test_multiple_jwts_in_one_string_are_all_redacted() -> None:
    jwt_a = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abc123"
    jwt_b = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIyIn0.def456"
    text = f"{jwt_a} and also {jwt_b}"
    result = sanitize_evidence(text)
    assert result.count("[JWT_REDACTED]") == 2
    assert "eyJ" not in result


# --- API key redaction ------------------------------------------------------


def test_anthropic_style_sk_key_is_redacted() -> None:
    result = sanitize_evidence("key=sk-ant-api03-AbCdEfGhIjKlMnOpQrStUv done")
    assert "[API_KEY_REDACTED]" in result
    assert "sk-ant-api03" not in result


def test_openai_project_sk_key_is_redacted() -> None:
    result = sanitize_evidence("sk-proj-AbCdEfGhIjKlMnOpQrStUv")
    assert result == "[API_KEY_REDACTED]"


def test_langfuse_pk_key_is_redacted() -> None:
    result = sanitize_evidence("pk-lf-AbCdEfGhIjKlMnOpQrStUv")
    assert result == "[API_KEY_REDACTED]"


def test_gitlab_personal_access_token_is_redacted() -> None:
    result = sanitize_evidence("token: glpat-AbCdEfGhIjKlMnOpQrSt-_xy")
    assert "[API_KEY_REDACTED]" in result
    assert "glpat-" not in result


def test_short_sk_prefixes_in_prose_are_not_redacted() -> None:
    # Negative case: protect against mangling prose. The minimum-length
    # guard in the API_KEY pattern (16+ chars after the prefix) should
    # leave these alone.
    text = "I said sk- and then sk-i-dunno, neither is a key."
    assert sanitize_evidence(text) == text


# --- SSN redaction ----------------------------------------------------------


def test_ssn_is_redacted() -> None:
    result = sanitize_evidence("SSN on file: 123-45-6789.")
    assert result == "SSN on file: [SSN_REDACTED]."


def test_phone_number_like_string_is_not_matched_as_ssn() -> None:
    # ``1-234-56-7890`` looks like an SSN tail but ``\b`` should anchor to
    # the leading ``1-`` and prevent a match. We assert that the literal
    # SSN_REDACTED token does not appear AND that the original digits
    # survive untouched.
    text = "Phone: 1-234-56-7890 (extension 5)."
    result = sanitize_evidence(text)
    assert "[SSN_REDACTED]" not in result
    assert "234-56-7890" in result


# --- MRN redaction ----------------------------------------------------------


def test_synthea_style_mrn_uuid_is_redacted() -> None:
    mrn = "550e8400-e29b-41d4-a716-446655440000"
    result = sanitize_evidence(f"patient_id={mrn}")
    assert result == "patient_id=[MRN_REDACTED]"


# --- Truncation -------------------------------------------------------------


def test_long_input_is_truncated_to_keep_plus_suffix() -> None:
    text = "a" * 1500
    result = sanitize_evidence(text)
    assert result.endswith(_TRUNCATION_SUFFIX)
    assert len(result) == DOCUMENT_TRUNCATION_KEEP + len(_TRUNCATION_SUFFIX)
    assert result[:DOCUMENT_TRUNCATION_KEEP] == "a" * DOCUMENT_TRUNCATION_KEEP


def test_input_exactly_at_threshold_is_not_truncated() -> None:
    text = "a" * DOCUMENT_TRUNCATION_THRESHOLD
    result = sanitize_evidence(text)
    assert result == text
    assert _TRUNCATION_SUFFIX not in result


# --- Combined input ---------------------------------------------------------


def test_jwt_ssn_and_mrn_in_one_pass_all_get_redacted() -> None:
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abc123"
    ssn = "123-45-6789"
    mrn = "550e8400-e29b-41d4-a716-446655440000"
    text = f"Token: {jwt} SSN {ssn} patient {mrn}."
    result = sanitize_evidence(text)
    assert "[JWT_REDACTED]" in result
    assert "[SSN_REDACTED]" in result
    assert "[MRN_REDACTED]" in result
    # Original sensitive content must not survive.
    assert "eyJ" not in result
    assert "123-45-6789" not in result
    assert mrn not in result


def test_redaction_order_jwt_wins_over_embedded_api_key_shape() -> None:
    # An ``sk-...`` shape buried inside a JWT-shaped blob: redaction order
    # in :func:`sanitize_evidence` runs JWT first, so the whole token
    # collapses to ``[JWT_REDACTED]`` and the ``[API_KEY_REDACTED]`` rule
    # never fires. We pin this behavior so a future refactor that swaps
    # the order has to update this test deliberately.
    jwt_like = (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzay1hbnQtYXBpMDMtQUJDREVGR0hJSktMTU5PUFFSUyJ9.sig123"
    )
    result = sanitize_evidence(jwt_like)
    assert result == "[JWT_REDACTED]"
    assert "[API_KEY_REDACTED]" not in result


# --- Idempotency ------------------------------------------------------------


def test_sanitize_evidence_is_idempotent() -> None:
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abc123"
    ssn = "123-45-6789"
    mrn = "550e8400-e29b-41d4-a716-446655440000"
    sample = f"Mixed evidence: {jwt} / {ssn} / {mrn} / sk-proj-AbCdEfGhIjKlMnOpQrStUv"
    once = sanitize_evidence(sample)
    twice = sanitize_evidence(once)
    assert once == twice
