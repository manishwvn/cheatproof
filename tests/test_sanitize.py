import json
from pathlib import Path

import pytest

from cheatproof.sanitize import REDACTED, assert_clean, sanitize

# Fake values built at runtime so no credential-shaped literal sits in the repo.
FAKE_KEY = "sk-" + "x" * 40
FAKE_LONG = "0123456789abcdef" * 2
MODEL = "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"
FIXTURE_ROOT = Path(__file__).parent / "fixtures"
FIXTURES = sorted(FIXTURE_ROOT.rglob("*.json"))


def test_sensitive_keys_are_redacted_case_insensitively():
    raw = {
        "Authorization": "Basic abc",
        "api_key": FAKE_KEY,
        "apikey": FAKE_KEY,
        "TOKEN": "t",
        "secret": "s",
        "password": "p",
        "Cookie": "c=1",
        "Set-Cookie": "c=2",
        "x-api-key": FAKE_KEY,
        "project_id": "project-123",
        "Organization": "org-abc",
        "org_id": "org-1",
        "user": "someone",
        "email": "a@example.com",
    }
    assert sanitize(raw) == {key: REDACTED for key in raw}


def test_sensitive_key_redacts_nested_value_whole():
    assert sanitize({"headers": {"authorization": {"scheme": "Bearer", "value": "v"}}}) == {
        "headers": {"authorization": REDACTED}
    }


def test_usage_numbers_and_content_are_kept():
    raw = {
        "object": "chat.completion",
        "finish_reason": "stop",
        "usage": {"prompt_tokens": 21, "completion_tokens": 5, "total_tokens": 26},
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "cheatproof ok"}}],
    }
    assert sanitize(raw) == raw


def test_response_ids_are_redacted_but_model_ids_are_kept():
    raw = {
        "id": "chatcmpl-" + "Q" * 29,
        "model": MODEL,
        "data": [{"id": MODEL, "object": "model"}, {"id": "call_1"}],
    }
    out = sanitize(raw)
    assert out["id"] == REDACTED
    assert out["model"] == MODEL
    assert out["data"][0]["id"] == MODEL
    assert out["data"][1]["id"] == REDACTED


def test_long_model_id_is_kept_under_id_but_redacted_as_content():
    long_model = "nvidia/" + "m" * 40
    assert sanitize({"id": long_model})["id"] == long_model
    assert sanitize({"content": long_model})["content"] == REDACTED


def test_email_bearer_and_key_strings_are_redacted_anywhere():
    raw = {
        "content": "write to a@example.com please",
        "header": f"Bearer {FAKE_KEY}",
        "nested": [["fine", {"deep": FAKE_KEY}], {"x": f"token={FAKE_LONG}"}],
        "detail": FAKE_LONG,
    }
    assert sanitize(raw) == {
        "content": REDACTED,
        "header": REDACTED,
        "nested": [["fine", {"deep": REDACTED}], {"x": REDACTED}],
        "detail": REDACTED,
    }


def test_sanitize_returns_a_deep_copy():
    raw = {"choices": [{"message": {"content": "hi"}}]}
    out = sanitize(raw)
    out["choices"][0]["message"]["content"] = "changed"
    assert raw["choices"][0]["message"]["content"] == "hi"


def test_sanitize_is_idempotent():
    raw = {"id": "chatcmpl-" + "Q" * 29, "user": "u", "content": "a@example.com", "model": MODEL}
    once = sanitize(raw)
    assert sanitize(once) == once


def test_unsupported_types_are_rejected():
    with pytest.raises(TypeError):
        sanitize({"x": object()})


def test_assert_clean_passes_on_sanitized_output():
    raw = {"id": "chatcmpl-" + "Q" * 29, "user": "u", "headers": {"authorization": f"Bearer {FAKE_KEY}"}}
    assert_clean(sanitize(raw))


def test_assert_clean_passes_on_model_ids_and_plain_content():
    assert_clean({"id": MODEL, "model": MODEL, "usage": {"total_tokens": 3}, "content": "cheatproof ok"})


def test_assert_clean_flags_raw_secret_in_nested_list():
    with pytest.raises(ValueError, match="remain"):
        assert_clean({"choices": [{"message": {"content": "ok"}}, {"note": [FAKE_KEY]}]})


def test_assert_clean_flags_sensitive_key_with_real_value():
    with pytest.raises(ValueError):
        assert_clean({"api_key": FAKE_KEY})


def test_assert_clean_flags_unredacted_response_id():
    with pytest.raises(ValueError):
        assert_clean({"id": "chatcmpl-" + "Q" * 29})


def test_assert_clean_error_names_the_path_not_the_value():
    with pytest.raises(ValueError) as err:
        assert_clean({"outer": {"email": "a@example.com"}})
    assert "outer/email" in str(err.value)
    assert "a@example.com" not in str(err.value)


@pytest.mark.skipif(not FIXTURES, reason="no recorded fixtures under tests/fixtures yet")
@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.relative_to(FIXTURE_ROOT).as_posix())
def test_recorded_fixtures_pass_assert_clean(path):
    assert_clean(json.loads(path.read_text()))
