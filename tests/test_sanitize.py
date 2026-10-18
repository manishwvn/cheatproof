import json
from pathlib import Path

import pytest

from cheatproof.budget import BudgetExceeded
from cheatproof.sanitize import REDACTED, assert_clean, sanitize
from scripts import smoke

# Fake values built at runtime so no credential-shaped literal sits in the repo.
FAKE_KEY = "sk-" + "x" * 40
FAKE_LONG = "0123456789abcdef" * 2
FAKE_JWT = "eyJ" + "h" * 12 + "." + "p" * 12 + "." + "s" * 12
FAKE_AWS_KEY_ID = "AKIA" + "0123456789ABCDEF"
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


def test_sensitive_words_match_as_substrings_and_identity_names_exactly():
    raw = {
        "session_id": "s-1",
        "auth_header": "h",
        "credential": "c",
        "passwd": "p",
        "email_address": "a",
        "tenant": "t",
        "workspace": "w",
        "account_id": "acct",
        "user_id": "u",
        "trace_id": "tr",
        "request_id": "r",
        "ip": "10.0.0.1",
        "host": "gpu-1",
    }
    assert sanitize(raw) == {key: REDACTED for key in raw}


def test_names_that_only_contain_an_identity_fragment_are_kept():
    raw = {"description": "a cat", "shipping": "standard", "object": "chat.completion"}
    assert sanitize(raw) == raw


def test_sensitive_key_redacts_nested_value_whole():
    assert sanitize({"headers": {"authorization": {"scheme": "Bearer", "value": "v"}}}) == {
        "headers": {"authorization": REDACTED}
    }


def test_null_and_empty_values_under_secret_names_carry_nothing_and_are_kept():
    raw = {"api_key": None, "token": "", "cookie": {}, "password": []}
    assert sanitize(raw) == raw
    assert_clean(raw)


def test_usage_numbers_and_content_are_kept():
    raw = {
        "object": "chat.completion",
        "finish_reason": "stop",
        "usage": {"prompt_tokens": 21, "completion_tokens": 5, "total_tokens": 26},
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "cheatproof ok"}}],
    }
    assert sanitize(raw) == raw


def test_usage_counters_survive_but_token_values_under_other_names_do_not():
    usage = {
        "max_tokens": 4096,
        "reasoning_tokens": 0,
        "completion_tokens_details": {"reasoning_tokens": 7, "accepted_prediction_tokens": 0},
        "prompt_tokens_details": None,
        "token_ids": None,
    }
    assert sanitize({"usage": usage}) == {"usage": usage}
    assert sanitize({"token": 12345}) == {"token": REDACTED}
    assert sanitize({"access_token": 12345}) == {"access_token": REDACTED}
    assert sanitize({"tokens_details": {"token_key": 5}}) == {"tokens_details": {"token_key": REDACTED}}


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


def test_model_id_exemption_is_limited_to_real_model_ids():
    assert sanitize({"id": "nvidia/Nemotron:latest"}) == {"id": "nvidia/Nemotron:latest"}
    assert sanitize({"model": "home/alice"}) == {"model": REDACTED}
    assert sanitize({"root": "Users/bob"}) == {"root": REDACTED}
    assert sanitize({"content": "/Users/bob/project/file.py"}) == {"content": REDACTED}


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


@pytest.mark.parametrize(
    "text",
    [
        f"jwt {FAKE_JWT}",
        f"aws {FAKE_AWS_KEY_ID}",
        "fetch https://bob:hunter2@localhost:8080/v1",
        "GET https://api.example.com/v1/models?api_key=abc123",
        "https://example.com/cb?x=1&signature=abc",
        "base64 " + "ab+/" * 8,
        "C:\\Users\\bob\\repo",
        "/home/ci/work/file.txt",
        "/Users/bob/project",
    ],
    ids=[
        "jwt",
        "aws-key-id",
        "url-credentials",
        "query-api-key",
        "query-signature",
        "base64-with-plus-slash",
        "windows-user-path",
        "home-path",
        "users-path",
    ],
)
def test_new_secret_patterns_are_redacted(text):
    assert sanitize({"content": text}) == {"content": REDACTED}
    with pytest.raises(ValueError):
        assert_clean({"content": text})


def test_secret_dict_keys_are_replaced_without_collisions():
    raw = {FAKE_KEY: 1, "a@example.com": 2, "plain": 3}
    out = sanitize(raw)
    assert out == {REDACTED: 1, "REDACTED_2": 2, "plain": 3}
    assert_clean(out)
    with pytest.raises(ValueError) as err:
        assert_clean(raw)
    assert "<secret-key>" in str(err.value)
    assert "a@example.com" not in str(err.value)
    assert FAKE_KEY not in str(err.value)


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


@pytest.mark.skipif(not FIXTURES, reason="no recorded fixtures under tests/fixtures yet")
@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.relative_to(FIXTURE_ROOT).as_posix())
def test_recorded_fixtures_are_fixed_points_of_sanitize(path):
    data = json.loads(path.read_text())
    assert sanitize(data) == data


def test_models_fixture_keeps_every_model_id():
    data = json.loads((FIXTURE_ROOT / "token_factory" / "models.json").read_text())
    ids = [m["id"] for m in sanitize(data)["data"]]
    assert ids == [m["id"] for m in data["data"]]
    assert MODEL in ids


def test_chat_fixture_keeps_model_id_and_usage_counts():
    data = json.loads((FIXTURE_ROOT / "token_factory" / "chat_completion.json").read_text())
    clean = sanitize(data)
    assert clean["id"] == REDACTED
    assert clean["model"] == MODEL
    assert clean["usage"] == {
        "completion_tokens": 64,
        "completion_tokens_details": None,
        "prompt_tokens": 24,
        "prompt_tokens_details": None,
        "total_tokens": 88,
    }


# scripts/smoke.py: the sandbox step and fixture recording. Kept in this file so no new test file is needed.


class HaltedBudget:
    """Stands in for a Budget whose cap tripped or whose ledger was halted."""

    def reserve_sandbox_run(self):
        raise BudgetExceeded("budget halted: test")


class FailingBudget:
    def reserve_sandbox_run(self):
        raise RuntimeError("network down")


def test_sandbox_step_reraises_budget_exceeded():
    with pytest.raises(BudgetExceeded):
        smoke.run_sandbox_step(HaltedBudget())


def test_sandbox_step_still_skips_other_failures(capsys):
    smoke.run_sandbox_step(FailingBudget())
    assert capsys.readouterr().out.startswith("sandbox step skipped (RuntimeError): network down")


def test_record_fixtures_writes_redacted_files(tmp_path):
    models = {
        "object": "list",
        "data": [{"id": MODEL, "object": "model", "owned_by": "a@example.com", "api_key": FAKE_KEY}],
    }
    completion = {
        "id": "chatcmpl-" + "Q" * 29,
        "model": MODEL,
        "object": "chat.completion",
        "usage": {"prompt_tokens": 24, "completion_tokens": 64, "total_tokens": 88},
        "choices": [{"message": {"role": "assistant", "content": f"Bearer {FAKE_KEY}"}}],
    }
    out_dir = tmp_path / "fixtures"
    smoke.record_fixtures(out_dir, models, completion)
    for name in ("models.json", "chat_completion.json"):
        text = (out_dir / name).read_text()
        assert FAKE_KEY not in text
        assert "a@example.com" not in text
        assert "chatcmpl-" not in text
        assert MODEL in text
        assert_clean(json.loads(text))
    chat = json.loads((out_dir / "chat_completion.json").read_text())
    assert chat["id"] == REDACTED
    assert chat["usage"] == {"prompt_tokens": 24, "completion_tokens": 64, "total_tokens": 88}
