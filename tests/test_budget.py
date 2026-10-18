import json
import math
import os
from types import SimpleNamespace

import httpx
import openai
import pytest

from cheatproof.budget import Budget, BudgetExceeded, Price
from cheatproof.llm import GuardedLLM

PRICE = Price(input_per_m=1.0, output_per_m=2.0)
OLD_MTIME_NS = 1_000_000_000 * 10**9  # 2001, far from now, so any rewrite of the file shows as a change


def make_budget(tmp_path, total=1.0, daily=1.0, runs=2, run_usd=0.01):
    return Budget(tmp_path / "ledger.json", total, daily, runs, prices={"m": PRICE}, sandbox_run_usd=run_usd)


class FakeCompletions:
    def __init__(self, usage=(100, 50), error=None):
        self.usage, self.error, self.calls = usage, error, 0

    def create(self, **kwargs):
        self.calls += 1
        if self.error:
            raise self.error
        p, c = self.usage
        return SimpleNamespace(usage=SimpleNamespace(prompt_tokens=p, completion_tokens=c))


def fake_client(completions):
    return SimpleNamespace(chat=SimpleNamespace(completions=completions))


def status_error(code):
    req = httpx.Request("POST", "https://example.invalid/v1/chat/completions")
    return openai.APIStatusError("err", response=httpx.Response(code, request=req), body=None)


def test_reserve_blocks_when_worst_case_exceeds_total_cap(tmp_path):
    b = make_budget(tmp_path, total=0.001)
    with pytest.raises(BudgetExceeded, match="total cap"):
        b.reserve("m", 1000, 1000)  # worst case $0.003


def test_daily_cap_blocks_independently(tmp_path):
    b = make_budget(tmp_path, total=10, daily=0.001)
    with pytest.raises(BudgetExceeded, match="daily cap"):
        b.reserve("m", 1000, 1000)


def test_settle_replaces_reservation_with_actual_cost(tmp_path):
    b = make_budget(tmp_path)
    hold = b.reserve("m", 1000, 1000)
    assert b.snapshot()["total_usd"] == pytest.approx(0.003)
    b.settle(hold, 100, 50)
    assert b.snapshot()["total_usd"] == pytest.approx(0.0002)


def test_ledger_is_shared_across_instances(tmp_path):
    make_budget(tmp_path).settle(make_budget(tmp_path).reserve("m", 1000, 0), 1000, 0)
    assert make_budget(tmp_path).snapshot()["total_usd"] == pytest.approx(0.001)


def test_unknown_model_uses_conservative_default_price(tmp_path):
    b = make_budget(tmp_path, total=100, daily=100)
    hold = b.reserve("unknown", 1_000_000, 0)
    assert hold.usd == pytest.approx(3.0)


def test_sandbox_run_cap(tmp_path):
    b = make_budget(tmp_path, runs=2)
    b.reserve_sandbox_run()
    b.reserve_sandbox_run()
    with pytest.raises(BudgetExceeded, match="sandbox run cap"):
        b.reserve_sandbox_run()


def test_guarded_chat_records_real_usage(tmp_path):
    b = make_budget(tmp_path)
    llm = GuardedLLM(b, client=fake_client(FakeCompletions(usage=(100, 50))))
    llm.chat("m", [{"role": "user", "content": "hi"}], max_tokens=100)
    assert b.snapshot()["total_usd"] == pytest.approx(0.0002)


def test_guarded_chat_refuses_before_calling_model_when_over_cap(tmp_path):
    completions = FakeCompletions()
    llm = GuardedLLM(make_budget(tmp_path, total=0.000001), client=fake_client(completions))
    with pytest.raises(BudgetExceeded):
        llm.chat("m", [{"role": "user", "content": "hi"}], max_tokens=10)
    assert completions.calls == 0


def test_http_402_halts_every_later_call(tmp_path):
    b = make_budget(tmp_path, total=10, daily=10)
    llm = GuardedLLM(b, client=fake_client(FakeCompletions(error=status_error(402))))
    with pytest.raises(openai.APIStatusError):
        llm.chat("m", [{"role": "user", "content": "hi"}], max_tokens=10)
    with pytest.raises(BudgetExceeded, match="halted"):
        b.reserve("m", 1, 1)
    with pytest.raises(BudgetExceeded, match="halted"):
        b.reserve_sandbox_run()


def test_rejected_call_still_counts_prompt_cost(tmp_path):
    b = make_budget(tmp_path, total=10, daily=10)
    llm = GuardedLLM(b, client=fake_client(FakeCompletions(error=status_error(400))))
    with pytest.raises(openai.APIStatusError):
        llm.chat("m", [{"role": "user", "content": "x" * 300}], max_tokens=10)
    assert b.snapshot()["total_usd"] > 0
    assert b.snapshot()["halted"] is None


def test_unbounded_output_is_rejected(tmp_path):
    llm = GuardedLLM(make_budget(tmp_path), client=fake_client(FakeCompletions()))
    with pytest.raises(ValueError):
        llm.chat("m", [], max_tokens=0)
    with pytest.raises(ValueError):
        llm.chat("m", [], max_tokens=10**6)


def test_sandbox_runs_count_toward_money_cap(tmp_path):
    b = make_budget(tmp_path, total=0.15, daily=1.0, runs=100, run_usd=0.1)
    b.reserve_sandbox_run()
    with pytest.raises(BudgetExceeded, match="total cap"):
        b.reserve_sandbox_run()
    assert b.snapshot()["sandbox_runs"] == 1


def test_stream_and_multiple_choices_are_rejected(tmp_path):
    llm = GuardedLLM(make_budget(tmp_path), client=fake_client(FakeCompletions()))
    for kwargs in ({"stream": True}, {"n": 2}, {"max_completion_tokens": 10**6}, {"extra_body": {}}):
        with pytest.raises(ValueError, match="unsupported"):
            llm.chat("m", [], max_tokens=10, **kwargs)


def test_server_error_keeps_worst_case_reservation(tmp_path):
    b = make_budget(tmp_path, total=10, daily=10)
    llm = GuardedLLM(b, client=fake_client(FakeCompletions(error=status_error(503))))
    with pytest.raises(openai.APIStatusError):
        llm.chat("m", [{"role": "user", "content": "hi"}], max_tokens=1000)
    assert b.snapshot()["total_usd"] >= PRICE.cost(0, 1000)


def test_tools_count_toward_input_estimate():
    from cheatproof.llm import estimate_tokens

    tools = [{"type": "function", "function": {"name": "read_file", "description": "x" * 300}}]
    assert estimate_tokens([], tools) > estimate_tokens([]) + 90


def test_ledger_path_must_be_absolute(monkeypatch):
    monkeypatch.setenv("SPEND_LEDGER", "runs/ledger.json")
    with pytest.raises(BudgetExceeded, match="absolute"):
        Budget.from_env()
    monkeypatch.delenv("SPEND_LEDGER")
    with pytest.raises(BudgetExceeded, match="absolute"):
        Budget.from_env()


def test_parallel_sandbox_reservations_never_pass_the_run_cap(tmp_path):
    # Each reservation opens its own lock file handle, so threads contend like separate processes.
    from concurrent.futures import ThreadPoolExecutor

    b = make_budget(tmp_path, total=10, daily=10, runs=5, run_usd=0.01)

    def try_run(_):
        try:
            b.reserve_sandbox_run()
            return True
        except BudgetExceeded:
            return False

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(try_run, range(40)))
    assert sum(results) == 5
    assert b.snapshot()["sandbox_runs"] == 5
    assert b.snapshot()["total_usd"] == pytest.approx(0.05)


def test_sandbox_run_returns_hold_and_halt_wins_over_run_cap(tmp_path):
    b = make_budget(tmp_path, runs=0, run_usd=0.01)
    b.halt("test")
    with pytest.raises(BudgetExceeded, match="halted"):
        b.reserve_sandbox_run()
    ok = make_budget(tmp_path / "other", runs=1, run_usd=0.01)
    assert ok.reserve_sandbox_run().usd == pytest.approx(0.01)


@pytest.fixture
def cap_env(monkeypatch, tmp_path):
    """Every setting from_env reads, set with monkeypatch so a developer's shell or .env cannot leak in."""
    values = {
        "SPEND_LEDGER": str(tmp_path / "ledger.json"),
        "SPEND_CAP_USD": "20",
        "DAILY_CAP_USD": "4",
        "SANDBOX_RUN_CAP": "250",
        "SANDBOX_RUN_USD": "0.05",
        "MODEL_PRICES_JSON": "{}",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def test_documented_caps_are_read_as_written(cap_env):
    b = Budget.from_env()
    assert b.total_cap_usd == 20.0
    assert b.daily_cap_usd == 4.0
    assert b.sandbox_run_cap == 250
    assert b.sandbox_run_usd == pytest.approx(0.05)


@pytest.mark.parametrize("value", ["20", "0.8", "2.5", "1e1"])
def test_finite_positive_money_cap_is_accepted(cap_env, monkeypatch, value):
    monkeypatch.setenv("SPEND_CAP_USD", value)
    assert Budget.from_env().total_cap_usd == pytest.approx(float(value))


@pytest.mark.parametrize("name", ["SPEND_CAP_USD", "DAILY_CAP_USD"])
def test_missing_money_cap_fails_closed(cap_env, monkeypatch, name):
    monkeypatch.delenv(name)
    with pytest.raises(BudgetExceeded, match=name):
        Budget.from_env()


@pytest.mark.parametrize("name", ["SPEND_CAP_USD", "DAILY_CAP_USD"])
@pytest.mark.parametrize("value", ["", "nan", "inf", "-inf", "-1", "0", "abc"])
def test_invalid_money_cap_fails_closed(cap_env, monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(BudgetExceeded, match=name):
        Budget.from_env()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("SANDBOX_RUN_CAP", "-1"),
        ("SANDBOX_RUN_CAP", "1.5"),
        ("SANDBOX_RUN_CAP", "nan"),
        ("SANDBOX_RUN_CAP", "inf"),
        ("SANDBOX_RUN_CAP", "abc"),
        ("SANDBOX_RUN_USD", "nan"),
        ("SANDBOX_RUN_USD", "inf"),
        ("SANDBOX_RUN_USD", "-1"),
        ("SANDBOX_RUN_USD", "0"),
        ("SANDBOX_RUN_USD", "abc"),
        ("MODEL_PRICES_JSON", '{"m": [NaN, 1]}'),
        ("MODEL_PRICES_JSON", '{"m": [Infinity, 1]}'),
        ("MODEL_PRICES_JSON", '{"m": ["nan", 1]}'),
        ("MODEL_PRICES_JSON", '{"m": [0, 1]}'),
        ("MODEL_PRICES_JSON", '{"m": [-1, 1]}'),
        ("MODEL_PRICES_JSON", '{"m": [1]}'),
        ("MODEL_PRICES_JSON", '["m"]'),
        ("MODEL_PRICES_JSON", "not json"),
    ],
)
def test_invalid_run_cap_and_price_settings_fail_closed(cap_env, monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(BudgetExceeded):
        Budget.from_env()


def test_run_cap_and_run_price_default_when_unset(cap_env, monkeypatch):
    monkeypatch.delenv("SANDBOX_RUN_CAP")
    monkeypatch.delenv("SANDBOX_RUN_USD")
    b = Budget.from_env()
    assert b.sandbox_run_cap == 250
    assert b.sandbox_run_usd == pytest.approx(0.05)


def test_model_prices_from_env_are_used(cap_env, monkeypatch):
    monkeypatch.setenv("MODEL_PRICES_JSON", json.dumps({"m": [0.06, 0.24]}))
    assert Budget.from_env().price("m") == Price(0.06, 0.24)


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf, -1.0, 0.0])
def test_constructor_refuses_bad_money_caps(tmp_path, bad):
    with pytest.raises(BudgetExceeded, match="total cap"):
        Budget(tmp_path / "ledger.json", bad, 1.0, 1)
    with pytest.raises(BudgetExceeded, match="daily cap"):
        Budget(tmp_path / "ledger.json", 1.0, bad, 1)


@pytest.mark.parametrize("bad", [math.nan, math.inf, -1.0, 0.0])
def test_constructor_refuses_bad_prices_and_run_price(tmp_path, bad):
    base = {
        "ledger": tmp_path / "ledger.json",
        "total_cap_usd": 1.0,
        "daily_cap_usd": 1.0,
        "sandbox_run_cap": 1,
    }
    with pytest.raises(BudgetExceeded, match="price"):
        Budget(**base, prices={"m": Price(bad, 1.0)})
    with pytest.raises(BudgetExceeded, match="price"):
        Budget(**base, prices={"m": Price(1.0, bad)})
    with pytest.raises(BudgetExceeded, match="price"):
        Budget(**base, default_price=Price(bad, 1.0))
    with pytest.raises(BudgetExceeded, match="SANDBOX_RUN_USD"):
        Budget(**base, sandbox_run_usd=bad)


@pytest.mark.parametrize("bad", [-1, True, 1.5, None])
def test_constructor_refuses_bad_run_cap(tmp_path, bad):
    with pytest.raises(BudgetExceeded, match="sandbox_run_cap"):
        Budget(tmp_path / "ledger.json", 1.0, 1.0, bad)


def test_zero_run_cap_means_no_sandbox_runs(tmp_path):
    b = make_budget(tmp_path, runs=0)
    with pytest.raises(BudgetExceeded, match="sandbox run cap 0"):
        b.reserve_sandbox_run()
    assert b.snapshot()["total_usd"] == 0.0


def test_non_finite_ledger_amount_is_refused(tmp_path):
    (tmp_path / "ledger.json").write_text('{"total_usd": NaN, "days": {}, "sandbox_runs": 0, "halted": null}')
    with pytest.raises(BudgetExceeded, match="non-finite"):
        make_budget(tmp_path).reserve("m", 1, 1)


def test_snapshot_does_not_modify_ledger(tmp_path):
    b = make_budget(tmp_path, total=10, daily=10)
    b.reserve("m", 1, 1)  # creates the ledger and its lock file
    ledger = tmp_path / "ledger.json"
    # Compact JSON, not the writer's indented form, so any rewrite would change the bytes.
    ledger.write_text(
        json.dumps({"total_usd": 0.5, "days": {}, "sandbox_runs": 1, "halted": None}, separators=(",", ":"))
    )
    os.utime(ledger, ns=(OLD_MTIME_NS, OLD_MTIME_NS))
    before = ledger.read_bytes()
    assert b.snapshot()["total_usd"] == pytest.approx(0.5)
    assert ledger.read_bytes() == before
    assert ledger.stat().st_mtime_ns == OLD_MTIME_NS


def test_snapshot_does_not_reset_a_cleared_halted_flag(tmp_path):
    b = make_budget(tmp_path, total=10, daily=10)
    ledger = tmp_path / "ledger.json"
    b.halt("HTTP 402 from Token Factory")
    assert b.snapshot()["halted"] == "HTTP 402 from Token Factory"
    state = json.loads(ledger.read_text())
    state["halted"] = None  # a person clears the flag by hand
    ledger.write_text(json.dumps(state))
    os.utime(ledger, ns=(OLD_MTIME_NS, OLD_MTIME_NS))
    before = ledger.read_bytes()
    assert b.snapshot()["halted"] is None
    assert ledger.read_bytes() == before
    assert ledger.stat().st_mtime_ns == OLD_MTIME_NS
    b.reserve("m", 1, 1)  # the cleared budget spends again


def test_snapshot_creates_nothing_when_no_ledger_exists(tmp_path):
    b = Budget(tmp_path / "missing" / "ledger.json", 1.0, 1.0, 1)
    assert b.snapshot() == {"total_usd": 0.0, "days": {}, "sandbox_runs": 0, "halted": None}
    assert not (tmp_path / "missing").exists()
