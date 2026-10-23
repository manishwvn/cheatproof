import errno
import json
import math
import os
from datetime import date
from pathlib import Path
from types import SimpleNamespace

import httpx
import openai
import pytest

from cheatproof.budget import (
    MAX_REAL_SPEND_CAP_USD,
    MAX_TOTAL_CAP_USD,
    Budget,
    BudgetExceeded,
    Hold,
    Price,
    create_ledger,
    init_ledger_from_env,
)
from cheatproof.llm import GuardedLLM

FAKE_LLM_SECRET = "FAKE-LLM-SECRET-402-do-not-print"

PRICE = Price(input_per_m=1.0, output_per_m=2.0)
OLD_MTIME_NS = 1_000_000_000 * 10**9  # 2001, far from now, so any rewrite of the file shows as a change
TODAY = date.today().isoformat()
pytestmark = pytest.mark.usefixtures("init_ledger")  # a missing ledger is refused


def make_budget(tmp_path, total=1.0, daily=None, runs=2, run_usd=0.01):
    # daily defaults to the total cap, so the daily cap never exceeds the total cap by accident.
    daily = total if daily is None else daily
    return Budget(tmp_path / "ledger.json", total, daily, runs, prices={"m": PRICE}, sandbox_run_usd=run_usd)


def write_ledger(tmp_path, **fields):
    state = {"total_usd": 0.0, "days": {}, "sandbox_runs": 0, "halted": None}
    state.update(fields)
    (tmp_path / "ledger.json").write_text(json.dumps(state))


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
    # A $3 hold fits under the $10 real-spend cap, so this test is about price only.
    b = Budget(tmp_path / "ledger.json", 20, 20, 2)
    hold = b.reserve("unknown", 1_000_000, 0)
    assert hold.usd == pytest.approx(3.0)


def test_sandbox_run_cap(tmp_path):
    b = make_budget(tmp_path, runs=2)
    assert b.reserve_sandbox_run() is None
    b.reserve_sandbox_run()
    with pytest.raises(BudgetExceeded, match="sandbox run cap 2 reached"):
        b.reserve_sandbox_run()
    assert b.snapshot()["sandbox_runs"] == 2


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
    with pytest.raises(BudgetExceeded, match="HTTP 402 from Token Factory"):
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


def test_sandbox_runs_book_no_money(tmp_path):
    # A Sandboxes run books no Token Factory money: it leaves total_usd and the daily ledger untouched.
    b = make_budget(tmp_path, total=0.15, runs=100, run_usd=0.1)
    b.reserve_sandbox_run()
    b.reserve_sandbox_run()
    s = b.snapshot()
    assert s["sandbox_runs"] == 2
    assert s["total_usd"] == 0.0
    assert s["days"] == {}


def test_sandbox_runs_pass_even_when_money_caps_are_spent(tmp_path):
    write_ledger(tmp_path, total_usd=1.0, days={TODAY: 1.0})
    b = make_budget(tmp_path, total=1.0, daily=1.0, runs=3)
    b.reserve_sandbox_run()
    with pytest.raises(BudgetExceeded, match="total cap"):
        b.reserve("m", 1, 1)
    assert b.snapshot()["sandbox_runs"] == 1
    assert b.snapshot()["total_usd"] == pytest.approx(1.0)


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
    assert b.snapshot()["total_usd"] == 0.0


def test_halt_wins_over_sandbox_run_cap_and_books_nothing(tmp_path):
    b = make_budget(tmp_path, runs=0, run_usd=0.01)
    b.halt("test")
    with pytest.raises(BudgetExceeded, match="halted"):
        b.reserve_sandbox_run()
    assert b.snapshot().get("sandbox_runs", 0) == 0
    create_ledger(tmp_path / "other" / "ledger.json")
    ok = make_budget(tmp_path / "other", runs=1, run_usd=0.01)
    assert ok.reserve_sandbox_run() is None
    assert ok.snapshot()["total_usd"] == 0.0


def test_halt_blocks_sandbox_runs_without_counting(tmp_path):
    b = make_budget(tmp_path, runs=5)
    b.halt("HTTP 402 from Token Factory")
    with pytest.raises(BudgetExceeded, match="budget halted: HTTP 402"):
        b.reserve_sandbox_run()
    assert b.snapshot()["sandbox_runs"] == 0


# --- settle: token counts and refunds -------------------------------------------------------------


@pytest.mark.parametrize("tokens", [math.nan, math.inf, -1, -100000, 1.0, True, None, "5", 10**400])
def test_settle_refuses_bad_token_counts_and_keeps_the_hold(tmp_path, tokens):
    b = make_budget(tmp_path, total=10, daily=10)
    hold = b.reserve("m", 1000, 1000)
    with pytest.raises(BudgetExceeded):
        b.settle(hold, tokens, 0)
    with pytest.raises(BudgetExceeded):
        b.settle(hold, 0, tokens)
    assert b.snapshot()["total_usd"] == pytest.approx(0.003)


@pytest.mark.parametrize("usd", [math.nan, math.inf, -1.0])
def test_settle_refuses_a_hold_with_a_bad_amount(tmp_path, usd):
    b = make_budget(tmp_path, total=10, daily=10)
    b.reserve("m", 1, 1)
    with pytest.raises(BudgetExceeded):
        b.settle(Hold("m", usd, TODAY), 1, 1)
    assert b.snapshot()["total_usd"] == pytest.approx(0.000003)


def test_settle_refunds_only_its_own_hold(tmp_path):
    b = make_budget(tmp_path, total=10, daily=10)
    first = b.reserve("m", 1000, 1000)  # $0.003
    b.reserve("m", 1000, 0)  # $0.001, still in flight
    b.settle(first, 0, 0)
    assert b.snapshot()["total_usd"] == pytest.approx(0.001)


def test_settle_never_takes_the_ledger_below_zero(tmp_path):
    b = make_budget(tmp_path, total=10, daily=10)
    b.reserve("m", 1, 1)
    forged = Hold("m", 5.0, TODAY)  # a hold larger than anything booked
    b.settle(forged, 0, 0)
    assert b.snapshot()["total_usd"] == 0.0
    assert b.snapshot()["days"][TODAY] == 0.0


def test_settle_books_an_overshoot_in_full(tmp_path):
    b = make_budget(tmp_path, total=10, daily=10)
    hold = b.reserve("m", 1, 1)  # $0.000003
    b.settle(hold, 1000, 0)  # actual $0.001
    assert b.snapshot()["total_usd"] == pytest.approx(0.001)


# --- reserve and _charge: input validation --------------------------------------------------------


@pytest.mark.parametrize("bad", [-100000, math.nan, math.inf, 1.0, True, None, 10**400])
def test_reserve_refuses_bad_token_counts_without_booking(tmp_path, bad):
    b = make_budget(tmp_path, total=10, daily=10)
    b.reserve("m", 1000, 1000)
    before = b.snapshot()["total_usd"]
    with pytest.raises(BudgetExceeded):
        b.reserve("m", bad, 0)  # input tokens
    with pytest.raises(BudgetExceeded):
        b.reserve("m", 0, bad)  # output tokens
    assert b.snapshot()["total_usd"] == pytest.approx(before)


@pytest.mark.parametrize("worst", [math.nan, math.inf, -1.0, None])
def test_charge_refuses_a_bad_amount_without_booking(tmp_path, worst):
    b = make_budget(tmp_path, total=10, daily=10)
    b.reserve("m", 1, 1)
    before = b.snapshot()["total_usd"]
    with pytest.raises(BudgetExceeded):
        b._reserve_usd("m", worst)
    assert b.snapshot()["total_usd"] == pytest.approx(before)


# --- ledger reads: every read refuses a malformed ledger ------------------------------------------


@pytest.mark.parametrize(
    "fields",
    [
        {"sandbox_runs": math.nan},
        {"sandbox_runs": -5},
        {"sandbox_runs": 1.5},
        {"sandbox_runs": True},
        {"sandbox_runs": "3"},
        {"sandbox_runs": None},
        {"halted": 5},
        {"halted": ""},
        {"halted": ["x"]},
        {"days": []},
        {"days": {TODAY: -1.0}},
        {"days": {TODAY: math.inf}},
        {"total_usd": math.inf},
        {"total_usd": -0.5},
        {"total_usd": True},
        {"total_usd": "1"},
        {"sandbox_cost_usd": math.nan},
        {"sandbox_cost_usd": -1.0},
        {"sandbox_cost_usd": "1"},
        {"sandbox_cost_days": []},
        {"sandbox_cost_days": {TODAY: -1.0}},
        {"trial_spend_usd": math.inf},
        {"trial_spend_usd": "1"},
    ],
)
def test_malformed_ledger_is_refused_by_every_read(tmp_path, fields):
    write_ledger(tmp_path, **fields)
    b = make_budget(tmp_path)
    with pytest.raises(BudgetExceeded):
        b.snapshot()
    with pytest.raises(BudgetExceeded):
        b.reserve("m", 1, 1)
    with pytest.raises(BudgetExceeded):
        b.reserve_sandbox_run()


@pytest.mark.parametrize("missing", ["total_usd", "days", "sandbox_runs"])
def test_ledger_missing_a_cap_field_is_refused(tmp_path, missing):
    state = {"total_usd": 0.0, "days": {}, "sandbox_runs": 0, "halted": None}
    del state[missing]
    (tmp_path / "ledger.json").write_text(json.dumps(state))
    with pytest.raises(BudgetExceeded):
        make_budget(tmp_path).snapshot()


@pytest.mark.parametrize("text", ["{not json", "[]", "null", '"x"'])
def test_unreadable_ledger_is_refused(tmp_path, text):
    (tmp_path / "ledger.json").write_text(text)
    with pytest.raises(BudgetExceeded):
        make_budget(tmp_path).snapshot()


@pytest.mark.parametrize("halted", [None, False, True, "HTTP 402 from Token Factory"])
def test_valid_halted_values_are_read(tmp_path, halted):
    write_ledger(tmp_path, halted=halted)
    assert make_budget(tmp_path).snapshot()["halted"] == halted


# --- halt: the stored reason always halts ---------------------------------------------------------


@pytest.mark.parametrize("reason", ["", None, "   ", 0, False, 402])
def test_halt_with_an_empty_or_non_text_reason_still_halts(tmp_path, reason):
    b = make_budget(tmp_path, total=10, daily=10)
    b.halt(reason)
    assert b.snapshot()["halted"] == "halted"
    with pytest.raises(BudgetExceeded, match="halted"):
        b.reserve("m", 1, 1)
    with pytest.raises(BudgetExceeded, match="halted"):
        b.reserve_sandbox_run()


# --- ceiling: $20 total, daily at most total ------------------------------------------------------


def test_total_cap_at_the_ceiling_is_accepted(tmp_path):
    assert Budget(tmp_path / "ledger.json", MAX_TOTAL_CAP_USD, 1.0, 1).total_cap_usd == 20.0


@pytest.mark.parametrize("bad", [20.0001, 1e308, 10**400])
def test_total_cap_above_the_ceiling_fails_closed(tmp_path, bad):
    with pytest.raises(BudgetExceeded, match="total cap"):
        Budget(tmp_path / "ledger.json", bad, 1.0, 1)


def test_daily_cap_above_total_cap_is_refused(tmp_path):
    with pytest.raises(BudgetExceeded, match="daily cap"):
        Budget(tmp_path / "ledger.json", 5.0, 5.01, 1)


def test_huge_int_money_values_raise_budget_exceeded(tmp_path):
    with pytest.raises(BudgetExceeded, match="daily cap"):
        Budget(tmp_path / "ledger.json", 1.0, 10**400, 1)
    with pytest.raises(BudgetExceeded, match="price"):
        Budget(tmp_path / "ledger.json", 1.0, 1.0, 1, prices={"m": Price(10**400, 1.0)})
    with pytest.raises(BudgetExceeded, match="SANDBOX_RUN_USD"):
        Budget(tmp_path / "ledger.json", 1.0, 1.0, 1, sandbox_run_usd=10**400)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("SPEND_CAP_USD", "1e308"),
        ("SPEND_CAP_USD", "1" + "0" * 400),
        ("SPEND_CAP_USD", "20.01"),
        ("DAILY_CAP_USD", "1e308"),
        ("DAILY_CAP_USD", "20.01"),
        ("SANDBOX_RUN_USD", "1" + "0" * 400),
        ("MODEL_PRICES_JSON", '{"m": [' + "1" * 400 + ", 1]}"),
    ],
)
def test_out_of_range_env_settings_fail_closed(cap_env, monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(BudgetExceeded):
        Budget.from_env()


def test_daily_cap_above_total_cap_fails_closed_from_env(cap_env, monkeypatch):
    monkeypatch.setenv("SPEND_CAP_USD", "4")
    monkeypatch.setenv("DAILY_CAP_USD", "4.01")
    with pytest.raises(BudgetExceeded, match="DAILY_CAP_USD"):
        Budget.from_env()


@pytest.fixture
def cap_env(monkeypatch, tmp_path):
    """Every setting from_env reads, set with monkeypatch so a developer's shell or .env cannot leak in."""
    values = {
        "SPEND_LEDGER": str(tmp_path / "ledger.json"),
        "SPEND_CAP_USD": "20",
        "DAILY_CAP_USD": "4",
        "SANDBOX_RUN_CAP": "250",
        "SANDBOX_RUN_USD": "0.05",
        "LOCAL_RUN_CAP": "2000",
        "TAVILY_CALL_CAP": "200",
        "MODEL_PRICES_JSON": "{}",
        "SANDBOX_COST_CAP_USD": "0.5",
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
    monkeypatch.setenv("DAILY_CAP_USD", value)  # the daily cap may not exceed the total cap
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
    assert b.snapshot().get("sandbox_runs", 0) == 0
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


def test_snapshot_refuses_a_missing_ledger_and_creates_nothing(tmp_path):
    b = Budget(tmp_path / "missing" / "ledger.json", 1.0, 1.0, 1)
    with pytest.raises(BudgetExceeded, match="budget init"):
        b.snapshot()
    assert not (tmp_path / "missing").exists()


# --- local runs and Tavily calls: counted against a cap, never priced -----------------------------


def make_counted(tmp_path, local=3, tavily=2):
    return Budget(
        tmp_path / "ledger.json",
        1.0,
        1.0,
        2,
        prices={"m": PRICE},
        local_run_cap=local,
        tavily_call_cap=tavily,
    )


def test_local_run_cap_is_enforced(tmp_path):
    b = make_counted(tmp_path, local=2)
    assert b.reserve_local_run() is None
    b.reserve_local_run()
    with pytest.raises(BudgetExceeded, match="local run cap 2 reached"):
        b.reserve_local_run()
    assert b.snapshot()["local_runs"] == 2


def test_tavily_call_cap_is_enforced(tmp_path):
    b = make_counted(tmp_path, tavily=1)
    b.reserve_tavily_call()
    with pytest.raises(BudgetExceeded, match="tavily call cap 1 reached"):
        b.reserve_tavily_call()
    assert b.snapshot()["tavily_calls"] == 1


def test_local_and_tavily_counters_book_no_money(tmp_path):
    b = make_counted(tmp_path, local=50, tavily=50)
    for _ in range(50):
        b.reserve_local_run()
        b.reserve_tavily_call()
    s = b.snapshot()
    assert s["local_runs"] == 50 and s["tavily_calls"] == 50
    assert s["total_usd"] == 0.0
    assert s["days"] == {}
    assert s["sandbox_runs"] == 0


def test_local_runs_and_sandbox_runs_have_separate_caps(tmp_path):
    b = make_counted(tmp_path, local=1)
    b.reserve_local_run()
    with pytest.raises(BudgetExceeded, match="local run cap"):
        b.reserve_local_run()
    b.reserve_sandbox_run()  # the sandbox cap is untouched by local runs
    assert b.snapshot()["sandbox_runs"] == 1
    assert b.snapshot()["total_usd"] == 0.0


def test_halt_blocks_local_runs_and_tavily_calls_without_counting(tmp_path):
    b = make_counted(tmp_path)
    b.halt("HTTP 402 from Token Factory")
    with pytest.raises(BudgetExceeded, match="budget halted: HTTP 402"):
        b.reserve_local_run()
    with pytest.raises(BudgetExceeded, match="budget halted: HTTP 402"):
        b.reserve_tavily_call()
    s = b.snapshot()
    assert s.get("local_runs", 0) == 0 and s.get("tavily_calls", 0) == 0


def test_zero_counter_caps_mean_no_local_runs_or_tavily_calls(tmp_path):
    b = make_counted(tmp_path, local=0, tavily=0)
    with pytest.raises(BudgetExceeded, match="local run cap 0 reached"):
        b.reserve_local_run()
    with pytest.raises(BudgetExceeded, match="tavily call cap 0 reached"):
        b.reserve_tavily_call()
    assert b.snapshot()["total_usd"] == 0.0


@pytest.mark.parametrize(
    ("method", "key"),
    [("reserve_local_run", "local_runs"), ("reserve_tavily_call", "tavily_calls")],
)
def test_parallel_counted_reservations_never_pass_the_cap(tmp_path, method, key):
    # Each reservation opens its own lock file handle, so threads contend like separate processes.
    from concurrent.futures import ThreadPoolExecutor

    b = make_counted(tmp_path, local=5, tavily=5)
    reserve = getattr(b, method)

    def try_call(_):
        try:
            reserve()
            return True
        except BudgetExceeded:
            return False

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(try_call, range(40)))
    assert sum(results) == 5
    assert b.snapshot()[key] == 5
    assert b.snapshot()["total_usd"] == 0.0


def test_old_ledger_without_the_new_counters_still_works(tmp_path):
    write_ledger(tmp_path, total_usd=0.5, sandbox_runs=1)  # no local_runs or tavily_calls keys
    b = make_counted(tmp_path, local=1, tavily=1)
    assert b.snapshot()["total_usd"] == pytest.approx(0.5)
    b.reserve_local_run()  # a missing counter reads as 0, so the first call passes
    b.reserve_tavily_call()
    s = b.snapshot()
    assert s["local_runs"] == 1 and s["tavily_calls"] == 1
    assert s["total_usd"] == pytest.approx(0.5) and s["sandbox_runs"] == 1


@pytest.mark.parametrize("key", ["local_runs", "tavily_calls"])
@pytest.mark.parametrize("value", [math.nan, -1, 1.5, True, "3", None, [1]])
def test_malformed_counter_in_ledger_is_refused_by_every_read(tmp_path, key, value):
    write_ledger(tmp_path, **{key: value})
    b = make_counted(tmp_path)
    with pytest.raises(BudgetExceeded, match="fix it by hand"):
        b.snapshot()
    with pytest.raises(BudgetExceeded):
        b.reserve_local_run()
    with pytest.raises(BudgetExceeded):
        b.reserve_tavily_call()
    with pytest.raises(BudgetExceeded):
        b.reserve_sandbox_run()


@pytest.mark.parametrize("bad", [-1, True, 1.5, None, "3", math.nan])
@pytest.mark.parametrize("kwarg", ["local_run_cap", "tavily_call_cap"])
def test_constructor_refuses_bad_counter_caps(tmp_path, kwarg, bad):
    with pytest.raises(BudgetExceeded, match=kwarg):
        Budget(tmp_path / "ledger.json", 1.0, 1.0, 1, **{kwarg: bad})


def test_counter_caps_default_in_the_constructor(tmp_path):
    b = Budget(tmp_path / "ledger.json", 1.0, 1.0, 1)
    assert b.local_run_cap == 2000
    assert b.tavily_call_cap == 200


def test_counter_caps_default_when_unset(cap_env, monkeypatch):
    monkeypatch.delenv("LOCAL_RUN_CAP")
    monkeypatch.delenv("TAVILY_CALL_CAP")
    b = Budget.from_env()
    assert b.local_run_cap == 2000
    assert b.tavily_call_cap == 200


def test_counter_caps_are_read_from_env(cap_env, monkeypatch):
    monkeypatch.setenv("LOCAL_RUN_CAP", "7")
    monkeypatch.setenv("TAVILY_CALL_CAP", "0")
    b = Budget.from_env()
    assert b.local_run_cap == 7
    assert b.tavily_call_cap == 0


@pytest.mark.parametrize("name", ["LOCAL_RUN_CAP", "TAVILY_CALL_CAP"])
@pytest.mark.parametrize("value", ["-1", "1.5", "nan", "inf", "abc", "", "1e3"])
def test_invalid_counter_cap_env_fails_closed(cap_env, monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(BudgetExceeded, match=name):
        Budget.from_env()


# --- Sandboxes cost log and the Token Factory trial cap -------------------------------------------


def make_capped(tmp_path, sandbox_cost=0.5, trial=0.74, total=20, daily=20, **extra):
    return Budget(
        tmp_path / "ledger.json",
        total,
        daily,
        250,
        prices={"m": PRICE},
        sandbox_cost_cap_usd=sandbox_cost,
        trial_credit_cap_usd=trial,
        **extra,
    )


def test_sandbox_cost_is_logged_and_not_halted_below_the_cap(tmp_path):
    b = make_capped(tmp_path)
    b.book_sandbox_cost(0.2)
    b.book_sandbox_cost(0.25)  # the sum is 0.45, still under 0.50
    s = b.snapshot()
    assert s["sandbox_cost_usd"] == pytest.approx(0.45)
    assert s["sandbox_cost_days"] == {TODAY: pytest.approx(0.45)}
    assert s["halted"] is None
    assert s["total_usd"] == 0.0 and s["days"] == {}  # Token Factory totals are untouched
    assert b.reserve_sandbox_run() is None  # runs still go on


def test_sandbox_cost_sum_exactly_at_the_cap_does_not_halt(tmp_path):
    b = make_capped(tmp_path)
    b.book_sandbox_cost(0.25)
    b.book_sandbox_cost(0.25)
    assert b.snapshot()["sandbox_cost_usd"] == pytest.approx(0.5)
    assert b.snapshot()["halted"] is None


def test_summed_sandbox_cost_over_the_cap_halts_and_stops_later_calls(tmp_path):
    b = make_capped(tmp_path)
    b.book_sandbox_cost(0.3)
    with pytest.raises(BudgetExceeded, match="above the .* cap"):
        b.book_sandbox_cost(0.3)  # the sum is 0.6, above 0.50
    s = b.snapshot()
    assert s["sandbox_cost_usd"] == pytest.approx(0.6)
    assert "Sandboxes cost" in s["halted"]
    with pytest.raises(BudgetExceeded, match="halted"):
        b.reserve_sandbox_run()
    with pytest.raises(BudgetExceeded, match="halted"):
        b.reserve("m", 1, 1)


@pytest.mark.parametrize("usd", [0.6, 1, 2.5])
def test_one_sandbox_cost_above_the_cap_halts(tmp_path, usd):
    b = make_capped(tmp_path)
    with pytest.raises(BudgetExceeded, match="cap"):
        b.book_sandbox_cost(usd)
    s = b.snapshot()
    assert s["halted"] and s["sandbox_cost_usd"] == pytest.approx(usd)


def test_halt_from_http_402_is_kept_when_a_sandbox_cost_lands_later(tmp_path):
    b = make_capped(tmp_path)
    b.halt("HTTP 402 from Sandboxes: payment required")
    with pytest.raises(BudgetExceeded, match="halted"):
        b.book_sandbox_cost(0.1)  # logged, and the in-flight call still stops
    s = b.snapshot()
    assert s["halted"] == "HTTP 402 from Sandboxes: payment required"
    assert s["sandbox_cost_usd"] == pytest.approx(0.1)


@pytest.mark.parametrize("bad", [math.nan, math.inf, -1.0, True, "0", 10**400])
def test_malformed_sandbox_cost_halts_and_is_not_logged(tmp_path, bad):
    b = make_capped(tmp_path)
    with pytest.raises(BudgetExceeded, match="malformed"):
        b.book_sandbox_cost(bad)
    s = b.snapshot()
    assert s["halted"] and "not a finite number" in s["halted"]
    assert s.get("sandbox_cost_usd", 0.0) == 0.0


def test_a_free_sandbox_result_writes_nothing(tmp_path):
    b = make_capped(tmp_path)
    before = (tmp_path / "ledger.json").read_text()
    b.book_sandbox_cost(0)
    assert (tmp_path / "ledger.json").read_text() == before


def test_logged_sandbox_cost_over_the_cap_refuses_the_next_run_even_after_a_manual_unhalt(tmp_path):
    # A person may clear `halted` by hand; a logged sum still over the cap must refuse the next run anyway.
    write_ledger(tmp_path, sandbox_cost_usd=0.9, sandbox_cost_days={TODAY: 0.9})
    b = make_capped(tmp_path)
    with pytest.raises(BudgetExceeded, match="sandbox cost cap"):
        b.reserve_sandbox_run()
    assert b.snapshot().get("sandbox_runs", 0) == 0


def test_trial_cap_refuses_token_factory_spend_past_0_74(tmp_path):
    b = make_capped(tmp_path)
    b.reserve("m", 500_000, 0)  # $0.50 held
    with pytest.raises(BudgetExceeded, match="trial credit cap"):
        b.reserve("m", 500_000, 0)  # $1.00 in all would pass $0.74
    s = b.snapshot()
    assert s["total_usd"] == pytest.approx(0.5)  # the refused call booked nothing
    assert s["trial_spend_usd"] == pytest.approx(0.5)


def test_trial_cap_allows_exactly_0_74_and_no_more(tmp_path):
    b = make_capped(tmp_path)
    b.reserve("m", 740_000, 0)  # $0.74 exactly
    with pytest.raises(BudgetExceeded, match="trial credit cap"):
        b.reserve("m", 1, 0)


def test_trial_cap_counts_spend_from_now_not_the_old_ledger_total(tmp_path):
    write_ledger(tmp_path, total_usd=5.0, days={TODAY: 5.0})  # spend from before the trial cap existed
    b = make_capped(tmp_path)
    b.reserve("m", 700_000, 0)  # $0.70 from now fits under $0.74, though the total is already $5.00
    assert b.snapshot()["trial_spend_usd"] == pytest.approx(0.7)


def test_trial_cap_gives_back_what_a_settled_hold_did_not_spend(tmp_path):
    b = make_capped(tmp_path)
    hold = b.reserve("m", 700_000, 0)  # $0.70 held
    b.settle(hold, 0, 0)  # actual $0
    b.reserve("m", 700_000, 0)  # the refund leaves room again
    assert b.snapshot()["trial_spend_usd"] == pytest.approx(0.7)


@pytest.mark.parametrize("bad", [math.nan, -1.0, 0.0])
def test_constructor_refuses_bad_sandbox_and_trial_caps(tmp_path, bad):
    with pytest.raises(BudgetExceeded, match="SANDBOX_COST_CAP_USD"):
        make_capped(tmp_path, sandbox_cost=bad)
    with pytest.raises(BudgetExceeded, match="TRIAL_CREDIT_CAP_USD"):
        make_capped(tmp_path, trial=bad)


def test_caps_default_when_unset(cap_env, monkeypatch):
    monkeypatch.delenv("SANDBOX_COST_CAP_USD")
    monkeypatch.delenv("REAL_SPEND_CAP_USD", raising=False)
    monkeypatch.delenv("TRIAL_CREDIT_CAP_USD", raising=False)
    b = Budget.from_env()
    assert b.real_spend_cap_usd == pytest.approx(10.0)
    assert b.trial_credit_cap_usd is None  # the old trial cap is only an extra cap, off unless set
    assert b.sandbox_cost_cap_usd == pytest.approx(0.50)


@pytest.mark.parametrize("value", ["", "nan", "inf", "-1", "0", "abc", "21", "1e308"])
def test_invalid_sandbox_cost_cap_falls_back_to_0_50_never_to_no_cap(cap_env, monkeypatch, value):
    monkeypatch.setenv("SANDBOX_COST_CAP_USD", value)
    assert Budget.from_env().sandbox_cost_cap_usd == pytest.approx(0.50)


@pytest.mark.parametrize("value", ["2", "0.25"])
def test_valid_sandbox_cost_cap_is_read(cap_env, monkeypatch, value):
    monkeypatch.setenv("SANDBOX_COST_CAP_USD", value)
    assert Budget.from_env().sandbox_cost_cap_usd == pytest.approx(float(value))


@pytest.mark.parametrize("value", ["", "nan", "inf", "-1", "0", "abc", "20.01"])
def test_invalid_trial_cap_fails_closed(cap_env, monkeypatch, value):
    monkeypatch.setenv("TRIAL_CREDIT_CAP_USD", value)
    with pytest.raises(BudgetExceeded, match="TRIAL_CREDIT_CAP_USD"):
        Budget.from_env()


# --- T43: total real-spend cap (trial + promo credit), hard ceiling $10 ---------------------------------------------


def test_real_spend_cap_defaults_to_10_and_ceiling_is_10(cap_env, monkeypatch):
    monkeypatch.delenv("REAL_SPEND_CAP_USD", raising=False)
    assert Budget.from_env().real_spend_cap_usd == 10.0
    assert MAX_REAL_SPEND_CAP_USD == 10.0
    assert Budget(Path("x.json"), 20, 4, 1).real_spend_cap_usd == 10.0


@pytest.mark.parametrize("value", ["7", "0.5", "10", "1e1"])
def test_valid_real_spend_cap_env_is_read(cap_env, monkeypatch, value):
    monkeypatch.setenv("REAL_SPEND_CAP_USD", value)
    assert Budget.from_env().real_spend_cap_usd == pytest.approx(float(value))


@pytest.mark.parametrize("value", ["11", "10.01", "20", "1e308", "0", "-1", "abc", "", "nan", "inf", "-inf"])
def test_invalid_or_too_high_real_spend_cap_env_fails_closed(cap_env, monkeypatch, value):
    monkeypatch.setenv("REAL_SPEND_CAP_USD", value)
    with pytest.raises(BudgetExceeded, match="REAL_SPEND_CAP_USD"):
        Budget.from_env()


@pytest.mark.parametrize("bad", [11, 10.01, 0, -1, math.nan, math.inf, True, "x"])
def test_constructor_refuses_a_bad_real_spend_cap(tmp_path, bad):
    with pytest.raises(BudgetExceeded, match="REAL_SPEND_CAP_USD"):
        make_capped(tmp_path, trial=None, real_spend_cap_usd=bad)


def test_real_spend_cap_halts_exactly_at_the_cap_with_reserve_estimates(tmp_path):
    b = make_capped(tmp_path, trial=None, real_spend_cap_usd=7)
    b.reserve("m", 3_000_000, 0)  # $3
    b.reserve("m", 4_000_000, 0)  # $4: exactly $7 is allowed
    with pytest.raises(BudgetExceeded, match="REAL_SPEND_CAP_USD"):
        b.reserve("m", 1, 0)  # one more token passes the cap
    s = b.snapshot()
    assert s["trial_spend_usd"] == pytest.approx(7.0)
    assert s["total_usd"] == pytest.approx(7.0)  # the refused call booked nothing


def test_default_cap_refuses_a_hold_that_would_pass_10(tmp_path):
    b = make_capped(tmp_path, trial=None)
    b.reserve("m", 9_000_000, 0)  # $9
    with pytest.raises(BudgetExceeded, match="REAL_SPEND_CAP_USD"):
        b.reserve("m", 2_000_000, 0)  # $11 in all


def test_old_trial_spend_field_still_counts_toward_the_real_cap(tmp_path):
    # The live ledger holds trial_spend_usd 0.3796; the field keeps its name and keeps counting.
    write_ledger(tmp_path, total_usd=0.535, days={TODAY: 0.2}, trial_spend_usd=0.3796)
    b = make_capped(tmp_path, trial=None)
    with pytest.raises(BudgetExceeded, match="REAL_SPEND_CAP_USD"):
        b.reserve("m", 9_700_000, 0)  # 0.3796 + 9.70 passes 10
    b.reserve("m", 9_600_000, 0)  # 0.3796 + 9.60 = 9.9796 fits
    assert b.snapshot()["trial_spend_usd"] == pytest.approx(9.9796)


def test_ledger_without_the_counter_reads_as_zero_and_a_bad_counter_is_refused(tmp_path):
    write_ledger(tmp_path)
    make_capped(tmp_path, trial=None).reserve("m", 1_000_000, 0)
    write_ledger(tmp_path, trial_spend_usd=-1)
    with pytest.raises(BudgetExceeded, match="trial_spend_usd"):
        make_capped(tmp_path, trial=None).reserve("m", 1, 0)


def test_daily_cap_stops_first_when_it_is_lower_than_the_real_cap(tmp_path):
    b = make_capped(tmp_path, trial=None, daily=4)
    b.reserve("m", 4_000_000, 0)  # $4 today
    with pytest.raises(BudgetExceeded, match="daily cap"):
        b.reserve("m", 1, 0)
    assert b.snapshot()["trial_spend_usd"] == pytest.approx(4.0)


def test_old_trial_cap_env_still_applies_when_stricter(cap_env, monkeypatch, tmp_path):
    monkeypatch.setenv("TRIAL_CREDIT_CAP_USD", "0.74")
    monkeypatch.setenv("MODEL_PRICES_JSON", json.dumps({"m": [1.0, 2.0]}))
    b = Budget.from_env()
    assert b.real_spend_cap_usd == 10.0 and b.trial_credit_cap_usd == pytest.approx(0.74)
    b.reserve("m", 700_000, 0)
    with pytest.raises(BudgetExceeded, match="TRIAL_CREDIT_CAP_USD"):
        b.reserve("m", 100_000, 0)  # 0.80 passes the stricter 0.74, though far under 10


def test_old_trial_cap_above_the_real_cap_does_not_raise_it(tmp_path):
    b = make_capped(tmp_path, trial=15)
    with pytest.raises(BudgetExceeded, match="REAL_SPEND_CAP_USD"):
        b.reserve("m", 11_000_000, 0)


# --- T35: a missing ledger is refused; only `budget init` creates one; halt is checked before every call -------------


@pytest.mark.parametrize(
    "call",
    [
        lambda b: b.reserve("m", 1, 1),
        lambda b: b.reserve_sandbox_run(),
        lambda b: b.reserve_local_run(),
        lambda b: b.reserve_tavily_call(),
        lambda b: b.halt("x"),
        lambda b: b.book_sandbox_cost(0.1),
        lambda b: b.book_sandbox_cost(0),
        lambda b: b.check_not_halted(),
        lambda b: b.snapshot(),
    ],
)
def test_missing_ledger_refuses_every_call_and_creates_nothing(tmp_path, call):
    (tmp_path / "ledger.json").unlink()  # the module fixture made one; this test needs none
    b = make_budget(tmp_path)
    with pytest.raises(BudgetExceeded, match="budget init"):
        call(b)
    assert not (tmp_path / "ledger.json").exists()


def test_create_ledger_writes_every_field_zeroed(tmp_path):
    path = create_ledger(tmp_path / "new" / "ledger.json")
    assert json.loads(path.read_text()) == {
        "total_usd": 0.0,
        "days": {},
        "sandbox_runs": 0,
        "local_runs": 0,
        "tavily_calls": 0,
        "halted": None,
        "sandbox_cost_usd": 0.0,
        "sandbox_cost_days": {},
        "trial_spend_usd": 0.0,
    }
    assert Budget(path, 1.0, 1.0, 1).snapshot()["halted"] is None


def test_create_ledger_refuses_an_existing_file_and_keeps_it(tmp_path):
    write_ledger(tmp_path, total_usd=0.5, halted="kept")
    before = (tmp_path / "ledger.json").read_text()
    with pytest.raises(BudgetExceeded, match="already exists"):
        create_ledger(tmp_path / "ledger.json")
    assert (tmp_path / "ledger.json").read_text() == before


def test_a_created_ledger_runs_paid_calls(tmp_path):
    (tmp_path / "ledger.json").unlink()
    (
        tmp_path / "ledger.lock"
    ).unlink()  # the lock left by the first create is a lost-ledger sign, so start clean
    create_ledger(tmp_path / "ledger.json")
    b = make_budget(tmp_path)
    hold = b.reserve("m", 1000, 0)
    assert b.settle(hold, 1000, 0) > 0


def test_init_ledger_from_env_needs_an_absolute_spend_ledger(tmp_path, monkeypatch):
    monkeypatch.delenv("SPEND_LEDGER", raising=False)
    with pytest.raises(BudgetExceeded, match="SPEND_LEDGER"):
        init_ledger_from_env()
    monkeypatch.setenv("SPEND_LEDGER", "relative/ledger.json")
    with pytest.raises(BudgetExceeded, match="SPEND_LEDGER"):
        init_ledger_from_env()
    target = tmp_path / "env" / "ledger.json"
    monkeypatch.setenv("SPEND_LEDGER", str(target))
    assert init_ledger_from_env() == target


def test_halt_is_checked_by_check_not_halted_and_on_the_free_cost_path(tmp_path):
    b = make_budget(tmp_path)
    b.check_not_halted()  # not halted: passes
    b.book_sandbox_cost(0)  # not halted: passes
    b.halt("HTTP 402 from Sandboxes")
    before = (tmp_path / "ledger.json").read_text()
    with pytest.raises(BudgetExceeded, match="budget halted"):
        b.check_not_halted()
    with pytest.raises(BudgetExceeded, match="budget halted"):
        b.book_sandbox_cost(0)
    assert (tmp_path / "ledger.json").read_text() == before


# --- T35 review: every ledger OSError is a refusal inside Budget; create_ledger is all-or-nothing ------------------


@pytest.mark.parametrize(
    "call",
    [
        lambda b: b.reserve("m", 1, 1),
        lambda b: b.reserve_sandbox_run(),
        lambda b: b.halt("x"),
        lambda b: b.book_sandbox_cost(0.1),
        lambda b: b.check_not_halted(),
        lambda b: b.snapshot(),
    ],
)
def test_a_ledger_that_cannot_be_read_or_written_refuses_without_the_os_text(tmp_path, call):
    (tmp_path / "ledger.json").unlink()
    (
        tmp_path / "ledger.json"
    ).mkdir()  # a directory where the ledger file should be: every read and write fails
    b = make_budget(tmp_path)
    with pytest.raises(BudgetExceeded, match="could not be read or written") as err:
        call(b)
    assert str(tmp_path) not in str(err.value)  # the type name only, never the path


def test_a_failed_ledger_write_refuses_and_keeps_the_old_ledger(tmp_path, monkeypatch):
    before = (tmp_path / "ledger.json").read_text()

    def full_disk(src, dst):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(os, "replace", full_disk)
    b = make_budget(tmp_path)
    with pytest.raises(BudgetExceeded, match="could not be read or written"):
        b.halt("x")
    assert (tmp_path / "ledger.json").read_text() == before


@pytest.mark.parametrize("step", ["fsync", "link"])
def test_create_ledger_failing_write_leaves_no_partial_file(tmp_path, monkeypatch, step):
    def full_disk(*args, **kwargs):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(os, step, full_disk)
    target = tmp_path / "new" / "ledger.json"
    with pytest.raises(BudgetExceeded, match="could not be read or written"):
        create_ledger(target)
    assert not target.exists()
    assert [p.name for p in (tmp_path / "new").iterdir()] == ["ledger.lock"]  # no temp file left behind


def test_create_ledger_link_refusal_says_already_exists(tmp_path, monkeypatch):
    def taken(src, dst):
        raise FileExistsError(errno.EEXIST, "File exists")

    monkeypatch.setattr(os, "link", taken)
    target = tmp_path / "new" / "ledger.json"
    with pytest.raises(BudgetExceeded, match="already exists"):
        create_ledger(target)
    assert [p.name for p in (tmp_path / "new").iterdir()] == ["ledger.lock"]


def test_a_non_utf8_ledger_is_refused_as_not_valid_json(tmp_path):
    (tmp_path / "ledger.json").write_bytes(
        b"\xff\xfe"
    )  # not text, so the decode fails before any JSON is read
    b = make_budget(tmp_path)
    with pytest.raises(BudgetExceeded, match="not valid JSON") as err:
        b.snapshot()
    assert "codec" not in str(err.value)  # no decode detail leaves
    with pytest.raises(BudgetExceeded, match="not valid JSON"):
        b.reserve("m", 1, 1)


# --- T45 review: a lost ledger is not silently replaced; a missing halted key is corrupt; 402 from the LLM ---------


def _lost_ledger_dir(tmp_path):
    """A directory where a ledger was created, then lost: the ledger file is gone and its lock file is left behind.
    The module's autouse ledger lives in tmp_path itself, so these tests use a subdirectory."""
    lost = tmp_path / "lost"
    create_ledger(lost / "ledger.json")
    (lost / "ledger.json").unlink()
    assert (lost / "ledger.lock").exists()
    return lost


def test_create_ledger_refuses_a_stale_lock_and_writes_nothing(tmp_path):
    lost = _lost_ledger_dir(tmp_path)
    with pytest.raises(BudgetExceeded, match="stale lock file") as err:
        create_ledger(lost / "ledger.json")
    assert not (lost / "ledger.json").exists()
    assert str(tmp_path) not in str(err.value)  # kind names only, no path


def test_create_ledger_refuses_a_backup_sibling_and_keeps_it(tmp_path):
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    (fresh / "ledger.json.bak").write_text("old spend")
    with pytest.raises(BudgetExceeded, match=r"backup file \(\*\.bak\)") as err:
        create_ledger(fresh / "ledger.json")
    assert not (fresh / "ledger.json").exists()
    assert (fresh / "ledger.json.bak").read_text() == "old spend"
    assert "ledger.json.bak" not in str(err.value)  # kind names only, never file names


def test_create_ledger_names_both_kinds_when_both_siblings_exist(tmp_path):
    lost = _lost_ledger_dir(tmp_path)
    (lost / "ledger.json.bak").write_text("old")
    with pytest.raises(BudgetExceeded, match="stale lock file and a backup file"):
        create_ledger(lost / "ledger.json")


def test_force_fresh_creates_past_lost_ledger_siblings_and_keeps_them(tmp_path):
    lost = _lost_ledger_dir(tmp_path)
    (lost / "ledger.json.bak").write_text("old")
    create_ledger(lost / "ledger.json", force_fresh=True)
    assert json.loads((lost / "ledger.json").read_text())["total_usd"] == 0.0
    assert (lost / "ledger.json.bak").read_text() == "old"


def test_force_fresh_never_overwrites_an_existing_ledger(tmp_path):
    write_ledger(tmp_path, total_usd=0.5, halted="kept")
    before = (tmp_path / "ledger.json").read_text()
    with pytest.raises(BudgetExceeded, match="already exists"):
        create_ledger(tmp_path / "ledger.json", force_fresh=True)
    assert (tmp_path / "ledger.json").read_text() == before


def test_init_ledger_from_env_refuses_lost_siblings_until_force_fresh(tmp_path, monkeypatch):
    target = tmp_path / "env" / "ledger.json"
    target.parent.mkdir()
    (target.parent / "ledger.json.bak").write_text("old")
    monkeypatch.setenv("SPEND_LEDGER", str(target))
    with pytest.raises(BudgetExceeded, match="backup file"):
        init_ledger_from_env()
    assert not target.exists()
    assert init_ledger_from_env(force_fresh=True) == target


def test_a_ledger_without_a_halted_key_is_refused_not_read_as_running(tmp_path):
    state = {
        "total_usd": 0.0,
        "days": {},
        "sandbox_runs": 0,
    }  # no halted key: a corrupt ledger, not a running one
    (tmp_path / "ledger.json").write_text(json.dumps(state))
    b = make_budget(tmp_path)
    with pytest.raises(BudgetExceeded, match="halted"):
        b.snapshot()
    with pytest.raises(BudgetExceeded, match="halted"):
        b.check_not_halted()
    with pytest.raises(BudgetExceeded, match="halted"):
        b.reserve("m", 1, 1)
    with pytest.raises(BudgetExceeded, match="halted"):
        b.reserve_sandbox_run()
    assert json.loads((tmp_path / "ledger.json").read_text()) == state  # nothing written


def test_http_402_from_the_llm_is_a_fixed_message_with_no_sdk_text(tmp_path):
    b = make_budget(tmp_path, total=10, daily=10)
    req = httpx.Request("POST", "https://example.invalid/v1/chat/completions")
    err = openai.APIStatusError(
        f"balance gone {FAKE_LLM_SECRET}",
        response=httpx.Response(402, request=req),
        body={"key": FAKE_LLM_SECRET},
    )
    llm = GuardedLLM(b, client=fake_client(FakeCompletions(error=err)))
    with pytest.raises(BudgetExceeded) as raised:
        llm.chat("m", [{"role": "user", "content": "hi"}], max_tokens=10)
    assert str(raised.value) == "HTTP 402 from Token Factory; the budget is halted"
    assert raised.value.__context__ is None and raised.value.__cause__ is None
    assert FAKE_LLM_SECRET not in repr(raised.value)
    assert "402" in b.snapshot()["halted"]


def test_http_402_the_ledger_cannot_halt_gives_a_fixed_message(tmp_path, monkeypatch):
    b = make_budget(tmp_path, total=10, daily=10)
    req = httpx.Request("POST", "https://example.invalid/v1/chat/completions")
    err = openai.APIStatusError("gone", response=httpx.Response(402, request=req), body=None)
    llm = GuardedLLM(b, client=fake_client(FakeCompletions(error=err)))

    def refused_halt(self, reason):
        raise BudgetExceeded("ledger gone")

    monkeypatch.setattr(Budget, "halt", refused_halt)
    with pytest.raises(BudgetExceeded) as raised:
        llm.chat("m", [{"role": "user", "content": "hi"}], max_tokens=10)
    assert str(raised.value) == "HTTP 402 from Token Factory; ledger could not be halted"
    assert raised.value.__context__ is None and raised.value.__cause__ is None


def test_a_non_402_llm_error_still_raises_the_sdk_error(tmp_path):
    b = make_budget(tmp_path, total=10, daily=10)
    llm = GuardedLLM(b, client=fake_client(FakeCompletions(error=status_error(500))))
    with pytest.raises(openai.APIStatusError):
        llm.chat("m", [{"role": "user", "content": "hi"}], max_tokens=10)
    assert b.snapshot()["halted"] is None  # a 5xx halts nothing
