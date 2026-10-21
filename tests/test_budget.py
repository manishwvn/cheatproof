import json
import math
import os
from datetime import date
from types import SimpleNamespace

import httpx
import openai
import pytest

from cheatproof.budget import MAX_TOTAL_CAP_USD, Budget, BudgetExceeded, Hold, Price
from cheatproof.llm import GuardedLLM

PRICE = Price(input_per_m=1.0, output_per_m=2.0)
OLD_MTIME_NS = 1_000_000_000 * 10**9  # 2001, far from now, so any rewrite of the file shows as a change
TODAY = date.today().isoformat()


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
    # The trial cap is lifted here: a $3 hold would otherwise hit the $0.74 trial cap, and this test is about price.
    b = Budget(tmp_path / "ledger.json", 20, 20, 2, trial_credit_cap_usd=20)
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
        "TRIAL_CREDIT_CAP_USD": "0.74",
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


def test_snapshot_creates_nothing_when_no_ledger_exists(tmp_path):
    b = Budget(tmp_path / "missing" / "ledger.json", 1.0, 1.0, 1)
    assert b.snapshot() == {"total_usd": 0.0, "days": {}, "sandbox_runs": 0, "halted": None}
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


def make_capped(tmp_path, sandbox_cost=0.5, trial=0.74, total=20, daily=20):
    return Budget(
        tmp_path / "ledger.json",
        total,
        daily,
        250,
        prices={"m": PRICE},
        sandbox_cost_cap_usd=sandbox_cost,
        trial_credit_cap_usd=trial,
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


def test_a_free_sandbox_result_writes_no_ledger(tmp_path):
    b = make_capped(tmp_path)
    b.book_sandbox_cost(0)
    assert not (tmp_path / "ledger.json").exists()


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


def test_trial_and_sandbox_cost_caps_default_when_unset(cap_env, monkeypatch):
    monkeypatch.delenv("TRIAL_CREDIT_CAP_USD")
    monkeypatch.delenv("SANDBOX_COST_CAP_USD")
    b = Budget.from_env()
    assert b.trial_credit_cap_usd == pytest.approx(0.74)
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
