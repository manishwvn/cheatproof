from types import SimpleNamespace

import httpx
import openai
import pytest

from cheatproof.budget import Budget, BudgetExceeded, Price
from cheatproof.llm import GuardedLLM

PRICE = Price(input_per_m=1.0, output_per_m=2.0)


def make_budget(tmp_path, total=1.0, daily=1.0, runs=2, run_usd=0.0):
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
    llm = GuardedLLM(make_budget(tmp_path, total=0.0), client=fake_client(completions))
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


def test_default_total_cap_is_the_one_documented_number(monkeypatch, tmp_path):
    monkeypatch.setenv("SPEND_LEDGER", str(tmp_path / "ledger.json"))
    monkeypatch.delenv("SPEND_CAP_USD", raising=False)
    assert Budget.from_env().total_cap_usd == 20.0
