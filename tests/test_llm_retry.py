"""T56: GuardedLLM retries transient Token Factory failures, at most twice, and every attempt goes through the budget.
Fake clients and an injected sleep only: no model, no network, no real wait."""

from types import SimpleNamespace

import httpx
import openai
import pytest

from rewardseal import llm as llm_module
from rewardseal.attacker import _failed_tokens
from rewardseal.budget import Budget, BudgetExceeded, Price, create_ledger
from rewardseal.llm import MAX_RETRIES, GuardedLLM

pytestmark = pytest.mark.usefixtures("init_ledger")

SECRET = "FAKE-RETRY-SECRET-do-not-print"
MESSAGES = [{"role": "user", "content": "hi"}]
REQ = httpx.Request("POST", "https://example.invalid/v1/chat/completions")


def status(code, cls=openai.APIStatusError):
    return cls(f"err {SECRET}", response=httpx.Response(code, request=REQ), body={"k": SECRET})


def unavailable():
    return status(503, openai.InternalServerError)


def ok(usage=(100, 50)):
    return SimpleNamespace(usage=SimpleNamespace(prompt_tokens=usage[0], completion_tokens=usage[1]))


class Script:
    """chat.completions.create answers from a list: an exception is raised, anything else is returned."""

    def __init__(self, *steps, on_call=None):
        self.steps, self.calls, self.on_call = list(steps), 0, on_call

    def create(self, **kwargs):
        self.calls += 1
        if self.on_call:
            self.on_call(self.calls)
        step = self.steps.pop(0)
        if isinstance(step, BaseException):
            raise step
        return step


def make_budget(tmp_path, total=1.0):
    return Budget(
        tmp_path / "ledger.json", total, total, 2, prices={"m": Price(1.0, 2.0)}, sandbox_run_usd=0.01
    )


def make(tmp_path, script, *, total=1.0, **kwargs):
    budget = make_budget(tmp_path, total)
    sleeps: list[float] = []
    client = SimpleNamespace(chat=SimpleNamespace(completions=script))
    llm = GuardedLLM(budget, client=client, sleep=sleeps.append, rand=lambda: 0.0, **kwargs)
    return budget, llm, sleeps


def count_reserves(monkeypatch):
    seen: list[int] = []
    real = Budget.reserve

    def spy(self, model, input_tokens, max_output_tokens):
        seen.append(max_output_tokens)
        return real(self, model, input_tokens, max_output_tokens)

    monkeypatch.setattr(Budget, "reserve", spy)
    return seen


def one_hold_usd(max_tokens=100):
    est_in = llm_module.estimate_tokens(MESSAGES)
    return (est_in * 1.0 + max_tokens * 2.0) / 1_000_000


def test_503_503_ok_succeeds_after_two_retries_with_three_reservations(tmp_path, monkeypatch, capsys):
    script = Script(unavailable(), unavailable(), ok())
    budget, llm, sleeps = make(tmp_path, script)
    reserves = count_reserves(monkeypatch)
    resp = llm.chat("m", MESSAGES, max_tokens=100)
    assert resp.usage.prompt_tokens == 100
    assert script.calls == 3 and llm.retries == 2 and len(reserves) == 3
    assert sleeps == [2.0, 6.0]
    # The two failed 5xx calls keep their worst case; the good one settles to the real usage (100 in, 50 out).
    assert budget.snapshot()["total_usd"] == pytest.approx(2 * one_hold_usd() + 200 / 1_000_000)
    err = capsys.readouterr().err
    assert "InternalServerError" in err and "1/2" in err and "2/2" in err
    assert SECRET not in err and "hi" not in err.replace("InternalServerError", "")


def test_503_three_times_stops_after_two_retries_and_raises_the_last_error(tmp_path, monkeypatch):
    script = Script(unavailable(), unavailable(), unavailable())
    budget, llm, sleeps = make(tmp_path, script)
    reserves = count_reserves(monkeypatch)
    with pytest.raises(openai.InternalServerError):
        llm.chat("m", MESSAGES, max_tokens=100)
    assert script.calls == 3 and llm.retries == 2 and len(reserves) == 3 and len(sleeps) == 2
    assert budget.snapshot()["halted"] is None
    assert budget.snapshot()["total_usd"] == pytest.approx(3 * one_hold_usd())  # nothing refunded


def test_the_error_after_the_last_failed_attempt_is_tagged_and_stderr_has_no_sdk_text(tmp_path, capsys):
    script = Script(unavailable(), unavailable(), unavailable())
    _, llm, _ = make(tmp_path, script)
    with pytest.raises(openai.InternalServerError) as raised:
        llm.chat("m", MESSAGES, max_tokens=100)
    assert raised.value.llm_retries == 2 and raised.value.llm_failed == 3
    err = capsys.readouterr().err
    assert SECRET not in err and "err " not in err and "example.invalid" not in err
    assert err.count("llm retry") == 2


def test_chat_counted_returns_the_retries_of_that_call_only(tmp_path):
    script = Script(unavailable(), unavailable(), ok(), ok())
    _, llm, _ = make(tmp_path, script)
    assert llm.chat_counted("m", MESSAGES, max_tokens=10)[1] == 2
    assert llm.chat_counted("m", MESSAGES, max_tokens=10)[1] == 0  # not a running total
    assert llm.retries == 2


def test_errors_that_are_not_retried_are_tagged_with_what_was_retried_before(tmp_path):
    script = Script(unavailable(), status(402))
    _, llm, _ = make(tmp_path, script)
    with pytest.raises(BudgetExceeded) as raised:
        llm.chat("m", MESSAGES, max_tokens=10)
    assert raised.value.llm_retries == 1 and raised.value.llm_failed == 1
    other = tmp_path / "other"  # the first call halted this ledger, so the 401 gets a new one
    other.mkdir()
    create_ledger(other / "ledger.json")
    script = Script(status(401))
    _, llm, _ = make(other, script)
    with pytest.raises(openai.APIStatusError) as raised:
        llm.chat("m", MESSAGES, max_tokens=10)
    assert raised.value.llm_retries == 0 and raised.value.llm_failed == 0


def test_the_wall_clock_cap_stops_a_retry_that_could_not_finish_in_time(tmp_path):
    assert (
        3 * llm_module.REQUEST_TIMEOUT_S + 10 <= llm_module.CHAT_WALL_CAP_S
    )  # the documented worst case fits
    now = [0.0]
    script = Script(unavailable(), ok(), on_call=lambda n: now.__setitem__(0, now[0] + 300.0))
    budget = make_budget(tmp_path)
    sleeps: list[float] = []
    client = SimpleNamespace(chat=SimpleNamespace(completions=script))
    llm = GuardedLLM(budget, client=client, sleep=sleeps.append, rand=lambda: 0.0, clock=lambda: now[0])
    with pytest.raises(openai.InternalServerError) as raised:
        llm.chat("m", MESSAGES, max_tokens=10)
    # 300 s gone, plus the 2 s wait, plus a full 120 s request would pass 400 s: no retry is started.
    assert (
        script.calls == 1 and sleeps == [] and raised.value.llm_retries == 0 and raised.value.llm_failed == 1
    )


def test_a_retry_that_fits_the_wall_clock_cap_runs(tmp_path):
    now = [0.0]
    script = Script(unavailable(), ok(), on_call=lambda n: now.__setitem__(0, now[0] + 100.0))
    budget = make_budget(tmp_path)
    client = SimpleNamespace(chat=SimpleNamespace(completions=script))
    llm = GuardedLLM(budget, client=client, sleep=lambda s: None, rand=lambda: 0.0, clock=lambda: now[0])
    llm.chat("m", MESSAGES, max_tokens=10)
    assert script.calls == 2


@pytest.mark.parametrize("code", [500, 502, 503, 504])
def test_each_retried_status_gets_a_second_try(tmp_path, code):
    script = Script(status(code), ok())
    _, llm, sleeps = make(tmp_path, script)
    llm.chat("m", MESSAGES, max_tokens=10)
    assert script.calls == 2 and llm.retries == 1 and sleeps == [2.0]


@pytest.mark.parametrize(
    "make_err",
    [lambda: openai.APITimeoutError(request=REQ), lambda: openai.APIConnectionError(request=REQ)],
)
def test_timeouts_and_dropped_connections_are_retried(tmp_path, make_err):
    script = Script(make_err(), ok())
    _, llm, sleeps = make(tmp_path, script)
    llm.chat("m", MESSAGES, max_tokens=10)
    assert script.calls == 2 and llm.retries == 1 and sleeps == [2.0]


def test_402_halts_at_once_with_no_retry(tmp_path):
    script = Script(status(402), ok())
    budget, llm, sleeps = make(tmp_path, script)
    with pytest.raises(BudgetExceeded, match="HTTP 402"):
        llm.chat("m", MESSAGES, max_tokens=10)
    assert script.calls == 1 and llm.retries == 0 and sleeps == []
    assert "402" in budget.snapshot()["halted"]


@pytest.mark.parametrize("code", [400, 401, 403, 404, 422, 429, 501])
def test_other_statuses_are_never_retried(tmp_path, code):
    # 429 on purpose, even with a short Retry-After: a rate limit and an exhausted quota look alike (see llm.py).
    err = status(code)
    err.response.headers["retry-after"] = "1"
    script = Script(err, ok())
    _, llm, sleeps = make(tmp_path, script)
    with pytest.raises(openai.APIStatusError):
        llm.chat("m", MESSAGES, max_tokens=10)
    assert script.calls == 1 and llm.retries == 0 and sleeps == []


def test_a_call_over_the_cap_is_not_made_and_not_retried(tmp_path):
    script = Script(ok())
    _, llm, sleeps = make(tmp_path, script, total=0.000001)
    with pytest.raises(BudgetExceeded):
        llm.chat("m", MESSAGES, max_tokens=10)
    assert script.calls == 0 and llm.retries == 0 and sleeps == []


def test_a_cap_reached_by_the_failed_attempt_stops_the_retry(tmp_path):
    script = Script(unavailable(), ok())
    _, llm, _ = make(tmp_path, script, total=one_hold_usd() * 1.5)  # room for one worst case, not two
    with pytest.raises(BudgetExceeded, match="cap"):
        llm.chat("m", MESSAGES, max_tokens=100)
    assert script.calls == 1  # the second attempt was refused before any request


def test_a_halt_set_while_waiting_stops_the_retry_before_the_wait(tmp_path):
    holder = {}

    def halt_on_first(n):
        if n == 1:
            holder["budget"].halt("halted by another process")

    script = Script(unavailable(), ok(), on_call=halt_on_first)
    budget, llm, sleeps = make(tmp_path, script)
    holder["budget"] = budget
    with pytest.raises(BudgetExceeded, match="halted") as raised:
        llm.chat("m", MESSAGES, max_tokens=10)
    assert script.calls == 1 and sleeps == [] and raised.value.__context__ is None


@pytest.mark.parametrize("halt_on_call", [1, 2])
def test_a_halt_after_a_failed_attempt_still_tags_that_attempt_as_failed(tmp_path, halt_on_call):
    # The attempt that failed was reserved and kept at its worst case, so the halt error counts it like any other
    # transient failure does: the attacker adds llm_failed attempts to its token totals.
    holder = {}

    def halt(n):
        if n == halt_on_call:
            holder["budget"].halt("halted by another process")

    script = Script(*[unavailable()] * halt_on_call, ok(), on_call=halt)
    budget, llm, sleeps = make(tmp_path, script)
    holder["budget"] = budget
    with pytest.raises(BudgetExceeded, match="halted") as raised:
        llm.chat("m", MESSAGES, max_tokens=10)
    assert script.calls == halt_on_call and sleeps == [2.0, 6.0][: halt_on_call - 1]
    assert raised.value.llm_retries == halt_on_call - 1 and raised.value.llm_failed == halt_on_call
    assert _failed_tokens(raised.value, 7, 3) == (halt_on_call * 7, halt_on_call * 3)
    # The money did not change: one worst-case hold per attempt, nothing refunded, nothing added.
    assert budget.snapshot()["total_usd"] == pytest.approx(halt_on_call * one_hold_usd(10))


def test_the_retry_limit_can_only_be_lowered(tmp_path):
    assert MAX_RETRIES == 2
    assert make(tmp_path, Script(), max_retries=10)[1].max_retries == 2
    script = Script(unavailable(), ok())
    _, llm, _ = make(tmp_path, script, max_retries=0)
    with pytest.raises(openai.InternalServerError):
        llm.chat("m", MESSAGES, max_tokens=10)
    assert script.calls == 1


def test_jitter_is_bounded(tmp_path):
    script = Script(unavailable(), unavailable(), ok())
    sleeps: list[float] = []
    client = SimpleNamespace(chat=SimpleNamespace(completions=script))
    llm = GuardedLLM(make_budget(tmp_path), client=client, sleep=sleeps.append, rand=lambda: 99.0)
    llm.chat("m", MESSAGES, max_tokens=10)
    assert sleeps == [3.0, 7.0]


def test_the_attack_summary_carries_llm_retries():
    from rewardseal.attacker import AttackResult
    from rewardseal.harden import _attack_summary

    def result(**kwargs):
        return AttackResult(True, "submit", [], 0, 0, "", **kwargs)

    assert _attack_summary(result(llm_retries=2))["llm_retries"] == 2
    assert _attack_summary(result())["llm_retries"] == 0
