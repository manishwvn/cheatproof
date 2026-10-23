"""sandbox_access.check_access with fakes only: no SDK network call, no .env read, no budget file."""

import importlib.util
from pathlib import Path

import pytest
from contree_sdk.sdk.exceptions import ApiStatusCodeError, ForbiddenError

from cheatproof.budget import Budget, BudgetExceeded, create_ledger

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "sandbox_access.py"
spec = importlib.util.spec_from_file_location("sandbox_access", SCRIPT)
sandbox_access = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sandbox_access)

FAKE_SECRET = "FAKE-SECRET-7f3a91-do-not-print"


class TransientError(Exception):
    """Stands in for a network hiccup. Its class name is what the script prints."""


class Probe:
    """Scripted outcomes for successive runs. A str is stdout; an exception is raised; the last one repeats."""

    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.runs = 0

    def next(self):
        self.runs += 1
        return self.outcomes.pop(0) if len(self.outcomes) > 1 else self.outcomes[0]


class FakeContreeResult:
    """Mirrors contree_sdk ContreeResult: `cost` lives here, on `.result`, not on the finished image."""

    def __init__(self, stdout, cost=0.0):
        self.stdout = stdout
        self.cost = cost


class FakeDone:
    """Mirrors the finished image `run(...).wait()` returns: `.result` holds the ContreeResult, `.stdout` proxies it."""

    def __init__(self, result):
        self.result = result

    @property
    def stdout(self):
        return self.result.stdout


class FakeImage:
    def __init__(self, probe):
        self.probe = probe
        self.stdout = None

    def run(self, command, *, args, disposable, timeout):
        assert command == "python"
        assert args == ["-c", "print('ok')"]
        assert disposable is True
        assert timeout == sandbox_access.RUN_TIMEOUT_S
        return self

    def wait(self):
        outcome = self.probe.next()
        if isinstance(outcome, BaseException):
            raise outcome
        if isinstance(outcome, FakeContreeResult):
            return FakeDone(outcome)
        return FakeDone(FakeContreeResult(outcome))


class FakeImages:
    def __init__(self, probe):
        self.probe = probe

    def use(self, ref):
        assert ref == "python:3.12-slim"
        return FakeImage(self.probe)


class FakeClient:
    def __init__(self, probe):
        self.images = FakeImages(probe)


class FakeBudget:
    def __init__(self, cap=None, halt_error=None):
        self.reserved = 0
        self.cap = cap
        self.halts = []
        self.costs = []
        self.halt_error = halt_error

    def reserve_sandbox_run(self):
        if self.cap is not None and self.reserved >= self.cap:
            raise BudgetExceeded("sandbox run cap reached")
        self.reserved += 1

    def book_sandbox_cost(self, usd):  # the real Budget logs and caps it; this fake only records it
        self.costs.append(usd)

    def check_not_halted(self):  # the real Budget reads the ledger; this fake reads its own halt list
        if self.halts:
            raise BudgetExceeded(f"budget halted: {self.halts[-1]}")

    def halt(self, reason):
        if self.halt_error is not None:
            raise self.halt_error
        self.halts.append(reason)


def run_check(outcomes, budget=None):
    probe = Probe(*outcomes)
    sleeps = []
    budget = budget or FakeBudget()
    code = sandbox_access.check_access(lambda: FakeClient(probe), budget, sleep=sleeps.append)
    return code, probe, sleeps, budget


def test_success_first_try(capsys):
    code, probe, sleeps, budget = run_check(["ok\n"])
    assert code == 0
    assert capsys.readouterr().out == "ACCESS OK\n"
    assert probe.runs == 1
    assert sleeps == []
    assert budget.reserved == 1


def test_success_after_two_transient_failures(capsys):
    code, probe, sleeps, budget = run_check([TransientError(), TransientError(), "ok\n"])
    assert code == 0
    assert capsys.readouterr().out == "ACCESS OK\n"
    assert probe.runs == 3
    assert sleeps == [2, 4]
    assert budget.reserved == 1  # one reservation per invocation, not per try


def test_auth_failure_exit_2_without_retry(capsys):
    code, probe, sleeps, _ = run_check([ForbiddenError(error="denied")])
    assert code == 2
    assert capsys.readouterr().out == "NO ACCESS (ForbiddenError 403)\n"
    assert probe.runs == 1
    assert sleeps == []


def test_401_status_exit_2(capsys):
    code, _, sleeps, _ = run_check([ApiStatusCodeError(status=401, error="bad token")])
    assert code == 2
    assert capsys.readouterr().out == "NO ACCESS (ApiStatusCodeError 401)\n"
    assert sleeps == []


def test_persistent_failure_exit_1_after_five_tries(capsys):
    code, probe, sleeps, budget = run_check([TransientError()])
    assert code == 1
    assert capsys.readouterr().out == "ERROR TransientError\n"
    assert probe.runs == 5
    assert sleeps == [2, 4, 8, 16]
    assert budget.reserved == 1


def test_stdout_without_ok_is_error(capsys):
    code, probe, _, _ = run_check(["nope\n"])
    assert code == 1
    assert capsys.readouterr().out == "ERROR UnexpectedOutput\n"
    assert probe.runs == 5


def test_budget_exceeded_stops_without_retry(capsys):
    code, probe, sleeps, _ = run_check([TransientError()], budget=FakeBudget(cap=0))
    assert code == 1
    assert capsys.readouterr().out == "ERROR BudgetExceeded\n"
    assert probe.runs == 0
    assert sleeps == []


@pytest.mark.parametrize(
    "outcomes",
    [
        [RuntimeError(f"token {FAKE_SECRET} rejected at https://example.invalid/?key={FAKE_SECRET}")],
        [ForbiddenError(error=FAKE_SECRET)],
        [ApiStatusCodeError(status=500, error=FAKE_SECRET), "ok\n"],
    ],
)
def test_output_never_contains_secret(capsys, outcomes):
    run_check(outcomes)
    captured = capsys.readouterr()
    assert FAKE_SECRET not in captured.out
    assert FAKE_SECRET not in captured.err


def test_one_reservation_covers_all_tries_even_at_cap_one(capsys):
    code, probe, _, budget = run_check([TransientError()], budget=FakeBudget(cap=1))
    assert code == 1
    assert capsys.readouterr().out == "ERROR TransientError\n"
    assert probe.runs == 5
    assert budget.reserved == 1


def test_402_halts_budget_without_retry(capsys):
    code, probe, sleeps, budget = run_check([ApiStatusCodeError(status=402, error="payment required")])
    assert code == 1
    assert capsys.readouterr().out == "ERROR budget halted (402)\n"
    assert probe.runs == 1
    assert sleeps == []
    assert len(budget.halts) == 1


def real_budget(tmp_path):
    create_ledger(tmp_path / "ledger.json")  # a ledger exists only once created, as `budget init` does
    return Budget(tmp_path / "ledger.json", 20.0, 20.0, 250, sandbox_cost_cap_usd=0.5)


@pytest.mark.parametrize("cost", [0.0004, 0.5])
def test_a_cost_under_the_cap_is_logged_and_access_is_ok(capsys, tmp_path, cost):
    # The SDK reports the cost on done.result.cost. The finished image has no cost of its own, so this must read .result.
    budget = real_budget(tmp_path)
    code, probe, sleeps, _ = run_check([FakeContreeResult("ok\n", cost=cost)], budget=budget)
    assert code == 0
    assert capsys.readouterr().out == "ACCESS OK\n"
    snap = budget.snapshot()
    assert snap["sandbox_cost_usd"] == pytest.approx(cost)
    assert snap["halted"] is None
    assert probe.runs == 1 and sleeps == []


@pytest.mark.parametrize("cost", [0.6, 1, 2.5])
def test_a_cost_over_the_cap_halts_the_budget_without_retry(capsys, tmp_path, cost):
    budget = real_budget(tmp_path)
    code, probe, sleeps, _ = run_check([FakeContreeResult("ok\n", cost=cost)], budget=budget)
    assert code == 1
    assert capsys.readouterr().out == "ERROR budget halted (cost)\n"
    assert probe.runs == 1
    assert sleeps == []
    assert "Sandboxes cost" in budget.snapshot()["halted"]


def test_a_malformed_cost_halts_the_budget_without_retry(capsys, tmp_path):
    budget = real_budget(tmp_path)
    code, probe, sleeps, _ = run_check([FakeContreeResult("ok\n", cost=float("nan"))], budget=budget)
    assert code == 1
    assert capsys.readouterr().out == "ERROR budget halted (cost)\n"
    assert probe.runs == 1 and sleeps == []
    assert budget.snapshot()["halted"]


def test_zero_cost_run_is_access_ok_and_logs_nothing(capsys):
    code, _, _, budget = run_check([FakeContreeResult("ok\n", cost=0)])
    assert code == 0
    assert capsys.readouterr().out == "ACCESS OK\n"
    assert budget.costs == [0]


def test_halt_that_cannot_be_written_is_reported_by_class(capsys):
    budget = FakeBudget(halt_error=BudgetExceeded("ledger is not valid JSON"))
    code, _, _, _ = run_check([ApiStatusCodeError(status=402, error="payment required")], budget=budget)
    assert code == 1
    assert capsys.readouterr().out == "ERROR BudgetExceeded\n"
