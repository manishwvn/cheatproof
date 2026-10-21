"""sandbox_access.check_access with fakes only: no SDK network call, no .env read, no budget file."""

import importlib.util
from pathlib import Path

import pytest
from contree_sdk.sdk.exceptions import ApiStatusCodeError, ForbiddenError

from cheatproof.budget import BudgetExceeded

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


class FakeResult:
    def __init__(self, stdout):
        self.stdout = stdout


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
        return FakeResult(outcome)


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
    def __init__(self, cap=None):
        self.reserved = 0
        self.cap = cap

    def reserve_sandbox_run(self):
        if self.cap is not None and self.reserved >= self.cap:
            raise BudgetExceeded("sandbox run cap reached")
        self.reserved += 1


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
    assert budget.reserved == 3


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
    assert budget.reserved == 5


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
