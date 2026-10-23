"""SandboxExecutor / SandboxSession against a fake contree client. No network, no real SDK calls.

VERIFY: the fake mirrors contree_sdk 0.3.6 as read from the installed source (images.use / images.oci,
image.run(...).wait(), image.result with exit_code/stdout/stderr/truncated). No recorded real response confirms it yet.
"""

import itertools
import os
import shlex
import shutil
import subprocess
import sys
import traceback
from types import SimpleNamespace
from uuid import uuid4

import pytest
from contree_sdk.sdk.exceptions import (
    ApiStatusCodeError,
    FailedOperationError,
    NotFoundError,
    OperationTimedOutError,
)
from contree_sdk.sdk.exceptions.api import RequestInfo, ResponseInfo

from cheatproof.budget import Budget, BudgetExceeded, create_ledger
from cheatproof.executor import (
    _BASELINE_SCRIPT,
    _DIFF_SCRIPT,
    _NETCUT_PROBE,
    _UNSTAGE_SCRIPT,
    EXEC_GRACE_S,
    IO_TIMEOUT_S,
    MAX_DIFF_BYTES,
    MAX_OUTPUT_BYTES,
    MAX_RUN_TIMEOUT_S,
    TIMEOUT_EXIT_CODE,
    DockerExecutor,
    EnvSpec,
    ExecutorRefused,
    ExecutorUnavailable,
    SandboxExecutor,
    SandboxSession,
    make_executor,
    start,
)

ENV = EnvSpec(image="python:3.12-slim")
TASK_ENV = EnvSpec(image="swebench/sweb.eval.x86_64.django_1776_django-11099:latest")
FETCH_ENV = EnvSpec(image="python:3.12-slim", network=True)
BASE_SHA = "0123456789abcdef0123456789abcdef01234567"
UNSHARE = "/usr/bin/unshare"
LIBC = "/lib/x86_64-linux-gnu/libc.so.6"
LOADER = "/lib64/ld-linux-x86-64.so.2"
CACHE = "/etc/ld.so.cache"
PRELOAD = "/etc/ld.so.preload"
WRAP = [UNSHARE, "-rn"]
FAKE_SECRET = "FAKE-SECRET-7f3a91-do-not-print"


class FakeBudget:
    def __init__(self, fail_after=None):
        self.sandbox_runs = 0
        self.fail_after = fail_after
        self.halted = None
        self.sandbox_costs = []

    def reserve_sandbox_run(self):
        if self.fail_after is not None and self.sandbox_runs >= self.fail_after:
            raise BudgetExceeded("sandbox run cap reached")
        self.sandbox_runs += 1

    def reserve_local_run(self):  # a sandbox session must never take a local run
        raise AssertionError("sandbox session reserved a local run")

    def book_sandbox_cost(self, usd):  # the real Budget logs and caps the cost; this fake only records it
        self.sandbox_costs.append(usd)

    def check_not_halted(self):  # the real Budget reads the ledger; this fake reads its own halt flag
        if self.halted:
            raise BudgetExceeded(f"budget halted: {self.halted}")

    def halt(self, reason):
        self.halted = reason


class FakeSandbox:
    """Stands in for ContreeSync. calls holds one SimpleNamespace per image.run(...).wait()."""

    def __init__(self):
        self.calls = []
        self.images = SimpleNamespace(use=self._use, oci=self._oci)
        self.resolved = []  # (method, name)
        self.resolve_error = None  # exception raised by images.use / images.oci
        self.probe_exit = 0  # exit code of the network-cut probe, whatever the unshare flag
        self.locate_exit = 0  # exit code of the script that finds unshare and its libraries
        self.locate_out = f"{UNSHARE}\n{LIBC}\n{LOADER}\n".encode()
        self.user = lambda argv: (0, b"ok\n", b"", False)  # answer to an attacker command
        self.diff_out = (0, b"diff --git a/f b/f\n", b"", False)
        self.untracked = b""
        self.raise_on = None  # callable(argv) -> exception or None
        self.tweak = None  # callable(argv, done): edit the finished image or its result before it is returned
        self.cost = 0.0  # cost every result reports
        # Files the host can read over the SDK. /etc/ld.so.preload is absent, as on a plain image.
        self.files = {UNSHARE: b"unshare-elf", LIBC: b"libc", LOADER: b"ld.so", CACHE: b"cache"}
        self.edits = {}  # (image uuid, path) -> bytes: a file an attacker command changed in that image
        self.reads = []  # (image uuid, path)
        self._ids = itertools.count(1)
        self.base = FakeImage(self, "base")

    def _use(self, name):
        self.resolved.append(("use", name))
        if self.resolve_error is not None:
            raise self.resolve_error
        return self.base

    def _oci(self, name):
        self.resolved.append(("oci", name))
        if self.resolve_error is not None:
            raise self.resolve_error
        return self.base

    def answer(self, argv):
        text = " ".join(argv)
        if "/proc/net/dev" in text:
            return self.probe_exit, b"", b"", False
        if "readlink -f" in text:
            return self.locate_exit, self.locate_out, b"", False
        if "rev-parse HEAD" in text:
            return 0, BASE_SHA.encode() + b"\n", b"", False
        if "ls-files --others" in text:
            return 0, self.untracked, b"", False
        if "read-tree" in text:
            return self.diff_out
        if "cat >" in text:
            return 0, b"", b"", False
        return self.user(argv)

    @property
    def execs(self):
        """Attacker commands only: the `sh -lc` calls (with or without an unshare prefix)."""
        return [c for c in self.calls if "-lc" in c.argv]


class FakeImage:
    def __init__(self, sandbox, uuid):
        self.sandbox = sandbox
        self.uuid = uuid

    def run(self, command, *, args=(), cwd=None, stdin=None, stdout=None, stderr=None, timeout=None, **kw):
        assert stdout is bytes and stderr is bytes  # the executor decodes itself
        call = SimpleNamespace(
            image=self.uuid,
            argv=[command, *args],
            cwd=cwd,
            stdin=stdin,
            timeout=timeout,
            disposable=kw["disposable"],
            cap=kw["truncate_output_at"],
        )
        return _Pending(self, call)

    def read(self, path):
        box = self.sandbox
        box.reads.append((self.uuid, path))
        data = box.edits[(self.uuid, path)] if (self.uuid, path) in box.edits else box.files.get(path)
        if data is None:
            raise NotFoundError()
        return data


class _Pending:
    def __init__(self, image, call):
        self.image, self.call = image, call

    def wait(self):
        box = self.image.sandbox
        box.calls.append(self.call)
        if box.raise_on is not None and (exc := box.raise_on(self.call.argv)) is not None:
            raise exc
        code, out, err, cut = box.answer(self.call.argv)
        new = None if self.call.disposable else f"img{next(box._ids)}"
        done = FakeImage(box, new)
        state = SimpleNamespace(timed_out=False)
        done.result = SimpleNamespace(
            exit_code=code,
            stdout=out,
            stderr=err,
            truncated=cut,
            cost=box.cost,
            _raw=SimpleNamespace(result=SimpleNamespace(state=state)),
        )
        if box.tweak is not None:
            box.tweak(self.call.argv, done)
        return done


def make(env=ENV, box=None, budget=None, **exec_kwargs):
    box = box or FakeSandbox()
    budget = budget or FakeBudget()
    executor = SandboxExecutor(client_factory=lambda: box, **exec_kwargs)
    return box, budget, executor.start(env, budget)


# --- start --------------------------------------------------------------------------------------------


def test_start_books_one_sandbox_run_and_records_baseline():
    box, budget, session = make()
    assert isinstance(session, SandboxSession)
    assert budget.sandbox_runs == 1
    assert box.resolved == [("use", ENV.image)]
    # find unshare, network probe, base commit, untracked list: all disposable, none of them an attacker command
    assert [c.disposable for c in box.calls] == [True, True, True, True]
    assert box.execs == []
    # the wrapper files are pinned from the base image, by the host, over the SDK
    assert {path for image, path in box.reads} == {UNSHARE, LIBC, LOADER, CACHE, PRELOAD}
    assert {image for image, _ in box.reads} == {"base"}


def test_task_images_go_through_oci_import_and_plain_images_through_use():
    box, _, _ = make(TASK_ENV)
    assert box.resolved == [("oci", TASK_ENV.image)]


def test_budget_refusal_stops_before_any_sandbox_call():
    box = FakeSandbox()
    with pytest.raises(BudgetExceeded):
        make(box=box, budget=FakeBudget(fail_after=0))
    assert box.calls == []
    assert box.resolved == []


def test_client_factory_failure_is_unavailable_and_books_nothing():
    budget = FakeBudget()

    def boom():
        raise ValueError("secret-looking detail")

    with pytest.raises(ExecutorUnavailable, match="ValueError") as err:
        SandboxExecutor(client_factory=boom).start(ENV, budget)
    assert "secret-looking" not in str(err.value)
    assert budget.sandbox_runs == 0


def test_missing_sdk_is_unavailable(monkeypatch):
    monkeypatch.setitem(
        sys.modules, "contree_sdk", None
    )  # makes `from contree_sdk import ...` raise ImportError
    budget = FakeBudget()
    with pytest.raises(ExecutorUnavailable, match="contree_sdk is not installed"):
        SandboxExecutor().start(ENV, budget)
    assert budget.sandbox_runs == 0


def test_start_uses_the_executor_it_is_given():
    box = FakeSandbox()
    budget = FakeBudget()
    with start(ENV, budget, executor=SandboxExecutor(client_factory=lambda: box)) as s:
        assert s.run("echo ok", timeout=5).stdout == "ok\n"


# --- exec ---------------------------------------------------------------------------------------------


def test_exec_runs_in_workdir_with_in_sandbox_timeout_and_host_backstop():
    box, _, session = make()
    res = session.run("echo hi", timeout=7.2)
    call = box.execs[-1]
    assert (res.exit_code, res.stdout, res.stderr) == (0, "ok\n", "")
    assert not (res.timed_out or res.truncated or res.reset)
    assert call.cwd == "/testbed"
    assert call.disposable is False  # file changes must reach the next call
    assert call.timeout == 8 + EXEC_GRACE_S
    assert call.argv[-2:] == ["cheatproof", "echo hi"]
    assert "timeout -s KILL 8" in call.argv[-3]


def test_exec_timeout_is_capped_and_validated():
    box, _, session = make()
    session.run("x", timeout=10**9)
    assert box.execs[-1].timeout == MAX_RUN_TIMEOUT_S + EXEC_GRACE_S
    for bad in (0, -1, float("nan")):
        with pytest.raises(ValueError, match="greater than 0"):
            session.run("x", timeout=bad)


def test_exec_nonzero_exit_and_stderr_pass_through():
    box, _, session = make()
    box.user = lambda argv: (3, b"", "böm".encode(), False)
    res = session.run("false", timeout=5)
    assert (res.exit_code, res.stderr) == (3, "böm")


def test_exec_operation_timeout_resets_and_books_another_run():
    box, budget, session = make()
    box.raise_on = lambda argv: (
        OperationTimedOutError(operation_uuid=uuid4()) if argv[-1] == "sleep 99" else None
    )
    session.run("echo one > f", timeout=5)
    res = session.run("sleep 99", timeout=3)
    assert res.exit_code == TIMEOUT_EXIT_CODE
    assert res.timed_out and res.reset
    assert "timed out after 3s" in res.stderr
    assert budget.sandbox_runs == 2
    box.raise_on = None
    session.run("ls", timeout=5)
    assert box.execs[-1].image == "base"  # back on the base image, not on the earlier write's result


def test_exec_budget_refusal_on_timeout_reset_propagates_and_kills_the_session():
    box, _, session = make(budget=FakeBudget(fail_after=1))
    box.raise_on = lambda argv: OperationTimedOutError(operation_uuid=uuid4())
    with pytest.raises(BudgetExceeded):
        session.run("sleep 99", timeout=3)
    box.raise_on = None
    with pytest.raises(RuntimeError, match="no live sandbox"):
        session.run("ls", timeout=5)


def test_exec_sdk_error_names_the_class_and_nothing_else():
    box, _, session = make()
    box.raise_on = lambda argv: FailedOperationError(operation_uuid=uuid4(), error="no capacity")
    with pytest.raises(RuntimeError, match=r"sandbox call failed: FailedOperationError$") as err:
        session.run("x", timeout=5)
    assert "no capacity" not in str(err.value)


def leaky_error(status=503):
    """An SDK error whose repr carries a URL, a header and server text, all with the same fake secret."""
    return ApiStatusCodeError(
        request=RequestInfo(url=f"https://api.example/{FAKE_SECRET}", method="POST"),
        response=ResponseInfo(headers={"authorization": f"Bearer {FAKE_SECRET}"}),
        status=status,
        error=f"upstream said {FAKE_SECRET}",
    )


def assert_no_secret(err):
    shown = [str(err), repr(err), "".join(traceback.format_exception(err))]
    assert all(FAKE_SECRET not in text for text in shown), shown
    assert err.__cause__ is None and err.__suppress_context__


def test_exec_sdk_error_reports_class_and_status_but_never_its_text():
    box, _, session = make()
    box.raise_on = lambda argv: leaky_error(503)
    with pytest.raises(RuntimeError) as err:
        session.run("x", timeout=5)
    assert str(err.value) == "sandbox call failed: ApiStatusCodeError (HTTP 503)"
    assert_no_secret(err.value)


def test_image_resolution_error_never_carries_the_sdk_text():
    box = FakeSandbox()
    box.resolve_error = leaky_error(500)
    with pytest.raises(ExecutorUnavailable) as err:
        make(box=box)
    assert "ApiStatusCodeError (HTTP 500)" in str(err.value)
    assert_no_secret(err.value)


def test_http_402_from_a_call_halts_the_budget_and_stops():
    box, budget, session = make()
    box.raise_on = lambda argv: leaky_error(402)
    with pytest.raises(BudgetExceeded, match="402") as err:
        session.run("x", timeout=5)
    assert budget.halted and "402" in budget.halted
    assert_no_secret(err.value)


def test_http_402_while_resolving_the_image_halts_the_budget():
    box, budget = FakeSandbox(), FakeBudget()
    box.resolve_error = leaky_error(402)
    with pytest.raises(BudgetExceeded) as err:
        make(box=box, budget=budget)
    assert budget.halted and "402" in budget.halted
    assert_no_secret(err.value)


def real_budget(tmp_path):
    # A real ledger, so the Sandboxes cost log, its $0.50 cap and the halt run as they do in production.
    create_ledger(tmp_path / "ledger.json")
    return Budget(tmp_path / "ledger.json", 20.0, 20.0, 250, sandbox_cost_cap_usd=0.5)


def test_sandbox_costs_under_the_cap_are_logged_and_the_run_goes_on(tmp_path):
    budget = real_budget(tmp_path)
    box, _, session = make(budget=budget)
    box.cost = 0.0004
    session.run("x", timeout=5)
    box.cost = 0.0006
    session.run("x", timeout=5)
    snap = budget.snapshot()
    assert snap["sandbox_cost_usd"] == pytest.approx(0.001)
    assert snap["halted"] is None
    assert snap["total_usd"] == 0.0  # Token Factory totals are untouched


def test_summed_sandbox_cost_over_the_cap_halts_the_real_ledger(tmp_path):
    budget = real_budget(tmp_path)
    box, _, session = make(budget=budget)
    box.cost = 0.3
    session.run("x", timeout=5)
    box.cost = 0.3  # the sum is 0.6, above 0.50
    with pytest.raises(BudgetExceeded, match="cost"):
        session.run("x", timeout=5)
    assert "Sandboxes cost" in budget.snapshot()["halted"]


@pytest.mark.parametrize("cost", [1, 0.5001])
def test_one_sandbox_cost_above_the_cap_halts_the_real_ledger(tmp_path, cost):
    budget = real_budget(tmp_path)
    box, _, session = make(budget=budget)
    box.cost = cost
    with pytest.raises(BudgetExceeded, match="cost"):
        session.run("x", timeout=5)
    assert budget.snapshot()["halted"]


@pytest.mark.parametrize("cost", [float("nan"), -1.0, "0", True])
def test_a_malformed_sandbox_cost_halts_the_real_ledger(tmp_path, cost):
    budget = real_budget(tmp_path)
    box, _, session = make(budget=budget)
    box.cost = cost
    with pytest.raises(BudgetExceeded, match="cost"):
        session.run("x", timeout=5)
    assert budget.snapshot()["halted"]


def test_http_402_halts_the_real_ledger_and_a_later_cost_cannot_clear_it(tmp_path):
    budget = real_budget(tmp_path)
    box, _, session = make(budget=budget)
    box.raise_on = lambda argv: leaky_error(402)
    with pytest.raises(BudgetExceeded, match="402"):
        session.run("x", timeout=5)
    calls_before = len(box.calls)
    box.raise_on = None
    box.cost = 0.1  # under the cap, but the budget is halted, so the call stops before the sandbox runs it
    with pytest.raises(BudgetExceeded, match="halted"):
        session.run("x", timeout=5)
    assert len(box.calls) == calls_before
    snap = budget.snapshot()
    assert "402" in snap["halted"]
    assert snap.get("sandbox_cost_usd", 0.0) == 0.0


def test_a_free_result_does_not_halt():
    box, budget, session = make()
    for cost in (0, 0.0, None):
        box.cost = cost
        session.run("x", timeout=5)
    assert budget.halted is None


def test_server_timed_out_flag_resets_like_an_operation_timeout():
    box, budget, session = make()

    def flag(argv, done):
        if argv[-1] == "sleep 99":
            done.result._raw.result.state.timed_out = True

    box.tweak = flag
    res = session.run("sleep 99", timeout=3)
    assert res.timed_out and res.reset and res.exit_code == TIMEOUT_EXIT_CODE
    assert budget.sandbox_runs == 2
    session.run("ls", timeout=5)
    assert box.execs[-1].image == "base"  # the timed-out run's image was not kept


@pytest.mark.parametrize("missing", ["raw", "result", "state", "flag", "not-a-bool"])
def test_unknown_server_timeout_state_fails_closed(missing):
    box, _, session = make()

    def drop(argv, done):
        if argv[-1] != "x":
            return
        raw = done.result._raw
        if missing == "raw":
            done.result._raw = None
        elif missing == "result":
            raw.result = None
        elif missing == "state":
            raw.result.state = None
        elif missing == "flag":
            del raw.result.state.timed_out
        else:
            raw.result.state.timed_out = "no"

    box.tweak = drop
    with pytest.raises(RuntimeError, match="did not say whether it timed out"):
        session.run("x", timeout=5)


def test_exec_output_cap_marks_truncation():
    box, _, session = make()
    box.user = lambda argv: (0, b"a" * (MAX_OUTPUT_BYTES + 500), b"e" * 10, False)
    res = session.run("big", timeout=5)  # the host cap, when the server did not cut
    assert res.truncated
    assert res.stdout.startswith("a" * 100)
    assert res.stdout.endswith(f"[truncated: over {MAX_OUTPUT_BYTES} bytes, first {MAX_OUTPUT_BYTES} kept]")
    assert res.stderr == "e" * 10
    assert box.execs[-1].cap == MAX_OUTPUT_BYTES


def test_exec_server_side_cut_is_marked_too():
    box, _, session = make()
    box.user = lambda argv: (0, b"a" * MAX_OUTPUT_BYTES, b"", True)
    res = session.run("big", timeout=5)
    assert res.truncated
    assert res.stdout.endswith("kept]")
    assert len(res.stdout) < MAX_OUTPUT_BYTES + 200


# --- write_file, diff ---------------------------------------------------------------------------------


def test_write_file_sends_data_over_stdin_and_advances_the_image():
    box, _, session = make()
    session.write_file("sub/dir/f.py", "print('é')\n")
    call = box.calls[-1]
    assert call.stdin == "print('é')\n".encode()
    assert call.disposable is False
    assert call.cwd == "/testbed"
    assert "mkdir -p -- sub/dir && cat > sub/dir/f.py" in call.argv[-1]
    session.run("cat sub/dir/f.py", timeout=5)
    assert box.execs[-1].image == "img1"  # runs on the image the write produced
    session.write_file("raw.bin", b"\x00\xff")
    assert box.calls[-1].stdin == b"\x00\xff"
    assert "mkdir" not in box.calls[-1].argv[-1]


def test_write_file_failure_raises():
    box, _, session = make()
    box.answer = lambda argv: (1, b"", b"Permission denied\n", False)
    with pytest.raises(RuntimeError, match="write_file 'x' failed.*Permission denied"):
        session.write_file("x", "d")


def test_diff_runs_the_shared_script_on_the_current_image():
    box, _, session = make()
    session.write_file("new.txt", "x")
    out = session.diff()
    call = box.calls[-1]
    assert out == "diff --git a/f b/f\n"
    assert call.disposable is True  # reading does not advance the image
    assert call.image == "img1"
    assert call.cap == MAX_DIFF_BYTES
    assert call.timeout == IO_TIMEOUT_S + EXEC_GRACE_S
    assert call.argv[-1] == _DIFF_SCRIPT.format(workdir="/testbed", base=BASE_SHA, unstage="")


def test_diff_unstages_files_untracked_at_start():
    box = FakeSandbox()
    box.untracked = b"build/\0cache.txt\0"
    _, _, session = make(box=box)
    session.diff()
    call = box.calls[-1]
    assert call.stdin == b"build\0cache.txt\0"  # trailing slash of a nested repo removed
    assert "update-index --force-remove -z --stdin" in call.argv[-1]


def test_diff_refuses_when_too_big_or_failing():
    box, _, session = make()
    box.diff_out = (0, b"d" * 10, b"", True)
    with pytest.raises(RuntimeError, match="MAX_DIFF_BYTES"):
        session.diff()
    box.diff_out = (128, b"", b"fatal: bad object\n", False)
    with pytest.raises(RuntimeError, match=r"diff failed \(128\).*bad object"):
        session.diff()
    box.diff_out = (0, b"", b"", False)
    box.raise_on = lambda argv: OperationTimedOutError(operation_uuid=uuid4())
    with pytest.raises(RuntimeError, match="diff timed out"):
        session.diff()


def test_diff_refuses_without_base_commit():
    box = FakeSandbox()
    box.answer = lambda argv: (
        (128, b"", b"not a repo", False) if "rev-parse" in " ".join(argv) else FakeSandbox.answer(box, argv)
    )
    _, _, session = make(box=box)
    with pytest.raises(RuntimeError, match="base commit was not recorded"):
        session.diff()


def test_baseline_failure_stops_the_start():
    box = FakeSandbox()
    box.answer = lambda argv: (
        (128, b"", b"fatal", False) if "ls-files" in " ".join(argv) else FakeSandbox.answer(box, argv)
    )
    with pytest.raises(RuntimeError, match="untracked-file baseline was not recorded"):
        make(box=box)


# --- reset, close -------------------------------------------------------------------------------------


def test_reset_returns_to_the_base_image_and_books_a_run():
    box, budget, session = make()
    session.write_file("f", "x")
    session.reset()
    assert budget.sandbox_runs == 2
    session.run("ls", timeout=5)
    assert box.execs[-1].image == "base"
    assert box.resolved == [("use", ENV.image)]  # the image is not resolved again


def test_reset_refused_by_budget_leaves_the_session_dead_until_a_reset_succeeds():
    budget = FakeBudget(fail_after=1)
    box, _, session = make(budget=budget)
    session.write_file("f", "x")
    with pytest.raises(BudgetExceeded):
        session.reset()
    calls = len(box.calls)
    for call in (lambda: session.run("ls", timeout=5), lambda: session.write_file("g", "y"), session.diff):
        with pytest.raises(RuntimeError, match="no live sandbox"):
            call()
    with pytest.raises(BudgetExceeded):
        session.reset()  # still refused: still dead
    assert len(box.calls) == calls  # nothing ran on the old image
    budget.fail_after = None
    session.reset()
    session.run("ls", timeout=5)
    assert box.execs[-1].image == "base"  # the earlier write is gone


def test_a_state_changing_call_without_an_image_kills_the_session():
    box, _, session = make()

    def lose(argv, done):
        if "cat >" in argv[-1]:
            done.uuid = None

    box.tweak = lose
    with pytest.raises(RuntimeError, match="no image"):
        session.write_file("f", "x")
    with pytest.raises(RuntimeError, match="no live sandbox"):
        session.run("ls", timeout=5)
    box.tweak = None
    session.reset()
    session.run("ls", timeout=5)
    assert box.execs[-1].image == "base"


def test_close_is_idempotent_and_ends_the_session():
    _, _, session = make()
    with session:
        pass
    session.close()
    for call in (
        lambda: session.run("x", timeout=1),
        lambda: session.write_file("f", "x"),
        session.diff,
        session.reset,
    ):
        with pytest.raises(RuntimeError, match="closed"):
            call()


# --- network ------------------------------------------------------------------------------------------


def test_network_is_off_by_default():
    box, _, session = make()
    locate, probe = box.calls[0], box.calls[1]
    assert locate.argv[:2] == ["sh", "-c"]  # the only call outside the wrapper: it finds the wrapper
    assert probe.argv == [UNSHARE, "-rn", "sh", "-c", _NETCUT_PROBE]
    session.run("curl example.com", timeout=5)
    argv = box.execs[-1].argv
    assert argv[:3] == [UNSHARE, "-rn", "sh"]  # absolute path: no PATH lookup an attacker file could win
    assert argv[3] == "-lc"


def test_every_call_after_the_probe_runs_under_the_wrapper():
    box, _, session = make()
    session.write_file("a/b.txt", "x")
    session.run("echo hi", timeout=5)
    session.diff()
    session.reset()
    session.write_file("c.txt", "y")
    session.run("ls", timeout=5)
    session.diff()
    after_locate = box.calls[1:]
    assert len(after_locate) == 9  # probe, 2 baseline calls, then write, run, diff twice (reset runs none)
    for call in after_locate:
        assert call.argv[:2] == WRAP, call.argv
    # write_file and diff included, and the wrapper sits before the shell, not inside it
    assert box.calls[-1].argv[2:4] == ["sh", "-c"] and "read-tree" in box.calls[-1].argv[-1]
    assert any(c.argv[2:4] == ["sh", "-c"] and "cat >" in c.argv[-1] for c in after_locate)


def test_network_fetch_experiment_gets_the_network():
    box, _, session = make(FETCH_ENV)
    assert all("unshare" not in c.argv for c in box.calls)  # no locate, no probe
    assert all(c.argv[0] == "sh" for c in box.calls)
    session.write_file("f", "x")
    session.run("curl example.com", timeout=5)
    session.diff()
    assert all(c.argv[0] == "sh" for c in box.calls)
    assert box.reads == []  # nothing to pin without a wrapper


def test_probe_proves_the_cut_not_just_that_unshare_runs():
    assert "/proc/net/dev" in _NETCUT_PROBE  # only lo may be listed
    assert "1.1.1.1" in _NETCUT_PROBE and "connect" in _NETCUT_PROBE  # and a connect attempt must fail


def test_network_off_falls_back_to_plain_unshare_when_user_namespaces_fail():
    box = FakeSandbox()
    box.answer = lambda argv: (
        (1, b"", b"unshare: unshare failed: Operation not permitted", False)
        if argv[:2] == [UNSHARE, "-rn"]
        else FakeSandbox.answer(box, argv)
    )
    _, _, session = make(box=box)
    session.run("x", timeout=5)
    assert box.execs[-1].argv[:3] == [UNSHARE, "-n", "sh"]
    probes = [c.argv[1] for c in box.calls if _NETCUT_PROBE in c.argv]
    assert probes == ["-rn", "-n"]  # -rn first; -n only after -rn failed at the start probe


def test_a_cut_that_the_probe_cannot_prove_refuses_to_start():
    for code in (1, 3, 4, 5):  # unshare failed, another interface, connect worked, no /proc/net/dev
        box = FakeSandbox()
        box.probe_exit = code
        with pytest.raises(ExecutorUnavailable, match="cannot cut the network") as err:
            make(box=box)
        assert f"unshare -rn exit {code}" in str(err.value) and f"unshare -n exit {code}" in str(err.value)
        assert "SANDBOX_NETWORK_TRUSTED" in str(err.value)
        assert box.execs == []  # no attacker command ran


def test_no_unshare_in_the_image_refuses_to_start():
    box = FakeSandbox()
    box.locate_exit = 1
    box.locate_out = b""
    with pytest.raises(ExecutorUnavailable, match="cannot cut the network.*no unshare"):
        make(box=box)
    assert box.execs == []


def test_wrapper_files_that_cannot_be_read_refuse_to_start():
    box = FakeSandbox()
    del box.files[LIBC]
    with pytest.raises(ExecutorUnavailable, match="cannot be read"):
        make(box=box)


def test_probe_sdk_error_is_raised_as_is_not_turned_into_the_trusted_hint():
    for error in (FailedOperationError(operation_uuid=uuid4(), error="no capacity"), leaky_error(503)):
        box = FakeSandbox()
        box.raise_on = lambda argv, error=error: error if _NETCUT_PROBE in argv else None
        with pytest.raises(RuntimeError, match="sandbox call failed") as err:
            make(box=box)
        assert not isinstance(err.value, ExecutorUnavailable)
        assert "SANDBOX_NETWORK_TRUSTED" not in str(err.value)
        assert_no_secret(err.value)


def test_probe_timeout_is_raised_as_a_timeout_not_the_trusted_hint():
    box = FakeSandbox()
    box.raise_on = lambda argv: (
        OperationTimedOutError(operation_uuid=uuid4()) if _NETCUT_PROBE in argv else None
    )
    with pytest.raises(RuntimeError, match="timed out") as err:
        make(box=box)
    assert not isinstance(err.value, ExecutorUnavailable)
    assert "SANDBOX_NETWORK_TRUSTED" not in str(err.value)


def test_locate_sdk_error_is_raised_as_is():
    box = FakeSandbox()
    box.raise_on = lambda argv: FailedOperationError(operation_uuid=uuid4(), error="x")
    with pytest.raises(RuntimeError, match="sandbox call failed: FailedOperationError"):
        make(box=box)


def test_network_off_trusted_platform_skips_the_probe():
    box = FakeSandbox()
    box.probe_exit = 1
    _, _, session = make(box=box, trust_no_network=True)
    session.run("x", timeout=5)
    assert box.execs[-1].argv[0] == "sh"
    assert box.reads == []


def test_trusted_flag_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv("SANDBOX_NETWORK_TRUSTED", "1")
    assert SandboxExecutor(client_factory=lambda: None)._trust_no_network is True
    monkeypatch.setenv("SANDBOX_NETWORK_TRUSTED", "0")
    assert SandboxExecutor(client_factory=lambda: None)._trust_no_network is False


# --- wrapper integrity --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "data"),
    [
        (UNSHARE, b'#!/bin/sh\nexec "$@"\n'),  # a shim that does not unshare
        (LIBC, b"evil libc"),
        (LOADER, b"evil loader"),
        (CACHE, b"cache that points at another libc"),
        (PRELOAD, b"/tmp/evil.so"),  # absent at start, present now
    ],
)
def test_tampered_wrapper_files_refuse_every_later_call_until_reset(path, data):
    box, _, session = make()
    session.write_file("f", "x")  # the attacker's run: its image is img1
    box.edits[("img1", path)] = data
    calls = len(box.calls)
    for call in (
        lambda: session.run("curl example.com", timeout=5),
        lambda: session.write_file("g", "y"),
        session.diff,
    ):
        with pytest.raises(ExecutorRefused, match="network wrapper tampered"):
            call()
    assert len(box.calls) == calls  # nothing ran on the tampered image
    session.reset()  # back to the base image: trusted again
    session.run("ls", timeout=5)
    assert box.execs[-1].image == "base"


def test_the_run_that_tampers_still_runs_cut_off_and_the_next_call_is_refused():
    box, _, session = make()
    session.run("cp /bin/true /usr/bin/unshare", timeout=5)
    assert box.execs[-1].argv[:2] == WRAP  # the tampering run itself was wrapped by the intact wrapper
    box.edits[("img1", UNSHARE)] = b"shim"
    with pytest.raises(ExecutorRefused, match="network wrapper tampered"):
        session.run("curl example.com", timeout=5)


def test_a_missing_wrapper_file_counts_as_tampered():
    box, _, session = make()
    session.write_file("f", "x")
    box.files.pop(LOADER)  # the loader is gone from the image the next call would run on
    with pytest.raises(ExecutorRefused, match="network wrapper tampered"):
        session.run("ls", timeout=5)


def test_an_image_that_passed_is_not_read_again():
    box, _, session = make()
    session.run("echo one", timeout=5)  # img1
    session.diff()
    session.diff()
    session.diff()
    on_img1 = [path for image, path in box.reads if image == "img1"]
    assert sorted(on_img1) == sorted([UNSHARE, LIBC, LOADER, CACHE, PRELOAD])  # once, not once per call
    session.run("echo two", timeout=5)  # runs on img1 and yields img2, which is read at the next call
    assert {image for image, _ in box.reads} == {"base", "img1"}
    session.diff()
    assert {image for image, _ in box.reads} == {"base", "img1", "img2"}


def test_the_base_image_is_not_read_again_after_a_reset():
    box, _, session = make()
    session.reset()
    session.run("ls", timeout=5)
    assert {image for image, _ in box.reads} == {"base"}
    assert len(box.reads) == 5  # the pins taken at start, nothing since


# --- git scripts --------------------------------------------------------------------------------------


@pytest.mark.parametrize("script", [_DIFF_SCRIPT, _UNSTAGE_SCRIPT, _BASELINE_SCRIPT])
def test_git_scripts_pin_the_keys_that_run_commands_by_themselves(script):
    for flag in (
        "-c core.fsmonitor=false",
        "-c core.hooksPath=/dev/null",
        "-c core.attributesFile=/dev/null",
        "-c core.excludesFile=/dev/null",
        "-c diff.external=",
        "--no-replace-objects",
    ):
        assert flag in script, flag
    for line in script.split("; "):  # every git call carries the options, none is bare
        if line.lstrip().startswith("git "):
            assert "core.fsmonitor=false" in line, line


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git on PATH")
def test_diff_script_does_not_run_a_repo_fsmonitor_command(tmp_path):
    home, repo, marker = tmp_path / "home", tmp_path / "repo", tmp_path / "ran"
    home.mkdir()
    repo.mkdir()
    env = {"PATH": os.environ["PATH"], "HOME": str(home), "GIT_CONFIG_NOSYSTEM": "1"}

    def git(*args):
        done = subprocess.run(
            ["git", "-C", str(repo), *args], env=env, capture_output=True, text=True, check=True
        )
        return done.stdout.strip()

    git("init", "-q")
    git("config", "user.email", "t@example.invalid")
    git("config", "user.name", "t")
    (repo / "a.txt").write_text("1\n")
    git("add", "-A")
    git("commit", "-qm", "c")
    base = git("rev-parse", "HEAD")
    hook = tmp_path / "hook.sh"
    hook.write_text(f"#!/bin/sh\ntouch {shlex.quote(str(marker))}\n")
    hook.chmod(0o755)
    git("config", "core.fsmonitor", str(hook))
    (repo / "a.txt").write_text("2\n")
    # control: plain git runs the repo's command, so the check below means something
    git("status", "--porcelain")
    if not marker.exists():
        pytest.skip("this git does not run core.fsmonitor here")
    marker.unlink()
    script = _DIFF_SCRIPT.format(workdir=shlex.quote(str(repo)), base=shlex.quote(base), unstage="")
    done = subprocess.run(["sh", "-c", script], env=env, capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stderr
    assert "+2" in done.stdout
    assert not marker.exists()


# --- choice, imports ----------------------------------------------------------------------------------


def test_make_executor_defaults_to_sandbox(monkeypatch):
    monkeypatch.delenv("EXECUTOR", raising=False)
    assert isinstance(make_executor(), SandboxExecutor)
    assert isinstance(make_executor("docker"), DockerExecutor)
    monkeypatch.setenv("EXECUTOR", "docker")
    assert isinstance(make_executor(), DockerExecutor)
    monkeypatch.setenv("EXECUTOR", "k8s")
    with pytest.raises(ValueError, match="docker or sandbox"):
        make_executor()


def test_executor_module_imports_without_contree_sdk():
    code = (
        "import sys; sys.modules['contree_sdk'] = None\n"
        "import cheatproof.executor as e\n"
        "assert e.SandboxExecutor(client_factory=lambda: None) is not None\n"
        "try:\n"
        "    e.SandboxExecutor().start(e.EnvSpec(image='x'), object())\n"
        "except e.ExecutorUnavailable:\n"
        "    print('ok')\n"
    )
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)
    assert done.stdout.strip() == "ok", done.stderr


# --- T35: ledger OSError is a refusal; halt before every exec; any 402 halts --------------------------------------


class Http402(Exception):
    """Not an SDK error, but it carries HTTP status 402, so it must halt the budget too."""

    status = 402


def test_http_402_from_a_non_sdk_exception_halts_the_budget(tmp_path):
    budget = real_budget(tmp_path)
    box, _, session = make(budget=budget)
    box.raise_on = lambda argv: Http402("payment required")
    with pytest.raises(BudgetExceeded, match="402"):
        session.run("x", timeout=5)
    assert "402" in budget.snapshot()["halted"]


def test_a_halt_stops_the_next_exec_even_a_free_one(tmp_path):
    budget = real_budget(tmp_path)
    box, _, session = make(budget=budget)
    budget.halt("manual halt")
    calls = len(box.calls)
    box.cost = 0  # a free call: the halt still stops it before the sandbox runs it
    with pytest.raises(BudgetExceeded, match="budget halted"):
        session.run("x", timeout=5)
    assert len(box.calls) == calls


def test_a_ledger_oserror_before_the_first_run_refuses_and_runs_nothing(tmp_path, monkeypatch):
    budget = real_budget(tmp_path)

    def broken_read(self):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(Budget, "_read", broken_read)
    box = FakeSandbox()
    with pytest.raises(BudgetExceeded, match="could not be read or written") as err:
        make(box=box, budget=budget)
    assert "No space" not in str(err.value)  # the type name only, never the OS text
    assert box.calls == []


def test_a_ledger_oserror_during_a_run_becomes_budget_exceeded(tmp_path, monkeypatch):
    budget = real_budget(tmp_path)
    box, _, session = make(budget=budget)
    calls = len(box.calls)

    def broken_read(self):
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(Budget, "_read", broken_read)
    with pytest.raises(BudgetExceeded, match="could not be read or written"):
        session.run("x", timeout=5)
    assert len(box.calls) == calls


def test_a_ledger_oserror_while_booking_a_cost_becomes_budget_exceeded(tmp_path, monkeypatch):
    budget = real_budget(tmp_path)
    box, _, session = make(budget=budget)
    box.cost = 0.1

    def broken_book(self, usd):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(Budget, "book_sandbox_cost", broken_book)
    with pytest.raises(BudgetExceeded, match="could not be read or written"):
        session.run("x", timeout=5)


def test_a_402_the_ledger_cannot_halt_gives_a_fixed_message_with_no_sdk_error(tmp_path, monkeypatch):
    budget = real_budget(tmp_path)
    box, _, session = make(budget=budget)
    box.raise_on = lambda argv: leaky_error(402)

    def refused_halt(self, reason):
        raise BudgetExceeded("ledger gone")

    monkeypatch.setattr(Budget, "halt", refused_halt)
    with pytest.raises(BudgetExceeded) as err:
        session.run("x", timeout=5)
    assert str(err.value) == "HTTP 402; ledger could not be halted"
    assert err.value.__context__ is None  # the SDK error is never the context
    assert err.value.__cause__ is None
    assert FAKE_SECRET not in repr(err.value)


# --- T45 review: the HTTP status also comes from exc.response.status_code, and a 402 in that shape halts ----------


class _ResponseShapedError(Exception):
    """An SDK-style error that carries its status only on .response, as httpx-based errors do."""

    def __init__(self, status):
        super().__init__(f"leaky server text {FAKE_SECRET}")
        self.response = SimpleNamespace(status_code=status)


class _StatusCodeShapedError(Exception):
    def __init__(self, status):
        super().__init__(f"leaky server text {FAKE_SECRET}")
        self.status_code = status


class _BothShapesError(Exception):
    def __init__(self):
        super().__init__(f"leaky {FAKE_SECRET}")
        self.status_code = 500
        self.response = SimpleNamespace(status_code=402)


@pytest.mark.parametrize(
    "exc, status",
    [
        (_StatusCodeShapedError(402), 402),
        (_ResponseShapedError(402), 402),
        (_ResponseShapedError(503), 503),
        (_ResponseShapedError(True), None),  # a bool is not a status
        (_ResponseShapedError("402"), None),  # nor is a string
        (_BothShapesError(), 500),  # exc.status_code is read before exc.response
        (Exception("no status"), None),
    ],
)
def test_http_status_reads_status_code_then_response_status_code(exc, status):
    from cheatproof.executor import _http_status

    assert _http_status(exc) == status


def test_describe_error_names_a_response_shaped_status_and_no_text():
    from cheatproof.executor import _describe_error

    text = _describe_error(_ResponseShapedError(503))
    assert text == "_ResponseShapedError (HTTP 503)"
    assert FAKE_SECRET not in text


def test_halt_for_payment_halts_on_a_response_shaped_402(tmp_path):
    from cheatproof.executor import _halt_for_payment

    budget = real_budget(tmp_path)
    err = _halt_for_payment(_ResponseShapedError(402), budget)
    assert str(err) == "HTTP 402 from Sandboxes; the budget is halted"
    assert "402" in budget.snapshot()["halted"]
    assert FAKE_SECRET not in repr(err) and FAKE_SECRET not in str(err)
    assert err.__context__ is None and err.__cause__ is None  # returned, not raised: no SDK context
    assert _halt_for_payment(_ResponseShapedError(503), budget) is None


def test_http_402_in_response_shape_from_a_call_halts_the_real_ledger(tmp_path):
    budget = real_budget(tmp_path)
    box, _, session = make(budget=budget)
    box.raise_on = lambda argv: _ResponseShapedError(402)
    with pytest.raises(BudgetExceeded, match="402") as err:
        session.run("x", timeout=5)
    assert "402" in budget.snapshot()["halted"]
    assert_no_secret(err.value)
