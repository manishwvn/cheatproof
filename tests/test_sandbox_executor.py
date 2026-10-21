"""SandboxExecutor / SandboxSession against a fake contree client. No network, no real SDK calls.

VERIFY: the fake mirrors contree_sdk 0.3.6 as read from the installed source (images.use / images.oci,
image.run(...).wait(), image.result with exit_code/stdout/stderr/truncated). No recorded real response confirms it yet.
"""

import itertools
import subprocess
import sys
from types import SimpleNamespace
from uuid import uuid4

import pytest
from contree_sdk.sdk.exceptions import FailedOperationError, OperationTimedOutError

from cheatproof.budget import BudgetExceeded
from cheatproof.executor import (
    _DIFF_SCRIPT,
    EXEC_GRACE_S,
    IO_TIMEOUT_S,
    MAX_DIFF_BYTES,
    MAX_OUTPUT_BYTES,
    MAX_RUN_TIMEOUT_S,
    TIMEOUT_EXIT_CODE,
    DockerExecutor,
    EnvSpec,
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


class FakeBudget:
    def __init__(self, fail_after=None):
        self.sandbox_runs = 0
        self.fail_after = fail_after

    def reserve_sandbox_run(self):
        if self.fail_after is not None and self.sandbox_runs >= self.fail_after:
            raise BudgetExceeded("sandbox run cap reached")
        self.sandbox_runs += 1

    def reserve_local_run(self):  # a sandbox session must never take a local run
        raise AssertionError("sandbox session reserved a local run")


class FakeSandbox:
    """Stands in for ContreeSync. calls holds one SimpleNamespace per image.run(...).wait()."""

    def __init__(self):
        self.calls = []
        self.images = SimpleNamespace(use=self._use, oci=self._oci)
        self.resolved = []  # (method, name)
        self.probe_exit = 0  # exit code of `unshare ... true`
        self.user = lambda argv: (0, b"ok\n", b"", False)  # answer to an attacker command
        self.diff_out = (0, b"diff --git a/f b/f\n", b"", False)
        self.untracked = b""
        self.raise_on = None  # callable(argv) -> exception or None
        self._ids = itertools.count(1)
        self.base = FakeImage(self, "base")

    def _use(self, name):
        self.resolved.append(("use", name))
        return self.base

    def _oci(self, name):
        self.resolved.append(("oci", name))
        return self.base

    def answer(self, argv):
        text = " ".join(argv)
        if argv[-1] == "true":
            return self.probe_exit, b"", b"", False
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
        done.result = SimpleNamespace(exit_code=code, stdout=out, stderr=err, truncated=cut, _raw=None)
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
    # network probe, base commit, untracked list: all disposable, none of them an attacker command
    assert [c.disposable for c in box.calls] == [True, True, True]
    assert box.execs == []


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


def test_exec_budget_refusal_on_timeout_reset_propagates():
    box, _, session = make(budget=FakeBudget(fail_after=1))
    box.raise_on = lambda argv: OperationTimedOutError(operation_uuid=uuid4())
    with pytest.raises(BudgetExceeded):
        session.run("sleep 99", timeout=3)


def test_exec_sdk_error_is_a_clear_runtime_error():
    box, _, session = make()
    box.raise_on = lambda argv: FailedOperationError(operation_uuid=uuid4(), error="no capacity")
    with pytest.raises(RuntimeError, match="FailedOperationError.*no capacity"):
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


def test_reset_refused_by_budget_leaves_session_usable():
    box, _, session = make(budget=FakeBudget(fail_after=1))
    session.write_file("f", "x")
    with pytest.raises(BudgetExceeded):
        session.reset()
    session.run("ls", timeout=5)
    assert box.execs[-1].image == "img1"


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
    probe = box.calls[0]
    assert probe.argv == ["unshare", "-n", "true"]
    session.run("curl example.com", timeout=5)
    argv = box.execs[-1].argv
    assert argv[:3] == ["unshare", "-n", "sh"]
    assert argv[3] == "-lc"


def test_network_fetch_experiment_gets_the_network():
    box, _, session = make(FETCH_ENV)
    assert all("unshare" not in c.argv for c in box.calls)  # no probe either
    session.run("curl example.com", timeout=5)
    assert box.execs[-1].argv[0] == "sh"


def test_network_off_falls_back_to_user_namespace_unshare():
    box = FakeSandbox()
    box.answer = lambda argv: (
        (1, b"", b"unshare: Operation not permitted", False)
        if argv[:2] == ["unshare", "-n"]
        else FakeSandbox.answer(box, argv)
    )
    _, _, session = make(box=box)
    session.run("x", timeout=5)
    assert box.execs[-1].argv[:3] == ["unshare", "-rn", "sh"]


def test_network_off_that_cannot_be_enforced_refuses_to_start():
    box = FakeSandbox()
    box.probe_exit = 1
    with pytest.raises(ExecutorUnavailable, match="cannot cut the network"):
        make(box=box)
    assert box.execs == []  # no attacker command ran


def test_network_off_trusted_platform_skips_the_probe():
    box = FakeSandbox()
    box.probe_exit = 1
    _, _, session = make(box=box, trust_no_network=True)
    session.run("x", timeout=5)
    assert box.execs[-1].argv[0] == "sh"


def test_trusted_flag_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv("SANDBOX_NETWORK_TRUSTED", "1")
    assert SandboxExecutor(client_factory=lambda: None)._trust_no_network is True
    monkeypatch.setenv("SANDBOX_NETWORK_TRUSTED", "0")
    assert SandboxExecutor(client_factory=lambda: None)._trust_no_network is False


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
