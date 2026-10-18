import re
import shlex
import sys
import time

import pytest

from cheatproof.budget import Budget, BudgetExceeded
from cheatproof.executor import (
    EXEC_GRACE_S,
    MAX_DIFF_BYTES,
    MAX_OUTPUT_BYTES,
    MAX_RUN_TIMEOUT_S,
    OUTPUT_KILL_EXIT_CODE,
    OUTPUT_MARGIN_BYTES,
    TIMEOUT_EXIT_CODE,
    DockerExecutor,
    EnvSpec,
    ExecutorRefused,
    ExecutorUnavailable,
    Result,
    SandboxExecutor,
    make_executor,
    start,
    subprocess_runner,
)

IMAGE = "python:3.12-slim"
ENV = EnvSpec(image=IMAGE)
CID = "abc123"
NAME_RE = re.compile(r"cheatproof-[0-9a-f]{32}")
RUN_CAP = MAX_OUTPUT_BYTES + OUTPUT_MARGIN_BYTES


class FakeDocker:
    """Stands in for the docker CLI. Records every call and answers the ones the executor makes.

    It never runs the real docker binary. log holds (argv, stdin); meta holds (timeout, max_bytes),
    one entry per call, in the same order.
    """

    def __init__(
        self,
        *,
        image_present=True,
        images=(),
        info_down_for=0,
        run_exit=0,
        run_result=None,
        exec_result=None,
        exec_raises=None,
        rm_results=(),
    ):
        self.image_present = image_present
        self.images = list(images)
        self.info_down_for = info_down_for
        self.run_exit = run_exit
        self.run_result = run_result  # replaces the docker run answer entirely
        self.exec_result = exec_result or Result(0, "", "", 0.0)
        self.exec_raises = exec_raises  # raised by every docker exec
        self.rm_results = list(rm_results)  # answers to docker rm -f, in order; then exit 0
        self.on_run = None
        self.log: list[tuple[list[str], bytes | None]] = []
        self.meta: list[tuple[float, int | None]] = []

    def __call__(self, argv, timeout, stdin=None, max_bytes=None):
        self.log.append((list(argv), stdin))
        self.meta.append((timeout, max_bytes))
        if argv[:2] == ["docker", "info"]:
            if self.info_down_for > 0:
                self.info_down_for -= 1
                return Result(1, "", "Cannot connect to the Docker daemon", 0.0)
            return Result(0, "", "", 0.0)
        if argv[:3] == ["docker", "image", "inspect"]:
            return Result(0 if self.image_present else 1, "{}", "", 0.0)
        if argv[:2] == ["docker", "images"]:
            return Result(0, "".join(f"{image}\n" for image in self.images), "", 0.0)
        if argv[:2] == ["docker", "run"]:
            if self.on_run:
                self.on_run()
            if self.run_result is not None:
                return self.run_result
            return Result(self.run_exit, f"{CID}\n", "" if self.run_exit == 0 else "pull denied", 0.0)
        if argv[:3] == ["docker", "rm", "-f"]:
            return self.rm_results.pop(0) if self.rm_results else Result(0, "", "", 0.0)
        if argv[:2] == ["docker", "exec"]:
            if self.exec_raises is not None:
                raise self.exec_raises
            return self.exec_result
        return Result(0, "", "", 0.0)

    def argvs(self, prefix):
        return [argv for argv, _ in self.log if argv[: len(prefix)] == prefix]

    def runs(self):
        return self.argvs(["docker", "run"])

    def names_removed(self):
        return [argv[3] for argv in self.argvs(["docker", "rm", "-f"])]


def run_name(fake, index=0):
    argv = fake.runs()[index]
    return argv[argv.index("--name") + 1]


def in_container_runs(fake):
    """(argv, host timeout) for each docker exec that runs a command through sh -lc."""
    return [
        (argv, meta[0])
        for (argv, _), meta in zip(fake.log, fake.meta, strict=True)
        if argv[:5] == ["docker", "exec", CID, "sh", "-lc"]
    ]


class FakeClock:
    """Injected clock: sleep() advances time at once, so the 120 s daemon wait costs nothing."""

    def __init__(self):
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def make_budget(tmp_path, runs=5):
    return Budget(tmp_path / "ledger.json", total_cap_usd=10.0, daily_cap_usd=10.0, sandbox_run_cap=runs)


def make_docker(runner, *, disk_gb=100.0, image_cap=6, platform="linux", clock=None):
    clock = clock or FakeClock()
    return DockerExecutor(
        runner=runner,
        disk_free_gb=lambda: disk_gb,
        min_free_gb=10.0,
        image_cap=image_cap,
        platform=platform,
        sleep=clock.sleep,
        clock=clock,
    )


# --- image validation -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "image",
    ["--privileged", "--network=host", "-v", "-", "", " python", "python image", "python;rm -rf"],
)
def test_image_that_could_read_as_an_option_is_refused(image):
    with pytest.raises(ValueError, match="invalid image name"):
        EnvSpec(image=image)


@pytest.mark.parametrize(
    "image",
    [
        "python:3.12-slim",
        "ghcr.io/org/app:1.0",
        "repo/img@sha256:" + "a" * 64,
        "swebench/sweb.eval.x86_64.django_1776_django-11099:latest",
    ],
)
def test_valid_image_names_are_accepted(image):
    assert EnvSpec(image=image).image == image


def test_image_follows_double_dash_in_run_and_inspect(tmp_path):
    fake = FakeDocker()
    with make_docker(fake).start(ENV, make_budget(tmp_path)):
        pass
    assert fake.argvs(["docker", "image", "inspect"]) == [["docker", "image", "inspect", "--", IMAGE]]
    (argv,) = fake.runs()
    assert argv[argv.index("--") + 1] == IMAGE


# --- container shape ---------------------------------------------------------------------------------


def test_container_has_no_network_no_mounts_and_limits(tmp_path):
    fake = FakeDocker()
    with make_docker(fake).start(ENV, make_budget(tmp_path)) as s:
        s.run("echo ok", timeout=5)
    (argv,) = fake.runs()
    assert argv[argv.index("--network") + 1] == "none"
    assert argv[argv.index("--cpus") + 1] == "2.0"
    assert argv[argv.index("--memory") + 1] == "4g"
    assert argv[argv.index("--pids-limit") + 1] == "512"
    assert argv[argv.index("--security-opt") + 1] == "no-new-privileges"
    assert argv[argv.index("--workdir") + 1] == "/testbed"
    assert "-d" in argv and "--rm" in argv
    assert not any(
        a in ("-v", "--volume", "--mount") or a.startswith(("--volume=", "--mount=")) for a in argv
    )
    assert argv[-3:] == [IMAGE, "sleep", "infinity"]
    (run_argv,) = fake.argvs(["docker", "exec", CID, "sh", "-lc"])
    assert run_argv[-2:] == ["cheatproof", "echo ok"]


def test_container_hardening_flags(tmp_path):
    fake = FakeDocker()
    with make_docker(fake).start(ENV, make_budget(tmp_path)):
        pass
    (argv,) = fake.runs()
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    assert argv[argv.index("--memory-swap") + 1] == argv[argv.index("--memory") + 1] == "4g"
    assert argv[argv.index("--ulimit") + 1] == "nofile=1024:1024"
    assert "--read-only" not in argv


def test_container_is_named_and_labelled(tmp_path):
    fake = FakeDocker()
    with make_docker(fake).start(ENV, make_budget(tmp_path)):
        pass
    (argv,) = fake.runs()
    assert NAME_RE.fullmatch(argv[argv.index("--name") + 1])
    assert argv[argv.index("--label") + 1] == "cheatproof=1"


def test_network_true_uses_bridge(tmp_path):
    fake = FakeDocker()
    with make_docker(fake).start(EnvSpec(image=IMAGE, network=True), make_budget(tmp_path)):
        pass
    (argv,) = fake.runs()
    assert argv[argv.index("--network") + 1] == "bridge"
    assert "none" not in argv


# --- budget ------------------------------------------------------------------------------------------


def test_each_start_and_reset_reserves_one_run_before_docker_run(tmp_path):
    budget = make_budget(tmp_path)
    fake = FakeDocker()
    seen = []
    fake.on_run = lambda: seen.append(budget.snapshot()["sandbox_runs"])
    s = make_docker(fake).start(ENV, budget)
    assert budget.snapshot()["sandbox_runs"] == 1
    s.reset()
    s.close()
    assert seen == [1, 2]
    assert budget.snapshot()["sandbox_runs"] == 2
    first, second = run_name(fake, 0), run_name(fake, 1)
    calls = [argv for argv, _ in fake.log]
    rm = calls.index(["docker", "rm", "-f", first])
    runs = [i for i, argv in enumerate(calls) if argv[:2] == ["docker", "run"]]
    assert runs[0] < rm < runs[1]
    assert second != first


def test_budget_exceeded_prevents_container_start(tmp_path):
    fake = FakeDocker()
    with pytest.raises(BudgetExceeded, match="sandbox run cap"):
        make_docker(fake).start(ENV, make_budget(tmp_path, runs=0))
    assert fake.runs() == []


def test_reset_over_budget_leaves_no_live_sandbox(tmp_path):
    fake = FakeDocker()
    s = make_docker(fake).start(ENV, make_budget(tmp_path, runs=1))
    with pytest.raises(BudgetExceeded):
        s.reset()
    assert len(fake.runs()) == 1
    with pytest.raises(RuntimeError, match="reset"):
        s.run("true", 5)


def test_budget_defaults_to_env_ledger(tmp_path, monkeypatch):
    monkeypatch.setenv("SPEND_LEDGER", str(tmp_path / "ledger.json"))
    monkeypatch.setenv("SPEND_CAP_USD", "20")
    monkeypatch.setenv("DAILY_CAP_USD", "4")
    fake = FakeDocker()
    with make_docker(fake).start(ENV):
        pass
    assert make_budget(tmp_path).snapshot()["sandbox_runs"] == 1


def test_missing_ledger_env_fails_closed(monkeypatch):
    monkeypatch.delenv("SPEND_LEDGER", raising=False)
    fake = FakeDocker()
    with pytest.raises(BudgetExceeded, match="SPEND_LEDGER"):
        make_docker(fake).start(ENV)
    assert fake.runs() == []


# --- image guards ------------------------------------------------------------------------------------


def test_disk_guard_refuses_new_image_before_any_pull(tmp_path):
    fake = FakeDocker(image_present=False)
    budget = make_budget(tmp_path)
    with pytest.raises(ExecutorRefused, match="MIN_FREE_DISK_GB"):
        make_docker(fake, disk_gb=5.0).start(ENV, budget)
    assert fake.runs() == []
    assert budget.snapshot()["sandbox_runs"] == 0


def test_disk_guard_skipped_when_image_is_local(tmp_path):
    fake = FakeDocker(image_present=True)
    with make_docker(fake, disk_gb=5.0).start(ENV, make_budget(tmp_path)):
        pass
    assert len(fake.runs()) == 1


def test_image_cap_refuses_new_image(tmp_path):
    fake = FakeDocker(image_present=False, images=[f"sha256:{n}" for n in range(6)])
    with pytest.raises(ExecutorRefused, match="DOCKER_IMAGE_CAP"):
        make_docker(fake).start(ENV, make_budget(tmp_path))
    assert fake.runs() == []


def test_image_cap_counts_distinct_image_ids(tmp_path):
    fake = FakeDocker(image_present=False, images=["a", "a", "b", "b", "b"])
    with make_docker(fake, image_cap=3).start(ENV, make_budget(tmp_path)):
        pass
    assert len(fake.runs()) == 1


def test_image_cap_allows_local_image_even_at_cap(tmp_path):
    fake = FakeDocker(image_present=True, images=[f"sha256:{n}" for n in range(6)])
    with make_docker(fake).start(ENV, make_budget(tmp_path)):
        pass
    assert fake.argvs(["docker", "images"]) == []
    assert len(fake.runs()) == 1


@pytest.mark.parametrize("raw", ["abc", "", "0.5", "0", "-3", "nan"])
def test_min_free_disk_env_falls_back_to_default_when_unusable(monkeypatch, tmp_path, raw):
    monkeypatch.setenv("MIN_FREE_DISK_GB", raw)
    fake = FakeDocker(image_present=False)
    # 5 GB free is refused under the default of 10. A literal 0.5, 0, -3 or nan would let it through.
    executor = DockerExecutor(runner=fake, disk_free_gb=lambda: 5.0, platform="linux")
    with pytest.raises(ExecutorRefused, match="MIN_FREE_DISK_GB=10"):
        executor.start(ENV, make_budget(tmp_path))
    assert fake.runs() == []


def test_min_free_disk_env_is_used_when_valid(monkeypatch, tmp_path):
    monkeypatch.setenv("MIN_FREE_DISK_GB", "2")
    fake = FakeDocker(image_present=False)
    executor = DockerExecutor(runner=fake, disk_free_gb=lambda: 5.0, platform="linux")
    with executor.start(ENV, make_budget(tmp_path)):
        pass
    assert len(fake.runs()) == 1


@pytest.mark.parametrize("raw", ["abc", "", "0", "-2", "1.5"])
def test_image_cap_env_falls_back_to_default_when_unusable(monkeypatch, tmp_path, raw):
    monkeypatch.setenv("DOCKER_IMAGE_CAP", raw)
    fake = FakeDocker(image_present=False, images=["a", "b", "c"])  # under the default of 6
    executor = DockerExecutor(runner=fake, disk_free_gb=lambda: 100.0, platform="linux")
    with executor.start(ENV, make_budget(tmp_path)):
        pass
    assert len(fake.runs()) == 1


def test_image_cap_env_is_used_when_valid(monkeypatch, tmp_path):
    monkeypatch.setenv("DOCKER_IMAGE_CAP", "2")
    fake = FakeDocker(image_present=False, images=["a", "b", "c"])
    executor = DockerExecutor(runner=fake, disk_free_gb=lambda: 100.0, platform="linux")
    with pytest.raises(ExecutorRefused, match="DOCKER_IMAGE_CAP=2"):
        executor.start(ENV, make_budget(tmp_path))
    assert fake.runs() == []


# --- daemon ------------------------------------------------------------------------------------------


def test_daemon_down_on_mac_opens_docker_then_refuses_after_120s(tmp_path):
    clock = FakeClock()
    fake = FakeDocker(info_down_for=10**6)
    budget = make_budget(tmp_path)
    with pytest.raises(ExecutorUnavailable, match="120"):
        make_docker(fake, platform="darwin", clock=clock).start(ENV, budget)
    assert ["open", "-a", "Docker"] in [argv for argv, _ in fake.log]
    assert clock.sleeps == [5] * 24
    assert fake.runs() == []
    assert budget.snapshot()["sandbox_runs"] == 0


def test_daemon_that_comes_up_after_open_is_used(tmp_path):
    clock = FakeClock()
    fake = FakeDocker(info_down_for=2)
    with make_docker(fake, platform="darwin", clock=clock).start(ENV, make_budget(tmp_path)):
        pass
    assert ["open", "-a", "Docker"] in [argv for argv, _ in fake.log]
    assert clock.sleeps == [5, 5]
    assert len(fake.runs()) == 1


def test_daemon_down_off_mac_raises_without_open_or_waiting(tmp_path):
    clock = FakeClock()
    fake = FakeDocker(info_down_for=10**6)
    with pytest.raises(ExecutorUnavailable, match="not running"):
        make_docker(fake, platform="linux", clock=clock).start(ENV, make_budget(tmp_path))
    assert not any(argv[0] == "open" for argv, _ in fake.log)
    assert clock.sleeps == []


# --- leaks: named containers, rm -f on failure, tolerant close --------------------------------------


@pytest.mark.parametrize(
    "run_result",
    [
        Result(125, "", "pull denied", 0.0),
        Result(TIMEOUT_EXIT_CODE, "", "[timed out after 900s]", 0.0, timed_out=True),
        Result(0, "\n", "", 0.0),
    ],
    ids=["run-fails", "run-times-out", "run-prints-no-id"],
)
def test_failed_docker_run_removes_the_named_container(tmp_path, run_result):
    fake = FakeDocker(run_result=run_result)
    with pytest.raises(ExecutorUnavailable, match="docker run failed"):
        make_docker(fake).start(ENV, make_budget(tmp_path))
    assert fake.names_removed() == [run_name(fake)]


def test_failure_after_docker_run_removes_the_container(tmp_path):
    fake = FakeDocker(exec_raises=ExecutorUnavailable("lost the daemon"))
    with pytest.raises(ExecutorUnavailable, match="lost the daemon"):
        make_docker(fake).start(ENV, make_budget(tmp_path))
    assert fake.names_removed() == [run_name(fake)]


def test_close_tolerates_no_such_container(tmp_path):
    fake = FakeDocker(rm_results=[Result(1, "", "Error response from daemon: No such container: x", 0.0)])
    s = make_docker(fake).start(ENV, make_budget(tmp_path))
    s.close()
    s.close()
    assert len(fake.argvs(["docker", "rm"])) == 1


def test_close_that_cannot_remove_keeps_the_name_so_a_retry_works(tmp_path):
    fake = FakeDocker(rm_results=[Result(1, "", "permission denied", 0.0)])
    s = make_docker(fake).start(ENV, make_budget(tmp_path))
    with pytest.raises(RuntimeError, match="permission denied"):
        s.close()
    s.close()  # retry: rm succeeds this time
    assert fake.names_removed() == [run_name(fake), run_name(fake)]
    with pytest.raises(RuntimeError, match="closed"):
        s.run("true", 5)


def test_reset_that_cannot_remove_the_old_container_starts_nothing(tmp_path):
    fake = FakeDocker(rm_results=[Result(1, "", "device or resource busy", 0.0)])
    budget = make_budget(tmp_path)
    s = make_docker(fake).start(ENV, budget)
    with pytest.raises(RuntimeError, match="device or resource busy"):
        s.reset()
    assert len(fake.runs()) == 1
    assert budget.snapshot()["sandbox_runs"] == 1
    s.close()
    assert fake.names_removed() == [run_name(fake), run_name(fake)]


# --- run: timeouts, output caps, host backstop -------------------------------------------------------


@pytest.mark.parametrize("bad", [0, -1, 0.0, float("nan")])
def test_run_refuses_a_timeout_that_is_not_positive(tmp_path, bad):
    fake = FakeDocker()
    s = make_docker(fake).start(ENV, make_budget(tmp_path))
    with pytest.raises(ValueError, match="greater than 0"):
        s.run("true", bad)
    assert in_container_runs(fake) == []
    s.close()


def test_run_wraps_command_in_container_timeout_with_host_backstop(tmp_path):
    fake = FakeDocker()
    with make_docker(fake).start(ENV, make_budget(tmp_path)) as s:
        s.run("pytest -q", timeout=4.2)
    ((argv, host_timeout),) = in_container_runs(fake)
    script = argv[5]
    assert "command -v timeout" in script
    assert "exec timeout -s KILL 5 sh -lc" in script  # 4.2 s rounds up to 5 s, inside the host backstop
    assert argv[-2:] == ["cheatproof", "pytest -q"]
    assert host_timeout == pytest.approx(4.2 + EXEC_GRACE_S)


def test_run_clamps_timeout_to_the_maximum(tmp_path):
    fake = FakeDocker()
    with make_docker(fake).start(ENV, make_budget(tmp_path)) as s:
        s.run("true", timeout=10**9)
    ((argv, host_timeout),) = in_container_runs(fake)
    assert f"exec timeout -s KILL {MAX_RUN_TIMEOUT_S} sh -lc" in argv[5]
    assert host_timeout == MAX_RUN_TIMEOUT_S + EXEC_GRACE_S


def test_host_timeout_kills_client_and_resets_the_sandbox(tmp_path):
    budget = make_budget(tmp_path)
    fake = FakeDocker()
    with make_docker(fake).start(ENV, budget) as s:
        fake.exec_result = Result(TIMEOUT_EXIT_CODE, "", "\n[timed out after 15s]", 0.0, timed_out=True)
        res = s.run("sleep 99", timeout=5)
        fake.exec_result = Result(0, "", "", 0.0)
    assert res.timed_out and res.exit_code == TIMEOUT_EXIT_CODE
    assert len(fake.runs()) == 2  # a fresh container replaced the old one
    assert fake.names_removed() == [run_name(fake, 0), run_name(fake, 1)]
    assert budget.snapshot()["sandbox_runs"] == 2


def test_run_output_is_capped_per_stream(tmp_path):
    big = "a" * (MAX_OUTPUT_BYTES * 3)
    fake = FakeDocker()
    with make_docker(fake).start(ENV, make_budget(tmp_path)) as s:
        fake.exec_result = Result(0, big, big, 0.0)
        res = s.run("cat big", timeout=5)
    assert res.truncated
    for stream in (res.stdout, res.stderr):
        assert len(stream.encode()) < MAX_OUTPUT_BYTES + 100
        assert "[truncated" in stream


def test_default_runner_caps_huge_stdout_and_kills_the_client():
    res = subprocess_runner([sys.executable, "-c", "print('x'*10_000_000)"], 30)
    assert res.truncated
    assert res.exit_code == OUTPUT_KILL_EXIT_CODE
    assert not res.timed_out
    assert len(res.stdout.encode()) <= RUN_CAP
    assert res.duration < 20


def test_default_runner_caps_huge_stderr_too():
    res = subprocess_runner([sys.executable, "-c", "import sys; sys.stderr.write('e'*10_000_000)"], 30)
    assert res.truncated
    assert len(res.stderr.encode()) <= RUN_CAP


def test_default_runner_max_bytes_sets_the_per_stream_limit():
    res = subprocess_runner([sys.executable, "-c", "print('x'*5000)"], 30, max_bytes=1000)
    assert res.truncated
    assert len(res.stdout.encode()) <= 1000


def test_default_runner_output_under_the_cap_is_intact():
    res = subprocess_runner([sys.executable, "-c", "print('x'*100)"], 30)
    assert not res.truncated
    assert res.stdout == "x" * 100 + "\n"


def test_default_runner_timeout_kills_the_client_and_reports_it():
    started = time.monotonic()
    res = subprocess_runner([sys.executable, "-c", "import time; time.sleep(10)"], 1)
    assert res.timed_out
    assert res.exit_code == TIMEOUT_EXIT_CODE
    assert "timed out after 1s" in res.stderr
    assert time.monotonic() - started < 8


def test_default_runner_feeds_stdin():
    res = subprocess_runner(
        [sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read())"], 30, b"hello"
    )
    assert res.stdout == "hello"


def test_default_runner_passes_argv_without_shell_and_reports_exit():
    res = subprocess_runner([sys.executable, "-c", "import sys; sys.stdout.write('ok'); sys.exit(3)"], 10)
    assert (res.exit_code, res.stdout) == (3, "ok")


def test_default_runner_reports_missing_binary_as_unavailable():
    with pytest.raises(ExecutorUnavailable, match="not found"):
        subprocess_runner(["cheatproof-no-such-binary"], 5)


# --- file transfer -----------------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["src/app.py", "it's a file.py", "/testbed/x; touch /tmp/pwned"])
def test_write_file_sends_data_on_stdin_with_quoted_path(tmp_path, path):
    fake = FakeDocker()
    data = b"print('hi')\n"
    with make_docker(fake).start(ENV, make_budget(tmp_path)) as s:
        s.write_file(path, data)
        argv, stdin = fake.log[-1]
    assert argv[:4] == ["docker", "exec", "-i", CID]
    assert path in shlex.split(argv[-1])
    assert "cat > " in argv[-1]
    assert stdin == data


# --- diff --------------------------------------------------------------------------------------------


def test_diff_uses_fresh_index_and_ignores_repo_side_tricks(tmp_path):
    fake = FakeDocker(exec_result=Result(0, "deadbeef\n", "", 0.0))
    with make_docker(fake).start(ENV, make_budget(tmp_path)) as s:
        fake.exec_result = Result(0, "diff --git a/x b/x\n", "", 0.0)
        out = s.diff()
        script = fake.argvs(["docker", "exec", CID, "sh", "-c"])[-1][-1]
        diff_max_bytes = fake.meta[-1][1]
    assert out == "diff --git a/x b/x\n"
    for flag in (
        "--no-replace-objects",
        "GIT_INDEX_FILE",
        "GIT_CONFIG_NOSYSTEM=1",
        "core.excludesFile=/dev/null",
        "read-tree deadbeef",
        "add -A -f",
        "diff --cached --binary",
        "--no-ext-diff",
        "--no-textconv",
    ):
        assert flag in script, flag
    assert diff_max_bytes == MAX_DIFF_BYTES


def test_diff_refuses_when_base_commit_was_not_recorded(tmp_path):
    fake = FakeDocker()  # rev-parse prints nothing, so the base is empty
    with make_docker(fake).start(ENV, make_budget(tmp_path)) as s:
        with pytest.raises(RuntimeError, match="base commit"):
            s.diff()
        assert not any("diff --cached" in argv[-1] for argv, _ in fake.log if argv[:2] == ["docker", "exec"])


def test_diff_failure_raises_instead_of_empty_patch(tmp_path):
    fake = FakeDocker(exec_result=Result(0, "deadbeef\n", "", 0.0))
    with make_docker(fake).start(ENV, make_budget(tmp_path)) as s:
        fake.exec_result = Result(128, "", "fatal: not a git repository", 0.0)
        with pytest.raises(RuntimeError, match="not a git repository"):
            s.diff()


def test_diff_over_the_cap_raises_instead_of_truncating(tmp_path):
    fake = FakeDocker(exec_result=Result(0, "deadbeef\n", "", 0.0))
    with make_docker(fake).start(ENV, make_budget(tmp_path)) as s:
        fake.exec_result = Result(OUTPUT_KILL_EXIT_CODE, "x" * 100, "", 0.0, truncated=True)
        with pytest.raises(RuntimeError, match="MAX_DIFF_BYTES"):
            s.diff()


def test_diff_timeout_raises(tmp_path):
    fake = FakeDocker(exec_result=Result(0, "deadbeef\n", "", 0.0))
    with make_docker(fake).start(ENV, make_budget(tmp_path)) as s:
        fake.exec_result = Result(TIMEOUT_EXIT_CODE, "", "", 0.0, timed_out=True)
        with pytest.raises(RuntimeError, match="timed out"):
            s.diff()


# --- executor choice and live test -------------------------------------------------------------------


def test_sandbox_env_is_unavailable_and_spends_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("EXECUTOR", "sandbox")
    budget = make_budget(tmp_path)
    with pytest.raises(ExecutorUnavailable, match="U3"):
        start(ENV, budget)
    assert budget.snapshot()["sandbox_runs"] == 0


def test_sandbox_stub_refuses_directly(tmp_path):
    with pytest.raises(ExecutorUnavailable, match="U3"):
        SandboxExecutor().start(ENV, make_budget(tmp_path))


def test_executor_choice_comes_from_env(monkeypatch):
    monkeypatch.delenv("EXECUTOR", raising=False)
    assert isinstance(make_executor(), DockerExecutor)
    monkeypatch.setenv("EXECUTOR", " Sandbox ")
    assert isinstance(make_executor(), SandboxExecutor)
    monkeypatch.setenv("EXECUTOR", "k8s")
    with pytest.raises(ValueError, match="docker or sandbox"):
        make_executor()


def test_start_uses_the_executor_it_is_given(tmp_path):
    fake = FakeDocker()
    with start(ENV, make_budget(tmp_path), executor=make_docker(fake)) as s:
        assert s.run("echo ok", timeout=5).exit_code == 0
    assert fake.argvs(["docker", "exec", CID, "sh", "-lc"])


@pytest.mark.docker
def test_live_docker_echo():
    """Runs the real docker CLI with python:3.12-slim. Skipped unless CHEATPROOF_DOCKER_TESTS=1 is set
    (see tests/conftest.py). Default test runs never call docker."""
    with start(EnvSpec(image=IMAGE), executor=DockerExecutor()) as s:
        res = s.run("echo ok", timeout=120)
    assert res.exit_code == 0
    assert res.stdout.strip() == "ok"
