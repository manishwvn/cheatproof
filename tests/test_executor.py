import os
import re
import shlex
import shutil
import subprocess
import sys
import time

import pytest

from cheatproof.budget import Budget, BudgetExceeded
from cheatproof.executor import (
    _BASELINE_SCRIPT,
    _DIFF_SCRIPT,
    _LEAKED,
    _UNSTAGE_SCRIPT,
    COLIMA_DF_TIMEOUT_S,
    EXEC_GRACE_S,
    GIB,
    IO_TIMEOUT_S,
    MAX_BASELINE_BYTES,
    MAX_DIFF_BYTES,
    MAX_OUTPUT_BYTES,
    MAX_RUN_TIMEOUT_S,
    OUTPUT_KILL_EXIT_CODE,
    OUTPUT_MARGIN_BYTES,
    PULL_TIMEOUT_S,
    RUN_TIMEOUT_S,
    TASK_IMAGE_PREFIXES,
    TIMEOUT_EXIT_CODE,
    DiskRefused,
    DockerExecutor,
    EnvSpec,
    ExecutorRefused,
    ExecutorUnavailable,
    Result,
    SandboxExecutor,
    is_task_image,
    make_executor,
    normalise_untracked,
    start,
    subprocess_runner,
)
from cheatproof.tasks import ALLOWED_IMAGE_PREFIXES

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
        ps_result=None,
        task_images=(),
        baseline_result=None,
        pull_result=None,
    ):
        self.task_images = list(task_images)  # answer to docker images with --filter (the task image count)
        self.image_present = image_present
        self.pull_result = pull_result  # answer to docker pull; succeeds when unset
        self.images = list(images)
        self.info_down_for = info_down_for
        self.run_exit = run_exit
        self.run_result = run_result  # replaces the docker run answer entirely
        self.exec_result = exec_result or Result(0, "", "", 0.0)
        self.exec_raises = exec_raises  # raised by every docker exec
        self.rm_results = list(rm_results)  # answers to docker rm -f, in order; then exit 0
        self.ps_result = ps_result  # answer to docker ps; prints nothing when unset
        # answer to the untracked-file baseline exec, a separate command from exec_result
        self.baseline_result = Result(0, "", "", 0.0) if baseline_result is None else baseline_result
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
        if argv[:2] == ["docker", "images"] and "--filter" in argv:
            return Result(0, "".join(f"{image}\n" for image in self.task_images), "", 0.0)
        if argv[:2] == ["docker", "images"]:
            return Result(0, "".join(f"{image}\n" for image in self.images), "", 0.0)
        if argv[:2] == ["docker", "pull"]:
            return self.pull_result or Result(0, "", "", 0.0)
        if argv[:2] == ["docker", "run"]:
            if self.on_run:
                self.on_run()
            if self.run_result is not None:
                return self.run_result
            return Result(self.run_exit, f"{CID}\n", "" if self.run_exit == 0 else "pull denied", 0.0)
        if argv[:3] == ["docker", "rm", "-f"]:
            return self.rm_results.pop(0) if self.rm_results else Result(0, "", "", 0.0)
        if argv[:2] == ["docker", "ps"]:
            return self.ps_result or Result(0, "", "", 0.0)
        if argv[:2] == ["docker", "exec"]:
            if self.exec_raises is not None:
                raise self.exec_raises
            if "ls-files --others" in argv[-1]:
                return self.baseline_result
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
    # Docker sessions count local runs, so `runs` sets local_run_cap. sandbox_run_cap is 0 here: if a
    # Docker start ever reserved a sandbox run instead, these tests would fail with "sandbox run cap 0".
    return Budget(
        tmp_path / "ledger.json",
        total_cap_usd=10.0,
        daily_cap_usd=10.0,
        sandbox_run_cap=0,
        local_run_cap=runs,
    )


def local_runs(budget):
    # The key is absent until the first local run is booked, which reads as 0.
    return budget.snapshot().get("local_runs", 0)


def make_docker(runner, *, disk_gb=100.0, image_cap=6, platform="linux", clock=None, pid=None):
    clock = clock or FakeClock()
    return DockerExecutor(
        runner=runner,
        disk_free_gb=lambda: disk_gb,
        min_free_gb=10.0,
        image_cap=image_cap,
        pid=pid,
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


def test_scratch_tmpfs_is_sized_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("DOCKER_TMPFS_MB", raising=False)
    fake = FakeDocker()
    with make_docker(fake).start(ENV, make_budget(tmp_path)):
        pass
    (argv,) = fake.runs()
    assert argv[argv.index("--tmpfs") + 1] == "/tmp:rw,nosuid,nodev,size=512m"
    assert "--read-only" not in argv


def test_scratch_tmpfs_size_comes_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("DOCKER_TMPFS_MB", "256")
    fake = FakeDocker()
    with make_docker(fake).start(ENV, make_budget(tmp_path)):
        pass
    (argv,) = fake.runs()
    assert argv[argv.index("--tmpfs") + 1] == "/tmp:rw,nosuid,nodev,size=256m"


@pytest.mark.parametrize("raw", ["abc", "", "0", "-2", "1.5", "nan"])
def test_scratch_tmpfs_env_falls_back_to_default_when_unusable(monkeypatch, tmp_path, raw):
    monkeypatch.setenv("DOCKER_TMPFS_MB", raw)
    fake = FakeDocker()
    with make_docker(fake).start(ENV, make_budget(tmp_path)):
        pass
    (argv,) = fake.runs()
    assert argv[argv.index("--tmpfs") + 1] == "/tmp:rw,nosuid,nodev,size=512m"


@pytest.mark.parametrize(
    ("raw", "size"),
    [("8192", 4096), ("4096", 4096), ("2048", 2048), ("99999999999999999999", 4096)],
)
def test_scratch_tmpfs_size_is_clamped_to_4096(monkeypatch, tmp_path, raw, size):
    monkeypatch.setenv("DOCKER_TMPFS_MB", raw)
    fake = FakeDocker()
    with make_docker(fake).start(ENV, make_budget(tmp_path)):
        pass
    (argv,) = fake.runs()
    assert argv[argv.index("--tmpfs") + 1] == f"/tmp:rw,nosuid,nodev,size={size}m"


def test_container_is_named_and_labelled(tmp_path):
    fake = FakeDocker()
    with make_docker(fake).start(ENV, make_budget(tmp_path)):
        pass
    (argv,) = fake.runs()
    assert NAME_RE.fullmatch(argv[argv.index("--name") + 1])
    assert argv[argv.index("--label") + 1] == "cheatproof=1"


def test_container_records_the_pid_of_the_process_that_started_it(tmp_path):
    fake = FakeDocker()
    with make_docker(fake, pid=lambda: 4242).start(ENV, make_budget(tmp_path)):
        pass
    (argv,) = fake.runs()
    labels = [argv[i + 1] for i, arg in enumerate(argv) if arg == "--label"]
    assert labels == ["cheatproof=1", "cheatproof.owner=4242"]


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
    fake.on_run = lambda: seen.append(local_runs(budget))
    s = make_docker(fake).start(ENV, budget)
    assert local_runs(budget) == 1
    s.reset()
    s.close()
    assert seen == [1, 2]
    assert local_runs(budget) == 2
    first, second = run_name(fake, 0), run_name(fake, 1)
    calls = [argv for argv, _ in fake.log]
    rm = calls.index(["docker", "rm", "-f", first])
    runs = [i for i, argv in enumerate(calls) if argv[:2] == ["docker", "run"]]
    assert runs[0] < rm < runs[1]
    assert second != first


def test_budget_exceeded_prevents_container_start(tmp_path):
    fake = FakeDocker()
    with pytest.raises(BudgetExceeded, match="local run cap 0 reached"):
        make_docker(fake).start(ENV, make_budget(tmp_path, runs=0))
    assert fake.runs() == []


def test_docker_start_books_a_local_run_and_no_money_or_sandbox_run(tmp_path):
    budget = make_budget(tmp_path)
    with make_docker(FakeDocker()).start(ENV, budget):
        pass
    s = budget.snapshot()
    assert s["local_runs"] == 1
    assert s["sandbox_runs"] == 0
    assert s["total_usd"] == 0.0


def test_local_run_cap_refuses_a_new_docker_start(tmp_path):
    budget = Budget(
        tmp_path / "ledger.json",
        total_cap_usd=10.0,
        daily_cap_usd=10.0,
        sandbox_run_cap=100,
        local_run_cap=1,
    )
    fake = FakeDocker()
    with make_docker(fake).start(ENV, budget):
        pass
    with pytest.raises(BudgetExceeded, match="local run cap 1 reached"):
        make_docker(fake).start(ENV, budget)
    assert len(fake.runs()) == 1


def test_halted_budget_blocks_a_docker_start_and_books_nothing(tmp_path):
    budget = make_budget(tmp_path)
    budget.halt("HTTP 402 from Token Factory")
    fake = FakeDocker()
    with pytest.raises(BudgetExceeded, match="budget halted"):
        make_docker(fake).start(ENV, budget)
    assert fake.runs() == []
    assert local_runs(budget) == 0


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
    assert local_runs(make_budget(tmp_path)) == 1


def test_missing_ledger_env_fails_closed(monkeypatch):
    monkeypatch.delenv("SPEND_LEDGER", raising=False)
    fake = FakeDocker()
    with pytest.raises(BudgetExceeded, match="SPEND_LEDGER"):
        make_docker(fake).start(ENV)
    assert fake.runs() == []


# --- image guards ------------------------------------------------------------------------------------


def assert_refused_before_docker_was_touched(fake):
    """A disk refusal comes before every daemon check: no docker info and no open -a Docker."""
    assert fake.argvs(["docker", "info"]) == []
    assert [argv for argv, _ in fake.log if argv[:1] == ["open"]] == []


def test_disk_guard_refuses_new_image_before_any_pull(tmp_path):
    fake = FakeDocker(image_present=False)
    budget = make_budget(tmp_path)
    with pytest.raises(ExecutorRefused, match="MIN_FREE_DISK_GB"):
        make_docker(fake, disk_gb=5.0).start(ENV, budget)
    assert fake.runs() == []
    assert local_runs(budget) == 0
    assert_refused_before_docker_was_touched(fake)


def test_disk_guard_applies_to_a_local_image_too(tmp_path):
    fake = FakeDocker(image_present=True)
    budget = make_budget(tmp_path)
    with pytest.raises(ExecutorRefused, match="MIN_FREE_DISK_GB"):
        make_docker(fake, disk_gb=5.0).start(ENV, budget)
    assert fake.runs() == []
    assert local_runs(budget) == 0
    assert_refused_before_docker_was_touched(fake)


def test_local_image_starts_when_disk_is_enough(tmp_path):
    fake = FakeDocker(image_present=True)
    with make_docker(fake, disk_gb=50.0).start(ENV, make_budget(tmp_path)):
        pass
    assert len(fake.runs()) == 1


def test_reset_refuses_when_disk_has_dropped_and_starts_nothing(tmp_path):
    free = [100.0]
    fake = FakeDocker()
    budget = make_budget(tmp_path)
    executor = DockerExecutor(runner=fake, disk_free_gb=lambda: free[0], min_free_gb=10.0, platform="linux")
    s = executor.start(ENV, budget)
    info_calls = len(fake.argvs(["docker", "info"]))
    free[0] = 5.0
    with pytest.raises(ExecutorRefused, match="MIN_FREE_DISK_GB"):
        s.reset()
    assert len(fake.argvs(["docker", "info"])) == info_calls  # no daemon check after the refusal
    assert not any(argv[:1] == ["open"] for argv, _ in fake.log)
    assert len(fake.runs()) == 1
    assert local_runs(budget) == 1
    with pytest.raises(RuntimeError, match="reset"):
        s.run("true", 5)
    s.close()


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
    # 7 GB free leaves 2.5 GB after a 4.5 GB pull: allowed at MIN_FREE_DISK_GB=2, refused at the default 10.
    fake = FakeDocker(image_present=False)
    executor = DockerExecutor(runner=fake, disk_free_gb=lambda: 7.0, platform="linux")
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
    assert local_runs(budget) == 0


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
    assert local_runs(budget) == 1
    s.close()
    assert fake.names_removed() == [run_name(fake), run_name(fake)]


# --- sweep: leftover cheatproof=1 containers at CLI start --------------------------------------------

SWEEP_ARGV = [
    "docker",
    "ps",
    "-a",
    "--filter",
    "label=cheatproof=1",
    "--format",
    '{{.ID}} {{.Label "cheatproof.owner"}}',
]
DEAD_PID = 2_147_483_646  # no process has this pid on macOS or Linux, so os.kill reports it gone


@pytest.fixture
def live_pid():
    """Pid of a child process that stays alive for the test."""
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        yield child.pid
    finally:
        child.kill()
        child.wait()


def sweep_listing(*lines):
    """docker ps output in the sweep format: one line per container, ID then owner label."""
    return Result(0, "".join(f"{line}\n" for line in lines), "", 0.0)


def test_sweep_lists_with_exact_argv_then_removes_dead_owners_by_id(tmp_path):
    fake = FakeDocker(
        ps_result=sweep_listing(f"c1 {DEAD_PID}", f"c2 {DEAD_PID}"),
        rm_results=[Result(0, "c1\nc2\n", "", 0.0)],
    )
    assert make_docker(fake).sweep_leftovers() == 2
    assert [argv for argv, _ in fake.log] == [SWEEP_ARGV, ["docker", "rm", "-f", "c1", "c2"]]


def test_sweep_keeps_a_container_whose_owner_is_alive(tmp_path, live_pid):
    fake = FakeDocker(ps_result=sweep_listing(f"c1 {live_pid}"))
    assert make_docker(fake).sweep_leftovers() == 0
    assert fake.argvs(["docker", "rm"]) == []


def test_sweep_removes_a_container_whose_owner_is_dead(tmp_path):
    fake = FakeDocker(ps_result=sweep_listing(f"c1 {DEAD_PID}"), rm_results=[Result(0, "c1\n", "", 0.0)])
    assert make_docker(fake).sweep_leftovers() == 1
    assert fake.argvs(["docker", "rm"]) == [["docker", "rm", "-f", "c1"]]


@pytest.mark.parametrize("line", ["c1", "c1 "])  # docker prints an empty field when the label is missing
def test_sweep_removes_a_container_without_an_owner_label(tmp_path, line):
    fake = FakeDocker(ps_result=sweep_listing(line), rm_results=[Result(0, "c1\n", "", 0.0)])
    assert make_docker(fake).sweep_leftovers() == 1
    assert fake.argvs(["docker", "rm"]) == [["docker", "rm", "-f", "c1"]]


@pytest.mark.parametrize("owner", ["abc", "-5", "0", "007", "1.5", "12abc", "1_000", "99999999999999999999"])
def test_sweep_removes_a_container_with_a_garbage_owner_label(tmp_path, owner):
    fake = FakeDocker(ps_result=sweep_listing(f"c1 {owner}"), rm_results=[Result(0, "c1\n", "", 0.0)])
    assert make_docker(fake).sweep_leftovers() == 1
    assert fake.argvs(["docker", "rm"]) == [["docker", "rm", "-f", "c1"]]


def test_sweep_keeps_a_container_owned_by_this_process_even_if_the_pid_looks_gone(tmp_path):
    fake = FakeDocker(ps_result=sweep_listing(f"c1 {DEAD_PID}"))
    assert make_docker(fake, pid=lambda: DEAD_PID).sweep_leftovers() == 0
    assert fake.argvs(["docker", "rm"]) == []


def test_sweep_treats_a_permission_error_from_kill_as_alive(tmp_path, monkeypatch):
    def denied(pid, sig):
        raise PermissionError(pid)

    monkeypatch.setattr(os, "kill", denied)
    fake = FakeDocker(ps_result=sweep_listing("c1 77"))
    assert make_docker(fake).sweep_leftovers() == 0
    assert fake.argvs(["docker", "rm"]) == []


def test_sweep_removes_only_the_dead_ones_from_a_mixed_listing(tmp_path, live_pid):
    fake = FakeDocker(
        ps_result=sweep_listing(f"live {live_pid}", f"dead {DEAD_PID}", "nolabel", "junk x"),
        rm_results=[Result(0, "dead\nnolabel\njunk\n", "", 0.0)],
    )
    assert make_docker(fake).sweep_leftovers() == 3
    assert fake.argvs(["docker", "rm"]) == [["docker", "rm", "-f", "dead", "nolabel", "junk"]]


def test_sweep_never_touches_images_volumes_or_prune(tmp_path):
    fake = FakeDocker(ps_result=sweep_listing(f"c1 {DEAD_PID}"), rm_results=[Result(0, "c1\n", "", 0.0)])
    make_docker(fake).sweep_leftovers()
    tokens = {token for argv, _ in fake.log for token in argv}
    assert not tokens & {"rmi", "prune", "volume", "system", "image"}


def test_sweep_with_no_labelled_containers_makes_no_rm_call(tmp_path):
    fake = FakeDocker()  # docker ps prints nothing
    assert make_docker(fake).sweep_leftovers() == 0
    assert fake.argvs(["docker", "rm"]) == []


def test_sweep_counts_only_what_docker_rm_reports(tmp_path):
    fake = FakeDocker(
        ps_result=sweep_listing(f"c1 {DEAD_PID}", f"c2 {DEAD_PID}"),
        rm_results=[Result(1, "c1\n", "No such container: c2", 0.0)],
    )
    assert make_docker(fake).sweep_leftovers() == 1


def test_sweep_when_ps_fails_returns_zero_and_removes_nothing(tmp_path):
    fake = FakeDocker(ps_result=Result(1, "", "Cannot connect to the Docker daemon", 0.0))
    assert make_docker(fake).sweep_leftovers() == 0
    assert fake.argvs(["docker", "rm"]) == []


def test_sweep_when_rm_fails_returns_zero_without_raising(tmp_path):
    fake = FakeDocker(
        ps_result=sweep_listing(f"c1 {DEAD_PID}"),
        rm_results=[Result(1, "", "device or resource busy", 0.0)],
    )
    assert make_docker(fake).sweep_leftovers() == 0


def test_sweep_when_docker_cannot_run_returns_zero_without_raising(tmp_path):
    def missing(argv, timeout, stdin=None, max_bytes=None):
        raise ExecutorUnavailable("docker not found on PATH")

    assert make_docker(missing).sweep_leftovers() == 0


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
    assert res.reset is True
    assert len(fake.runs()) == 2  # a fresh container replaced the old one
    assert fake.names_removed() == [run_name(fake, 0), run_name(fake, 1)]
    assert local_runs(budget) == 2


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
        script = fake.argvs(["docker", "exec", "-i", CID, "sh", "-c"])[-1][-1]
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


# --- untracked-file start list -----------------------------------------------------------------------


def diff_calls(fake):
    """(argv, stdin) of each docker exec that builds a diff, in call order."""
    return [
        (argv, stdin)
        for argv, stdin in fake.log
        if argv[:2] == ["docker", "exec"] and "diff --cached" in argv[-1]
    ]


def baseline_calls(fake):
    """(argv, max_bytes) of each docker exec that lists the untracked paths, in call order."""
    return [
        (argv, meta[1])
        for (argv, _), meta in zip(fake.log, fake.meta, strict=True)
        if argv[:2] == ["docker", "exec"] and "ls-files --others" in argv[-1]
    ]


def test_start_list_is_taken_at_start_and_again_at_reset(tmp_path):
    fake = FakeDocker()
    with make_docker(fake).start(ENV, make_budget(tmp_path)) as s:
        assert len(baseline_calls(fake)) == 1
        s.reset()
        assert len(baseline_calls(fake)) == 2
    argv, max_bytes = baseline_calls(fake)[-1]
    assert argv[:3] == ["docker", "exec", CID]
    assert "ls-files --others -z" in argv[-1]  # NUL-separated, every untracked path
    assert "--exclude-standard" not in argv[-1]  # ignored files are listed too
    assert "-C /testbed" in argv[-1]
    assert max_bytes == MAX_BASELINE_BYTES


@pytest.mark.parametrize(
    "answer",
    [
        Result(1, "", "ls-files: permission denied", 0.0),
        Result(TIMEOUT_EXIT_CODE, "", "\n[timed out after 120s]", 0.0, timed_out=True),
        Result(OUTPUT_KILL_EXIT_CODE, "x" * 100, "", 0.0, truncated=True),
    ],
    ids=["exit-1", "timeout", "over-cap"],
)
def test_start_list_that_is_not_recorded_stops_the_start(tmp_path, answer):
    fake = FakeDocker(baseline_result=answer)
    with pytest.raises(RuntimeError, match="baseline was not recorded"):
        make_docker(fake).start(ENV, make_budget(tmp_path))
    assert run_name(fake) in fake.names_removed()


def test_start_list_that_fails_at_reset_leaves_no_sandbox_to_diff(tmp_path):
    fake = FakeDocker(exec_result=Result(0, "deadbeef\n", "", 0.0))
    with make_docker(fake).start(ENV, make_budget(tmp_path)) as s:
        fake.baseline_result = Result(TIMEOUT_EXIT_CODE, "", "[timed out]", 0.0, timed_out=True)
        with pytest.raises(RuntimeError, match="baseline was not recorded"):
            s.reset()
        with pytest.raises(RuntimeError, match="no live sandbox"):
            s.diff()
        assert not diff_calls(fake)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"", b""),
        (b"a b.py\0-lead.py\0", b"a b.py\0-lead.py\0"),
        (b"nested/\0x\0", b"nested\0x\0"),  # a nested repo is listed with a slash and indexed without
        (b"\0\0nested/\0", b"nested\0"),
        (b"dir//\0", b"dir/\0"),  # only one trailing slash goes
    ],
)
def test_start_list_is_normalised_for_update_index(raw, expected):
    assert normalise_untracked(raw) == expected


def test_diff_sends_the_start_list_on_stdin_and_unstages_it(tmp_path):
    fake = FakeDocker(
        exec_result=Result(0, "deadbeef\n", "", 0.0),  # the base commit
        baseline_result=Result(0, "build/lib/x.py\0nested/\0", "", 0.0),
    )
    with make_docker(fake).start(ENV, make_budget(tmp_path)) as s:
        s.diff()
    ((argv, stdin),) = diff_calls(fake)
    script = argv[-1]
    assert argv[:4] == ["docker", "exec", "-i", CID]
    assert stdin == b"build/lib/x.py\0nested\0"  # the list the host recorded, normalised
    unstage_at = script.index("update-index --force-remove -z --stdin")
    assert script.index("add -A -f") < unstage_at < script.index("diff --cached --binary")
    assert "-C /testbed" in script
    assert "rm --cached" not in script


def test_empty_start_list_has_no_unstage_step(tmp_path):
    fake = FakeDocker(exec_result=Result(0, "deadbeef\n", "", 0.0))  # the base commit
    with make_docker(fake).start(ENV, make_budget(tmp_path)) as s:
        s.diff()
    ((argv, stdin),) = diff_calls(fake)
    assert "update-index" not in argv[-1]
    assert stdin == b""


# --- real git, no docker: the diff script against a repo shaped like a task image ---------------------


def _git_env(home):
    # Nothing from the developer's git config or environment reaches the test repos.
    return {"PATH": os.environ["PATH"], "HOME": str(home), "GIT_CONFIG_NOSYSTEM": "1"}


def _git(home, cwd, *args):
    out = subprocess.run(
        ["git", "-C", str(cwd), "-c", "user.name=t", "-c", "user.email=t@t", *args],
        check=True,
        capture_output=True,
        text=True,
        env=_git_env(home),
    )
    return out.stdout


def _sh(home, script, stdin=None):
    return subprocess.run(
        ["sh", "-c", script], input=stdin, capture_output=True, env=_git_env(home), check=False
    )


def _task_image_repo(home, root):
    """One commit, then the files an install leaves untracked."""
    repo = root / "testbed"
    repo.mkdir(parents=True)
    _git(home, repo, "init", "-q")
    (repo / ".gitignore").write_text("ignored/\n")
    (repo / "a.py").write_text("print('a')\n")
    _git(home, repo, "add", "-A")
    _git(home, repo, "commit", "-qm", "base")
    for rel, text in [
        ("build/lib/x.py", "old build\n"),
        ("a b.py", "spaces\n"),
        ("*.py", "literal glob\n"),
        ("-lead.py", "leading dash\n"),
        ("ignored/old.txt", "ignored\n"),
    ]:
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
    nested = repo / "nested"
    nested.mkdir()
    _git(home, nested, "init", "-q")
    (nested / "inner.txt").write_text("inner\n")
    _git(home, nested, "add", "-A")
    _git(home, nested, "commit", "-qm", "inner")
    return repo


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git on PATH")
def test_real_git_patch_leaves_start_files_out_and_applies_to_a_fresh_copy(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    repo = _task_image_repo(home, tmp_path / "start")
    base = _git(home, repo, "rev-parse", "HEAD").strip()
    listed = _sh(home, _BASELINE_SCRIPT.format(workdir=shlex.quote(str(repo))))
    assert listed.returncode == 0, listed.stderr
    baseline = normalise_untracked(listed.stdout)
    for name in (b"build/lib/x.py", b"a b.py", b"*.py", b"-lead.py", b"ignored/old.txt", b"nested"):
        assert name + b"\0" in baseline, name
    # attacker session: a tracked edit, a new file, an edit and a delete of files untracked at start.
    # A deleted start-list path is not in the temp index, and that must not fail the unstage.
    (repo / "a.py").write_text("print('changed')\n")
    (repo / "new.py").write_text("print('new')\n")
    (repo / "build" / "lib" / "x.py").write_text("attacker build\n")
    (repo / "-lead.py").unlink()
    script = _DIFF_SCRIPT.format(
        workdir=shlex.quote(str(repo)),
        base=shlex.quote(base),
        unstage=_UNSTAGE_SCRIPT.format(workdir=shlex.quote(str(repo))),
    )
    res = _sh(home, script, stdin=baseline)
    assert res.returncode == 0, res.stderr
    headers = [line for line in res.stdout.decode().splitlines() if line.startswith("diff --git ")]
    assert headers == ["diff --git a/a.py b/a.py", "diff --git a/new.py b/new.py"]
    assert b"+print('changed')" in res.stdout
    # the same start state, built again: the patch must apply there
    fresh = _task_image_repo(home, tmp_path / "fresh")
    patch = tmp_path / "attack.patch"
    patch.write_bytes(res.stdout)
    check = subprocess.run(
        ["git", "-C", str(fresh), "apply", "--check", str(patch)],
        capture_output=True,
        text=True,
        env=_git_env(home),
        check=False,
    )
    assert check.returncode == 0, check.stderr


# --- executor choice and live test -------------------------------------------------------------------


def test_executor_choice_comes_from_env(monkeypatch):
    monkeypatch.delenv("EXECUTOR", raising=False)
    assert isinstance(make_executor(), SandboxExecutor)  # the default; the docker cases are in the next lines
    monkeypatch.setenv("EXECUTOR", " Docker ")
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


TASK_ENV = EnvSpec(image="swebench/sweb.eval.x86_64.demo:latest")


def test_pull_refused_when_disk_after_pull_would_be_low(tmp_path):
    # 14 GB free, a 4.5 GB pull would leave 9.5 GB, under the 10 GB floor: skip as "disk", pull nothing.
    fake = FakeDocker(image_present=False)
    with pytest.raises(DiskRefused, match="MIN_FREE_DISK_GB"):
        make_docker(fake, disk_gb=14.0).start(TASK_ENV, make_budget(tmp_path))
    assert fake.runs() == []


def test_pull_allowed_with_room_after_pull(tmp_path):
    fake = FakeDocker(image_present=False)
    with make_docker(fake, disk_gb=15.0).start(TASK_ENV, make_budget(tmp_path)):
        pass
    assert len(fake.runs()) == 1


def test_local_image_needs_no_pull_room(tmp_path):
    fake = FakeDocker(image_present=True)
    with make_docker(fake, disk_gb=11.0).start(TASK_ENV, make_budget(tmp_path)):
        pass
    assert len(fake.runs()) == 1


def test_task_image_cap_refuses_third_task_image(tmp_path):
    fake = FakeDocker(image_present=False, task_images=["sha256:a", "sha256:b"])
    with pytest.raises(DiskRefused, match="TASK_IMAGE_CAP"):
        make_docker(fake).start(TASK_ENV, make_budget(tmp_path))
    assert fake.runs() == []


def test_task_image_cap_ignores_other_images(tmp_path):
    fake = FakeDocker(image_present=False, images=["x", "y", "z"], task_images=["sha256:a"])
    with make_docker(fake).start(TASK_ENV, make_budget(tmp_path)):
        pass
    assert len(fake.runs()) == 1


def test_release_image_removes_only_task_images():
    fake = FakeDocker()
    executor = make_docker(fake)
    assert executor.release_image("swebench/sweb.eval.x86_64.demo:latest") is True
    assert executor.release_image("pgvector/pgvector:pg16") is False
    assert executor.release_image("fde1-app:latest") is False
    assert executor.release_image("swebench/nested/name:latest") is False
    removed = fake.argvs(["docker", "image", "rm"])
    assert removed == [["docker", "image", "rm", "--", "swebench/sweb.eval.x86_64.demo:latest"]]
    assert all("-f" not in argv and "--force" not in argv for argv in removed)


def test_pull_check_uses_docker_image_store_free_space(tmp_path):
    # Host has 12 GB (7.5 GB after a 4.5 GB pull, above the floor), the VM store has 90 GB: the pull goes ahead.
    fake = FakeDocker(image_present=False)
    executor = DockerExecutor(
        runner=fake,
        disk_free_gb=lambda: 12.0,
        min_free_gb=5.0,
        image_store_free_gb=lambda: 90.0,
        platform="linux",
    )
    with executor.start(TASK_ENV, make_budget(tmp_path)):
        pass
    assert len(fake.runs()) == 1


def test_pull_refused_when_image_store_is_low(tmp_path):
    fake = FakeDocker(image_present=False)
    executor = DockerExecutor(
        runner=fake,
        disk_free_gb=lambda: 90.0,
        min_free_gb=5.0,
        image_store_free_gb=lambda: 8.0,
        platform="linux",
    )
    with pytest.raises(DiskRefused, match="Docker image store"):
        executor.start(TASK_ENV, make_budget(tmp_path))
    assert fake.runs() == []


COLIMA_DF = (
    "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
    "/dev/vdb1 102624184 2643668 94721356 3% /var/lib/docker\n"
)


@pytest.fixture(autouse=True)
def colima_absent(monkeypatch):
    """colima is looked up on this machine's PATH. Tests answer for it: absent, unless a test asks for it present."""
    monkeypatch.setattr("cheatproof.executor._colima_installed", lambda: False)


@pytest.fixture
def colima_present(monkeypatch):
    monkeypatch.setattr("cheatproof.executor._colima_installed", lambda: True)


def test_colima_store_free_reads_the_var_lib_docker_row(colima_present):
    def runner(argv, timeout, stdin=None, max_bytes=None):
        assert argv == ["colima", "ssh", "--", "df", "-Pk", "/var/lib/docker"]
        return Result(0, COLIMA_DF, "", 0.0)

    assert round(DockerExecutor(runner=runner, platform="linux")._colima_store_free_gb(), 1) == 90.3


def test_colima_df_has_its_own_short_timeout(colima_present):
    timeouts = []

    def runner(argv, timeout, stdin=None, max_bytes=None):
        timeouts.append(timeout)
        return Result(0, COLIMA_DF, "", 0.0)

    DockerExecutor(runner=runner, platform="linux")._colima_store_free_gb()
    assert timeouts == [COLIMA_DF_TIMEOUT_S]
    assert COLIMA_DF_TIMEOUT_S < IO_TIMEOUT_S


def test_colima_store_free_takes_the_docker_row_not_the_last_line(colima_present):
    # Another mount listed after /var/lib/docker: the last line is not the image store.
    df = COLIMA_DF + "tmpfs 1000 0 1000 0% /run\n"

    def runner(argv, timeout, stdin=None, max_bytes=None):
        return Result(0, df, "", 0.0)

    assert round(DockerExecutor(runner=runner, platform="linux")._colima_store_free_gb(), 1) == 90.3


def test_colima_df_without_a_docker_row_is_unreadable(colima_present):
    df = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 1 1 1 1% /\n"

    def runner(argv, timeout, stdin=None, max_bytes=None):
        return Result(0, df, "", 0.0)

    with pytest.raises(DiskRefused, match="image store unreadable"):
        DockerExecutor(runner=runner, platform="linux")._colima_store_free_gb()


def test_colima_store_free_is_none_when_colima_is_not_installed():
    def runner(argv, timeout, stdin=None, max_bytes=None):
        raise AssertionError("colima is not installed: nothing may be asked of it")

    assert DockerExecutor(runner=runner, platform="linux")._colima_store_free_gb() is None


@pytest.mark.parametrize(
    "answer",
    [
        Result(1, "", "no vm", 0.0),
        Result(TIMEOUT_EXIT_CODE, "", "\n[timed out after 120s]", 0.0, timed_out=True),
        Result(OUTPUT_KILL_EXIT_CODE, COLIMA_DF, "", 0.0, truncated=True),
        ExecutorUnavailable("colima not found on PATH"),
        OSError("ssh could not start"),
    ],
    ids=["ssh-fails", "ssh-times-out", "ssh-output-cut", "colima-vanished", "os-error"],
)
def test_colima_ssh_that_fails_is_unreadable_not_the_host_disk(colima_present, answer):
    def runner(argv, timeout, stdin=None, max_bytes=None):
        if isinstance(answer, Exception):
            raise answer
        return answer

    with pytest.raises(DiskRefused, match="image store unreadable"):
        DockerExecutor(runner=runner, disk_free_gb=lambda: 100.0, platform="linux")._colima_store_free_gb()


def test_colima_ssh_failure_refuses_the_pull_and_starts_nothing(tmp_path, colima_present):
    # The host has 100 GB, but colima is installed and its store cannot be read: no fallback to the host.
    fake = FakeDocker(image_present=False)

    def runner(argv, timeout, stdin=None, max_bytes=None):
        if argv[:1] == ["colima"]:
            return Result(1, "", "vm not running", 0.0)
        return fake(argv, timeout, stdin, max_bytes=max_bytes)

    budget = make_budget(tmp_path)
    with pytest.raises(DiskRefused, match="image store unreadable"):
        DockerExecutor(runner=runner, disk_free_gb=lambda: 100.0, platform="linux").start(TASK_ENV, budget)
    assert fake.argvs(["docker", "pull"]) == []
    assert fake.runs() == []
    assert local_runs(budget) == 0


def test_colima_absent_pull_is_measured_on_the_host(tmp_path):
    # colima is not installed: the host disk counts. 15 GB less the 4.5 GB pull keeps the 10 GB floor.
    fake = FakeDocker(image_present=False)
    executor = DockerExecutor(runner=fake, disk_free_gb=lambda: 15.0, platform="linux")
    with executor.start(TASK_ENV, make_budget(tmp_path)):
        pass
    assert len(fake.argvs(["docker", "pull"])) == 1


def test_colima_pull_refused_when_the_host_disk_would_drop_under_the_floor(tmp_path):
    # The VM store has 90 GB, but the pull grows the VM disk file on the Mac: 14 GB less 4.5 GB is under 10 GB.
    fake = FakeDocker(image_present=False)
    executor = DockerExecutor(
        runner=fake,
        disk_free_gb=lambda: 14.0,
        image_store_free_gb=lambda: 90.0,
        platform="linux",
    )
    with pytest.raises(DiskRefused, match="free host disk"):
        executor.start(TASK_ENV, make_budget(tmp_path))
    assert fake.argvs(["docker", "pull"]) == []


def test_colima_pull_allowed_when_host_and_store_both_keep_the_floor(tmp_path):
    fake = FakeDocker(image_present=False)
    executor = DockerExecutor(
        runner=fake,
        disk_free_gb=lambda: 15.0,
        image_store_free_gb=lambda: 90.0,
        platform="linux",
    )
    with executor.start(TASK_ENV, make_budget(tmp_path)):
        pass
    assert len(fake.argvs(["docker", "pull"])) == 1


def test_pull_killed_at_the_output_cap_is_unavailable_and_starts_nothing(tmp_path):
    # docker pull that printed past the cap is killed (exit 137, truncated): a failed pull, with the tail of stderr.
    answer = Result(OUTPUT_KILL_EXIT_CODE, "", "x" * 2000 + "layer 3 failed", 0.0, truncated=True)
    fake = FakeDocker(image_present=False, pull_result=answer)
    budget = make_budget(tmp_path)
    with pytest.raises(ExecutorUnavailable, match=r"docker pull failed \(137\)") as info:
        make_docker(fake).start(TASK_ENV, budget)
    assert str(info.value).endswith("layer 3 failed")
    assert len(str(info.value)) < 600  # the tail is kept, not the whole output
    assert fake.runs() == []
    assert local_runs(budget) == 1


def test_daemon_lost_mid_pull_is_unavailable_and_starts_nothing(tmp_path):
    answer = Result(1, "", "Cannot connect to the Docker daemon at unix:///var/run/docker.sock.", 0.0)
    fake = FakeDocker(image_present=False, pull_result=answer)
    budget = make_budget(tmp_path)
    with pytest.raises(ExecutorUnavailable, match="Cannot connect to the Docker daemon"):
        make_docker(fake).start(TASK_ENV, budget)
    assert fake.runs() == []
    assert fake.names_removed() == []
    assert local_runs(budget) == 1


@pytest.fixture(autouse=True)
def no_leaked_containers_between_tests():
    """_LEAKED is process-wide: clear it around each test, so one test's failed close reaches no other test's sweep."""
    _LEAKED.clear()
    yield
    _LEAKED.clear()


# --- task image prefixes (item 1: swerebench/ as well as swebench/) ----------------------------------

SWEREBENCH_ENV = EnvSpec(image="swerebench/sweb.eval.x86_64.demo:latest")


def test_task_prefixes_match_the_loader_namespaces():
    # tasks.py refuses any other namespace, so the executor must count and release exactly those.
    assert TASK_IMAGE_PREFIXES == ALLOWED_IMAGE_PREFIXES == ("swebench/", "swerebench/")


@pytest.mark.parametrize(
    "image",
    ["swebench/sweb.eval.x86_64.demo:latest", "swerebench/sweb.eval.x86_64.demo:latest"],
)
def test_images_in_either_task_namespace_are_task_images(image):
    assert is_task_image(image)


@pytest.mark.parametrize(
    "image",
    [
        "swebench/",
        "swerebench/",
        "swebench/nested/name:latest",
        "swerebench/nested/name:latest",
        "swerebenchx/name:latest",
        "other/swerebench/name:latest",
        "pgvector/pgvector:pg16",
        "fde1-app:latest",
    ],
)
def test_other_names_are_not_task_images(image):
    assert not is_task_image(image)


def test_task_image_count_filters_on_every_task_prefix(tmp_path):
    fake = FakeDocker(image_present=False)
    with make_docker(fake).start(SWEREBENCH_ENV, make_budget(tmp_path)):
        pass
    (count_argv,) = [argv for argv in fake.argvs(["docker", "images"]) if "--filter" in argv]
    assert count_argv == [
        "docker",
        "images",
        "-q",
        "--filter",
        "reference=swebench/*",
        "--filter",
        "reference=swerebench/*",
    ]


def test_swerebench_pull_counts_against_task_image_cap(tmp_path):
    fake = FakeDocker(image_present=False, task_images=["sha256:a", "sha256:b"])
    with pytest.raises(DiskRefused, match="TASK_IMAGE_CAP"):
        make_docker(fake).start(SWEREBENCH_ENV, make_budget(tmp_path))
    assert fake.runs() == []
    assert fake.argvs(["docker", "pull"]) == []


def test_release_removes_a_swerebench_task_image_without_force():
    fake = FakeDocker()
    assert make_docker(fake).release_image(SWEREBENCH_ENV.image) is True
    assert fake.argvs(["docker", "image", "rm"]) == [["docker", "image", "rm", "--", SWEREBENCH_ENV.image]]


# --- pull before run (item 8) ------------------------------------------------------------------------


def timed_calls(fake, prefix):
    """(argv, host timeout) of each call whose argv starts with prefix, in call order."""
    return [
        (argv, meta[0])
        for (argv, _), meta in zip(fake.log, fake.meta, strict=True)
        if argv[: len(prefix)] == prefix
    ]


def test_missing_task_image_is_pulled_before_docker_run_on_its_own_clock(tmp_path):
    fake = FakeDocker(image_present=False)
    with make_docker(fake).start(TASK_ENV, make_budget(tmp_path)):
        pass
    ((pull_argv, pull_timeout),) = timed_calls(fake, ["docker", "pull"])
    ((run_argv, run_timeout),) = timed_calls(fake, ["docker", "run"])
    assert pull_argv == ["docker", "pull", "--", TASK_ENV.image]
    assert pull_timeout == PULL_TIMEOUT_S == 1800
    assert run_timeout == RUN_TIMEOUT_S
    calls = [argv for argv, _ in fake.log]
    assert calls.index(pull_argv) < calls.index(run_argv)


def test_local_image_is_not_pulled(tmp_path):
    fake = FakeDocker(image_present=True)
    with make_docker(fake).start(TASK_ENV, make_budget(tmp_path)):
        pass
    assert fake.argvs(["docker", "pull"]) == []


def test_guard_refusal_pulls_nothing(tmp_path):
    fake = FakeDocker(image_present=False)
    with pytest.raises(DiskRefused, match="MIN_FREE_DISK_GB"):
        make_docker(fake, disk_gb=14.0).start(TASK_ENV, make_budget(tmp_path))
    assert fake.argvs(["docker", "pull"]) == []


@pytest.mark.parametrize(
    "answer",
    [
        Result(1, "", "manifest unknown", 0.0),
        Result(TIMEOUT_EXIT_CODE, "", "[timed out after 1800s]", 0.0, timed_out=True),
    ],
    ids=["pull-fails", "pull-times-out"],
)
def test_failed_pull_is_unavailable_starts_nothing_but_counts_its_run(tmp_path, answer):
    # The run is reserved before the pull, so a failed pull still counts one local run (see test below).
    fake = FakeDocker(image_present=False, pull_result=answer)
    budget = make_budget(tmp_path)
    with pytest.raises(ExecutorUnavailable, match="docker pull failed"):
        make_docker(fake).start(TASK_ENV, budget)
    assert fake.runs() == []
    assert local_runs(budget) == 1


def test_local_run_is_counted_before_the_pull_starts(tmp_path):
    budget = make_budget(tmp_path)
    fake = FakeDocker(image_present=False)
    counted_at_pull = []

    def runner(argv, timeout, stdin=None, max_bytes=None):
        if argv[:2] == ["docker", "pull"]:
            counted_at_pull.append(local_runs(budget))
        return fake(argv, timeout, stdin, max_bytes=max_bytes)

    with make_docker(runner).start(TASK_ENV, budget):
        pass
    assert counted_at_pull == [1]


def test_spent_local_run_cap_refuses_before_any_pull(tmp_path):
    fake = FakeDocker(image_present=False)
    with pytest.raises(BudgetExceeded, match="local run cap 0 reached"):
        make_docker(fake).start(TASK_ENV, make_budget(tmp_path, runs=0))
    assert fake.argvs(["docker", "pull"]) == []
    assert fake.runs() == []


# --- disk containment (item 2): per-file size limit, free space after each run ------------------------


def test_container_file_size_limit_defaults_to_4_gb(tmp_path, monkeypatch):
    monkeypatch.delenv("CONTAINER_FSIZE_GB", raising=False)
    fake = FakeDocker()
    with make_docker(fake).start(ENV, make_budget(tmp_path)):
        pass
    (argv,) = fake.runs()
    ulimits = [argv[i + 1] for i, arg in enumerate(argv) if arg == "--ulimit"]
    assert ulimits == ["nofile=1024:1024", f"fsize={4 * GIB}"]


@pytest.mark.parametrize(
    ("raw", "gb"),
    [("2", 2), ("1.5", 1.5), ("abc", 4), ("0.5", 4), ("nan", 4)],
)
def test_container_file_size_limit_comes_from_env_when_usable(monkeypatch, tmp_path, raw, gb):
    monkeypatch.setenv("CONTAINER_FSIZE_GB", raw)
    fake = FakeDocker()
    with make_docker(fake).start(ENV, make_budget(tmp_path)):
        pass
    (argv,) = fake.runs()
    ulimits = [argv[i + 1] for i, arg in enumerate(argv) if arg == "--ulimit"]
    assert f"fsize={int(gb * GIB)}" in ulimits


def store_executor(fake, store, *, min_free_gb=10.0, run_min_free_gb=2.0, clock=None):
    """Host disk is always fine here, so only the image store decides the post-run check."""
    clock = clock or FakeClock()
    return DockerExecutor(
        runner=fake,
        disk_free_gb=lambda: 100.0,
        min_free_gb=min_free_gb,
        run_min_free_gb=run_min_free_gb,
        image_store_free_gb=store,
        platform="linux",
        sleep=clock.sleep,
        clock=clock,
    )


def test_post_run_check_runs_after_every_command(tmp_path):
    checks = []

    def store():
        checks.append(True)
        return 90.0

    fake = FakeDocker()
    with store_executor(fake, store).start(ENV, make_budget(tmp_path)) as s:
        for _ in range(3):
            s.run("true", timeout=5)
    assert len(checks) == 3
    assert len(fake.runs()) == 1  # no reset on a healthy run


def test_command_that_fills_the_disk_is_caught_on_completion(tmp_path):
    # Same clock reading for both runs: the second command fills the store and is refused at once, not at a later check.
    free = [90.0]
    fake = FakeDocker()
    s = store_executor(fake, lambda: free[0]).start(ENV, make_budget(tmp_path))
    assert s.run("true", timeout=5).exit_code == 0
    free[0] = 1.5
    with pytest.raises(DiskRefused, match="RUN_MIN_FREE_GB=2") as info:
        s.run("dd if=/dev/zero of=/x bs=1M count=9999", timeout=5)
    assert info.value.result is not None and info.value.result.exit_code == 0
    assert len(fake.runs()) == 1  # no reset: the sandbox stays as the run left it
    s.close()


def test_disk_refused_after_a_kill_and_reset_keeps_the_reset_note(tmp_path):
    free = [90.0]
    fake = FakeDocker()
    s = store_executor(fake, lambda: free[0]).start(ENV, make_budget(tmp_path))
    fake.exec_result = Result(TIMEOUT_EXIT_CODE, "", "\n[timed out after 5s]", 0.0, timed_out=True)
    free[0] = 1.5  # the disk is low by the time the killed command's sandbox has been reset
    with pytest.raises(DiskRefused, match="sandbox was reset") as info:
        s.run("sleep 99", timeout=5)
    res = info.value.result
    assert res is not None and res.reset is True and res.timed_out is True
    assert res.exit_code == TIMEOUT_EXIT_CODE and "[timed out after 5s]" in res.stderr
    assert len(fake.runs()) == 2  # the reset started a fresh container before the check
    s.close()


def test_reset_refused_after_a_kill_keeps_the_killed_result(tmp_path):
    # The reset's start needs a pull (the image is gone) and the image store is too low for it: the reset is refused.
    free = [90.0]
    fake = FakeDocker()
    s = store_executor(fake, lambda: free[0]).start(ENV, make_budget(tmp_path))
    fake.exec_result = Result(TIMEOUT_EXIT_CODE, "", "\n[timed out after 5s]", 0.0, timed_out=True)
    fake.image_present = False
    free[0] = 3.0
    with pytest.raises(DiskRefused, match="nothing pulled") as info:
        s.run("sleep 99", timeout=5)
    res = info.value.result
    assert res is not None and res.reset is True and res.timed_out is True
    assert res.exit_code == TIMEOUT_EXIT_CODE and "[timed out after 5s]" in res.stderr
    assert fake.argvs(["docker", "pull"]) == []
    assert len(fake.runs()) == 1  # the refused reset started no container
    s.close()


def test_unreadable_image_store_after_a_run_refuses_and_poisons_the_session(tmp_path, colima_present):
    fake = FakeDocker()
    colima_down = [False]

    def runner(argv, timeout, stdin=None, max_bytes=None):
        if argv[:1] == ["colima"]:
            return Result(1, "", "vm stopped", 0.0) if colima_down[0] else Result(0, COLIMA_DF, "", 0.0)
        return fake(argv, timeout, stdin, max_bytes=max_bytes)

    executor = DockerExecutor(runner=runner, disk_free_gb=lambda: 100.0, min_free_gb=10.0, platform="linux")
    s = executor.start(ENV, make_budget(tmp_path))
    colima_down[0] = True
    with pytest.raises(DiskRefused, match="image store unreadable"):
        s.run("true", timeout=5)
    with pytest.raises(DiskRefused, match="image store unreadable"):
        s.run("true", timeout=5)  # poisoned: refused before docker is asked anything
    s.close()


def test_post_run_check_that_cannot_read_the_disk_poisons_the_session(tmp_path):
    # Any failure to read the free disk after a run refuses like a low disk: the result travels, the session is poisoned.
    broken = [False]

    def store():
        if broken[0]:
            raise OSError("df could not run")
        return 90.0

    fake = FakeDocker()
    s = store_executor(fake, store).start(ENV, make_budget(tmp_path))
    broken[0] = True
    with pytest.raises(DiskRefused, match="df could not run") as info:
        s.run("true", timeout=5)
    assert info.value.result is not None and info.value.result.exit_code == 0
    calls = len(fake.log)
    with pytest.raises(DiskRefused, match="df could not run"):
        s.run("true", timeout=5)  # poisoned: refused before docker is asked anything
    assert len(fake.log) == calls
    assert len(fake.runs()) == 1  # no reset: the sandbox stays as the run left it
    s.close()


def test_healthy_run_right_after_a_pull_does_not_trip_the_post_run_check(tmp_path):
    # The pull takes the free disk from 15 GB to 6 GB: under MIN_FREE_DISK_GB=10, over RUN_MIN_FREE_GB=2.
    free = [15.0]
    fake = FakeDocker(image_present=False)

    def runner(argv, timeout, stdin=None, max_bytes=None):
        if argv[:2] == ["docker", "pull"]:
            free[0] = 6.0
        return fake(argv, timeout, stdin, max_bytes=max_bytes)

    clock = FakeClock()
    executor = DockerExecutor(
        runner=runner,
        disk_free_gb=lambda: free[0],
        min_free_gb=10.0,
        platform="linux",
        sleep=clock.sleep,
        clock=clock,
    )
    with executor.start(TASK_ENV, make_budget(tmp_path)) as s:
        assert s.run("true", timeout=5).exit_code == 0
    assert len(fake.runs()) == 1


@pytest.mark.parametrize(("free", "refused"), [(1.5, True), (2.5, False)], ids=["below-floor", "above-floor"])
def test_post_run_floor_is_run_min_free_gb(tmp_path, free, refused):
    disk = [100.0]
    fake = FakeDocker()
    clock = FakeClock()
    executor = DockerExecutor(
        runner=fake,
        disk_free_gb=lambda: disk[0],
        min_free_gb=10.0,
        platform="linux",
        sleep=clock.sleep,
        clock=clock,
    )
    with executor.start(ENV, make_budget(tmp_path)) as s:
        disk[0] = free  # the disk drops during the run; the start floor (10 GB) does not apply to a run
        if refused:
            with pytest.raises(DiskRefused, match="RUN_MIN_FREE_GB=2"):
                s.run("true", timeout=5)
        else:
            assert s.run("true", timeout=5).exit_code == 0


@pytest.mark.parametrize(("raw", "floor"), [("3", 3.0), ("abc", 2.0), ("0.5", 2.0), ("nan", 2.0), ("", 2.0)])
def test_run_min_free_comes_from_env_when_usable(monkeypatch, raw, floor):
    monkeypatch.setenv("RUN_MIN_FREE_GB", raw)
    assert DockerExecutor(runner=FakeDocker(), platform="linux")._run_min_free_gb == floor


def test_low_disk_after_a_run_poisons_the_session_and_resets_nothing(tmp_path):
    fake = FakeDocker()
    checks = []

    def store():
        checks.append(True)
        return 1.5  # below RUN_MIN_FREE_GB=2

    budget = make_budget(tmp_path)
    s = store_executor(fake, store).start(ENV, budget)
    with pytest.raises(DiskRefused, match="Docker image store"):
        s.run("dd if=/dev/zero of=/x bs=1M count=9999", timeout=5)
    assert len(checks) == 1
    assert len(fake.runs()) == 1  # no reset: the sandbox stays as the run left it
    assert fake.names_removed() == []
    s.close()
    assert fake.names_removed() == [run_name(fake, 0)]
    assert local_runs(budget) == 1


@pytest.mark.parametrize(
    "call",
    [
        lambda s: s.run("true", timeout=5),
        lambda s: s.write_file("notes.txt", b"x"),
        lambda s: s.diff(),
        lambda s: s.reset(),
    ],
    ids=["run", "write_file", "diff", "reset"],
)
def test_poisoned_session_refuses_every_call_but_close(tmp_path, call):
    fake = FakeDocker()
    s = store_executor(fake, lambda: 1.5).start(ENV, make_budget(tmp_path))
    with pytest.raises(DiskRefused):
        s.run("dd if=/dev/zero of=/x bs=1M count=9999", timeout=5)
    calls = len(fake.log)
    with pytest.raises(DiskRefused, match="RUN_MIN_FREE_GB"):
        call(s)
    assert len(fake.log) == calls  # nothing reached docker: no exec, no reset, no daemon check
    assert len(fake.runs()) == 1
    s.close()  # close still removes the sandbox
    assert fake.names_removed() == [run_name(fake, 0)]


def test_colima_missing_from_path_falls_back_to_the_host_for_pulls_and_runs(tmp_path):
    fake = FakeDocker(image_present=False)

    def runner(argv, timeout, stdin=None, max_bytes=None):
        if argv[:1] == ["colima"]:
            raise ExecutorUnavailable("colima not found on PATH")  # what subprocess_runner raises
        return fake(argv, timeout, stdin, max_bytes=max_bytes)

    assert DockerExecutor(runner=runner, platform="linux")._colima_store_free_gb() is None
    # Host 15 GB: a 4.5 GB pull leaves 10.5 GB, above the floor, so the pull goes ahead on the host count.
    executor = DockerExecutor(runner=runner, disk_free_gb=lambda: 15.0, platform="linux")
    with executor.start(TASK_ENV, make_budget(tmp_path)) as s:
        assert s.run("true", timeout=5).exit_code == 0
    assert len(fake.argvs(["docker", "pull"])) == 1
    assert len(fake.runs()) == 1


# --- output cap kill (item 6) -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("answer", "resets"),
    [
        (Result(OUTPUT_KILL_EXIT_CODE, "x" * 100, "", 0.0, truncated=True), True),
        (Result(OUTPUT_KILL_EXIT_CODE, "", "", 0.0), False),  # the command's own exit 137, no cap hit
    ],
    ids=["host-killed-at-output-cap", "command-exits-137-by-itself"],
)
def test_output_cap_kill_resets_the_sandbox_and_marks_the_result(tmp_path, answer, resets):
    fake = FakeDocker()
    budget = make_budget(tmp_path)
    with make_docker(fake).start(ENV, budget) as s:
        fake.exec_result = answer
        res = s.run("cat huge", timeout=5)
        fake.exec_result = Result(0, "", "", 0.0)
    assert res.exit_code == OUTPUT_KILL_EXIT_CODE
    assert res.truncated is answer.truncated
    # The same reset signal a host timeout carries. timed_out stays for the host timeout alone.
    assert res.reset is resets
    assert res.timed_out is False
    assert len(fake.runs()) == (2 if resets else 1)
    assert local_runs(budget) == (2 if resets else 1)


# --- containers whose close failed (item 5) -----------------------------------------------------------


def test_container_whose_close_failed_is_removed_by_the_next_sweep(tmp_path):
    fake = FakeDocker(rm_results=[Result(1, "", "device or resource busy", 0.0)])
    s = make_docker(fake).start(ENV, make_budget(tmp_path))
    with pytest.raises(RuntimeError, match="device or resource busy"):
        s.close()
    name = run_name(fake)
    assert _LEAKED == {name}
    # The next task opens a new executor. Its owner pid is this process, which is alive, so only _LEAKED finds it.
    assert make_docker(fake).sweep_leftovers() == 1
    assert fake.names_removed() == [name, name]
    assert _LEAKED == set()


def test_close_retry_that_succeeds_clears_the_leak(tmp_path):
    fake = FakeDocker(rm_results=[Result(1, "", "device or resource busy", 0.0)])
    s = make_docker(fake).start(ENV, make_budget(tmp_path))
    with pytest.raises(RuntimeError, match="device or resource busy"):
        s.close()
    assert _LEAKED == {run_name(fake)}
    s.close()
    assert _LEAKED == set()


def test_leak_that_still_cannot_be_removed_stays_for_the_next_try(tmp_path):
    fake = FakeDocker(rm_results=[Result(1, "", "busy", 0.0), Result(1, "", "busy", 0.0)])
    s = make_docker(fake).start(ENV, make_budget(tmp_path))
    with pytest.raises(RuntimeError, match="busy"):
        s.close()
    name = run_name(fake)
    assert make_docker(fake).sweep_leftovers() == 0
    assert _LEAKED == {name}


def test_failed_start_cleanup_that_cannot_remove_is_swept_later(tmp_path):
    fake = FakeDocker(
        exec_raises=ExecutorUnavailable("lost the daemon"), rm_results=[Result(1, "", "busy", 0.0)]
    )
    with pytest.raises(ExecutorUnavailable, match="lost the daemon"):
        make_docker(fake).start(ENV, make_budget(tmp_path))
    name = run_name(fake)
    assert _LEAKED == {name}
    assert make_docker(fake).sweep_leftovers() == 1
    assert fake.names_removed() == [name, name]
    assert _LEAKED == set()


def test_release_image_removes_a_leaked_container_first_and_never_forces_the_image(tmp_path):
    fake = FakeDocker(rm_results=[Result(1, "", "device or resource busy", 0.0)])
    s = make_docker(fake).start(TASK_ENV, make_budget(tmp_path))
    with pytest.raises(RuntimeError, match="device or resource busy"):
        s.close()
    name = run_name(fake)
    assert make_docker(fake).release_image(TASK_ENV.image) is True
    calls = [argv for argv, _ in fake.log]
    image_rm = ["docker", "image", "rm", "--", TASK_ENV.image]
    assert calls.index(["docker", "rm", "-f", name]) < calls.index(image_rm)
    assert "-f" not in image_rm and "--force" not in image_rm
    assert _LEAKED == set()


def test_sweep_leaves_a_live_sessions_container_alone(tmp_path):
    fake = FakeDocker()
    with make_docker(fake).start(ENV, make_budget(tmp_path)):
        assert make_docker(fake).sweep_leftovers() == 0
        assert fake.argvs(["docker", "rm"]) == []
    assert fake.names_removed() == [run_name(fake)]  # only the session's own close removed it
