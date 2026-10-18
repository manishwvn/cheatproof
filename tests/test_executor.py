import shlex
import sys

import pytest

from cheatproof.budget import Budget, BudgetExceeded
from cheatproof.executor import (
    MAX_OUTPUT_BYTES,
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


class FakeDocker:
    """Stands in for the docker CLI. Records every call and answers the ones the executor makes."""

    def __init__(self, *, image_present=True, images=(), info_down_for=0, run_exit=0, exec_result=None):
        self.image_present = image_present
        self.images = list(images)
        self.info_down_for = info_down_for
        self.run_exit = run_exit
        self.exec_result = exec_result or Result(0, "", "", 0.0)
        self.on_run = None
        self.log: list[tuple[list[str], bytes | None]] = []

    def __call__(self, argv, timeout, stdin=None):
        self.log.append((list(argv), stdin))
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
            return Result(self.run_exit, f"{CID}\n", "" if self.run_exit == 0 else "pull denied", 0.0)
        if argv[:2] == ["docker", "exec"]:
            return self.exec_result
        return Result(0, "", "", 0.0)

    def argvs(self, prefix):
        return [argv for argv, _ in self.log if argv[: len(prefix)] == prefix]

    def runs(self):
        return self.argvs(["docker", "run"])


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
    assert fake.argvs(["docker", "exec", CID, "sh", "-lc"]) == [
        ["docker", "exec", CID, "sh", "-lc", "echo ok"]
    ]


def test_network_true_uses_bridge(tmp_path):
    fake = FakeDocker()
    with make_docker(fake).start(EnvSpec(image=IMAGE, network=True), make_budget(tmp_path)):
        pass
    (argv,) = fake.runs()
    assert argv[argv.index("--network") + 1] == "bridge"
    assert "none" not in argv


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
    calls = [argv for argv, _ in fake.log]
    rm = calls.index(["docker", "rm", "-f", CID])
    runs = [i for i, argv in enumerate(calls) if argv[:2] == ["docker", "run"]]
    assert runs[0] < rm < runs[1]


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


def test_timeout_returns_124_with_note_and_does_not_raise(tmp_path):
    fake = FakeDocker()
    sleeper = [sys.executable, "-c", "import time; time.sleep(30)"]

    def runner(argv, timeout, stdin=None):
        if "-lc" in argv:
            return subprocess_runner(sleeper, timeout, stdin)
        return fake(argv, timeout, stdin)

    with make_docker(runner).start(ENV, make_budget(tmp_path)) as s:
        res = s.run("sleep 99", timeout=0.5)
    assert res.exit_code == 124
    assert "timed out after 0.5s" in res.stderr


def test_default_runner_passes_argv_without_shell_and_reports_exit():
    res = subprocess_runner([sys.executable, "-c", "import sys; sys.stdout.write('ok'); sys.exit(3)"], 10)
    assert (res.exit_code, res.stdout) == (3, "ok")


def test_default_runner_reports_missing_binary_as_unavailable():
    with pytest.raises(ExecutorUnavailable, match="not found"):
        subprocess_runner(["cheatproof-no-such-binary"], 5)


def test_run_output_is_capped_per_stream(tmp_path):
    big = "a" * (MAX_OUTPUT_BYTES * 3)
    fake = FakeDocker(exec_result=Result(0, big, big, 0.0))
    with make_docker(fake).start(ENV, make_budget(tmp_path)) as s:
        res = s.run("cat big", timeout=5)
    for stream in (res.stdout, res.stderr):
        assert len(stream.encode()) < MAX_OUTPUT_BYTES + 100
        assert "[truncated" in stream


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


def test_diff_stages_everything_and_diffs_against_start_commit(tmp_path):
    fake = FakeDocker(exec_result=Result(0, "deadbeef\n", "", 0.0))
    with make_docker(fake).start(ENV, make_budget(tmp_path)) as s:
        fake.exec_result = Result(0, "diff --git a/x b/x\n", "", 0.0)
        out = s.diff()
        script = fake.argvs(["docker", "exec"])[-1][-1]
    assert out == "diff --git a/x b/x\n"
    assert "git add -A" in script
    assert "git diff --cached" in script
    assert "deadbeef" in script


def test_diff_failure_raises_instead_of_empty_patch(tmp_path):
    fake = FakeDocker()
    with make_docker(fake).start(ENV, make_budget(tmp_path)) as s:
        fake.exec_result = Result(128, "", "fatal: not a git repository", 0.0)
        with pytest.raises(RuntimeError, match="not a git repository"):
            s.diff()


def test_close_is_idempotent_and_blocks_later_use(tmp_path):
    fake = FakeDocker()
    s = make_docker(fake).start(ENV, make_budget(tmp_path))
    s.close()
    s.close()
    assert len(fake.argvs(["docker", "rm"])) == 1
    with pytest.raises(RuntimeError, match="closed"):
        s.run("true", 5)


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
    with start(EnvSpec(image=IMAGE), executor=DockerExecutor()) as s:
        res = s.run("echo ok", timeout=120)
    assert res.exit_code == 0
    assert res.stdout.strip() == "ok"
