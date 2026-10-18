"""Execution backends for untrusted task code (ADR 0002).

Local Docker runs each session in a container with no network (unless EnvSpec asks), CPU, memory
and PID limits, and no host mounts. Files reach the container over stdin. Token Factory Sandboxes
is a stub until access is granted (U3). Every session start, including a reset, reserves one
sandbox run in cheatproof/budget.py before the container exists.
"""

from __future__ import annotations

import os
import posixpath
import shlex
import shutil
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Protocol, Self

from cheatproof.budget import Budget

MAX_OUTPUT_BYTES = 64 * 1024  # per stream, per run() call
TIMEOUT_EXIT_CODE = 124  # same as timeout(1)
PIDS_LIMIT = 512
DAEMON_WAIT_S = 120
DAEMON_POLL_S = 5
DAEMON_CHECK_TIMEOUT_S = 30
IO_TIMEOUT_S = 120
RUN_TIMEOUT_S = 900  # docker run may pull an image first
DESTROY_TIMEOUT_S = 60
GIB = 1024**3


class ExecutorRefused(RuntimeError):
    """A guard stopped a new image pull (low disk, too many local images). Nothing was deleted."""


class ExecutorUnavailable(RuntimeError):
    """The backend cannot start a session now (Docker daemon down, Sandboxes not enabled)."""


@dataclass(frozen=True)
class EnvSpec:
    image: str
    workdir: str = "/testbed"
    network: bool = False
    cpus: float = 2.0
    memory: str = "4g"


@dataclass(frozen=True)
class Result:
    exit_code: int
    stdout: str
    stderr: str
    duration: float


# argv (no shell), timeout in seconds, stdin -> Result. The runner enforces the timeout.
Runner = Callable[[list[str], float, bytes | None], Result]


def _decode(raw: bytes | str | None) -> str:
    if raw is None:
        return ""
    return raw if isinstance(raw, str) else raw.decode("utf-8", "replace")


def subprocess_runner(argv: list[str], timeout: float, stdin: bytes | None = None) -> Result:
    """Default runner. A timeout returns exit 124 with a note in stderr instead of raising."""
    started = time.monotonic()
    try:
        proc = subprocess.run(argv, input=stdin, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        note = f"\n[timed out after {timeout:g}s]"
        elapsed = time.monotonic() - started
        return Result(TIMEOUT_EXIT_CODE, _decode(exc.stdout), _decode(exc.stderr) + note, elapsed)
    except FileNotFoundError as exc:
        raise ExecutorUnavailable(f"{argv[0]} not found on PATH") from exc
    return Result(proc.returncode, _decode(proc.stdout), _decode(proc.stderr), time.monotonic() - started)


def _cap(text: str) -> str:
    raw = text.encode("utf-8", "replace")
    if len(raw) <= MAX_OUTPUT_BYTES:
        return text
    kept = raw[:MAX_OUTPUT_BYTES].decode("utf-8", "ignore")
    return f"{kept}\n[truncated {len(raw) - MAX_OUTPUT_BYTES} bytes]"


def _root_free_gb() -> float:
    return shutil.disk_usage("/").free / GIB


class Session(ABC):
    """One running sandbox. Use as a context manager so it is always closed."""

    @abstractmethod
    def run(self, cmd: str, timeout: float) -> Result:
        """Run cmd with `sh -lc` in the workdir. Timeout gives exit 124. Output capped per stream."""

    @abstractmethod
    def write_file(self, path: str, data: bytes | str) -> None:
        """Write data to path (relative paths start in the workdir), creating parent directories."""

    @abstractmethod
    def diff(self) -> str:
        """Patch of all changes since start, tracked and untracked. Raises if git fails."""

    @abstractmethod
    def reset(self) -> None:
        """Destroy the sandbox and start a fresh one from the same image. Reserves one sandbox run."""

    @abstractmethod
    def close(self) -> None:
        """Destroy the sandbox. Safe to call twice."""

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


class Executor(Protocol):
    def start(self, env: EnvSpec, budget: Budget | None = None) -> Session: ...


class DockerExecutor:
    """Local Docker backend. Shells out to the docker CLI through an injectable runner."""

    def __init__(
        self,
        *,
        runner: Runner = subprocess_runner,
        disk_free_gb: Callable[[], float] = _root_free_gb,
        min_free_gb: float | None = None,
        image_cap: int | None = None,
        platform: str = sys.platform,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._runner = runner
        self._disk_free_gb = disk_free_gb
        self._min_free_gb = (
            min_free_gb if min_free_gb is not None else float(os.environ.get("MIN_FREE_DISK_GB", "10"))
        )
        self._image_cap = image_cap if image_cap is not None else int(os.environ.get("DOCKER_IMAGE_CAP", "6"))
        self._platform = platform
        self._sleep = sleep
        self._clock = clock

    def start(self, env: EnvSpec, budget: Budget | None = None) -> Session:
        return DockerSession(self, env, Budget.from_env() if budget is None else budget)

    def _docker(self, args: list[str], timeout: float, stdin: bytes | None = None) -> Result:
        return self._runner(["docker", *args], timeout, stdin)

    def _ensure_daemon(self) -> None:
        if self._docker(["info"], DAEMON_CHECK_TIMEOUT_S).exit_code == 0:
            return
        if self._platform != "darwin":
            raise ExecutorUnavailable("Docker daemon is not running; start Docker and retry")
        self._runner(["open", "-a", "Docker"], DAEMON_CHECK_TIMEOUT_S, None)
        deadline = self._clock() + DAEMON_WAIT_S
        while True:
            self._sleep(DAEMON_POLL_S)
            if self._docker(["info"], DAEMON_CHECK_TIMEOUT_S).exit_code == 0:
                return
            if self._clock() >= deadline:
                break
        raise ExecutorUnavailable(f"Docker daemon still down {DAEMON_WAIT_S}s after 'open -a Docker'")

    def _preflight(self, image: str) -> None:
        # Only a pull needs guards. A local image starts with no disk or image-count check.
        if self._docker(["image", "inspect", image], IO_TIMEOUT_S).exit_code == 0:
            return
        free = self._disk_free_gb()
        if free < self._min_free_gb:
            raise ExecutorRefused(
                f"{image} is not local and free disk is {free:.1f} GB, below MIN_FREE_DISK_GB="
                f"{self._min_free_gb:g}; nothing pulled"
            )
        count = self._local_image_count()
        if count >= self._image_cap:
            raise ExecutorRefused(
                f"{image} is not local and {count} images are present, at DOCKER_IMAGE_CAP="
                f"{self._image_cap}; nothing pulled, nothing deleted"
            )

    def _local_image_count(self) -> int:
        res = self._docker(["images", "-q"], IO_TIMEOUT_S)
        if res.exit_code != 0:
            raise ExecutorUnavailable(f"docker images failed: {res.stderr.strip()[-300:]}")
        return len({line.strip() for line in res.stdout.splitlines() if line.strip()})

    def _create(self, env: EnvSpec) -> str:
        network = "bridge" if env.network else "none"
        argv = [
            "run",
            "-d",
            "--rm",
            "--network",
            network,
            "--cpus",
            str(env.cpus),
            "--memory",
            env.memory,
            "--pids-limit",
            str(PIDS_LIMIT),
            "--security-opt",
            "no-new-privileges",
            "--workdir",
            env.workdir,
            env.image,
            "sleep",
            "infinity",
        ]
        res = self._docker(argv, RUN_TIMEOUT_S)
        cid = res.stdout.strip()
        if res.exit_code != 0 or not cid:
            raise ExecutorUnavailable(f"docker run failed ({res.exit_code}): {res.stderr.strip()[-500:]}")
        return cid

    def _base_commit(self, cid: str, workdir: str) -> str:
        script = f"cd {shlex.quote(workdir)} && git rev-parse HEAD"
        res = self._docker(["exec", cid, "sh", "-c", script], IO_TIMEOUT_S)
        return res.stdout.strip() if res.exit_code == 0 else ""


class DockerSession(Session):
    def __init__(self, executor: DockerExecutor, env: EnvSpec, budget: Budget) -> None:
        self._executor = executor
        self._env = env
        self._budget = budget
        self._cid: str | None = None
        self._base = ""
        self._closed = False
        self._launch()

    def _launch(self) -> None:
        self._executor._ensure_daemon()
        self._executor._preflight(self._env.image)
        self._budget.reserve_sandbox_run()  # before the container exists; BudgetExceeded propagates
        self._cid = self._executor._create(self._env)
        self._base = self._executor._base_commit(self._cid, self._env.workdir)

    def _live(self) -> str:
        if self._closed:
            raise RuntimeError("session is closed")
        if self._cid is None:
            raise RuntimeError("no live sandbox: an earlier reset() failed; call reset() again")
        return self._cid

    def _destroy(self) -> None:
        if self._cid is not None:
            # docker rm -f kills the container. Exit code ignored: --rm may already have removed it.
            self._executor._docker(["rm", "-f", self._cid], DESTROY_TIMEOUT_S)
            self._cid = None

    def run(self, cmd: str, timeout: float) -> Result:
        res = self._executor._docker(["exec", self._live(), "sh", "-lc", cmd], timeout)
        return replace(res, stdout=_cap(res.stdout), stderr=_cap(res.stderr))

    def write_file(self, path: str, data: bytes | str) -> None:
        payload = data.encode("utf-8") if isinstance(data, str) else data
        script = f"cat > {shlex.quote(path)}"
        parent = posixpath.dirname(path)
        if parent:
            script = f"mkdir -p -- {shlex.quote(parent)} && {script}"
        res = self._executor._docker(["exec", "-i", self._live(), "sh", "-c", script], IO_TIMEOUT_S, payload)
        if res.exit_code != 0:
            raise RuntimeError(f"write_file {path!r} failed ({res.exit_code}): {res.stderr.strip()[-300:]}")

    def diff(self) -> str:
        # Diffs against the commit recorded at start, so a commit made inside the sandbox cannot hide changes.
        # git add -A stages untracked files; .gitignore still applies. Output is not capped.
        base = shlex.quote(self._base or "HEAD")
        workdir = shlex.quote(self._env.workdir)
        script = f"cd {workdir} && git add -A && git diff --cached --no-color --binary {base}"
        res = self._executor._docker(["exec", self._live(), "sh", "-c", script], IO_TIMEOUT_S)
        if res.exit_code != 0:
            raise RuntimeError(f"diff failed ({res.exit_code}): {res.stderr.strip()[-300:]}")
        return res.stdout

    def reset(self) -> None:
        if self._closed:
            raise RuntimeError("session is closed")
        self._destroy()
        self._launch()

    def close(self) -> None:
        if not self._closed:
            self._destroy()
            self._closed = True


class SandboxExecutor:
    """Token Factory Sandboxes backend (ADR 0002). Stub: access is gated (U3), so start() refuses.

    contree_sdk is imported only once access exists, so this module imports without it.
    """

    def start(self, env: EnvSpec, budget: Budget | None = None) -> Session:
        raise ExecutorUnavailable("Sandboxes access pending (U3)")


def make_executor(name: str | None = None) -> Executor:
    """Backend named by EXECUTOR (default docker)."""
    choice = (name or os.environ.get("EXECUTOR") or "docker").strip().lower()
    if choice == "docker":
        return DockerExecutor()
    if choice == "sandbox":
        return SandboxExecutor()
    raise ValueError(f"EXECUTOR must be docker or sandbox, got {choice!r}")


def start(env: EnvSpec, budget: Budget | None = None, executor: Executor | None = None) -> Session:
    """Start a session on the backend named by EXECUTOR, or on the given executor."""
    return (make_executor() if executor is None else executor).start(env, budget)
