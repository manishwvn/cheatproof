"""Execution backends for untrusted task code (ADR 0002).

Local Docker runs each session in a container with no network (unless EnvSpec asks), CPU, memory
and PID limits, and no host mounts. Files reach the container over stdin. Token Factory Sandboxes
is a stub until access is granted (U3). Every session start, including a reset, reserves one
sandbox run in cheatproof/budget.py before the container exists.
"""

from __future__ import annotations

import contextlib
import math
import os
import posixpath
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Protocol, Self

from cheatproof.budget import Budget

MAX_OUTPUT_BYTES = 64 * 1024  # kept per stream, per run() call
OUTPUT_MARGIN_BYTES = 4 * 1024  # the host reads this far past the cap, then kills the client
MAX_DIFF_BYTES = 8 * 1024 * 1024  # diff() raises above this; it never truncates a patch
MAX_RUN_TIMEOUT_S = 1800
EXEC_GRACE_S = 10  # host waits this long past the in-container timeout before it kills docker exec
TIMEOUT_EXIT_CODE = 124  # same as timeout(1)
OUTPUT_KILL_EXIT_CODE = 137  # 128 + SIGKILL: the host killed the client for exceeding its output cap
PIDS_LIMIT = 512
DAEMON_WAIT_S = 120
DAEMON_POLL_S = 5
DAEMON_CHECK_TIMEOUT_S = 30
IO_TIMEOUT_S = 120
RUN_TIMEOUT_S = 900  # docker run may pull an image first
DESTROY_TIMEOUT_S = 60
GIB = 1024**3
READ_CHUNK = 64 * 1024
PIPE_POLL_S = 0.05
PIPE_JOIN_S = 2
IMAGE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./:@-]*")
TMPFS_MAX_MB = 4096  # DOCKER_TMPFS_MB above this is clamped: tmpfs pages come out of the memory limit
OWNER_RE = re.compile(r"[1-9][0-9]*")  # a cheatproof.owner label is a decimal pid: no 0, no leading zeros
PID_MAX = 2**31 - 1  # pid_t is a signed 32-bit int: a larger label cannot name a process
# One line per container: its ID, then its cheatproof.owner label (empty when the label is missing).
SWEEP_FORMAT = '{{.ID}} {{.Label "cheatproof.owner"}}'

# Runs in the container as `sh -lc <this> cheatproof <cmd>`, so $1 is the command. timeout(1) with KILL
# stops a command that ignores TERM. Without timeout(1) in the image the command is unbounded inside, and
# the host backstop in DockerSession.run is the only limit.
_IN_CONTAINER_TIMEOUT = (
    'if command -v timeout >/dev/null 2>&1; then exec timeout -s KILL {seconds} sh -lc "$1"; '
    'else exec sh -lc "$1"; fi'
)

# Runs in the container. A fresh index file, read from the start commit, means a replace ref, an
# assume-unchanged bit or a skip-worktree bit in the sandbox cannot hide a change. The index path must not
# exist yet (git rejects an empty index file), so it lives in a new temp directory. Repo-level git config
# and attributes are still untrusted: T05/T06 restore the hidden tests at grade time. -f stages ignored
# files too (an attacker can hide a file via .git/info/exclude); bytecode and cache dirs are left out to keep
# the patch small, so the grader must clear __pycache__ before grading (stale .pyc is a hole of its own).
_DIFF_SCRIPT = (
    'set -e; export GIT_CONFIG_NOSYSTEM=1; tmp=$(mktemp -d); export GIT_INDEX_FILE="$tmp/index"; '
    "trap 'rm -rf \"$tmp\"' EXIT; "
    "git --no-replace-objects -C {workdir} -c core.excludesFile=/dev/null read-tree {base}; "
    "git --no-replace-objects -C {workdir} -c core.excludesFile=/dev/null add -A -f -- . "
    "':(exclude,glob)**/__pycache__/**' ':(exclude,glob)**/.pytest_cache/**' ':(exclude,glob)**/*.egg-info/**'; "
    "git --no-replace-objects -C {workdir} -c core.excludesFile=/dev/null "
    "diff --cached --binary --no-color --no-ext-diff --no-textconv {base}"
)


class ExecutorRefused(RuntimeError):
    """A guard stopped a session start or reset (low disk, too many local images). No image was deleted."""


class ExecutorUnavailable(RuntimeError):
    """The backend cannot start a session now (Docker daemon down, Sandboxes not enabled)."""


@dataclass(frozen=True)
class EnvSpec:
    image: str
    workdir: str = "/testbed"
    network: bool = False
    cpus: float = 2.0
    memory: str = "4g"

    def __post_init__(self) -> None:
        # The image becomes a docker positional argument. A name that could parse as an option
        # (--privileged, --network=host) is refused here, before any docker call.
        if not IMAGE_RE.fullmatch(self.image):
            raise ValueError(f"invalid image name {self.image!r}: use letters, digits and ._:@/- only")


@dataclass(frozen=True)
class Result:
    exit_code: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False  # the host killed the client at its timeout
    truncated: bool = False  # output was cut at a cap; diff() raises instead of setting this


# argv (no shell), timeout in seconds, stdin -> Result. The runner enforces the timeout.
# Callers pass max_bytes only when they set it; the default runner accepts it.
Runner = Callable[..., Result]


def _decode(raw: bytes | str | None) -> str:
    if raw is None:
        return ""
    return raw if isinstance(raw, str) else raw.decode("utf-8", "replace")


def _kill_group(proc: subprocess.Popen) -> None:
    """SIGKILL the client's process group (the client leads it), then reap the client."""
    with contextlib.suppress(OSError):  # the group may already be gone
        os.killpg(proc.pid, signal.SIGKILL)
    proc.wait()


class _Pipe:
    """Reads one child pipe on a thread. Keeps at most `limit` bytes, then stops and sets `overflow`."""

    def __init__(self, stream, limit: int, overflow: threading.Event) -> None:
        self._stream = stream
        self._limit = limit
        self._overflow = overflow
        self.buf = bytearray()
        self.over = False
        self._thread = threading.Thread(target=self._pump, daemon=True)
        self._thread.start()

    def _pump(self) -> None:
        fd = self._stream.fileno()
        while True:
            try:
                chunk = os.read(fd, READ_CHUNK)
            except OSError:
                return
            if not chunk:
                return
            room = self._limit - len(self.buf)
            if len(chunk) > room:
                self.buf += chunk[:room]
                self.over = True
                self._overflow.set()
                return
            self.buf += chunk

    def finish(self) -> None:
        self._thread.join(PIPE_JOIN_S)
        if not self._thread.is_alive():
            self._stream.close()


def _feed(stream, data: bytes) -> None:
    with contextlib.suppress(OSError):  # the client exited or was killed before it read all of stdin
        stream.write(data)
    with contextlib.suppress(OSError):
        stream.close()


def subprocess_runner(
    argv: list[str],
    timeout: float,
    stdin: bytes | None = None,
    *,
    max_bytes: int = MAX_OUTPUT_BYTES + OUTPUT_MARGIN_BYTES,
) -> Result:
    """Default runner. argv runs without a shell.

    Each stream is read through a pipe up to max_bytes. Past that the client is killed and the result is
    marked truncated, so host memory stays bounded. A timeout kills the client and returns exit 124 with
    timed_out set and a note in stderr instead of raising.
    """
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,  # its own process group, so the kill reaches anything it started
        )
    except FileNotFoundError as exc:
        raise ExecutorUnavailable(f"{argv[0]} not found on PATH") from exc

    overflow = threading.Event()
    out = _Pipe(proc.stdout, max_bytes, overflow)
    err = _Pipe(proc.stderr, max_bytes, overflow)
    if stdin is not None:
        threading.Thread(target=_feed, args=(proc.stdin, stdin), daemon=True).start()

    deadline = started + timeout
    timed_out = False
    while proc.poll() is None and not overflow.is_set():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            break
        overflow.wait(min(PIPE_POLL_S, remaining))
    stopped = proc.poll() is None  # the loop ended early: on timeout or on output overflow
    _kill_group(proc)
    out.finish()
    err.finish()

    note = ""
    if timed_out:
        code, note = TIMEOUT_EXIT_CODE, f"\n[timed out after {timeout:g}s]"
    else:
        code = OUTPUT_KILL_EXIT_CODE if stopped else proc.returncode
    return Result(
        code,
        _decode(bytes(out.buf)),
        _decode(bytes(err.buf)) + note,
        time.monotonic() - started,
        timed_out=timed_out,
        truncated=out.over or err.over,
    )


def _cap(text: str) -> tuple[str, bool]:
    """Keep the first MAX_OUTPUT_BYTES of a stream. Returns (text, cut)."""
    raw = text.encode("utf-8", "replace")
    if len(raw) <= MAX_OUTPUT_BYTES:
        return text, False
    kept = raw[:MAX_OUTPUT_BYTES].decode("utf-8", "ignore")
    return f"{kept}\n[truncated: over {MAX_OUTPUT_BYTES} bytes, first {MAX_OUTPUT_BYTES} kept]", True


def _root_free_gb() -> float:
    return shutil.disk_usage("/").free / GIB


def _env_min_one[N: (int, float)](name: str, default: N, cast: Callable[[str], N]) -> N:
    """A number from the environment. Unparsable, non-finite or below 1 falls back to the default."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = cast(raw)
    except ValueError:
        return default
    return value if math.isfinite(value) and value >= 1 else default


class Session(ABC):
    """One running sandbox. Use as a context manager so it is always closed."""

    @abstractmethod
    def run(self, cmd: str, timeout: float) -> Result:
        """Run cmd with `sh -lc` in the workdir. timeout must be > 0 and is capped at MAX_RUN_TIMEOUT_S.

        The command gets exit 124 when the container timeout fires. If the host had to kill the client,
        the result has timed_out=True and the sandbox has been reset. Output is capped per stream.
        """

    @abstractmethod
    def write_file(self, path: str, data: bytes | str) -> None:
        """Write data to path (relative paths start in the workdir), creating parent directories."""

    @abstractmethod
    def diff(self) -> str:
        """Patch of all changes since start, tracked and untracked. Raises if git fails, if the base
        commit was not recorded, or if the patch is larger than MAX_DIFF_BYTES."""

    @abstractmethod
    def reset(self) -> None:
        """Destroy the sandbox and start a fresh one from the same image. Reserves one sandbox run."""

    @abstractmethod
    def close(self) -> None:
        """Destroy the sandbox. Safe to call twice. Raises RuntimeError if removal fails; retry close."""

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
        pid: Callable[[], int] | None = None,
        platform: str = sys.platform,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._runner = runner
        self._disk_free_gb = disk_free_gb
        self._min_free_gb = (
            min_free_gb if min_free_gb is not None else _env_min_one("MIN_FREE_DISK_GB", 10.0, float)
        )
        self._image_cap = image_cap if image_cap is not None else _env_min_one("DOCKER_IMAGE_CAP", 6, int)
        # Clamped, not refused: a larger tmpfs would take more of the container memory limit.
        self._tmpfs_mb = min(_env_min_one("DOCKER_TMPFS_MB", 512, int), TMPFS_MAX_MB)
        self._pid = pid if pid is not None else os.getpid  # owner of the containers this process starts
        self._platform = platform
        self._sleep = sleep
        self._clock = clock

    def start(self, env: EnvSpec, budget: Budget | None = None) -> Session:
        return DockerSession(self, env, Budget.from_env() if budget is None else budget)

    def _docker(
        self, args: list[str], timeout: float, stdin: bytes | None = None, max_bytes: int | None = None
    ) -> Result:
        argv = ["docker", *args]
        if max_bytes is None:
            return self._runner(argv, timeout, stdin)
        return self._runner(argv, timeout, stdin, max_bytes=max_bytes)

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

    def _check_free_disk(self) -> None:
        # Every start and every reset, local image or not: a running container writes to the host disk too.
        free = self._disk_free_gb()
        if free < self._min_free_gb:
            raise ExecutorRefused(
                f"free disk is {free:.1f} GB, below MIN_FREE_DISK_GB={self._min_free_gb:g}; "
                "no container started"
            )

    def _preflight(self, image: str) -> None:
        # Only a pull needs the image-count guard. A local image starts with no image-count check.
        if self._docker(["image", "inspect", "--", image], IO_TIMEOUT_S).exit_code == 0:
            return
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

    def _create(self, env: EnvSpec) -> tuple[str, str]:
        """Start the container. Returns (name, id). A failure after docker run removes the named container."""
        network = "bridge" if env.network else "none"
        name = f"cheatproof-{uuid.uuid4().hex}"
        # /tmp is a sized tmpfs, so scratch files cannot fill the host disk. The root fs is not --read-only:
        # task repos must stay writable for the attacker and the grader. --storage-opt size= is not used
        # because Docker Desktop's overlay2 does not support it without xfs pquota.
        # tmpfs pages are charged to the --memory cgroup: a full /tmp hits the memory limit, not ENOSPC.
        argv = [
            "run",
            "-d",
            "--rm",
            "--name",
            name,
            "--label",
            "cheatproof=1",
            "--label",
            f"cheatproof.owner={self._pid()}",
            "--network",
            network,
            "--cpus",
            str(env.cpus),
            "--memory",
            env.memory,
            "--memory-swap",
            env.memory,  # equal to --memory, so no swap
            "--pids-limit",
            str(PIDS_LIMIT),
            "--tmpfs",
            f"/tmp:rw,nosuid,nodev,size={self._tmpfs_mb}m",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--ulimit",
            "nofile=1024:1024",
            "--workdir",
            env.workdir,
            "--",  # docker's flag parser (pflag) stops at --, so the image is always positional
            env.image,
            "sleep",
            "infinity",
        ]
        try:
            res = self._docker(argv, RUN_TIMEOUT_S)
        except BaseException:
            self._remove_quietly(name)
            raise
        cid = res.stdout.strip()
        if res.exit_code != 0 or not cid:
            self._remove_quietly(name)  # also covers a docker run that timed out or printed no id
            raise ExecutorUnavailable(f"docker run failed ({res.exit_code}): {res.stderr.strip()[-500:]}")
        return name, cid

    def _remove_quietly(self, name: str) -> None:
        """docker rm -f after a failed start. Errors are dropped so the original error reaches the caller.
        A leftover is still findable by its cheatproof=1 label."""
        with contextlib.suppress(Exception):
            self._docker(["rm", "-f", name], DESTROY_TIMEOUT_S)

    def _owner_alive(self, owner: str) -> bool:
        """True only for a pid this host has alive. A missing or garbage label is not alive."""
        if not OWNER_RE.fullmatch(owner):
            return False
        pid = int(owner)
        if pid > PID_MAX:
            return False
        if pid == self._pid():
            return True
        try:
            os.kill(pid, 0)  # signal 0 checks that the pid exists and sends nothing
        except ProcessLookupError:
            return False
        except PermissionError:
            return True  # exists, owned by another user
        return True

    def sweep_leftovers(self) -> int:
        """Stop and remove cheatproof=1 containers whose cheatproof.owner pid is dead on this host, or whose
        owner label is missing or garbage. A live owner's container is kept, so a concurrent harden is not
        killed. Returns how many docker rm reported removed. Containers only: never images, volumes or the
        build cache. Best-effort: a docker error returns 0 and leaves the containers for the next sweep."""
        removed = 0
        with contextlib.suppress(Exception):
            listed = self._docker(
                ["ps", "-a", "--filter", "label=cheatproof=1", "--format", SWEEP_FORMAT], IO_TIMEOUT_S
            )
            dead: list[str] = []
            if listed.exit_code == 0:
                for line in listed.stdout.splitlines():
                    fields = line.split()
                    if fields and not self._owner_alive(fields[1] if len(fields) > 1 else ""):
                        dead.append(fields[0])
            if dead:
                removed = len(self._docker(["rm", "-f", *dead], DESTROY_TIMEOUT_S).stdout.split())
        return removed

    def _base_commit(self, cid: str, workdir: str) -> str:
        script = f"cd {shlex.quote(workdir)} && git rev-parse HEAD"
        res = self._docker(["exec", cid, "sh", "-c", script], IO_TIMEOUT_S)
        return res.stdout.strip() if res.exit_code == 0 else ""


class DockerSession(Session):
    def __init__(self, executor: DockerExecutor, env: EnvSpec, budget: Budget) -> None:
        self._executor = executor
        self._env = env
        self._budget = budget
        self._name: str | None = None
        self._cid: str | None = None
        self._base = ""
        self._closed = False
        self._launch()

    def _launch(self) -> None:
        self._executor._check_free_disk()  # first: a refusal never opens Docker Desktop
        self._executor._ensure_daemon()
        self._executor._preflight(self._env.image)
        self._budget.reserve_sandbox_run()  # before the container exists; BudgetExceeded propagates
        self._name, self._cid = self._executor._create(self._env)
        self._base = ""
        try:
            self._base = self._executor._base_commit(self._cid, self._env.workdir)
        except BaseException:
            self._executor._remove_quietly(self._name)
            self._name = self._cid = None
            raise

    def _live(self) -> str:
        if self._closed:
            raise RuntimeError("session is closed")
        if self._cid is None:
            raise RuntimeError("no live sandbox: an earlier reset() failed; call reset() again")
        return self._cid

    def _destroy(self) -> None:
        if self._name is None:
            return
        # docker rm -f kills the container. "No such container" means --rm already removed it.
        res = self._executor._docker(["rm", "-f", self._name], DESTROY_TIMEOUT_S)
        if res.exit_code != 0 and "No such container" not in res.stderr:
            raise RuntimeError(
                f"docker rm -f {self._name} failed ({res.exit_code}): {res.stderr.strip()[-300:]}"
            )
        self._name = None
        self._cid = None

    def run(self, cmd: str, timeout: float) -> Result:
        if not timeout > 0:  # also refuses NaN
            raise ValueError(f"run timeout must be greater than 0 seconds, got {timeout!r}")
        limit = min(float(timeout), MAX_RUN_TIMEOUT_S)
        cid = self._live()
        # The in-container timeout normally fires first and leaves the container usable. The host waits
        # EXEC_GRACE_S longer as a backstop, for a hung docker exec or an image without timeout(1).
        script = _IN_CONTAINER_TIMEOUT.format(seconds=max(1, math.ceil(limit)))
        res = self._executor._docker(
            ["exec", cid, "sh", "-lc", script, "cheatproof", cmd], limit + EXEC_GRACE_S
        )
        if res.timed_out:
            # The host killed docker exec, so the command may still run in the container. reset() removes
            # that container and every process in it. Files written earlier in this session are lost,
            # and the reset reserves one more sandbox run.
            self.reset()
        stdout, out_cut = _cap(res.stdout)
        stderr, err_cut = _cap(res.stderr)
        return replace(res, stdout=stdout, stderr=stderr, truncated=res.truncated or out_cut or err_cut)

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
        cid = self._live()
        if not self._base:
            raise RuntimeError("base commit was not recorded at start; refusing to build a diff")
        script = _DIFF_SCRIPT.format(workdir=shlex.quote(self._env.workdir), base=shlex.quote(self._base))
        res = self._executor._docker(
            ["exec", cid, "sh", "-c", script], IO_TIMEOUT_S, max_bytes=MAX_DIFF_BYTES
        )
        if res.timed_out:
            raise RuntimeError(f"diff timed out after {IO_TIMEOUT_S}s")
        if res.truncated:
            raise RuntimeError(f"diff is over MAX_DIFF_BYTES={MAX_DIFF_BYTES}; refusing to truncate it")
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
