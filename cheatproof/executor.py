"""Execution backends for untrusted task code (ADR 0002).

Local Docker runs each session in a container with no network (unless EnvSpec asks), CPU, memory
and PID limits, and no host mounts. Files reach the container over stdin. Token Factory Sandboxes
(contree_sdk) is the default backend: SandboxSession mirrors DockerSession on a chain of SDK images. Every Docker
session start, including a reset, counts one local run in cheatproof/budget.py before any pull and before the container exists. So a spent LOCAL_RUN_CAP
never pulls an image, and a failed pull still counts its run. Local runs are free and count only toward
LOCAL_RUN_CAP. A Sandboxes session reserves one sandbox run per start and per reset instead.
"""

from __future__ import annotations

import contextlib
import hashlib
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

from cheatproof.budget import Budget, BudgetExceeded

MAX_OUTPUT_BYTES = 64 * 1024  # kept per stream, per run() call
OUTPUT_MARGIN_BYTES = 4 * 1024  # the host reads this far past the cap, then kills the client
MAX_DIFF_BYTES = 8 * 1024 * 1024  # diff() raises above this; it never truncates a patch
# The start list of untracked paths. Over this, the session refuses to start.
MAX_BASELINE_BYTES = 8 * 1024 * 1024
MAX_RUN_TIMEOUT_S = 1800
EXEC_GRACE_S = 10  # host waits this long past the in-container timeout before it kills docker exec
TIMEOUT_EXIT_CODE = 124  # same as timeout(1)
OUTPUT_KILL_EXIT_CODE = 137  # 128 + SIGKILL: the host killed the client for exceeding its output cap
PIDS_LIMIT = 512
DAEMON_WAIT_S = 120
DAEMON_POLL_S = 5
DAEMON_CHECK_TIMEOUT_S = 30
IO_TIMEOUT_S = 120
COLIMA_DF_TIMEOUT_S = 15  # one df on the colima VM is quick; a longer wait only delays the refusal
RUN_TIMEOUT_S = 900  # docker run of an image that is already local (the pull has its own clock)
PULL_TIMEOUT_S = 1800  # a task image is about 4 GB unpacked; a slow pull must not hit the run timeout
DESTROY_TIMEOUT_S = 60
# Largest single file a container process may write (RLIMIT_FSIZE), in GiB. Env CONTAINER_FSIZE_GB overrides it.
CONTAINER_FSIZE_GB = 4.0
# Free GB after a run below which the session is poisoned (DiskRefused). Env RUN_MIN_FREE_GB overrides it. It is lower
# than MIN_FREE_DISK_GB, the floor for starts and pulls, so a healthy run right after a pull does not trip it.
RUN_MIN_FREE_GB = 2.0
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

# Git options for every script below. The repo, its config and its attributes are attacker-writable, so the
# keys that run a command by themselves are pinned on the command line (which beats every config file):
# core.fsmonitor and core.hooksPath. A filter driver named in .gitattributes and defined in .git/config cannot be
# switched off from here, since its name is not known; the sandbox cuts the network for these scripts too
# (SandboxSession wraps every call), and a Docker container has none. That bounds a filter, it does not stop it.
_GIT_ENV = "export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null; "
_GIT_OPTS = (
    "-c core.excludesFile=/dev/null -c core.attributesFile=/dev/null -c core.hooksPath=/dev/null "
    "-c core.fsmonitor=false -c diff.external="
)

# Runs in the container. A fresh index file, read from the start commit, means a replace ref, an
# assume-unchanged bit or a skip-worktree bit in the sandbox cannot hide a change. The index path must not
# exist yet (git rejects an empty index file), so it lives in a new temp directory. Repo-level git config
# and attributes are still untrusted: T05/T06 restore the hidden tests at grade time. -f stages ignored
# files too (an attacker can hide a file via .git/info/exclude); bytecode and cache dirs are left out to keep
# the patch small, so the grader must clear __pycache__ before grading (stale .pyc is a hole of its own).
# Files untracked at start are not part of the patch. The start list arrives on stdin, and _UNSTAGE_SCRIPT
# drops those paths from the temp index after the add. update-index takes literal paths.
_DIFF_SCRIPT = (
    "set -e; " + _GIT_ENV + 'tmp=$(mktemp -d); export GIT_INDEX_FILE="$tmp/index"; '
    "trap 'rm -rf \"$tmp\"' EXIT; "
    "git --no-replace-objects -C {workdir} " + _GIT_OPTS + " read-tree {base}; "
    "git --no-replace-objects -C {workdir} " + _GIT_OPTS + " add -A -f -- . "
    "':(exclude,glob)**/__pycache__/**' ':(exclude,glob)**/.pytest_cache/**' ':(exclude,glob)**/*.egg-info/**'; "
    "{unstage}"
    "git --no-replace-objects -C {workdir} " + _GIT_OPTS + " "
    "diff --cached --binary --no-color --no-ext-diff --no-textconv {base}"
)

# Only when the start list is not empty; with an empty list the diff script has no unstage step.
_UNSTAGE_SCRIPT = (
    "git --no-replace-objects -C {workdir} " + _GIT_OPTS + " update-index --force-remove -z --stdin; "
)

# Runs in the container at start and at reset, before any attacker command. Lists every untracked path, ignored
# ones included, NUL-separated and relative to the workdir. The host keeps the list (DockerSession._untracked),
# so nothing in the container is trusted to hold it.
_BASELINE_SCRIPT = (
    "set -e; " + _GIT_ENV + "git --no-replace-objects -C {workdir} " + _GIT_OPTS + " ls-files --others -z"
)


def normalise_untracked(raw: bytes) -> bytes:
    """Start list in the form update-index --stdin -z reads: NUL-terminated, no empty entries. A nested repo
    is listed as `name/` and indexed as `name`, so one trailing slash goes."""
    names = (name.removesuffix(b"/") for name in raw.split(b"\0") if name)
    return b"".join(name + b"\0" for name in names if name)


class ExecutorRefused(RuntimeError):
    """A guard stopped a session start, reset or call (low disk, too many local images, a tampered network wrapper).
    No image was deleted."""


class DiskRefused(ExecutorRefused):
    """The disk is too low for the next step: a pull would leave less than MIN_FREE_DISK_GB, or a run left less than
    RUN_MIN_FREE_GB, or the image store cannot be read. After such a run the session is poisoned, and every later call
    on it raises this too."""

    # Set by run() when the refusal came after a command: that command's Result, with its reset note, is kept here.
    result: Result | None = None


# Task images this project pulls (SWE-bench eval images, about 4 GB each unpacked). Only these are ever removed.
# Same namespaces as cheatproof.tasks.ALLOWED_IMAGE_PREFIXES; tasks imports this module, so it is repeated here.
TASK_IMAGE_PREFIXES = ("swebench/", "swerebench/")


def is_task_image(image: str) -> bool:
    # One name segment after a prefix, the same set the `docker images --filter reference=<prefix>*` calls count.
    return any(
        image.startswith(prefix) and len(image) > len(prefix) and "/" not in image[len(prefix) :]
        for prefix in TASK_IMAGE_PREFIXES
    )


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
    # The host killed the client, at its timeout or at its output cap, and run() reset the sandbox. Set by run() only.
    reset: bool = False


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


def _colima_installed() -> bool:
    """colima is on PATH. Then pulls land in its VM, and only the VM's /var/lib/docker counts for them."""
    return shutil.which("colima") is not None


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
    """One running sandbox. Use as a context manager so it is always closed.

    A session whose post-run disk check failed is poisoned: run, write_file, diff and reset raise DiskRefused from then
    on. close still removes the sandbox.
    """

    @abstractmethod
    def run(self, cmd: str, timeout: float) -> Result:
        """Run cmd with `sh -lc` in the workdir. timeout must be > 0 and is capped at MAX_RUN_TIMEOUT_S.

        The command gets exit 124 when the container timeout fires. If the host had to kill the client, at its
        timeout or at its output cap, the sandbox has been reset and the result has reset=True. Output is capped per
        stream. After every run, including one that ended in a reset, the free disk is checked at once. Below
        RUN_MIN_FREE_GB, or when the image store cannot be read, DiskRefused is raised and the session is poisoned.
        Nothing is reset on that path, and the DiskRefused carries the run's Result in its result attribute.
        """

    @abstractmethod
    def write_file(self, path: str, data: bytes | str) -> None:
        """Write data to path (relative paths start in the workdir), creating parent directories."""

    @abstractmethod
    def diff(self) -> str:
        """Patch of changes since start, tracked and untracked, except files already untracked at start
        (see DockerSession.diff). Raises if git fails, if the base commit or the baseline was not recorded,
        or if the patch is larger than MAX_DIFF_BYTES."""

    @abstractmethod
    def reset(self) -> None:
        """Destroy the sandbox and start a fresh one from the same image. Reserves one sandbox run. A poisoned session
        raises DiskRefused instead."""

    @abstractmethod
    def close(self) -> None:
        """Destroy the sandbox. Safe to call twice. Raises RuntimeError if removal fails; retry close."""

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


class Executor(Protocol):
    def start(self, env: EnvSpec, budget: Budget | None = None) -> Session: ...


# Names of containers this process started and could not remove: a close that failed, or a cleanup after a failed
# start. Their sessions have given up on them. The next task-start sweep and every image release remove them by
# name, and a close retry that finds one already gone counts as closed. Module-level on purpose: each task opens
# its own executor, and the sweep at the next task start has to see what an earlier one left behind.
_LEAKED: set[str] = set()


class DockerExecutor:
    """Local Docker backend. Shells out to the docker CLI through an injectable runner."""

    def __init__(
        self,
        *,
        runner: Runner = subprocess_runner,
        disk_free_gb: Callable[[], float] = _root_free_gb,
        min_free_gb: float | None = None,
        run_min_free_gb: float | None = None,
        image_cap: int | None = None,
        task_image_cap: int | None = None,
        pull_estimate_gb: float | None = None,
        image_store_free_gb: Callable[[], float | None] | None = None,
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
        self._run_min_free_gb = (
            run_min_free_gb
            if run_min_free_gb is not None
            else _env_min_one("RUN_MIN_FREE_GB", RUN_MIN_FREE_GB, float)
        )
        self._image_cap = image_cap if image_cap is not None else _env_min_one("DOCKER_IMAGE_CAP", 6, int)
        # At most this many task images on disk at once, and the disk an unknown pull is assumed to take.
        self._task_image_cap = (
            task_image_cap if task_image_cap is not None else _env_min_one("TASK_IMAGE_CAP", 2, int)
        )
        # Pulls land in the Docker VM's image store (colima: a sparse disk), not on the host's free space.
        self._image_store_free_gb = (
            image_store_free_gb if image_store_free_gb is not None else self._colima_store_free_gb
        )
        self._pull_estimate_gb = (
            pull_estimate_gb if pull_estimate_gb is not None else _env_min_one("PULL_ESTIMATE_GB", 4.5, float)
        )
        # Clamped, not refused: a larger tmpfs would take more of the container memory limit.
        self._tmpfs_mb = min(_env_min_one("DOCKER_TMPFS_MB", 512, int), TMPFS_MAX_MB)
        self._fsize_bytes = int(_env_min_one("CONTAINER_FSIZE_GB", CONTAINER_FSIZE_GB, float) * GIB)
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

    def _preflight(self, image: str) -> bool:
        """The guards for a start, before any pull. True when the image is not local and must be pulled. A local
        image needs nothing and gets no guard. A refusal raises here, so it pulls nothing."""
        # Only a pull needs the image-count guard. A local image starts with no image-count check.
        if self._docker(["image", "inspect", "--", image], IO_TIMEOUT_S).exit_code == 0:
            return False
        count = self._local_image_count()
        if count >= self._image_cap:
            raise ExecutorRefused(
                f"{image} is not local and {count} images are present, at DOCKER_IMAGE_CAP="
                f"{self._image_cap}; nothing pulled, nothing deleted"
            )
        free, where = self._store_free()
        if free - self._pull_estimate_gb < self._min_free_gb:
            raise DiskRefused(
                f"{image} is not local: free {where} disk is {free:.1f} GB, and a pull of about "
                f"{self._pull_estimate_gb:g} GB would leave less than MIN_FREE_DISK_GB={self._min_free_gb:g}; "
                "nothing pulled"
            )
        if where != "host":
            # colima: the pull grows the VM's disk file on the Mac, and freed blocks stay in that file, so the host
            # disk keeps the floor too.
            host = self._disk_free_gb()
            if host - self._pull_estimate_gb < self._min_free_gb:
                raise DiskRefused(
                    f"{image} is not local: free host disk is {host:.1f} GB, and a pull of about "
                    f"{self._pull_estimate_gb:g} GB would leave less than MIN_FREE_DISK_GB={self._min_free_gb:g}; "
                    "nothing pulled"
                )
        if is_task_image(image):
            tasks = self._task_image_count()
            if tasks >= self._task_image_cap:
                raise DiskRefused(
                    f"{image} is not local and {tasks} task images are present, at TASK_IMAGE_CAP="
                    f"{self._task_image_cap}; release finished task images first; nothing pulled"
                )
        return True

    def _pull(self, image: str) -> None:
        """docker pull on its own clock (PULL_TIMEOUT_S). A failed pull is ExecutorUnavailable."""
        res = self._docker(["pull", "--", image], PULL_TIMEOUT_S)
        if res.exit_code != 0:
            raise ExecutorUnavailable(f"docker pull failed ({res.exit_code}): {res.stderr.strip()[-500:]}")

    def _store_free(self) -> tuple[float, str]:
        """Free GB where pulls and containers land: the colima VM's image store, or the host when there is none.
        The label is "host" for the host disk and "Docker image store" otherwise."""
        store = self._image_store_free_gb()
        if store is None:
            return self._disk_free_gb(), "host"
        return store, "Docker image store"

    def _colima_store_free_gb(self) -> float | None:
        """Free GiB of /var/lib/docker inside the colima VM. None when colima is not installed (the host disk counts).
        When colima is installed its store must be readable: a failed, timed-out or truncated ssh, or no
        /var/lib/docker row, raises DiskRefused. The pull is refused, never measured on the host instead.
        By design, colima installed but stopped (or Docker Desktop active instead) refuses every pull."""
        if not _colima_installed():
            return None
        try:
            # VERIFY (live, owner approval): the row format below assumes /var/lib/docker is its own mount in the VM.
            # That is unconfirmed until a real `colima ssh -- df -Pk /var/lib/docker` output is recorded here.
            res = self._runner(
                ["colima", "ssh", "--", "df", "-Pk", "/var/lib/docker"], COLIMA_DF_TIMEOUT_S, None
            )
        except (OSError, subprocess.SubprocessError, ExecutorUnavailable) as exc:
            raise DiskRefused(f"image store unreadable: colima ssh failed ({exc})") from exc
        if res.timed_out or res.truncated or res.exit_code != 0:
            raise DiskRefused(
                f"image store unreadable: colima ssh exit {res.exit_code}"
                f"{', timed out' if res.timed_out else ''}{', output truncated' if res.truncated else ''}"
            )
        # df -Pk: Filesystem, 1024-blocks, Used, Available, Capacity, Mounted on. Match the row by its mount point.
        for line in res.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 4 and fields[-1] == "/var/lib/docker":
                try:
                    return int(fields[3]) * 1024 / GIB
                except ValueError:
                    break
        raise DiskRefused("image store unreadable: no /var/lib/docker row in colima df output")

    def _task_image_count(self) -> int:
        filters: list[str] = []
        for prefix in TASK_IMAGE_PREFIXES:
            filters += ["--filter", f"reference={prefix}*"]
        res = self._docker(["images", "-q", *filters], IO_TIMEOUT_S)
        if res.exit_code != 0:
            raise ExecutorUnavailable(f"docker images failed: {res.stderr.strip()[-300:]}")
        return len({line.strip() for line in res.stdout.splitlines() if line.strip()})

    def release_image(self, image: str) -> bool:
        """Remove a finished task image to free disk. Only task images (TASK_IMAGE_PREFIXES); never another project's
        image. The image removal is never forced: a container that still uses the image keeps it. Containers this
        process could not remove are removed first (see _LEAKED), since they would keep it in use. True when the
        image was removed."""
        if not is_task_image(image):
            return False
        self._remove_leaked()
        return self._docker(["image", "rm", "--", image], DESTROY_TIMEOUT_S).exit_code == 0

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
            # One file may not grow past this. The free-space check after each run() bounds the total.
            "--ulimit",
            f"fsize={self._fsize_bytes}",
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
        A container that is still there is recorded in _LEAKED, so a later sweep or image release removes it."""
        gone = False
        with contextlib.suppress(Exception):
            res = self._docker(["rm", "-f", name], DESTROY_TIMEOUT_S)
            gone = res.exit_code == 0 or "No such container" in res.stderr
        if not gone:
            _LEAKED.add(name)

    def _remove_leaked(self) -> int:
        """docker rm -f for each name in _LEAKED. A name that docker reports gone leaves _LEAKED; one that still
        fails stays for the next try. Returns how many docker rm removed. Containers only, never images."""
        removed = 0
        for name in sorted(_LEAKED):
            with contextlib.suppress(Exception):  # the name stays in _LEAKED for the next try
                res = self._docker(["rm", "-f", name], DESTROY_TIMEOUT_S)
                if res.exit_code == 0:
                    removed += 1
                if res.exit_code == 0 or "No such container" in res.stderr:
                    _LEAKED.discard(name)
        return removed

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
        owner label is missing or garbage, and the containers this process could not remove (_LEAKED), by name.
        A live owner's container is kept, so a concurrent harden is not killed. Returns how many docker rm reported
        removed. Containers only: never images, volumes or the build cache. Best-effort: a docker error returns 0
        and leaves the containers for the next sweep."""
        removed = self._remove_leaked()
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
                removed += len(self._docker(["rm", "-f", *dead], DESTROY_TIMEOUT_S).stdout.split())
        return removed

    def _base_commit(self, cid: str, workdir: str) -> str:
        script = f"cd {shlex.quote(workdir)} && git rev-parse HEAD"
        res = self._docker(["exec", cid, "sh", "-c", script], IO_TIMEOUT_S)
        return res.stdout.strip() if res.exit_code == 0 else ""

    def _untracked_paths(self, cid: str, workdir: str) -> bytes:
        script = _BASELINE_SCRIPT.format(workdir=shlex.quote(workdir))
        res = self._docker(["exec", cid, "sh", "-c", script], IO_TIMEOUT_S, max_bytes=MAX_BASELINE_BYTES)
        if res.exit_code != 0 or res.timed_out or res.truncated:
            raise RuntimeError(
                f"untracked-file baseline was not recorded (exit {res.exit_code}, timed_out={res.timed_out}, "
                f"truncated={res.truncated}): {res.stderr.strip()[-300:]}"
            )
        # The runner decodes stdout as UTF-8 with replacement, so a name that is not valid UTF-8 comes back
        # changed and matches no index entry. That file stays in the patch: visible at grading, never hidden.
        return normalise_untracked(res.stdout.encode("utf-8"))


class DockerSession(Session):
    def __init__(self, executor: DockerExecutor, env: EnvSpec, budget: Budget) -> None:
        self._executor = executor
        self._env = env
        self._budget = budget
        self._name: str | None = None
        self._cid: str | None = None
        self._base = ""
        # Start list of untracked paths, NUL-terminated. Held here on the host, never read back from the container.
        self._untracked: bytes | None = None
        self._closed = False
        # Set when the post-run disk check found the disk low. From then on every call but close raises it.
        self._poisoned: str | None = None
        self._launch()

    def _launch(self) -> None:
        self._executor._check_free_disk()  # first: a refusal never opens Docker Desktop
        self._executor._ensure_daemon()
        # The guards come first: a refusal pulls nothing and counts no run. pull says whether the image must be pulled.
        pull = self._executor._preflight(self._env.image)
        # Local Docker is free: books $0 and counts only toward LOCAL_RUN_CAP, not the money caps.
        with _ledger_io():
            self._budget.reserve_local_run()  # before any pull and the container; BudgetExceeded propagates
        if pull:
            self._executor._pull(self._env.image)  # its own clock; a failed pull is ExecutorUnavailable
        self._name, self._cid = self._executor._create(self._env)
        self._base = ""
        self._untracked = None
        try:
            self._base = self._executor._base_commit(self._cid, self._env.workdir)
            self._untracked = self._executor._untracked_paths(self._cid, self._env.workdir)
        except BaseException:
            self._executor._remove_quietly(self._name)
            self._name = self._cid = None
            raise

    def _check_poisoned(self) -> None:
        if self._poisoned is not None:
            raise DiskRefused(self._poisoned)

    def _live(self) -> str:
        self._check_poisoned()
        if self._closed:
            raise RuntimeError("session is closed")
        if self._cid is None:
            raise RuntimeError("no live sandbox: an earlier reset() failed; call reset() again")
        # Every Docker exec (run, write_file, diff) goes through here, so a halt stops each one, free or paid.
        with _ledger_io():
            self._budget.check_not_halted()
        return self._cid

    def _destroy(self) -> None:
        if self._name is None:
            return
        # docker rm -f kills the container. "No such container" means --rm already removed it.
        try:
            res = self._executor._docker(["rm", "-f", self._name], DESTROY_TIMEOUT_S)
        except BaseException:
            # Not confirmed removed: a later sweep or image release removes it by name.
            _LEAKED.add(self._name)
            raise
        if res.exit_code != 0 and "No such container" not in res.stderr:
            _LEAKED.add(self._name)
            raise RuntimeError(
                f"docker rm -f {self._name} failed ({res.exit_code}): {res.stderr.strip()[-300:]}"
            )
        _LEAKED.discard(self._name)
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
        killed = res.timed_out or (res.truncated and res.exit_code == OUTPUT_KILL_EXIT_CODE)
        stdout, out_cut = _cap(res.stdout)
        stderr, err_cut = _cap(res.stderr)
        result = replace(
            res, stdout=stdout, stderr=stderr, truncated=res.truncated or out_cut or err_cut, reset=killed
        )
        if killed:
            # The host killed docker exec, at its timeout or at its output cap, so the command may still run in the
            # container. reset() removes that container and every process in it. Files written earlier in this
            # session are lost, and the reset reserves one more sandbox run. A reset refused by a disk guard keeps
            # the killed run's Result on the exception, as the post-run refusal does.
            try:
                self.reset()
            except DiskRefused as exc:
                exc.result = result
                raise
        try:
            self._check_disk_after_run(killed)
        except DiskRefused as exc:
            # The refusal replaces the return value, so the Result (reset note included) travels on the exception.
            exc.result = result
            raise
        return result

    def _check_disk_after_run(self, reset: bool) -> None:
        """The free-space check after every run, so a command that fills the disk is caught on the run that filled it.
        Below RUN_MIN_FREE_GB, or when the image store cannot be read, the session is poisoned and DiskRefused is
        raised. Nothing is reset on this path: the sandbox and what it wrote stay as they are, and every later call
        except close is refused. reset says the run was killed and the sandbox reset, and the message keeps that."""
        executor = self._executor
        try:
            free, where = executor._store_free()
        except Exception as exc:  # noqa: BLE001 - any read failure: the disk is not known to be fine, so refuse
            if isinstance(exc, DiskRefused):
                reason = str(exc)
            else:
                reason = f"free disk could not be read after a run ({type(exc).__name__}: {exc})"
        else:
            if free >= executor._run_min_free_gb:
                return
            floor = executor._run_min_free_gb
            reason = f"free {where} disk is {free:.1f} GB after a run, below RUN_MIN_FREE_GB={floor:g}"
        if reset:
            reason += "; the command was killed and the sandbox was reset before this check"
        self._poisoned = f"{reason}; this session is refused from here on (nothing was reset)"
        raise DiskRefused(self._poisoned)

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
        """Patch of changes since start: tracked files, and files created since start.

        Files that were untracked at start (an install's build tree, say) are never graded: changes to them are
        dropped from the patch. The grader applies this patch to a fresh container from the same image, which
        already has those files, so including them would fail with "already exists in working directory". The
        list of those paths is recorded before any attacker command and held on the host. Raises if the base
        commit or that list was not recorded.
        """
        cid = self._live()
        if not self._base:
            raise RuntimeError("base commit was not recorded at start; refusing to build a diff")
        if self._untracked is None:
            raise RuntimeError("untracked-file baseline was not recorded at start; refusing to build a diff")
        unstage = _UNSTAGE_SCRIPT.format(workdir=shlex.quote(self._env.workdir)) if self._untracked else ""
        script = _DIFF_SCRIPT.format(
            workdir=shlex.quote(self._env.workdir), base=shlex.quote(self._base), unstage=unstage
        )
        # -i: the start list goes to update-index on stdin, as write_file sends its data.
        res = self._executor._docker(
            ["exec", "-i", cid, "sh", "-c", script],
            IO_TIMEOUT_S,
            stdin=self._untracked,
            max_bytes=MAX_DIFF_BYTES,
        )
        if res.timed_out:
            raise RuntimeError(f"diff timed out after {IO_TIMEOUT_S}s")
        if res.truncated:
            raise RuntimeError(f"diff is over MAX_DIFF_BYTES={MAX_DIFF_BYTES}; refusing to truncate it")
        if res.exit_code != 0:
            raise RuntimeError(f"diff failed ({res.exit_code}): {res.stderr.strip()[-300:]}")
        return res.stdout

    def reset(self) -> None:
        self._check_poisoned()
        if self._closed:
            raise RuntimeError("session is closed")
        self._destroy()
        self._launch()

    def close(self) -> None:
        if not self._closed:
            self._destroy()
            self._closed = True


# Token Factory Sandboxes (contree_sdk). The SDK has no network switch, so network-off is enforced inside the sandbox:
# every call after the start probe, attacker command or not, runs under `<unshare> -rn` (a new, empty network namespace
# inside a new user namespace). A start probes that this cuts the network and refuses to start when it does not (fail
# closed), unless SANDBOX_NETWORK_TRUSTED=1 says the owner confirmed the platform itself has no egress. A network-fetch
# EnvSpec (network=True) runs commands as they are.
#
# Containment: best effort. What holds:
# - The wrapper is called by absolute path, resolved in the base image, and wraps run, write_file, diff and the
#   baseline calls alike. The probe runs under it and proves the cut: /proc/net/dev lists only lo, and a connect
#   attempt fails.
# - -rn first. In a user namespace the attacker holds no capability over the host network namespace, so setns()
#   into it (nsenter -t 1 -n) fails. Plain -n is the fallback for a platform without user namespaces.
# - The attacker can replace the wrapper binary or its loader, libc or preload list in the image chain. Before a call
#   on an image that an attacker command produced, the host reads those files from that image over the SDK, not
#   through the image's own tools (which the attacker may have replaced too), and compares their sha256 with the
#   values pinned from the base image. A difference refuses the call: ExecutorRefused("network wrapper tampered").
#   Images are immutable and the call runs on the image that was read, so there is no gap between check and use.
# Residual risk:
# - With the -n fallback a root attacker can setns() back out. The cut then stops accidental egress only.
# - Not covered by the check: the kernel, locale and gconv data and NSS modules libc may load, glibc-hwcaps library
#   directories, and any platform path that leaves the sandbox's own network namespace (a host-side proxy, a shared
#   unix socket). The probe sees interfaces and one connect, not every route out.
# - diff() and the baseline run the image's own git and sh. Filter drivers named in .gitattributes and defined in
#   .git/config still run code there. Without network they cannot fetch or leak; they can still change the patch text.
# - A busybox unshare is not supported (its applet name is lost when run by its real path): the start refuses.
# VERIFY (live, owner approval): `unshare -rn` works in Sandboxes; `nsenter -t 1 -n` fails under it; the SDK reads
# files over image.read() and reports a missing file as NotFoundError.
SANDBOX_TRUSTED_ENV = "SANDBOX_NETWORK_TRUSTED"
# Tried in order. -r maps the caller to root in a new user namespace. Plain -n needs CAP_SYS_ADMIN in the host user
# namespace, and a process that has it can setns() back out, so it is the weaker cut and only the fallback.
_UNSHARE_FLAGS = ("-rn", "-n")
_LD_SO_PRELOAD = (
    "/etc/ld.so.preload"  # a library listed here loads into every dynamic program, unshare included
)
_LD_SO_CACHE = "/etc/ld.so.cache"  # decides which libc the loader picks
MAX_PINNED_FILES = 16

# Runs in the base image before any attacker command. Prints the resolved path of unshare, then the resolved path of
# each file ldd says it loads (the loader and libc). One path per line.
_LOCATE_UNSHARE = (
    'u=$(command -v unshare) || exit 1; u=$(readlink -f -- "$u") || exit 1; echo "$u"; '
    'ldd "$u" 2>/dev/null | while read -r line; do '
    'for w in $line; do case "$w" in /*) readlink -f -- "$w";; esac; done; done; exit 0'
)

# Runs under the wrapper. Exit 0 only when /proc/net/dev lists nothing but lo and a connect attempt fails.
# Exit 3: another interface. 4: the connect attempt worked or could not be made. 5: /proc/net/dev unreadable.
# Without a python in the image there is no connect client, and the interface check stands alone.
_NETCUT_PROBE = """set -f
[ -r /proc/net/dev ] || { echo "cannot read /proc/net/dev" >&2; exit 5; }
bad=; lo=
while IFS=: read -r name rest; do
  case "$name" in "Inter-|"*|" face |"*) continue ;; esac
  set -- $name
  [ $# -eq 0 ] && continue
  if [ "$1" = lo ]; then lo=1; else bad="$bad $1"; fi
done < /proc/net/dev
if [ -n "$bad" ]; then echo "non-loopback interfaces:$bad" >&2; exit 3; fi
[ -n "$lo" ] || { echo "no loopback in /proc/net/dev" >&2; exit 5; }
py=$(command -v python3 || command -v python || true)
if [ -n "$py" ]; then
  "$py" -c 'import socket, sys
s = socket.socket()
s.settimeout(3)
try:
    s.connect(("1.1.1.1", 443))
except OSError:
    sys.exit(0)
sys.exit(1)' && exit 0
  echo "connect attempt did not fail" >&2
  exit 4
fi
exit 0
"""


class _SandboxTimeout(RuntimeError):
    """The Sandboxes operation did not finish in time (the SDK cancelled it) or the server flagged a timeout."""


def _sdk_exceptions():
    """contree_sdk.sdk.exceptions, or None when contree_sdk is not installed."""
    try:
        from contree_sdk.sdk import exceptions
    except ImportError:
        return None
    return exceptions


def _http_status(exc: BaseException) -> int | None:
    for name in ("status", "status_code"):
        value = getattr(exc, name, None)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return None


def _describe_error(exc: BaseException) -> str:
    """Class name and HTTP status, nothing else: an SDK error's repr carries the URL, headers and server text."""
    status = _http_status(exc)
    return type(exc).__name__ if status is None else f"{type(exc).__name__} (HTTP {status})"


@contextlib.contextmanager
def _ledger_io():
    """A ledger OSError during a run is a refusal, not a raw error: the run stops, and no paid call goes out past it."""
    try:
        yield
    except OSError as exc:
        raise BudgetExceeded(
            f"spend ledger could not be read or written ({type(exc).__name__}); refusing to run"
        ) from None


def _halt_for_payment(exc: BaseException, budget: Budget) -> BudgetExceeded | None:
    """HTTP 402 halts every paid call (CLAUDE.md rule 1). Returns the error to raise, or None for any other status.

    Returned, never raised: a caller raises it after its except block, so the SDK error never becomes __context__.
    When the ledger refuses the halt, the message is fixed text: the SDK error's URL and headers never reach it."""
    if _http_status(exc) != 402:
        return None
    halted = True
    try:
        with _ledger_io():
            budget.halt("HTTP 402 from Sandboxes: payment required")
    except BudgetExceeded:
        halted = False  # the inner error is dropped unread
    if not halted:
        return BudgetExceeded("HTTP 402; ledger could not be halted")
    return BudgetExceeded("HTTP 402 from Sandboxes; the budget is halted")


def _server_timed_out(res: object) -> bool:
    """The server's own timed_out flag, read from private SDK fields. Missing means unknown, and unknown raises."""
    raw = getattr(res, "_raw", None)  # private in the SDK
    state = getattr(getattr(raw, "result", None), "state", None)
    flag = getattr(state, "timed_out", None)
    if flag is True or flag is False:
        return flag
    raise RuntimeError("sandbox result did not say whether it timed out; refusing to guess")


def _default_client():
    """A contree_sdk.ContreeSync client. Credentials come from the SDK's own environment lookup (NEBIUS_API_KEY and
    NEBIUS_PROJECT_ID, or the SDK's auth.ini); this module never reads them."""
    try:
        from contree_sdk import ContreeSync
    except ImportError as exc:
        raise ExecutorUnavailable(
            "contree_sdk is not installed; run uv sync (or set EXECUTOR=docker)"
        ) from exc
    return ContreeSync()


class SandboxExecutor:
    """Token Factory Sandboxes backend (ADR 0002), on contree_sdk. The SDK is imported lazily, so this module
    imports without it.

    client_factory builds the SDK client on the first start (tests inject a fake). A ConTree sandbox is a chain of
    images: each state-changing call runs on the current image and yields the next one, so a reset is a return to
    the base image. The SDK has no image delete, so a session leaves its image chain in the account.
    """

    def __init__(
        self,
        *,
        client_factory: Callable[[], object] | None = None,
        trust_no_network: bool | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client_factory = _default_client if client_factory is None else client_factory
        self._client: object | None = None
        self._lock = threading.Lock()
        self._trust_no_network = (
            os.environ.get(SANDBOX_TRUSTED_ENV) == "1" if trust_no_network is None else trust_no_network
        )
        self._clock = clock

    def start(self, env: EnvSpec, budget: Budget | None = None) -> Session:
        return SandboxSession(self, env, Budget.from_env() if budget is None else budget)

    def _get_client(self):
        with self._lock:
            if self._client is None:
                try:
                    self._client = self._client_factory()
                except ExecutorUnavailable:
                    raise
                except Exception as exc:  # noqa: BLE001 - only the class name leaves this function
                    raise ExecutorUnavailable(
                        f"Sandboxes client could not be built: {type(exc).__name__}"
                    ) from None
            return self._client

    def _resolve_image(self, image: str, budget: Budget | None = None):
        """The SDK image object for a name. Task images (swebench/*) are imported from the registry on first use and
        found by tag after that; any other name is looked up by tag with no import."""
        client = self._get_client()
        failure: BaseException
        try:
            return client.images.oci(image) if is_task_image(image) else client.images.use(image)
        except Exception as exc:  # noqa: BLE001 - only the class name and status leave this function
            paid = None if budget is None else _halt_for_payment(exc, budget)
            failure = paid or ExecutorUnavailable(
                f"image {image} could not be resolved: {_describe_error(exc)}"
            )
        raise failure from None  # outside the except block: the SDK error is never the __context__


class SandboxSession(Session):
    """One Sandboxes session: the current image, advanced by write_file and run, and the base image for reset."""

    def __init__(self, executor: SandboxExecutor, env: EnvSpec, budget: Budget) -> None:
        self._executor = executor
        self._env = env
        self._budget = budget
        self._client = executor._get_client()  # before the reservation: a missing SDK or key counts no run
        self._closed = False
        self._base_image = None
        self._cur = None  # None: no live sandbox (a reset was refused, or a call lost its image)
        self._base = ""
        self._untracked: bytes | None = None
        # argv prefix that cuts the network: [unshare path, flag]. Empty when the network is on or trusted off.
        self._netns: list[str] = []
        # sha256 of each file the wrapper depends on, pinned from the base image. None: the file is absent.
        self._pinned: dict[str, str | None] = {}
        self._verified: object = None  # uuid of the last image whose pinned files matched
        self._launch()

    def _launch(self) -> None:
        # Dead until the new run is booked: a reset the budget refuses leaves no live sandbox, as DockerSession's
        # container is already gone at that point. Only a successful reset revives the session.
        self._cur = None
        self._verified = None
        with _ledger_io():
            self._budget.reserve_sandbox_run()  # a paid session books one run before any import or exec
        if self._base_image is None:
            image = self._executor._resolve_image(self._env.image, self._budget)
            self._base_image = image
            self._cur = image
            self._probe_network()
            self._base = self._base_commit()
            self._untracked = self._untracked_paths()
        self._cur = self._base_image

    def _open(self) -> None:
        if self._closed:
            raise RuntimeError("session is closed")

    def _live(self) -> None:
        self._open()
        if self._cur is None:
            raise RuntimeError("no live sandbox: the last reset() or call failed; call reset() again")

    def _translate(self, exc: Exception, timeout: float | None = None) -> Exception | None:
        """The error to raise for an SDK error, or None for any other exception (the caller re-raises that one).
        Never carries the SDK error's text: its repr holds the URL and headers. HTTP 402 halts the budget."""
        # HTTP 402 halts on any exception, not only SDK errors (T35 d). Checked first, so no other branch can skip it.
        paid = _halt_for_payment(exc, self._budget)
        if paid is not None:
            return paid
        sdk = _sdk_exceptions()
        if sdk is None or not isinstance(exc, sdk.ContreeError):
            return None
        if timeout is not None and isinstance(exc, sdk.OperationTimedOutError):
            return _SandboxTimeout(f"sandbox operation timed out after {timeout:g}s")
        return RuntimeError(f"sandbox call failed: {_describe_error(exc)}")

    def _check_cost(self, res: object) -> None:
        """Log the cost a Sandboxes result reports. The budget halts only when the logged Sandboxes sum passes its cap,
        or when the cost is malformed (see Budget.book_sandbox_cost). Token Factory totals are not touched."""
        cost = getattr(res, "cost", None)
        if cost is None:
            return
        with _ledger_io():
            self._budget.book_sandbox_cost(cost)

    def _digest(self, image, path: str) -> str | None:
        """sha256 of a file in an image, read by the host over the SDK. None when the file is absent."""
        failure: Exception | None = None
        try:
            data = image.read(path)
        except Exception as exc:
            sdk = _sdk_exceptions()
            if sdk is not None and isinstance(exc, sdk.NotFoundError):
                return None
            failure = self._translate(exc)
            if failure is None:
                raise
        if failure is not None:
            raise failure from None  # outside the except block: the SDK error is never the __context__
        return hashlib.sha256(_as_bytes(data)).hexdigest()

    def _verify_wrapper(self, image) -> None:
        """Refuse when a file the network wrapper depends on differs from the base image. The base image is trusted
        by construction, and an image that already passed is not read again."""
        if image is self._base_image:
            return
        key = getattr(image, "uuid", None)
        if key is not None and key == self._verified:
            return
        for path, expected in self._pinned.items():
            if self._digest(image, path) != expected:
                raise ExecutorRefused("network wrapper tampered")
        self._verified = key

    def _call(
        self,
        argv: list[str],
        *,
        timeout: float,
        stdin: bytes | None = None,
        disposable: bool,
        cap: int = MAX_OUTPUT_BYTES,
        wrap: bool = True,
    ) -> tuple[Result, bool]:
        """One exec on the current image, under the network wrapper unless wrap=False (only the start probe, which
        runs the wrapper itself). Returns (result with raw decoded streams, server_cut). A non-disposable call
        advances the current image. Raises _SandboxTimeout on an operation timeout, RuntimeError on an SDK error,
        BudgetExceeded on HTTP 402 or a Sandboxes cost over its cap, ExecutorRefused when the wrapper was tampered with."""
        image = self._cur
        if image is None:
            raise RuntimeError("no live sandbox: the last reset() or call failed; call reset() again")
        with _ledger_io():
            self._budget.check_not_halted()  # before every exec, the cost-0 ones included: a halt stops the next call
        if wrap and self._netns:
            self._verify_wrapper(image)
            argv = [*self._netns, *argv]
        started = self._executor._clock()
        failure: Exception | None = None
        try:
            done = image.run(
                argv[0],
                args=argv[1:],
                cwd=self._env.workdir,
                stdin=stdin,
                stdout=bytes,
                stderr=bytes,
                timeout=math.ceil(timeout) + EXEC_GRACE_S,
                disposable=disposable,
                truncate_output_at=cap,
            ).wait()
        except Exception as exc:
            failure = self._translate(exc, timeout)
            if failure is None:
                raise
        if failure is not None:
            raise failure from None  # outside the except block: the SDK error is never the __context__
        res = done.result
        self._check_cost(res)
        if _server_timed_out(res):
            raise _SandboxTimeout(f"sandbox flagged a timeout after {timeout:g}s")
        if not disposable:
            if getattr(done, "uuid", None) is None:
                # The call ran but the next image is unknown. Keeping the old one would drop its effects without
                # a word, so the session is dead until reset() (the same rule as a refused reset).
                self._cur = None
                raise RuntimeError("sandbox returned no image for a state-changing call; call reset()")
            self._cur = done
        out, err_bytes = (_as_bytes(res.stdout), _as_bytes(res.stderr))
        elapsed = self._executor._clock() - started
        cut = bool(res.truncated)
        return Result(
            res.exit_code, out.decode("utf-8", "replace"), err_bytes.decode("utf-8", "replace"), elapsed
        ), cut

    def _probe_network(self) -> None:
        if self._env.network or self._executor._trust_no_network:
            return
        refusal = (
            "cannot cut the network in this sandbox ({why}); nothing was run. "
            f"Set {SANDBOX_TRUSTED_ENV}=1 only if the platform has no egress"
        )
        # SDK errors and timeouts propagate from here on: an outage is not a missing wrapper.
        located, _ = self._call(
            ["sh", "-c", _LOCATE_UNSHARE], timeout=IO_TIMEOUT_S, disposable=True, wrap=False
        )
        paths = [line for line in located.stdout.splitlines() if line.startswith("/")]
        if located.exit_code != 0 or not paths:
            raise ExecutorUnavailable(refusal.format(why="no unshare in the image"))
        unshare = paths[0]
        pinned = [*dict.fromkeys(paths)][:MAX_PINNED_FILES]
        exits = []
        for flag in _UNSHARE_FLAGS:
            res, _ = self._call(
                [unshare, flag, "sh", "-c", _NETCUT_PROBE], timeout=IO_TIMEOUT_S, disposable=True, wrap=False
            )
            if res.exit_code == 0:
                digests = {path: self._digest(self._base_image, path) for path in pinned}
                if any(digest is None for digest in digests.values()):
                    raise ExecutorUnavailable(
                        refusal.format(why="the wrapper files cannot be read to pin them")
                    )
                digests[_LD_SO_PRELOAD] = self._digest(self._base_image, _LD_SO_PRELOAD)
                digests[_LD_SO_CACHE] = self._digest(self._base_image, _LD_SO_CACHE)
                self._pinned = digests
                self._netns = [unshare, flag]
                return
            exits.append(f"unshare {flag} exit {res.exit_code}")
        raise ExecutorUnavailable(refusal.format(why=", ".join(exits)))

    def _base_commit(self) -> str:
        script = f"cd {shlex.quote(self._env.workdir)} && git rev-parse HEAD"
        res, _ = self._call(["sh", "-c", script], timeout=IO_TIMEOUT_S, disposable=True)
        return res.stdout.strip() if res.exit_code == 0 else ""

    def _untracked_paths(self) -> bytes:
        script = _BASELINE_SCRIPT.format(workdir=shlex.quote(self._env.workdir))
        try:
            res, cut = self._call(
                ["sh", "-c", script], timeout=IO_TIMEOUT_S, disposable=True, cap=MAX_BASELINE_BYTES
            )
        except _SandboxTimeout as exc:
            raise RuntimeError(f"untracked-file baseline was not recorded: {exc}") from exc
        if res.exit_code != 0 or cut:
            raise RuntimeError(
                f"untracked-file baseline was not recorded (exit {res.exit_code}, truncated={cut}): "
                f"{res.stderr.strip()[-300:]}"
            )
        return normalise_untracked(res.stdout.encode("utf-8"))

    def run(self, cmd: str, timeout: float) -> Result:
        if not timeout > 0:  # also refuses NaN
            raise ValueError(f"run timeout must be greater than 0 seconds, got {timeout!r}")
        limit = min(float(timeout), MAX_RUN_TIMEOUT_S)
        self._live()
        script = _IN_CONTAINER_TIMEOUT.format(seconds=max(1, math.ceil(limit)))
        argv = ["sh", "-lc", script, "cheatproof", cmd]
        try:
            res, cut = self._call(argv, timeout=limit, disposable=False)
        except _SandboxTimeout:
            # The operation was cancelled, so the command may still run in the sandbox. Like DockerSession, go back to
            # the base image: files written earlier in this session are lost, and the reset books one more run.
            self.reset()
            return Result(
                TIMEOUT_EXIT_CODE, "", f"[timed out after {limit:g}s]", limit, timed_out=True, reset=True
            )
        stdout, out_cut = _cap_stream(res.stdout, cut)
        stderr, err_cut = _cap_stream(res.stderr, cut)
        return replace(res, stdout=stdout, stderr=stderr, truncated=out_cut or err_cut)

    def write_file(self, path: str, data: bytes | str) -> None:
        self._live()
        payload = data.encode("utf-8") if isinstance(data, str) else data
        script = f"cat > {shlex.quote(path)}"
        parent = posixpath.dirname(path)
        if parent:
            script = f"mkdir -p -- {shlex.quote(parent)} && {script}"
        res, _ = self._call(["sh", "-c", script], timeout=IO_TIMEOUT_S, stdin=payload, disposable=False)
        if res.exit_code != 0:
            raise RuntimeError(f"write_file {path!r} failed ({res.exit_code}): {res.stderr.strip()[-300:]}")

    def diff(self) -> str:
        """Same patch as DockerSession.diff, built by the same script on the current image (see there)."""
        self._live()
        if not self._base:
            raise RuntimeError("base commit was not recorded at start; refusing to build a diff")
        if self._untracked is None:
            raise RuntimeError("untracked-file baseline was not recorded at start; refusing to build a diff")
        unstage = _UNSTAGE_SCRIPT.format(workdir=shlex.quote(self._env.workdir)) if self._untracked else ""
        script = _DIFF_SCRIPT.format(
            workdir=shlex.quote(self._env.workdir), base=shlex.quote(self._base), unstage=unstage
        )
        try:
            res, cut = self._call(
                ["sh", "-c", script],
                timeout=IO_TIMEOUT_S,
                stdin=self._untracked,
                disposable=True,
                cap=MAX_DIFF_BYTES,
            )
        except _SandboxTimeout as exc:
            raise RuntimeError(f"diff timed out after {IO_TIMEOUT_S}s") from exc
        if cut:
            raise RuntimeError(f"diff is over MAX_DIFF_BYTES={MAX_DIFF_BYTES}; refusing to truncate it")
        if res.exit_code != 0:
            raise RuntimeError(f"diff failed ({res.exit_code}): {res.stderr.strip()[-300:]}")
        return res.stdout

    def reset(self) -> None:
        self._open()
        self._launch()

    def close(self) -> None:
        # Nothing to destroy: the SDK has no image delete and an exec leaves no process behind.
        self._closed = True


def _as_bytes(value: object) -> bytes:
    if value is None:
        return b""
    return value if isinstance(value, bytes) else str(value).encode("utf-8")


def _cap_stream(text: str, server_cut: bool) -> tuple[str, bool]:
    """_cap, plus the same marker when the server already cut the stream at MAX_OUTPUT_BYTES."""
    out, cut = _cap(text)
    if not cut and server_cut and len(text.encode("utf-8")) >= MAX_OUTPUT_BYTES:
        return f"{out}\n[truncated: over {MAX_OUTPUT_BYTES} bytes, first {MAX_OUTPUT_BYTES} kept]", True
    return out, cut


def make_executor(name: str | None = None) -> Executor:
    """Backend named by EXECUTOR (default sandbox: Token Factory Sandboxes). EXECUTOR=docker uses local Docker."""
    choice = (name or os.environ.get("EXECUTOR") or "sandbox").strip().lower()
    if choice == "docker":
        return DockerExecutor()
    if choice == "sandbox":
        return SandboxExecutor()
    raise ValueError(f"EXECUTOR must be docker or sandbox, got {choice!r}")


def start(env: EnvSpec, budget: Budget | None = None, executor: Executor | None = None) -> Session:
    """Start a session on the backend named by EXECUTOR, or on the given executor."""
    return (make_executor() if executor is None else executor).start(env, budget)
