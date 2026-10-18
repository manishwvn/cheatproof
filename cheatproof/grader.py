"""Grade a candidate patch against a task's hidden tests (ADR 0002, T03).

grade() runs inside a Session and is the only place that decides pass or fail, so the gold gate, the empty
gate and the attacker share one rule. The caller resets the session first. Repo git config, attributes and
filter drivers are untrusted, so every git call carries the hardening in GIT_PREFIX. Node ids and paths come
from the dataset and reach the shell only quoted, and a node id that pytest could read as an option is refused.
"""

from __future__ import annotations

import contextlib
import re
import shlex
import time
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from itertools import pairwise
from typing import TYPE_CHECKING

from cheatproof.executor import Result, Session

if TYPE_CHECKING:
    from cheatproof.tasks import TaskSpec

DEFAULT_WORKDIR = "/testbed"
LOG_TAIL_CHARS = 4000
STEP_TIMEOUT_S = 300  # one git, find or cleanup step; grade's timeout bounds the pytest batches
MAX_BATCH_NODES = 200  # keeps one batch's -rA summary well under the executor's 64 KiB output cap
MAX_BATCH_CHARS = 60_000  # one command is one argv string; Linux caps a single argument at 128 KiB
PYTEST_CMD = (
    "PYTHONDONTWRITEBYTECODE=1 python -m pytest -p no:cacheprovider --color=no --tb=no --show-capture=no -rA"
)
# Every git call the grader and the exposure scan make. System and global config are ignored, and so are
# repo hooks, fsmonitor and external diff drivers. Objects are read without replace refs.
GIT_PREFIX = (
    "GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null git --no-replace-objects --literal-pathspecs "
    "-c core.hooksPath=/dev/null -c core.attributesFile=/dev/null -c core.fsmonitor=false -c diff.external= "
)
OUTCOME_WORDS = frozenset({"PASSED", "FAILED", "ERROR", "SKIPPED", "XFAIL", "XPASS"})
SUMMARY_HEADER_RE = re.compile(r"^=+ short test summary info =+$", re.MULTILINE)
SECTION_END_RE = re.compile(r"^=+ .+ =+$")
SHA_RE = re.compile(r"[0-9a-fA-F]{7,40}")


@dataclass(frozen=True)
class GradeResult:
    passed: bool
    f2p_passed: int
    f2p_total: int
    p2p_passed: int
    p2p_total: int
    applied: bool  # the candidate and the hidden tests both applied (an empty candidate counts as applied)
    error: str | None
    log_tail: str  # the last LOG_TAIL_CHARS of the logs


@dataclass(frozen=True)
class GateReport:
    gold: GradeResult
    empty: GradeResult

    @property
    def ok(self) -> bool:
        return self.gold.passed and not self.empty.passed


class _GradeStep(Exception):
    """A grading step failed. grade() turns the message into GradeResult.error."""


def git_command(workdir: str, args: str) -> str:
    """Shell line that runs `git <args>` in workdir with the hardening above. args must already be quoted."""
    return f"cd {shlex.quote(workdir)} && {GIT_PREFIX}{args}"


def error_tail(res: Result) -> str:
    return (res.stderr or res.stdout).strip()[-300:]


def checked_node(node: str) -> str:
    """Refuse a node id that is empty, starts with '-' (pytest would read it as an option) or has a line break."""
    if not node or node.startswith("-") or any(ch in node for ch in "\r\n\0"):
        raise ValueError(
            f"invalid test node id {node!r}: must be non-empty, not start with '-', no line breaks"
        )
    return node


def checked_sha(sha: str) -> str:
    if not SHA_RE.fullmatch(sha):
        raise ValueError(f"invalid commit id {sha!r}: expected 7 to 40 hex digits")
    return sha


def node_file(node: str) -> str:
    """File part of a node id: 'tests/test_x.py::TestA::test_b' gives 'tests/test_x.py'."""
    return node.split("::", 1)[0]


def diff_files(patch: str) -> list[tuple[str, bool]]:
    """(path, is_new) for each file a unified diff changes, read from its --- and +++ header pair.

    A rename or a binary-only change has no such header and is not listed. A path must be relative and stay
    inside the workdir, otherwise ValueError, so it never reaches a shell or an rm.
    """
    lines = patch.splitlines()
    files: dict[str, bool] = {}
    for old_line, new_line in pairwise(lines):
        if not (old_line.startswith("--- ") and new_line.startswith("+++ ")):
            continue
        old = _header_path(old_line[4:], "a/")
        new = _header_path(new_line[4:], "b/")
        path = new if new is not None else old
        if path is None:
            continue  # /dev/null on both sides
        files[_safe_relpath(path)] = old is None
    return list(files.items())


def _header_path(raw: str, prefix: str) -> str | None:
    path = raw.split("\t", 1)[0].strip()
    if path == "/dev/null":
        return None
    if len(path) >= 2 and path[0] == path[-1] == '"':
        path = path[1:-1]
    return path.removeprefix(prefix)


def _safe_relpath(path: str) -> str:
    if not path or path.startswith("/") or ".." in path.split("/") or any(ch in path for ch in "\r\n\0"):
        raise ValueError(f"unsafe path in patch: {path!r}")
    return path


def node_outcomes(output: str, nodes: Iterable[str]) -> dict[str, bool]:
    """Pass or fail for each node id, read from the last -rA short summary in pytest's stdout.

    Only summary lines count, so a test that prints a fake "PASSED ..." line cannot pass. A node passes when
    PASSED is its only status line; a teardown ERROR blocks it. A node with no status line counts as failed.
    """
    wanted = set(nodes)
    seen: dict[str, set[str]] = {node: set() for node in wanted}
    headers = list(SUMMARY_HEADER_RE.finditer(output))
    if headers:
        for line in output[headers[-1].end() :].splitlines():
            if SECTION_END_RE.match(line):
                break
            status, _, rest = line.partition(" ")
            node = _summary_node(rest, wanted) if status in OUTCOME_WORDS else None
            if node is not None:
                seen[node].add(status)
    return {node: seen[node] == {"PASSED"} for node in wanted}


def _summary_node(rest: str, wanted: set[str]) -> str | None:
    """The node a summary line names. The line may carry ' - <message>' after it, and a node id may itself
    contain ' - ' (a parametrized id), so every split point is tried."""
    if rest in wanted:
        return rest
    for match in re.finditer(" - ", rest):
        if rest[: match.start()] in wanted:
            return rest[: match.start()]
    return None


def _batches(nodes: Sequence[str]) -> list[list[str]]:
    batches: list[list[str]] = []
    current: list[str] = []
    size = 0
    for node in nodes:
        cost = len(shlex.quote(node)) + 1
        if current and (len(current) == MAX_BATCH_NODES or size + cost > MAX_BATCH_CHARS):
            batches.append(current)
            current, size = [], 0
        current.append(node)
        size += cost
    if current:
        batches.append(current)
    return batches


def _exec(session: Session, cmd: str, timeout: float, logs: list[str], label: str) -> Result:
    res = session.run(cmd, timeout)
    logs.append(f"$ {label}\n{res.stdout}{res.stderr}")
    return res


def _clear_caches(session: Session, workdir: str, logs: list[str]) -> None:
    # Stale .pyc or __pycache__ from the sandbox could stand in for the code under test. .git is skipped.
    script = (
        f"cd {shlex.quote(workdir)} && "
        "find . -name .git -prune -o -name __pycache__ -type d -prune -exec rm -rf -- {} + && "
        "find . -name .git -prune -o -name '*.pyc' -type f -exec rm -f -- {} +"
    )
    res = _exec(session, script, STEP_TIMEOUT_S, logs, "clear caches")
    if res.exit_code != 0:
        raise _GradeStep(f"cache cleanup failed: {error_tail(res)}")


def _git_apply(session: Session, workdir: str, path: str, logs: list[str]) -> Result:
    return _exec(session, git_command(workdir, f"apply -- {shlex.quote(path)}"), STEP_TIMEOUT_S, logs, path)


def _apply_candidate(session: Session, workdir: str, scratch: str, patch: str, logs: list[str]) -> None:
    path = f"{scratch}/candidate.diff"
    session.write_file(path, patch)
    res = _git_apply(session, workdir, path, logs)
    if res.exit_code != 0:
        raise _GradeStep(f"candidate patch did not apply: {error_tail(res)}")


def _apply_hidden_tests(
    session: Session,
    workdir: str,
    scratch: str,
    base: str,
    test_patch: str,
    files: list[tuple[str, bool]],
    logs: list[str],
) -> None:
    path = f"{scratch}/hidden-tests.diff"
    session.write_file(path, test_patch)
    if _git_apply(session, workdir, path, logs).exit_code == 0:
        return
    # The candidate may have edited or created these files. Put the originals back and try once more.
    created = [rel for rel, is_new in files if is_new]
    existing = [rel for rel, is_new in files if not is_new]
    if created:
        cmd = f"cd {shlex.quote(workdir)} && rm -f -- " + " ".join(shlex.quote(p) for p in created)
        _exec(session, cmd, STEP_TIMEOUT_S, logs, "remove test files the candidate created")
    if existing:
        args = f"checkout {shlex.quote(base)} -- " + " ".join(shlex.quote(p) for p in existing)
        res = _exec(session, git_command(workdir, args), STEP_TIMEOUT_S, logs, "restore test files to base")
        if res.exit_code != 0:
            raise _GradeStep(f"could not restore test files to base: {error_tail(res)}")
    res = _git_apply(session, workdir, path, logs)
    if res.exit_code != 0:
        raise _GradeStep(f"hidden tests did not apply: {error_tail(res)}")


def _run_tests(
    session: Session, workdir: str, nodes: Sequence[str], deadline: float, logs: list[str]
) -> tuple[dict[str, bool], str | None]:
    outcomes: dict[str, bool] = {}
    error: str | None = None
    for batch in _batches(nodes):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return outcomes, "out of time before every test ran"
        args = " ".join(shlex.quote(node) for node in batch)
        cmd = f"cd {shlex.quote(workdir)} && {PYTEST_CMD} {args}"
        res = _exec(session, cmd, remaining, logs, f"pytest ({len(batch)} node ids)")
        outcomes.update(node_outcomes(res.stdout, batch))
        if res.timed_out:
            return outcomes, f"pytest timed out after {remaining:.0f}s"
        if res.exit_code not in (0, 1) and error is None:
            error = f"pytest exited {res.exit_code}"
    return outcomes, error


def grade(
    session: Session,
    task: TaskSpec,
    patch: str,
    timeout: float = 1800,
    *,
    workdir: str = DEFAULT_WORKDIR,
) -> GradeResult:
    """Apply patch and the hidden tests in session, run FAIL_TO_PASS and PASS_TO_PASS, and report.

    The caller resets the session first. An empty patch skips the candidate apply (the empty gate). A failed
    apply gives applied=False and passed=False, with the git error in error. timeout bounds the pytest runs.
    If a run times out, the session has been reset by then; do not reuse it.
    """
    if not timeout > 0:
        raise ValueError(f"grade timeout must be greater than 0 seconds, got {timeout!r}")
    f2p = [checked_node(node) for node in task.fail_to_pass]
    p2p = [checked_node(node) for node in task.pass_to_pass]
    base = checked_sha(task.base_commit)
    files = diff_files(task.test_patch)
    if not f2p:
        return GradeResult(False, 0, 0, 0, len(p2p), False, "task has no FAIL_TO_PASS tests", "")

    nodes = list(dict.fromkeys(f2p + p2p))
    deadline = time.monotonic() + timeout
    scratch = (
        f"/tmp/cheatproof-{uuid.uuid4().hex}"  # host-chosen and unguessable; never taken from the sandbox
    )
    logs: list[str] = []
    applied = False
    outcomes: dict[str, bool] = {}
    error: str | None = None
    try:
        _clear_caches(session, workdir, logs)
        if patch.strip():
            _apply_candidate(session, workdir, scratch, patch, logs)
        if task.test_patch.strip():
            _apply_hidden_tests(session, workdir, scratch, base, task.test_patch, files, logs)
        applied = True
        outcomes, error = _run_tests(session, workdir, nodes, deadline, logs)
    except _GradeStep as exc:
        error = str(exc)
    finally:
        with contextlib.suppress(Exception):  # cleanup must not hide the grade; a leftover dir is harmless
            session.run(f"rm -rf -- {shlex.quote(scratch)}", STEP_TIMEOUT_S)

    f2p_passed = sum(outcomes.get(node, False) for node in f2p)
    p2p_passed = sum(outcomes.get(node, False) for node in p2p)
    passed = applied and error is None and f2p_passed == len(f2p) and p2p_passed == len(p2p)
    return GradeResult(
        passed=passed,
        f2p_passed=f2p_passed,
        f2p_total=len(f2p),
        p2p_passed=p2p_passed,
        p2p_total=len(p2p),
        applied=applied,
        error=error,
        log_tail="\n".join(logs)[-LOG_TAIL_CHARS:],
    )


def gold_gate(
    session: Session, task: TaskSpec, timeout: float = 1800, *, workdir: str = DEFAULT_WORKDIR
) -> GradeResult:
    """Grade the gold patch. It must pass."""
    return grade(session, task, task.gold_patch, timeout, workdir=workdir)


def empty_gate(
    session: Session, task: TaskSpec, timeout: float = 1800, *, workdir: str = DEFAULT_WORKDIR
) -> GradeResult:
    """Grade no patch. It must fail."""
    return grade(session, task, "", timeout, workdir=workdir)


def run_gates(
    session: Session, task: TaskSpec, timeout: float = 1800, *, workdir: str = DEFAULT_WORKDIR
) -> GateReport:
    """Gold gate, then empty gate, each on a freshly reset session."""
    session.reset()
    gold = gold_gate(session, task, timeout, workdir=workdir)
    session.reset()
    empty = empty_gate(session, task, timeout, workdir=workdir)
    return GateReport(gold=gold, empty=empty)
