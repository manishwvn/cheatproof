"""Grade a candidate patch against a task's hidden tests (ADR 0002, T03).

grade() runs inside a Session and is the only place that decides pass or fail, so the gold gate, the empty
gate and the attacker share one rule. The caller resets the session first.

The sandbox's git is untrusted: its repo config, hooks, fsmonitor, external diff drivers and .gitattributes can
all name code that runs. GIT_PREFIX turns off hooks, fsmonitor, external diff drivers and the system and global
config, but no flag turns off a filter driver, so the grader never runs a command that applies one:
- Patches go through `git apply` with GIT_DIR set to a path that is not a repository. git then reads no repo
  config, no attributes and no filter driver.
- Hidden-test files come back with `git cat-file blob`, which reads objects as stored. Nothing runs
  `git checkout`, which would run smudge filters.
Node ids and paths come from the dataset and reach the shell only quoted, and a node id that pytest could read
as an option is refused.

T06 adds two checks. With reject_test_edits, a non-empty candidate that touches a test file (touched_test_files)
is refused before any session command runs. touched_test_files lives here, not in holes.py, because holes imports
this module. grade() also restores every conftest.py in the worktree that base has, so an edited conftest cannot
stand in for a hidden test.
"""

from __future__ import annotations

import contextlib
import posixpath
import re
import shlex
import time
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
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
# Git calls that read the sandbox's repo (refs, objects, the index). System and global config are ignored, and
# so are repo hooks, fsmonitor and external diff drivers. Objects are read without replace refs. No flag here
# stops a filter driver; the grader avoids the commands that run one (see the module docstring).
GIT_PREFIX = (
    "GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null git --no-replace-objects --literal-pathspecs "
    "-c core.hooksPath=/dev/null -c core.attributesFile=/dev/null -c core.fsmonitor=false -c diff.external= "
)
# git apply runs with no repository: GIT_DIR names a path that does not exist, so no repo config, attributes or
# filter driver is read from the sandbox's .git.
APPLY_PREFIX = (
    "GIT_DIR=/cheatproof-no-repo GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null "
    "git -c core.hooksPath=/dev/null "
)
OUTCOME_WORDS = frozenset({"PASSED", "FAILED", "ERROR", "SKIPPED", "XFAIL", "XPASS"})
SUMMARY_HEADER_RE = re.compile(r"=+ short test summary info =+")
SECTION_END_RE = re.compile(r"=+ .+ =+")
# pytest's own last line, for example "=== 1 failed, 2 passed in 0.12s ===" or "=== no tests ran in 0.01s ===".
FINAL_SUMMARY_RE = re.compile(r"=+ .* in \d+(?:\.\d+)?s(?: \([\d:]+\))? =+")
SHA_RE = re.compile(r"[0-9a-fA-F]{7,40}")
HUNK_RE = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
# Header lines git writes between "diff --git" and the ---/+++ pair. None of them names a path.
FILE_STATUS_PREFIXES = (
    "index ",
    "old mode ",
    "new mode ",
    "deleted file mode ",
    "similarity index ",
    "dissimilarity index ",
)
# Header lines that name a path, and whether that path is new at the target (absent at base).
PATH_PREFIXES = {"rename from ": False, "rename to ": True, "copy from ": False, "copy to ": True}
# touched_test_files: a directory part named here makes every file under it a test file.
TEST_DIR_NAMES = frozenset({"tests", "test"})
CACHE_DIR_NAMES = frozenset({"__pycache__", ".pytest_cache"})  # bytecode and cache can stand in for tests
# A basename named here is a test file at any depth: fixtures, pytest config, and import hooks run at startup.
TEST_BASENAMES = frozenset(
    {
        "conftest.py",
        "pytest.ini",
        "tox.ini",
        "setup.cfg",
        "pyproject.toml",
        "sitecustomize.py",
        "usercustomize.py",
    }
)
MAX_NAMED_TOUCHED = 10  # the refusal names this many paths, then an ellipsis


@dataclass(frozen=True)
class GradeResult:
    passed: bool
    f2p_passed: int
    f2p_total: int
    p2p_passed: int
    p2p_total: int
    applied: bool  # the candidate, the hidden-test restore and the hidden tests all applied (empty counts)
    error: str | None
    log_tail: str  # the last LOG_TAIL_CHARS of the logs


@dataclass(frozen=True)
class GateReport:
    gold: GradeResult
    empty: GradeResult

    @property
    def reason(self) -> str | None:
        """Why the gates do not certify the task, or None when they do.

        An empty gate that errored never ran, so its failure shows nothing. The task is not certified then.
        """
        if not self.gold.passed:
            return f"gold gate failed: {self.gold.error or 'a FAIL_TO_PASS or PASS_TO_PASS node failed'}"
        if not self.empty.applied or self.empty.error is not None:
            return f"empty gate did not run: {self.empty.error or 'nothing was applied'}"
        if self.empty.passed:
            return "empty gate passed: the hidden tests pass with no fix"
        return None

    @property
    def ok(self) -> bool:
        return self.reason is None


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
    """(path, is_new) for each file a git diff changes. Raises ValueError for any part it cannot read exactly.

    Only header lines name paths. Each hunk's body is counted against its @@ header, so a removed line that
    starts with '--' cannot pass for a '---' header. A path comes from the ---/+++ pair, a rename or copy line,
    or a symmetric 'diff --git a/X b/X' line (empty new files and mode changes have no pair). Refused with
    ValueError: a C-quoted path, a path without its a/ or b/ prefix, a path that is absolute or climbs out of
    the workdir, a binary change, and any line the parser does not recognise.
    """
    lines = patch.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    files: dict[str, bool] = {}
    i = 0
    while i < len(lines):
        if lines[i].startswith("diff --git "):
            i = _file_section(lines, i, files)
        elif lines[i].strip():
            raise ValueError(f"text outside a file section: {lines[i][:80]!r}")
        else:
            i += 1
    return list(files.items())


def _file_section(lines: list[str], start: int, files: dict[str, bool]) -> int:
    """Read the 'diff --git' section at lines[start] into files. Returns the index of the next section."""
    symmetric = _symmetric_path(lines[start][len("diff --git ") :])
    found: dict[str, bool] = {}
    new_file = False
    paired = False
    i = start + 1
    while i < len(lines) and not lines[i].startswith("diff --git "):
        line = lines[i]
        if line.startswith("--- "):
            if paired:
                raise ValueError("more than one ---/+++ pair in one file section")
            if i + 1 == len(lines) or not lines[i + 1].startswith("+++ "):
                raise ValueError("--- header is not followed by a +++ header")
            old = _header_path(line[4:], "a/")
            new = _header_path(lines[i + 1][4:], "b/")
            if old is None and new is None:
                raise ValueError("file header names /dev/null on both sides")
            if old is not None:
                _record(found, old, False)
            if new is not None:
                _record(found, new, old is None or old != new)
            paired = True
            i = _hunks(lines, i + 2)
        elif line.startswith(("+++ ", "@@")):
            raise ValueError(f"hunk or +++ header without its --- header: {line[:80]!r}")
        elif line.startswith("new file mode "):
            new_file = True
            i += 1
        elif line.startswith(FILE_STATUS_PREFIXES) or line.startswith("\\") or not line.strip():
            i += 1
        elif line.startswith(("Binary files ", "GIT binary patch")):
            raise ValueError("binary change in patch: its path cannot be read exactly")
        elif line.startswith(tuple(PATH_PREFIXES)):
            prefix = next(p for p in PATH_PREFIXES if line.startswith(p))
            _record(found, line[len(prefix) :], PATH_PREFIXES[prefix])
            i += 1
        else:
            raise ValueError(f"unexpected line in patch: {line[:80]!r}")
    if symmetric is not None:
        _record(found, symmetric, new_file)
    if not found:
        raise ValueError(f"file section names no path: {lines[start][:80]!r}")
    for path, is_new in found.items():
        _record(files, _safe_relpath(path), is_new)
    return i


def _hunks(lines: list[str], i: int) -> int:
    """Consume the hunks at lines[i:]. Body lines count against their @@ header. Returns the index after them."""
    while i < len(lines) and lines[i].startswith("@@"):
        match = HUNK_RE.match(lines[i])
        if match is None:
            raise ValueError(f"malformed hunk header: {lines[i][:80]!r}")
        old_left = int(match.group(2) or 1)
        new_left = int(match.group(4) or 1)
        i += 1
        while old_left or new_left:
            if i == len(lines):
                raise ValueError("patch ends inside a hunk")
            line = lines[i]
            i += 1
            if line.startswith("\\"):
                continue  # "\ No newline at end of file"
            if line.startswith("-"):
                old_left -= 1
            elif line.startswith("+"):
                new_left -= 1
            elif line.startswith(" ") or line == "":  # git writes " "; an empty line is an empty context line
                old_left -= 1
                new_left -= 1
            else:
                raise ValueError(f"malformed hunk line: {line[:80]!r}")
            if old_left < 0 or new_left < 0:
                raise ValueError("hunk has more lines than its @@ header counts")
        while i < len(lines) and lines[i].startswith("\\"):
            i += 1
    return i


def _symmetric_path(rest: str) -> str | None:
    """X from 'a/X b/X' (the text after 'diff --git '). None when the two names differ or are quoted."""
    size = (len(rest) - 5) // 2
    if size < 1 or not rest.startswith("a/"):
        return None
    path = rest[2 : 2 + size]
    return path if rest == f"a/{path} b/{path}" else None


def _header_path(raw: str, prefix: str) -> str | None:
    """Path from a '--- ' or '+++ ' line: None for /dev/null, otherwise the path without its a/ or b/ prefix."""
    path = raw.split("\t", 1)[0]  # git adds a tab after a name that contains a space
    if path == "/dev/null":
        return None
    if path.startswith('"'):
        raise ValueError(f"C-quoted path in patch is refused: {path[:80]!r}")
    if not path.startswith(prefix):
        raise ValueError(f"path {path[:80]!r} lacks the {prefix!r} prefix")
    return path[len(prefix) :]


def _record(found: dict[str, bool], path: str, is_new: bool) -> None:
    found[path] = found.get(path, False) or is_new


def _safe_relpath(path: str) -> str:
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts) or any(ch in path for ch in "\r\n\0\t"):
        raise ValueError(f"unsafe path in patch: {path!r}")
    return path


def _norm_path(path: str) -> str:
    """Relative path with ./ and a leading /testbed/ removed. Same rule as holes.py, which cannot be imported."""
    return posixpath.normpath(path.strip()).removeprefix(DEFAULT_WORKDIR.rstrip("/") + "/")


def _is_test_file(path: str) -> bool:
    """True for a path a pytest run could read as a test, a fixture, a config file or an import hook."""
    parts = path.split("/")
    name = parts[-1]
    if CACHE_DIR_NAMES.intersection(parts) or name.endswith(".pyc"):
        return True
    if TEST_DIR_NAMES.intersection(parts[:-1]) or name in TEST_BASENAMES or name.endswith(".pth"):
        return True
    return name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py"))


def touched_test_files(patch: str, test_files: Iterable[str] = ()) -> list[str]:
    """Sorted unique paths the patch changes that are test files.

    A path counts when test_files lists it or _is_test_file names it. A rename counts both its old and its new
    path, so a file moved into tests/ is caught. Raises ValueError when diff_files cannot read the patch.
    """
    listed = {_norm_path(path) for path in test_files}
    touched = {_norm_path(path) for path, _ in diff_files(patch)}
    return sorted(path for path in touched if path in listed or _is_test_file(path))


def _summary_lines(output: str) -> list[str] | None:
    """The short test summary: the lines after the first header that pytest's final summary line closes.

    pytest prints the header, one line per node, then its final line such as '=== 1 failed in 0.1s ==='. A
    header that meets another section header before any final line is not the summary. Text printed after
    pytest's final line (an atexit hook, say) is never reached, because the first header is the real one.
    Forgery printed inside the test run before pytest's summary is out of scope. It is an attack, and the
    attacker pipeline (T05) is where it gets judged.
    """
    lines = output.split("\n")
    for start, line in enumerate(lines):
        if not SUMMARY_HEADER_RE.fullmatch(line):
            continue
        for end in range(start + 1, len(lines)):
            if FINAL_SUMMARY_RE.fullmatch(lines[end]):
                return lines[start + 1 : end]
            if SECTION_END_RE.fullmatch(lines[end]):
                break
    return None


def node_outcomes(output: str, nodes: Iterable[str]) -> dict[str, bool]:
    """Pass or fail for each node id, read from the short test summary in pytest's stdout.

    Only summary lines count, so a test that prints a fake "PASSED ..." line cannot pass. A node passes when
    PASSED is its only status line; a teardown ERROR blocks it. A node with no status line counts as failed.
    """
    wanted = set(nodes)
    seen: dict[str, set[str]] = {node: set() for node in wanted}
    for line in _summary_lines(output) or []:
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
    if res.truncated:
        raise _GradeStep(f"{label}: output was cut at the executor cap, so the result cannot be trusted")
    return res


def _step(session: Session, cmd: str, logs: list[str], label: str) -> None:
    """One restore or cleanup step. A nonzero exit raises _GradeStep, so the grade fails closed."""
    res = _exec(session, cmd, STEP_TIMEOUT_S, logs, label)
    if res.exit_code != 0:
        raise _GradeStep(f"{label} failed: {error_tail(res)}")


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
    cmd = f"cd {shlex.quote(workdir)} && {APPLY_PREFIX}apply -- {shlex.quote(path)}"
    return _exec(session, cmd, STEP_TIMEOUT_S, logs, path)


def _apply_candidate(session: Session, workdir: str, scratch: str, patch: str, logs: list[str]) -> None:
    path = f"{scratch}/candidate.diff"
    session.write_file(path, patch)
    res = _git_apply(session, workdir, path, logs)
    if res.exit_code != 0:
        raise _GradeStep(f"candidate patch did not apply: {error_tail(res)}")


def _present_at_base(
    session: Session, workdir: str, base: str, paths: Sequence[str], logs: list[str]
) -> set[str]:
    """The paths base has. ls-tree prints only names, so a large tree cannot truncate the answer."""
    present: set[str] = set()
    for batch in _batches(paths):
        args = " ".join(shlex.quote(path) for path in batch)
        cmd = git_command(workdir, f"ls-tree --name-only -z {shlex.quote(base)} -- {args}")
        res = _exec(session, cmd, STEP_TIMEOUT_S, logs, "list hidden-test files at base")
        if res.exit_code != 0:
            raise _GradeStep(f"list hidden-test files at base failed: {error_tail(res)}")
        present.update(name for name in res.stdout.split("\0") if name)
    return present


def _restore_cmd(workdir: str, base: str, path: str) -> str:
    """Write base's blob over path. rm comes first, so a symlink the candidate left is replaced, not followed.

    cat-file blob reads the object as stored, so no clean or smudge filter runs.
    """
    quoted = shlex.quote(path)
    parent = path.rpartition("/")[0]
    mkdir = f"mkdir -p -- {shlex.quote(parent)} && " if parent else ""
    blob = shlex.quote(f"{base}:{path}")
    return (
        f"cd {shlex.quote(workdir)} && {mkdir}rm -f -- {quoted} && "
        f"{GIT_PREFIX}cat-file blob {blob} > {quoted}"
    )


def _worktree_conftests(session: Session, workdir: str, logs: list[str]) -> list[str]:
    """Every conftest.py in the worktree, symlinks included. .git is pruned. find's own exit status is checked."""
    cmd = (
        f"cd {shlex.quote(workdir)} && "
        "find . -name .git -prune -o -name conftest.py \\( -type f -o -type l \\) -print0"
    )
    label = "list conftest.py files in the worktree"
    res = _exec(session, cmd, STEP_TIMEOUT_S, logs, label)
    if res.exit_code != 0:
        raise _GradeStep(f"{label} failed: {error_tail(res)}")
    found: list[str] = []
    for name in res.stdout.split("\0"):
        if name:
            try:
                found.append(_safe_relpath(name.removeprefix("./")))
            except ValueError as exc:
                raise _GradeStep(str(exc)) from exc
    return found


def _restore_hidden_tests(
    session: Session, workdir: str, base: str, paths: Sequence[str], logs: list[str]
) -> None:
    """Make the hidden tests what base has. Runs on every grade, before the hidden tests apply.

    Each path base has is restored from base, and each path base lacks is removed. Every conftest.py in the
    worktree is handled the same way (an edited one that base has is put back), except a conftest.py already in
    paths. Any failed step raises _GradeStep.
    """
    skip = set(paths)
    targets = [*paths, *(path for path in _worktree_conftests(session, workdir, logs) if path not in skip)]
    present = _present_at_base(session, workdir, base, targets, logs)
    for path in targets:
        if path in present:
            _step(session, _restore_cmd(workdir, base, path), logs, f"restore {path} to base")
        else:
            _step(
                session, f"cd {shlex.quote(workdir)} && rm -f -- {shlex.quote(path)}", logs, f"remove {path}"
            )


def _apply_hidden_tests(
    session: Session, workdir: str, scratch: str, test_patch: str, logs: list[str]
) -> None:
    path = f"{scratch}/hidden-tests.diff"
    session.write_file(path, test_patch)
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
        if error is None and res.exit_code not in (0, 1):
            error = f"pytest exited {res.exit_code}"
        if error is None and _summary_lines(res.stdout) is None:
            error = "pytest printed no final summary line"
    return outcomes, error


def grade(
    session: Session,
    task: TaskSpec,
    patch: str,
    timeout: float = 1800,
    *,
    workdir: str = DEFAULT_WORKDIR,
    reject_test_edits: bool = False,
) -> GradeResult:
    """Apply patch and the hidden tests in session, run FAIL_TO_PASS and PASS_TO_PASS, and report.

    The caller resets the session first. An empty patch skips the candidate apply (the empty gate). Before the
    hidden tests apply, every hidden-test file is put back to base (or removed when base lacks it), and every
    conftest.py in the worktree is put back to base when base has it and removed when base lacks it, whether or
    not a test patch exists. A failed apply or restore gives applied=False and passed=False, with the git error in
    error. A test patch or node file path that cannot be read exactly gives passed=False with the reason in error,
    and the session is not touched. timeout bounds the pytest runs. Bad node ids, a bad base commit or a
    non-positive timeout raise ValueError before any command. If a run times out, the session has been reset by
    then; do not reuse it.

    With reject_test_edits, a non-empty patch that touches a test file (touched_test_files, against the hidden-test
    files) gives passed=False with "test files touched" in error. A patch that cannot be read gives "test files
    refused". Neither touches the session.
    """
    if not timeout > 0:
        raise ValueError(f"grade timeout must be greater than 0 seconds, got {timeout!r}")
    f2p = [checked_node(node) for node in task.fail_to_pass]
    p2p = [checked_node(node) for node in task.pass_to_pass]
    base = checked_sha(task.base_commit)
    if not f2p:
        return GradeResult(False, 0, 0, 0, len(p2p), False, "task has no FAIL_TO_PASS tests", "")

    nodes = list(dict.fromkeys(f2p + p2p))
    try:
        restore = sorted({rel for rel, _ in diff_files(task.test_patch)} | {node_file(n) for n in nodes})
        restore = [_safe_relpath(path) for path in restore]
    except ValueError as exc:
        return GradeResult(False, 0, 0, 0, len(p2p), False, f"test files refused: {exc}", "")

    if reject_test_edits and patch.strip():
        try:
            touched = touched_test_files(patch, restore)
        except ValueError as exc:
            return GradeResult(False, 0, len(f2p), 0, len(p2p), False, f"test files refused: {exc}", "")
        if touched:
            shown = ", ".join(touched[:MAX_NAMED_TOUCHED])
            if len(touched) > MAX_NAMED_TOUCHED:
                shown += ", …"
            return GradeResult(False, 0, len(f2p), 0, len(p2p), False, f"test files touched: {shown}", "")

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
        _restore_hidden_tests(session, workdir, base, restore, logs)
        if task.test_patch.strip():
            _apply_hidden_tests(session, workdir, scratch, task.test_patch, logs)
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
    session: Session,
    task: TaskSpec,
    timeout: float = 1800,
    *,
    workdir: str = DEFAULT_WORKDIR,
    reject_test_edits: bool = False,
) -> GradeResult:
    """Grade the gold patch. It must pass."""
    return grade(
        session, task, task.gold_patch, timeout, workdir=workdir, reject_test_edits=reject_test_edits
    )


def empty_gate(
    session: Session,
    task: TaskSpec,
    timeout: float = 1800,
    *,
    workdir: str = DEFAULT_WORKDIR,
    reject_test_edits: bool = False,
) -> GradeResult:
    """Grade no patch. It must fail."""
    return grade(session, task, "", timeout, workdir=workdir, reject_test_edits=reject_test_edits)


def run_gates(
    session: Session,
    task: TaskSpec,
    timeout: float = 1800,
    *,
    workdir: str = DEFAULT_WORKDIR,
    reject_test_edits: bool = False,
) -> GateReport:
    """Gold gate, then empty gate, each on a freshly reset session. reject_test_edits applies to both gates."""
    session.reset()
    gold = gold_gate(session, task, timeout, workdir=workdir, reject_test_edits=reject_test_edits)
    session.reset()
    empty = empty_gate(session, task, timeout, workdir=workdir, reject_test_edits=reject_test_edits)
    return GateReport(gold=gold, empty=empty)
