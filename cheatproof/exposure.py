"""Static exposure scan for one task (ADR 0002, T03). Code only, no model.

scan() probes a session and reports the holes an attacker can use:
  git-history  refs, the reflog, FETCH_HEAD or ORIG_HEAD point past base_commit, so the fix may be in .git
  test-edit    the uid running the agent can write a test file the grader does not restore from base. The grader
               restores its node-id files, its test_patch paths and every conftest.py before it grades, so a writable
               one of those is covered. Any other writable test file (a helper under a tests/ dir) is a hole, except
               as root: test -w is true for every file as root, so the probe cannot tell those apart. As root such a
               file is labelled "writable as root" and is not a hole. holes.py still judges the final diff.
  network      a TCP connection to 1.1.1.1:53 succeeds

The scan is read-only: it writes nothing, resets nothing and deletes nothing. A probe that cannot run, or whose
input the grader would refuse, counts as a hole, with an "unverified" or "unverifiable" note in its evidence, so a
clean report never rests on a check that did not run.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from cheatproof.executor import Result, Session
from cheatproof.grader import (
    DEFAULT_WORKDIR,
    STEP_TIMEOUT_S,
    checked_sha,
    error_tail,
    git_command,
    redact_text,
    restore_paths,
    restored_conftest,
)

if TYPE_CHECKING:
    from cheatproof.tasks import TaskSpec

HOLE_GIT_HISTORY = "git-history"
HOLE_TEST_EDIT = "test-edit"
HOLE_NETWORK = "network"
PROBE_TIMEOUT_S = 15  # the host's cap on one network probe; each probe also gives up its connect after 3 s
CONNECT_PROBE = "import socket; socket.create_connection(('1.1.1.1', 53), timeout=3).close()"
# Tried in order. A probe whose program is missing (exit 127) hands over to the next. The first that runs decides.
NETWORK_PROBES = (
    ("python3", f"python3 -c {shlex.quote(CONNECT_PROBE)}"),
    ("python", f"python -c {shlex.quote(CONNECT_PROBE)}"),
    ("bash /dev/tcp", "timeout 3 bash -c '</dev/tcp/1.1.1.1/53'"),
)
MISSING_EXIT = 127  # shell status for "command not found"
REF_FORMAT = "%(objectname)|%(*objectname)|%(refname)"  # *objectname is the peeled target of an annotated tag
# What counts as a test file for the test-edit probe: test modules, conftest.py, and anything under a test dir.
TEST_FILE_TESTS = (
    "-name 'test_*.py' -o -name '*_test.py' -o -name conftest.py "
    "-o -path '*/test/*' -o -path '*/tests/*' -o -path '*/testing/*'"
)


@dataclass(frozen=True)
class ExposureReport:
    future_git: bool
    future_git_evidence: list[str]
    tests_writable: bool  # observed: the probe uid can write at least one test path, covered or not
    writable_tests: list[str]  # those paths, or an "unverified" / "unverifiable" note
    restore_covered: bool  # every writable test path is restored from base, and none is only writable as root
    unrestored_tests: list[
        str
    ]  # writable test paths the grader does not restore (not as root), or the note; empty if covered
    network: bool
    network_evidence: list[str]
    holes: list[str]  # HOLE_* labels, in the order git-history, test-edit, network
    # Unrestored test paths seen as root: a note, not a hole. Last, with a default, so older constructions still work.
    writable_as_root: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _TestProbe:
    writable: list[str]
    unrestored: list[str]  # a subset of writable
    as_root: list[str]  # a subset of writable: unrestored paths the probe saw as root


def scan(session: Session, task: TaskSpec, *, workdir: str = DEFAULT_WORKDIR) -> ExposureReport:
    try:
        base = checked_sha(task.base_commit)
    except ValueError as exc:
        git_evidence = [_unverifiable(exc)]  # no base, so history cannot be checked: fail closed
    else:
        git_evidence = _git_history(session, base, workdir)
    tests = _writable_tests(session, task, workdir)
    network, network_evidence = _network(session)
    # The holes and the restore check are judged on the raw values, before any text is redacted or cut.
    holes = [
        label
        for label, hit in (
            (HOLE_GIT_HISTORY, bool(git_evidence)),
            (HOLE_TEST_EDIT, bool(tests.unrestored)),
            (HOLE_NETWORK, network),
        )
        if hit
    ]
    return ExposureReport(
        future_git=bool(git_evidence),
        future_git_evidence=_evidence(git_evidence),
        tests_writable=bool(tests.writable),
        writable_tests=_redacted(tests.writable),
        restore_covered=not tests.unrestored and not tests.as_root,
        unrestored_tests=_redacted(tests.unrestored),
        writable_as_root=_redacted(tests.as_root),
        network=network,
        network_evidence=_evidence(network_evidence),
        holes=holes,
    )


# Evidence and test paths are free text: a ref name or a file name comes from the task repo. Each secret-like word
# goes to REDACTED and the path or finding type stays. The redaction runs on the whole line before the cut, so a
# secret cannot survive as a prefix. The cut keeps every string under the certificate's 2000-char limit. The leak
# guard at certificate write still refuses any value this misses.
EVIDENCE_CHARS = 300


def _redacted(lines: list[str]) -> list[str]:
    return [redact_text(line) for line in lines]


def _evidence(lines: list[str]) -> list[str]:
    return [redact_text(line)[:EVIDENCE_CHARS] for line in lines]


def _unverified(what: str, res: Result) -> str:
    tail = error_tail(res)
    return f"unverified: {what} failed (exit {res.exit_code})" + (f": {tail}" if tail else "")


def _unverifiable(exc: ValueError) -> str:
    return f"unverifiable: {exc}"


def _is_base(sha: str, base: str) -> bool:
    return bool(sha) and sha.lower().startswith(base.lower())


def _git_history(session: Session, base: str, workdir: str) -> list[str]:
    evidence: list[str] = []

    # Commits that some ref reaches but base does not: the usual place for a future fix.
    res = session.run(
        git_command(workdir, f"rev-list --count --all --not {shlex.quote(base)}"), STEP_TIMEOUT_S
    )
    if res.exit_code != 0 or not res.stdout.strip().isdigit():
        evidence.append(_unverified("rev-list", res))
    elif int(res.stdout) > 0:
        evidence.append(f"{int(res.stdout)} commit(s) past base reachable from refs")

    # Refs (branches, tags, packed-refs) that point anywhere other than base.
    res = session.run(
        git_command(workdir, f"for-each-ref --format={shlex.quote(REF_FORMAT)}"), STEP_TIMEOUT_S
    )
    if res.exit_code != 0:
        evidence.append(_unverified("for-each-ref", res))
    else:
        for line in res.stdout.splitlines():
            obj, _, rest = line.partition("|")
            peeled, _, ref = rest.partition("|")
            target = peeled or obj
            if target and not _is_base(target, base):
                evidence.append(f"ref {ref} points at {target[:12]}")

    # Reflog entries past base: a checkout of the fix leaves it there even after a reset.
    res = session.run(git_command(workdir, "reflog show --all --format=%H"), STEP_TIMEOUT_S)
    if res.exit_code != 0:
        evidence.append(_unverified("reflog", res))
    else:
        stray = {line.strip() for line in res.stdout.splitlines() if line.strip()}
        stray = {sha for sha in stray if not _is_base(sha, base)}
        if stray:
            evidence.append(f"reflog holds {len(stray)} commit(s) other than base")

    for name in ("ORIG_HEAD", "FETCH_HEAD"):
        res = session.run(git_command(workdir, f"rev-parse -q --verify {name}"), STEP_TIMEOUT_S)
        if res.exit_code == 1:
            continue  # rev-parse -q exits 1 when the name does not exist
        if res.exit_code != 0:
            evidence.append(_unverified(f"rev-parse {name}", res))
        elif not _is_base(res.stdout.strip(), base):
            evidence.append(f"{name} points at {res.stdout.strip()[:12]}")
    return evidence


def _covered_check(path: str) -> str:
    # test -w only reads permissions, and as root it is true for every file. A missing file is judged by its dir.
    q = shlex.quote(path)
    return (
        f'p={q}; if [ -e "$p" ]; then test -w "$p"; else test -w "$(dirname -- "$p")"; fi '
        "&& printf 'covered %s\\n' \"$p\""
    )


def _probe_script(workdir: str, covered: list[str]) -> str:
    """One shell run that reports the writable test paths. Output lines:
    'covered <path>' for a path the grader restores (a restore-set path, or any conftest.py) that the uid can write,
    'uncovered <path>' for another writable test file when the uid is not root,
    'writable-as-root <path>' for the same file when the uid is root (test -w is true for everything as root), and
    a final 'done'.

    The listing runs before the loop, so a failed find ends the probe with exit 3 rather than a partial list.
    """
    checks = "; ".join(_covered_check(path) for path in covered) or "true"
    skip = "|".join(shlex.quote("./" + path) for path in covered) or "''"
    return (
        f"cd {shlex.quote(workdir)} || exit 2; "
        'tag=uncovered; [ "$(id -u)" = 0 ] && tag=writable-as-root; '
        f"{checks}; "
        f"found=$(find . -name .git -prune -o -type f \\( {TEST_FILE_TESTS} \\) -print) "
        "|| { echo 'test file listing failed' >&2; exit 3; }; "
        "printf '%s\\n' \"$found\" | while IFS= read -r f; do "
        f'case "$f" in {skip}) continue ;; esac; '
        'case "$f" in */conftest.py|conftest.py) '
        'if [ -w "$f" ]; then printf \'covered %s\\n\' "${f#./}"; fi; continue ;; esac; '
        'if [ -w "$f" ]; then printf \'%s %s\\n\' "$tag" "${f#./}"; fi; '
        "done; printf 'done\\n'"
    )


def _writable_tests(session: Session, task: TaskSpec, workdir: str) -> _TestProbe:
    try:
        covered = restore_paths(task)  # the grader's restore set; grade() uses the same list
    except ValueError as exc:
        note = _unverifiable(exc)  # the grader would refuse this id or path, so its restore set is unknown
        return _TestProbe([note], [note], [])
    res = session.run(_probe_script(workdir, covered), STEP_TIMEOUT_S)
    lines = res.stdout.splitlines()
    if res.truncated:
        note = "unverified: writability check output was cut"
        return _TestProbe([note], [note], [])
    if res.exit_code != 0:
        note = _unverified("writability check", res)
        return _TestProbe([note], [note], [])
    if "done" not in lines:
        note = "unverified: writability check did not finish"
        return _TestProbe([note], [note], [])
    listed = set(covered)
    writable: list[str] = []
    unrestored: list[str] = []
    as_root: list[str] = []
    for line in lines:
        kind, _, path = line.partition(" ")
        if kind == "covered" and (path in listed or restored_conftest(path)):
            writable.append(path)
        elif kind == "uncovered" and path:
            writable.append(path)
            unrestored.append(path)
        elif kind == "writable-as-root" and path:
            writable.append(path)
            as_root.append(path)
    return _TestProbe(writable, unrestored, as_root)


def _network(session: Session) -> tuple[bool, list[str]]:
    for name, cmd in NETWORK_PROBES:
        res = session.run(cmd, PROBE_TIMEOUT_S)
        if res.timed_out:
            return True, [
                _unverified(f"network probe ({name})", res)
            ]  # killed by the host: unknown, fail closed
        if res.exit_code == 0:
            return True, [f"connected to 1.1.1.1:53 ({name})"]
        if res.exit_code == 1:
            return False, []  # the connect failed: no route or refused
        if res.exit_code != MISSING_EXIT:
            return True, [_unverified(f"network probe ({name})", res)]  # unexpected status: assume reachable
        # This program is missing here. Try the next probe.
    return True, ["unverified: probe unavailable (python3, python and bash /dev/tcp all missing)"]
