"""Static exposure scan for one task (ADR 0002, T03). Code only, no model.

scan() probes a session and reports the holes an attacker can use:
  git-history  refs, the reflog, FETCH_HEAD or ORIG_HEAD point past base_commit, so the fix may be in .git
  test-edit    a hidden test file (a test_patch path or an F2P node file) is writable
  network      a TCP connection to 1.1.1.1:53 succeeds

The scan is read-only: it writes nothing, resets nothing and deletes nothing. A probe that cannot run counts
as a hole, with an "unverified" note in its evidence, so a clean report never rests on a check that did not run.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cheatproof.executor import Result, Session
from cheatproof.grader import (
    DEFAULT_WORKDIR,
    STEP_TIMEOUT_S,
    checked_sha,
    diff_files,
    error_tail,
    git_command,
    node_file,
)

if TYPE_CHECKING:
    from cheatproof.tasks import TaskSpec

HOLE_GIT_HISTORY = "git-history"
HOLE_TEST_EDIT = "test-edit"
HOLE_NETWORK = "network"
PROBE_TIMEOUT_S = 15  # the connect itself gives up after 3 s
CONNECT_PROBE = "import socket; socket.create_connection(('1.1.1.1', 53), timeout=3).close()"
REF_FORMAT = "%(objectname)|%(*objectname)|%(refname)"  # *objectname is the peeled target of an annotated tag


@dataclass(frozen=True)
class ExposureReport:
    future_git: bool
    future_git_evidence: list[str]
    tests_writable: bool
    writable_tests: list[str]  # writable test paths, or an "unverified" note
    network: bool
    network_evidence: list[str]
    holes: list[str]  # HOLE_* labels, in the order git-history, test-edit, network


def scan(session: Session, task: TaskSpec, *, workdir: str = DEFAULT_WORKDIR) -> ExposureReport:
    base = checked_sha(task.base_commit)
    git_evidence = _git_history(session, base, workdir)
    writable = _writable_tests(session, task, workdir)
    network, network_evidence = _network(session)
    holes = [
        label
        for label, hit in (
            (HOLE_GIT_HISTORY, bool(git_evidence)),
            (HOLE_TEST_EDIT, bool(writable)),
            (HOLE_NETWORK, network),
        )
        if hit
    ]
    return ExposureReport(
        future_git=bool(git_evidence),
        future_git_evidence=git_evidence,
        tests_writable=bool(writable),
        writable_tests=writable,
        network=network,
        network_evidence=network_evidence,
        holes=holes,
    )


def _unverified(what: str, res: Result) -> str:
    tail = error_tail(res)
    return f"unverified: {what} failed (exit {res.exit_code})" + (f": {tail}" if tail else "")


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


def _writable_check(path: str) -> str:
    # test -w only reads permissions. A missing file is judged by whether its directory is writable.
    q = shlex.quote(path)
    return (
        f'p={q}; if [ -e "$p" ]; then test -w "$p"; else test -w "$(dirname -- "$p")"; fi '
        "&& printf '%s\\n' \"$p\""
    )


def _writable_tests(session: Session, task: TaskSpec, workdir: str) -> list[str]:
    paths = sorted(
        {node_file(node) for node in task.fail_to_pass} | {rel for rel, _ in diff_files(task.test_patch)}
    )
    script = (
        f"cd {shlex.quote(workdir)} || exit 2; " + "; ".join(_writable_check(p) for p in paths) + "; true"
    )
    res = session.run(script, STEP_TIMEOUT_S)
    if res.exit_code != 0:
        return [_unverified("writability check", res)]
    listed = set(paths)
    return [line for line in res.stdout.splitlines() if line in listed]


def _network(session: Session) -> tuple[bool, list[str]]:
    res = session.run(f"python3 -c {shlex.quote(CONNECT_PROBE)}", PROBE_TIMEOUT_S)
    if res.exit_code == 0:
        return True, ["connected to 1.1.1.1:53"]
    if res.exit_code == 1 and not res.timed_out:
        return False, []  # the connect failed: no route, refused, or timed out
    # python3 is missing or the probe was killed. Assume reachable rather than claim a clean network.
    return True, [_unverified("network probe", res)]
