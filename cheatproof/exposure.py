"""Static exposure scan for one task (ADR 0002, T03). Code only, no model.

scan() probes a session and reports the holes an attacker can use:
  git-history  refs, the reflog, FETCH_HEAD or ORIG_HEAD point past base_commit, so the fix may be in .git
  test-edit    the uid running the agent can write a test file the grader does not restore from base. The grader
               restores its node-id files, its test_patch paths and every conftest.py before it grades, so a writable
               one of those is covered. Any other writable test file (a helper under a tests/ dir) is a hole, except
               as root: test -w is true for every file as root, so the probe cannot tell those apart. As root such a
               file is labelled "writable as root" and is not a hole. holes.py still judges the final diff.
  network      a TCP connection to 1.1.1.1:53 succeeds

T53 first listed, at scan time, the non-test lines that ALL future commits add, under a global cap (400 commits, 60 KB
of added lines). Real repos always hit that cap (a repo with 378 future commits was cut at 60 KB of raw added lines), so
the list was never complete and a git-history hole could never be confirmed. T55 replaces it. scan() keeps only the
cheap pre-attack evidence: counts, refs and the short ids of the future commits (future_commit_ids). The lines are read
AFTER the attack by future_scan(), in the same session and before the grade resets it, for the few paths that matter:
the non-test files the attacker's final diff touches plus those the gold patch touches. holes.classify then compares
the passing diff with those lines. Digests (holes.future_line_digest: sha256 prefixes, never text) are for the
git-ignored <stem>.rounds.json only. A certificate holds FutureScan.to_dict: paths, short commit ids and counts.
future_added_lines, future_added_complete and future_added_digests stay for records made by T53 code; scan() no longer
fills them.

The scan is read-only: it writes nothing, resets nothing and deletes nothing. A probe that cannot run, or whose
input the grader would refuse, counts as a hole, with an "unverified" or "unverifiable" note in its evidence, so a
clean report never rests on a check that did not run.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

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
from cheatproof.holes import FutureAdded, future_line_digest, future_scan_paths

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
# T55 caps. The pre-attack scan lists the future commits (short ids only); future_scan() reads the lines they add to the
# target paths. There is no byte cap on the whole history: these are sanity limits on the targeted set, and a limit
# that is hit makes the scan incomplete (complete False), never a silently partial list.
FUTURE_LIST_MAX = 5000  # commits listed; one more than this means an incomplete list
FUTURE_SCAN_BYTES = 2 * 1024 * 1024  # added-line output read in all by one targeted scan
FUTURE_BATCH = 100  # commits per diff run; a run whose output the executor cut is split in two and retried
FUTURE_MAX_EXECS = 60  # sandbox runs one targeted scan may use
FUTURE_PATHS_MAX = 200  # paths in the pathspec
FUTURE_POSITIVE_MAX = 1500  # pre-attack ids named again as starting points (keeps the command short)
SHORT_SHA = (
    12  # hex chars of a commit id a certificate shows; every revision the scan passes is a full 40-hex id
)
FUTURE_PAGE = (
    1500  # ids per listing run: 1500 full ids (41 bytes each) stay under the executor's 64 KiB stream cap
)
CERT_PATHS = 40  # paths and commit ids a certificate record shows
FULL_SHA = re.compile(r"[0-9a-f]{40}")
# awk: print the added lines of non-test files. A "+++ b/path" line sets the file only inside a diff header (from
# "diff --git" to the first "@@"), so an added line whose text starts with "++ " is kept; test dirs, test_*.py,
# *_test.py and conftest.py are skipped (the same files holes.is_test_path treats as tests).
ADDED_LINES_AWK = (
    "/^diff --git /{hdr=1; next} /^@@ /{hdr=0; next} hdr && !/^\\+\\+\\+ /{next} "
    "hdr {f=substr($0,5); "
    "skip=(f ~ /(^|\\/)tests?\\//|| f ~ /(^|\\/)test_[^\\/]*\\.py$/|| f ~ /_test\\.py$/|| f ~ /(^|\\/)conftest\\.py$/); next} "
    "/^\\+/ && !skip {print substr($0,2)}"
)
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
    # T53 fields, kept for records made by T53 code (global digests of every future-added line). T55 scan() leaves them
    # at 0 / False / None: the lines are read after the attack, see FutureScan. RoundReport.to_dict drops the digests.
    future_added_lines: int = 0
    future_added_complete: bool = False
    future_added_digests: list[str] | None = field(default=None, repr=False)
    # T55: full 40-hex ids of the commits past base that the scan listed (None: it could not list them), the
    # ids ORIG_HEAD / FETCH_HEAD name, and whether the listing is whole (no cut, no unverified history source).
    # future_scan() needs them to tell the attacker's own new commits from the task's future ones. NOT written to the
    # certificate (harden._exposure_dict drops them).
    future_commit_ids: list[str] | None = field(default=None, repr=False)
    future_extra_revs: list[str] = field(default_factory=list, repr=False)
    future_list_complete: bool = False

    def future_added(self) -> FutureAdded | None:
        """The T53 digests in the form holes.classify takes, or None when there are none (every T55 scan)."""
        if self.future_added_digests is None:
            return None
        return FutureAdded(frozenset(self.future_added_digests), self.future_added_complete)


@dataclass(frozen=True)
class FutureScan:
    """T55: what the targeted scan after the attack read. paths are the non-test files looked at; commits_scanned counts
    the future commits that touch them; commit_ids are the first CERT_PATHS of those (full ids; the certificate
    shows SHORT_SHA hex); lines is the number of
    distinct non-trivial added lines (digests); complete is False when a cap was hit, a source was unverified or a run
    failed, so "no shared line" is then no proof. digests are NOT in to_dict: only the git-ignored rounds.json has them."""

    paths: tuple[str, ...]
    commits_scanned: int
    commit_ids: tuple[str, ...]
    lines: int
    complete: bool
    digests: tuple[str, ...] | None = field(default=None, repr=False)  # None: the lines could not be listed

    def to_dict(self) -> dict[str, Any]:
        shown = [redact_text(path)[:EVIDENCE_CHARS] for path in self.paths[:CERT_PATHS]]
        if len(self.paths) > CERT_PATHS:
            shown.append(f"... +{len(self.paths) - CERT_PATHS} more path(s)")
        return {
            "paths": shown,
            "commits_scanned": self.commits_scanned,
            "commit_ids": [sha[:SHORT_SHA] for sha in self.commit_ids[:CERT_PATHS]],
            "lines": self.lines,
            "complete": self.complete,
        }

    def future_added(self) -> FutureAdded | None:
        if self.digests is None:
            return None
        return FutureAdded(frozenset(self.digests), self.complete)


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
        future: tuple[list[str] | None, bool] = (None, False)
        extra_revs: list[str] = []
    else:
        git_evidence, extra_revs = _git_history(session, base, workdir)
        future = (
            _future_commits(session, base, workdir, extra_revs, git_evidence) if git_evidence else ([], True)
        )
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
        future_commit_ids=future[0],
        future_extra_revs=list(extra_revs),
        future_list_complete=future[1],
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


def _git_history(session: Session, base: str, workdir: str) -> tuple[list[str], list[str]]:
    """(evidence lines, commit ids named by ORIG_HEAD / FETCH_HEAD). The ids go to _future_added: those two files can
    point at a fix that no branch, tag or reflog entry reaches."""
    evidence: list[str] = []
    pseudo_revs: list[str] = []

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
            pseudo_revs.append(res.stdout.strip().lower())
    return evidence, pseudo_revs


def _full_ids(stdout: str) -> list[str]:
    """Full commit ids of a `--format=%H` listing, in order, once each. Split on "\\n" only. A full 40-hex id as a
    revision cannot be shadowed by a branch or tag of the same name (git reads a full id as an object first)."""
    found = (line.strip().lower() for line in stdout.split("\n"))
    return list(dict.fromkeys(sha for sha in found if FULL_SHA.fullmatch(sha)))


def _list_ids(
    session: Session, workdir: str, selection: str, spec: str = ""
) -> tuple[list[str] | None, bool]:
    """(full ids newest first, cut) for a `log` selection, FUTURE_PAGE per run (so no run's output is cut by the
    executor), at most FUTURE_LIST_MAX ids. cut is True when more existed. Ids are None when a run failed."""
    ids: list[str] = []
    while len(ids) <= FUTURE_LIST_MAX:
        want = min(FUTURE_PAGE, FUTURE_LIST_MAX + 1 - len(ids))
        res = session.run(
            git_command(workdir, f"log {selection} --format=%H --skip={len(ids)} --max-count={want}{spec}"),
            STEP_TIMEOUT_S,
        )
        if res.exit_code != 0 or res.truncated or res.timed_out:
            return None, False
        page = _full_ids(res.stdout)
        ids = list(dict.fromkeys([*ids, *page]))
        if len(page) < want:
            break
    return ids[:FUTURE_LIST_MAX], len(ids) > FUTURE_LIST_MAX


def _future_commits(
    session: Session,
    base: str,
    workdir: str,
    extra_revs: Sequence[str] = (),
    history_evidence: Sequence[str] = (),
) -> tuple[list[str] | None, bool]:
    """T55: (full ids of the commits past base, list is whole). Cheap runs, no diff text. Ids are None when the
    listing could not run. Every source _git_history reports is walked: all refs, the reflog (a branch deleted after a
    fix commit leaves the fix only there) and the commits ORIG_HEAD / FETCH_HEAD name. The list is not whole when a
    history probe ended "unverified" (a source that could not be enumerated) or the listing hit FUTURE_LIST_MAX.

    future_scan() keeps these ids: a commit that is not among them was made after this scan, by the attacker."""
    revs = " ".join(shlex.quote(rev) for rev in extra_revs if FULL_SHA.fullmatch(rev))
    ids, cut = _list_ids(session, workdir, f"--all --reflog {revs} --not {shlex.quote(base)}")
    if ids is None:
        return None, False
    unverified = any(line.startswith(("unverified", "unverifiable")) for line in history_evidence)
    return ids, not unverified and not cut


def _pathspec(paths: Sequence[str]) -> str:
    return " -- " + " ".join(shlex.quote(path) for path in paths)


def future_scan(
    session: Session,
    task: TaskSpec,
    report: ExposureReport | None,
    final_diff: str | None,
    *,
    workdir: str = DEFAULT_WORKDIR,
) -> FutureScan:
    """T55: the targeted scan, run after the attack in the attacker's own session, before the grade resets it.

    paths = the non-test files the final diff touches plus the gold patch's non-test files (holes.future_scan_paths).
    The future commits are those `log --all --reflog` (with ORIG_HEAD / FETCH_HEAD, and the pre-attack ids as starting
    points while they are few) reaches past base, limited to paths, that the pre-attack scan (report) already listed:
    a commit made since by the attacker is not "future" and is left out. For them it reads the ADDED lines of those
    paths only (never a diff of an unrelated file) and keeps sha256 digests of the non-trivial ones. Read-only; every
    run goes through session.run, so the budget's halt check applies.

    There is no cap on the history as a whole. The sanity caps (FUTURE_LIST_MAX commits, FUTURE_SCAN_BYTES of output,
    FUTURE_MAX_EXECS runs, FUTURE_PATHS_MAX paths) make complete False when hit, as do an unverified history source
    in the pre-attack scan, a diff that could not be read exactly, and a failed run. A scan that could not run
    gives digests None, which classify treats as a lead only."""
    paths, exact = future_scan_paths(final_diff, task)
    shown = tuple(paths)
    if report is None or report.future_commit_ids is None:
        return FutureScan(
            shown, 0, (), 0, False, None
        )  # no pre-attack list: own commits cannot be told apart
    try:
        base = checked_sha(task.base_commit)
    except ValueError:
        return FutureScan(shown, 0, (), 0, False, None)
    pre = report.future_commit_ids
    if not pre or not paths:
        # Nothing past base, or no source file to look in: no line can be shared. Whole only if the list was.
        whole = report.future_list_complete and (exact or not pre)
        return FutureScan(shown, 0, (), 0, whole, ())
    capped = len(paths) > FUTURE_PATHS_MAX
    spec = _pathspec(paths[:FUTURE_PATHS_MAX])
    starts = [*(r for r in report.future_extra_revs if FULL_SHA.fullmatch(r))]
    # The pre-attack ids are named again, so a ref or reflog entry the attacker deleted since does not hide them. Too
    # many for one command line: not named, and the scan is then not complete (a deleted ref could hide a commit).
    named = len(pre) <= FUTURE_POSITIVE_MAX
    if named:
        starts += pre
    revs = " ".join(shlex.quote(rev) for rev in dict.fromkeys(starts))
    found, cut = _list_ids(
        session, workdir, f"--all --reflog {revs} --not {shlex.quote(base)} --full-history --no-merges", spec
    )
    if found is None:
        return FutureScan(shown, 0, (), 0, False, None)
    known = set(pre)
    ids = [sha for sha in found if sha in known]  # the attacker's own new commits are not future commits
    complete = report.future_list_complete and exact and not capped and named and not cut
    digests, done, complete_here = _read_added(session, workdir, ids, spec)
    return FutureScan(
        shown,
        len(done),
        tuple(done[:CERT_PATHS]),
        0 if digests is None else len(digests),
        complete and complete_here,
        None if digests is None else tuple(sorted(digests)),
    )


def _read_added(
    session: Session, workdir: str, ids: list[str], spec: str
) -> tuple[set[str] | None, list[str], bool]:
    """(digests, ids read, whole). The ids go through in batches of FUTURE_BATCH; a run the executor cut is split in two
    and retried, and a single commit whose lines still do not fit makes the result incomplete. Digests are None when no
    run succeeded."""
    awk = shlex.quote(ADDED_LINES_AWK)
    digests: set[str] = set()
    done: list[str] = []
    pending = [ids[i : i + FUTURE_BATCH] for i in range(0, len(ids), FUTURE_BATCH)]
    execs = read = 0
    whole = True
    ran = False
    while pending:
        batch = pending.pop(0)
        if execs >= FUTURE_MAX_EXECS or read >= FUTURE_SCAN_BYTES:
            return (digests if ran else None), done, False
        execs += 1
        show = (
            "log --no-walk=unsorted --no-merges --format= -p --unified=0 --no-color --no-ext-diff --no-textconv --text "
            f"{' '.join(batch)}{spec} | awk {awk} | awk '!s[$0]++'"
        )
        res = session.run(git_command(workdir, show), STEP_TIMEOUT_S)
        if res.truncated and len(batch) > 1:
            half = len(batch) // 2
            pending[:0] = [batch[:half], batch[half:]]
            continue
        if res.exit_code != 0 or res.timed_out or res.stderr.strip():
            return (digests if ran else None), done, False
        ran = True
        whole = whole and not res.truncated  # one commit that adds more than a run can return
        read += len(res.stdout.encode("utf-8", "replace"))
        done += batch
        # Split on "\n" only, as awk and holes._changes do: splitlines() would also cut at \x0c, \x85 and U+2028.
        digests.update(d for line in res.stdout.split("\n") if (d := future_line_digest(line)) is not None)
    return (digests if ran or not ids else None), done, whole and read <= FUTURE_SCAN_BYTES


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
