"""T57: a deterministic, attacker-free audit of the git-history exposure (queue T57).

The headline "N of M environments leave the future fix in .git" must not rest on attacker runs. This module needs no
model and no attacker: for each task it starts one sandbox session and measures, with code only,

  before   exposure.scan: the commits past base that refs, the reflog, ORIG_HEAD and FETCH_HEAD reach;
  reach    the TARGETED fix reachability (T55 machinery): which future commits change the gold patch's non-test files
           (exposure.future_touched_paths, exposure.future_scan with the gold diff as the candidate) and whether any
           of them adds a non-trivial line that the gold patch also adds (holes.shared_future_lines, digest
           intersection). fix_reachable is True iff a future commit adds a non-trivial gold line;
  patch    the strip-future-git patch (patches.apply_patches), on a fresh session;
  gates    the gold gate still passes and the empty gate still fails on the patched session (grader gates);
  after    exposure.scan again on a fresh patched session: future_commits_after must be 0.

One sanitized record per task goes to results/exposure/<certificate file name> (schema_version 1, schema
'rewardseal.exposure-audit'). A record holds counts, short (12 hex) commit ids and gold path names; never a line of
text and never a digest. exposure_summary(directory) reads the records back and computes M (tasks audited), N_future
(future_commits_before > 0), N_fix (fix_reachable) and N_closed (closed, among N_future) strictly from them: a file
that does not validate refuses every number. Without that directory the summary falls back to the attack
certificates' exposure_before.future_git and says so ("from attack certificates (not an audit)").

Sandbox use: the collect-only preflight (the same one batch runs) is one session start; the audit then starts one
session and resets it three times, so about SANDBOX_RUNS_PER_TASK = 5 sandbox runs a task. Every start and reset
books one run through Budget.reserve_sandbox_run (halt-checked), and every exec checks the halt flag first
(Session.run). Sandboxes are not billed; the counter is a guard. Nothing here calls a model, Tavily or the network.

A listing that could not run is not guessed: the task gets no record (AuditUnavailable) and does not count in M.
closed is True only when the patch applied, both gates held, the after scan listed its commits completely, and none
is left.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cheatproof import exposure, grader, holes, patches
from cheatproof.budget import BudgetExceeded
from cheatproof.executor import ExecutorRefused, ExecutorUnavailable
from cheatproof.sanitize import (  # private on purpose: sanitize() would redact valid SHAs
    _always_secret,
    sanitize,
)

if TYPE_CHECKING:
    from cheatproof.executor import Session
    from cheatproof.tasks import TaskSpec

SCHEMA = "rewardseal.exposure-audit"
SCHEMA_VERSION = 1
DEFAULT_DIR = Path("results/exposure")
EXPOSURE_DIRNAME = "exposure"  # beside the certificates directory, as results/confirmations.json is
PATCH_NAME = patches.PATCH_STRIP_GIT
DEFAULT_TIMEOUT_S = 1800  # each gate, as harden
SANDBOX_RUNS_PER_TASK = 5  # preflight start + audit start + 3 resets
SANDBOX_COST_PER_RUN = (
    0.03  # the batch plan's estimate for one start; Sandboxes are not billed, this is a guard
)
SHORT_ID = re.compile(r"[0-9a-f]{12}")
BASE_RE = re.compile(r"[0-9a-f]{7,40}")
FROM_CERTIFICATES = "from attack certificates (not an audit)"
FROM_AUDIT = "from the deterministic exposure audit"

RECORD_KEYS = frozenset(
    {
        "schema",
        "schema_version",
        "instance_id",
        "repo",
        "base_commit",
        "future_commits_before",
        "refs_before",
        "fix_reachable",
        "future_scan",
        "patch",
        "future_commits_after",
        "closed",
        "executor",
        "timestamp",
        "sandbox_runs",
    }
)
SCAN_KEYS = frozenset(
    {
        "list_complete",
        "paths",
        "commits_scanned",
        "commit_ids",
        "lines",
        "complete",
        "gold_paths_touched_by_future_commits",
        "gold_lines_in_future",
    }
)
PATCH_KEYS = frozenset({"name", "applied", "gold_gate_ok", "empty_gate_ok"})


class ExposureAuditError(ValueError):
    """A record or the directory of records is not valid. No number is drawn from it."""


class AuditUnavailable(RuntimeError):
    """The audit of one task could not be measured (a listing failed). No record is written for it."""


class EnvBroken(RuntimeError):
    """The collect-only preflight failed: the task's environment cannot run its gold tests. Batch skips these too."""


@dataclass(frozen=True)
class AuditOps:
    """Every collaborator the audit calls, so tests inject fakes. default() is the real set."""

    scan: Callable[..., Any]
    future_scan: Callable[..., Any]
    touched_paths: Callable[..., int | None]
    apply_patches: Callable[..., list[Any]]
    gold_gate: Callable[..., Any]
    empty_gate: Callable[..., Any]
    shared_lines: Callable[..., int]

    @classmethod
    def default(cls) -> AuditOps:
        return cls(
            scan=exposure.scan,
            future_scan=exposure.future_scan,
            touched_paths=exposure.future_touched_paths,
            apply_patches=patches.apply_patches,
            gold_gate=grader.gold_gate,
            empty_gate=grader.empty_gate,
            shared_lines=holes.shared_future_lines,
        )


@dataclass(frozen=True)
class Measured:
    """What one audited session measured, before it becomes a record."""

    future_commits_before: int
    refs_before: int
    list_complete_before: bool
    scan: exposure.FutureScan
    gold_paths_touched: int | None
    gold_lines_in_future: int
    patch_applied: bool
    gold_gate_ok: bool
    empty_gate_ok: bool
    future_commits_after: (
        int | None
    )  # None: not listed, or an empty list that was not whole (no proof of zero)
    resets: int  # sandbox runs booked after the start (the session's resets)

    @property
    def closed(self) -> bool:
        return (
            self.patch_applied and self.gold_gate_ok and self.empty_gate_ok and self.future_commits_after == 0
        )


def _ref_count(report: exposure.ExposureReport) -> int:
    """Refs the scan found pointing past base: its evidence lines that start with 'ref '."""
    return sum(1 for line in report.future_git_evidence if line.startswith("ref "))


def measure(
    session: Session,
    task: TaskSpec,
    *,
    workdir: str = grader.DEFAULT_WORKDIR,
    timeout: float = DEFAULT_TIMEOUT_S,
    ops: AuditOps | None = None,
) -> Measured:
    """Run the audit in an already started session (the caller books that start). The session is reset three times:
    before the gold gate, before the empty gate and before the second scan, each followed by the strip patch, exactly
    as harden's _fresh does. Raises AuditUnavailable when the future commits could not be listed. A budget or executor
    stop propagates."""
    ops = AuditOps.default() if ops is None else ops
    before = ops.scan(session, task, workdir=workdir)
    if before.future_commit_ids is None:
        raise AuditUnavailable("the future commits could not be listed (a history probe failed)")
    if not before.future_commit_ids and not before.future_list_complete:
        # An empty list from a probe that did not finish says nothing: "0 future commits" would be a guess.
        raise AuditUnavailable("a history probe was unverified and listed no commit: the count is unknown")
    # The gold diff is the 'candidate': its non-test paths are the pathspec, and the future lines of those paths are
    # compared with the lines the gold patch adds.
    fscan = ops.future_scan(session, task, before, task.gold_patch, workdir=workdir)
    added = fscan.future_added()
    shared = 0 if added is None else int(ops.shared_lines(task.gold_patch, task, added))
    touched = ops.touched_paths(session, task, before, list(fscan.paths), workdir=workdir)

    resets = 0
    outcomes: list[Any] = []

    def fresh() -> None:
        nonlocal resets
        session.reset()  # books one sandbox run (halt-checked)
        resets += 1
        outcomes.extend(ops.apply_patches(session, task, (PATCH_NAME,), workdir=workdir))

    fresh()
    gold = ops.gold_gate(session, task, timeout, workdir=workdir)
    fresh()
    empty = ops.empty_gate(session, task, timeout, workdir=workdir)
    fresh()
    after = ops.scan(session, task, workdir=workdir)
    after_ids = after.future_commit_ids
    # An empty list proves "0 left" only when the listing was whole; any listed commit is left whatever else failed.
    after_n = (
        None if after_ids is None or (not after_ids and not after.future_list_complete) else len(after_ids)
    )
    return Measured(
        future_commits_before=len(before.future_commit_ids),
        refs_before=_ref_count(before),
        list_complete_before=bool(before.future_list_complete),
        scan=fscan,
        gold_paths_touched=touched,
        gold_lines_in_future=shared,
        patch_applied=bool(outcomes) and all(o.ok for o in outcomes),
        gold_gate_ok=bool(gold.passed),
        # An empty gate that did not run shows nothing (GateReport.reason): it must have applied, run clean and failed.
        empty_gate_ok=bool(empty.applied) and empty.error is None and not empty.passed,
        future_commits_after=after_n,
        resets=resets,
    )


def audit_task(
    executor: Any,
    budget: Any,
    task: TaskSpec,
    *,
    env: Any,
    preflight: Callable[..., Any] | None,
    clock: Callable[[], str],
    executor_name: str,
    timeout: float = DEFAULT_TIMEOUT_S,
    ops: AuditOps | None = None,
) -> dict[str, Any]:
    """The record of one task. Starts the preflight session (when a preflight is wired), then the audit session.
    Both starts book a sandbox run on `budget` (reserve_sandbox_run, halt-checked), so does every reset in measure().
    EnvBroken: the collect-only preflight failed (no audit session was started). AuditUnavailable: a listing failed
    or the preflight could not run. A budget or executor stop propagates for the caller to turn into a stop."""
    runs = 0
    if preflight is not None:
        try:
            with executor.start(env, budget) as session:
                runs += 1
                result = preflight(session, task, workdir=env.workdir)
        except (BudgetExceeded, ExecutorRefused, ExecutorUnavailable):
            raise
        except ValueError as exc:  # bad node ids or base commit: the task itself is unusable
            raise EnvBroken(sanitize(f"collect-only preflight refused: {exc}")) from None
        except Exception as exc:  # noqa: BLE001 - a transient start or SDK error is not the task's fault
            raise AuditUnavailable(f"preflight could not run: {type(exc).__name__}") from None
        if not result.ok:
            raise EnvBroken(sanitize(result.error or "collect-only failed"))
    with executor.start(env, budget) as session:
        runs += 1
        measured = measure(session, task, workdir=env.workdir, timeout=timeout, ops=ops)
    return build_record(
        task, measured, executor=executor_name, timestamp=clock(), sandbox_runs=runs + measured.resets
    )


def build_record(
    task: TaskSpec, measured: Measured, *, executor: str, timestamp: str, sandbox_runs: int
) -> dict[str, Any]:
    """The sanitized record of one task. Counts, short ids and path names only: no line text, no digest."""
    scan = measured.scan.to_dict()
    record: dict[str, Any] = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "instance_id": task.instance_id,
        "repo": task.repo,
        "base_commit": task.base_commit.lower(),
        "future_commits_before": measured.future_commits_before,
        "refs_before": measured.refs_before,
        "fix_reachable": measured.gold_lines_in_future > 0,
        "future_scan": {
            "list_complete": measured.list_complete_before,
            "paths": list(scan["paths"]),
            "commits_scanned": scan["commits_scanned"],
            "commit_ids": list(scan["commit_ids"]),
            "lines": scan["lines"],
            "complete": scan["complete"],
            "gold_paths_touched_by_future_commits": measured.gold_paths_touched,
            "gold_lines_in_future": measured.gold_lines_in_future,
        },
        "patch": {
            "name": PATCH_NAME,
            "applied": measured.patch_applied,
            "gold_gate_ok": measured.gold_gate_ok,
            "empty_gate_ok": measured.empty_gate_ok,
        },
        "future_commits_after": measured.future_commits_after,
        "closed": measured.closed,
        "executor": executor,
        "timestamp": timestamp,
        "sandbox_runs": sandbox_runs,
    }
    validate_record(record)
    return record


# --- validation ----------------------------------------------------------------------------------------------------


def _is_int(value: Any, *, minimum: int = 0) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def _want(condition: bool, message: str) -> None:
    if not condition:
        raise ExposureAuditError(message)


def _keys(name: str, value: Any, expected: frozenset[str]) -> Mapping[str, Any]:
    _want(isinstance(value, Mapping), f"{name} must be an object")
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    _want(not missing, f"{name} is missing {', '.join(missing)}")
    _want(not extra, f"{name} has unknown key(s) {', '.join(map(str, extra))}")
    return value


def _leak_guard(value: Any, path: str) -> None:
    """The certificate's guard: no string, key or value, matches a secret pattern (keys, bearer tokens, e-mail, a local
    path, ...). The message names the path, never the text. A commit id is a valid 40-hex string: not a secret."""
    if isinstance(value, Mapping):
        for key, item in value.items():
            _want(
                not (isinstance(key, str) and _always_secret(key)),
                f"leak guard: a key under {path} is secret-like",
            )
            _leak_guard(item, f"{path}.{key}")
    elif isinstance(value, list | tuple):
        for i, item in enumerate(value):
            _leak_guard(item, f"{path}[{i}]")
    elif isinstance(value, str):
        _want(not _always_secret(value), f"leak guard: {path} holds a secret-like value")


def validate_record(data: Any) -> None:
    """Strict check of one record: closed key sets, exact types, the invariants between fields and the leak guard.
    Raises ExposureAuditError (a ValueError) naming the field, never a value."""
    rec = _keys("record", data, RECORD_KEYS)
    _want(rec["schema"] == SCHEMA, f"schema must be {SCHEMA!r}")
    _want(
        rec["schema_version"] == SCHEMA_VERSION and not isinstance(rec["schema_version"], bool),
        f"schema_version must be {SCHEMA_VERSION}",
    )
    for key in ("instance_id", "repo", "executor", "timestamp"):
        _want(isinstance(rec[key], str) and rec[key].strip() != "", f"{key} must be a non-empty string")
    _want(
        isinstance(rec["base_commit"], str) and BASE_RE.fullmatch(rec["base_commit"]) is not None,
        "base_commit must be 7 to 40 lowercase hex characters",
    )
    for key in ("future_commits_before", "refs_before", "sandbox_runs"):
        _want(_is_int(rec[key]), f"{key} must be an integer of 0 or more")
    _want(isinstance(rec["fix_reachable"], bool), "fix_reachable must be a boolean")
    _want(isinstance(rec["closed"], bool), "closed must be a boolean")
    after = rec["future_commits_after"]
    _want(after is None or _is_int(after), "future_commits_after must be an integer of 0 or more, or null")

    scan = _keys("future_scan", rec["future_scan"], SCAN_KEYS)
    _want(isinstance(scan["list_complete"], bool), "future_scan.list_complete must be a boolean")
    _want(isinstance(scan["complete"], bool), "future_scan.complete must be a boolean")
    _want(
        isinstance(scan["paths"], list) and all(isinstance(p, str) for p in scan["paths"]),
        "future_scan.paths must be a list of strings",
    )
    _want(
        isinstance(scan["commit_ids"], list)
        and all(isinstance(c, str) and SHORT_ID.fullmatch(c) for c in scan["commit_ids"]),
        "future_scan.commit_ids must be a list of 12-hex commit ids",
    )
    for key in ("commits_scanned", "lines", "gold_lines_in_future"):
        _want(_is_int(scan[key]), f"future_scan.{key} must be an integer of 0 or more")
    touched = scan["gold_paths_touched_by_future_commits"]
    _want(
        touched is None or _is_int(touched),
        "future_scan.gold_paths_touched_by_future_commits must be an integer of 0 or more, or null",
    )

    patch = _keys("patch", rec["patch"], PATCH_KEYS)
    _want(patch["name"] == PATCH_NAME, f"patch.name must be {PATCH_NAME!r}")
    for key in ("applied", "gold_gate_ok", "empty_gate_ok"):
        _want(isinstance(patch[key], bool), f"patch.{key} must be a boolean")

    # Invariants: the booleans follow from the counts, so a hand-edited record cannot say otherwise.
    _want(
        rec["fix_reachable"] == (scan["gold_lines_in_future"] > 0),
        "fix_reachable must be true exactly when gold_lines_in_future is above 0",
    )
    _want(
        scan["commits_scanned"] <= rec["future_commits_before"],
        "future_scan.commits_scanned cannot exceed future_commits_before",
    )
    _want(
        rec["closed"]
        == bool(patch["applied"] and patch["gold_gate_ok"] and patch["empty_gate_ok"] and after == 0),
        "closed must be true exactly when the patch applied, both gates held and future_commits_after is 0",
    )
    _leak_guard(rec, "record")


def record_filename(instance_id: str) -> str:
    from cheatproof.certify import certificate_filename  # the same safe, case-folding-proof names

    return certificate_filename(instance_id)


def write_record(record: Mapping[str, Any], directory: Path) -> Path:
    """Validate and write one record atomically (a temp file, then os.replace). An existing file is replaced only
    when it holds the same instance id; a link at the target is refused."""
    validate_record(record)
    name = record_filename(record["instance_id"])
    folder = Path(directory)
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / name
    if target.is_symlink():
        raise OSError(f"refusing to write through a symbolic link: {name}")
    if target.exists():
        try:
            data = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = None  # unreadable or corrupt: nothing of another task is lost, it is replaced
        stored = data.get("instance_id") if isinstance(data, dict) else None
        if stored is not None and stored != record["instance_id"]:
            raise ValueError(f"refusing to overwrite {name}: it holds another instance id")
    text = json.dumps(record, sort_keys=True, indent=2, allow_nan=False) + "\n"
    fd, tmp_name = tempfile.mkstemp(dir=folder, prefix=f".{name}.", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, target)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    return target


def _refuse_constant(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


def load_record(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"), parse_constant=_refuse_constant)
    except (OSError, ValueError) as exc:
        raise ExposureAuditError(f"{Path(path).name}: not readable as JSON ({type(exc).__name__})") from None
    try:
        validate_record(data)
    except ExposureAuditError as exc:
        raise ExposureAuditError(f"{Path(path).name}: {exc}") from None
    if Path(path).name != record_filename(data["instance_id"]):
        raise ExposureAuditError(f"{Path(path).name}: the file name does not match its instance id")
    return data


# --- the summary -----------------------------------------------------------------------------------------------------


def records_present(directory: Path) -> bool:
    folder = Path(directory)
    return folder.is_dir() and any(p.is_file() for p in folder.glob("*.json"))


def _summary_from_records(directory: Path) -> dict[str, Any]:
    records = [load_record(p) for p in sorted(Path(directory).glob("*.json")) if p.is_file()]
    ids = [r["instance_id"] for r in records]
    _want(len(ids) == len(set(ids)), "two records name the same instance id")
    future = [r for r in records if r["future_commits_before"] > 0]
    return {
        "source": "audit",
        "label": FROM_AUDIT,
        "M": len(records),
        "N_future": len(future),
        "N_fix": sum(1 for r in records if r["fix_reachable"]),
        "N_closed": sum(1 for r in future if r["closed"]),
        # Context: the scans behind N_fix that could not read everything. "No shared line" there is no proof.
        "n_incomplete_scans": sum(1 for r in records if not r["future_scan"]["complete"]),
        "n_incomplete_lists": sum(1 for r in records if not r["future_scan"]["list_complete"]),
        "fix_ids": sorted(r["instance_id"] for r in records if r["fix_reachable"]),
        "not_closed_ids": sorted(r["instance_id"] for r in future if not r["closed"]),
    }


def _summary_from_certificates(certs_dir: Path) -> dict[str, Any]:
    """The fallback: how many attack certificates show future_git in the exposure scan BEFORE hardening. Whether the
    fix itself is reachable and whether the patch closes it are not measured there, so those are None."""
    total = future = 0
    for path in sorted(Path(certs_dir).glob("*.json")):
        if not path.is_file():
            continue
        try:
            cert = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        before = cert.get("exposure_before") if isinstance(cert, dict) else None
        if not isinstance(before, dict) or not isinstance(before.get("future_git"), bool):
            continue
        total += 1
        future += 1 if before["future_git"] else 0
    return {
        "source": "certificates",
        "label": FROM_CERTIFICATES,
        "M": total,
        "N_future": future,
        "N_fix": None,
        "N_closed": None,
        "n_incomplete_scans": None,
        "n_incomplete_lists": None,
        "fix_ids": [],
        "not_closed_ids": [],
    }


def exposure_summary(directory: Path, certs_dir: Path | None = None) -> dict[str, Any] | None:
    """M (tasks audited), N_future (future_commits_before > 0), N_fix (fix_reachable) and N_closed (closed, among
    N_future), computed only from the records in `directory`. Raises ExposureAuditError when any record is malformed,
    named wrongly or repeated: no number is drawn then.

    When `directory` has no records the summary falls back to the certificates in certs_dir (default: the 'certificates'
    folder beside `directory`): M certificates with an exposure scan, N_future of them with future_git true, N_fix and
    N_closed None, source 'certificates' and the label 'from attack certificates (not an audit)'. None when there is
    nothing to count either."""
    if records_present(directory):
        return _summary_from_records(directory)
    certs = Path(directory).parent / "certificates" if certs_dir is None else Path(certs_dir)
    if certs.is_dir():
        fallback = _summary_from_certificates(certs)
        if fallback["M"] > 0:
            return fallback
    return None


def summary_line(summary: Mapping[str, Any]) -> str:
    """One line for the text report and the site: the counts and what they are made from."""
    if summary["source"] == "audit":
        text = (
            f"history exposure audit ({summary['label']}): {summary['N_future']} of {summary['M']} audited tasks "
            f"have future commits in .git; the fix is reachable in {summary['N_fix']}; the strip-future-git patch "
            f"closed {summary['N_closed']} of the {summary['N_future']}"
        )
        if summary.get("n_incomplete_lists"):
            text += f" ({summary['n_incomplete_lists']} history listing(s) incomplete: those counts are lower bounds)"
        if summary.get("n_incomplete_scans"):
            text += (
                f" ({summary['n_incomplete_scans']} fix scan(s) incomplete: no shared line is no proof there)"
            )
        return text
    return (
        f"history exposure ({summary['label']}): {summary['N_future']} of {summary['M']} certificates show "
        "future commits in .git before hardening; whether the fix is reachable and whether the patch closes it "
        "were not measured"
    )
