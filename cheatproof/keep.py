"""Keep a paid run's raw evidence locally (T42) and re-check its hole labels offline.

Every harden or batch run keeps, beside the certificates directory and under the git-ignored traces/ folder, named by
the certificate's file stem:
- <stem>.jsonl            the full attacker trace (every step of every attack round, written by attacker.attack)
- <stem>.before.diff      the RAW attack diff of the first round
- <stem>.after.diff       the RAW attack diff of the re-attack round (only when that round ran an attack)
- <stem>.diff             the RAW final diff: the last round's attack diff
- <stem>.restore.json     the task's restore set (grader.restore_paths), written before the paid run
- <stem>.rounds.json      per round: the grade inputs classify was given, the labels harden recorded, the exposure
                          flags and refs classify was given, the attack summary's auto_submitted and outcome (T49), and
                          the sha256 digests of the non-trivial lines future commits add (T53, never their text). Only
                          this git-ignored file holds the digests: the certificate has just their count.

Nothing here is ever committed (results/traces/ is in .gitignore, and `git add -f` is denied). A file already there
is renamed to <name>.<UTC time>.old, never overwritten.

recheck() re-runs holes.classify on the kept diff, trace and restore set with no network, sandbox, model or budget.
It compares the recomputed labels, primary and exploited with those recorded in rounds.json, then applies the same
legit_fix rule as harden (holes.downgrade_legit_fix) and compares the recomputed outcome with the recorded one. Older
files that do not record the exposure and attack inputs are compared on labels, primary and exploited only. A file
from before T53 has no future-added digests: classify then keeps the pre-T53 rule (the history commands alone label
git-history), so its labels replay as recorded, and render() says the digests were not recorded. render()
prints labels, outcomes and test path names only, never diff text.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cheatproof import holes
from cheatproof.grader import restore_paths
from cheatproof.harden import _visible_passed

if TYPE_CHECKING:
    from cheatproof.tasks import TaskSpec

ROUND_NAMES = ("before", "after")
SCHEMA = 1
PRIVATE_DIR = 0o700
PRIVATE_FILE = 0o600
STEM = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
PATH_CHARS = 200


class KeepError(Exception):
    """A kept piece is missing or unreadable. The message names it."""


def valid_stem(stem: str) -> bool:
    """A certificate stem: no path separator, so it cannot climb out of the traces folder."""
    return bool(STEM.match(stem)) and ".." not in stem


def _make_folder(folder: Path) -> None:
    """Create the traces folder private (0700) when it is new. A symbolic link is refused."""
    if folder.is_symlink():
        raise OSError(f"refusing to write through a symbolic link: {folder.name}")
    if not folder.exists():
        folder.mkdir(parents=True, mode=PRIVATE_DIR)
        os.chmod(folder, PRIVATE_DIR)  # the umask may have narrowed or widened the mode of mkdir


def _aside_path(folder: Path, name: str) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    aside = folder / f"{name}.{stamp}.old"
    number = 1
    while aside.exists() or aside.is_symlink():
        number += 1
        aside = folder / f"{name}.{stamp}.{number}.old"
    return aside


def _aside(folder: Path, name: str) -> None:
    """Rename folder/name to <name>.<UTC time>.old when it exists. Nothing is overwritten or deleted."""
    target = folder / name
    if not (target.exists() or target.is_symlink()):
        return
    target.rename(_aside_path(folder, name))


def copy_aside(folder: Path, name: str) -> Path | None:
    """Copy folder/name to <name>.<UTC time>.old (same naming as _aside) and leave the original in place, so the final
    write is the only thing that replaces it. None when there is no such file. A link is refused. T38: a rerun never
    destroys the certificate it replaces; *.old files are ignored by the report and the site, which read *.json."""
    target = folder / name
    if target.is_symlink():
        raise OSError(f"refusing to copy through a symbolic link: {name}")
    if not target.exists():
        return None
    aside = _aside_path(folder, name)
    shutil.copy2(target, aside)
    return aside


def _write(folder: Path, name: str, text: str) -> Path:
    """Write folder/name with mode 0600; an existing file is renamed aside first. A symbolic link is refused."""
    target = folder / name
    if target.is_symlink():
        raise OSError(f"refusing to write through a symbolic link: {name}")
    _make_folder(folder)
    _aside(folder, name)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, PRIVATE_FILE)
    with os.fdopen(fd, "w", encoding="utf-8", errors="replace") as out:
        out.write(text)
    os.chmod(target, PRIVATE_FILE)
    return target


def secure_trace(folder: Path, stem: str) -> None:
    """Make <stem>.jsonl private (0600). It is created empty first when the attacker has not written it yet."""
    path = folder / f"{stem}.jsonl"
    if path.is_symlink():
        raise OSError(f"refusing to write through a symbolic link: {path.name}")
    _make_folder(folder)
    os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, PRIVATE_FILE))
    os.chmod(path, PRIVATE_FILE)


def _json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, indent=2) + "\n"


def restore_set(task: TaskSpec) -> list[str] | None:
    """grader.restore_paths(task), or None when the node ids or paths cannot be read exactly (fail closed)."""
    try:
        return restore_paths(task)
    except ValueError:
        return None


RUN_FILES = (
    "{stem}.restore.json",
    "{stem}.rounds.json",
    "{stem}.before.diff",
    "{stem}.after.diff",
    "{stem}.diff",
)


def start_run(traces_dir: Path, stem: str, task: TaskSpec) -> None:
    """Before the paid run: set aside every kept file of an earlier run, cache the task's restore set, and make the
    trace file private. OSError propagates; the caller refuses the run before any spend."""
    _make_folder(traces_dir)
    for pattern in RUN_FILES:
        _aside(traces_dir, pattern.format(stem=stem))
    data = {"schema": SCHEMA, "instance_id": task.instance_id, "restore_paths": restore_set(task)}
    _write(traces_dir, f"{stem}.restore.json", _json(data))
    secure_trace(traces_dir, stem)


def _round_inputs(rnd: Any, result: Any) -> dict[str, Any]:
    """What classify was given for one round, rebuilt as harden._play computed it, plus the recorded labels."""
    diff = result.final_diff if result.diff_ok else None
    hidden: bool | None = None
    visible: bool | None = None
    forged: list[str] = []
    if diff and rnd.no_attempt is None and rnd.attack_grade is not None:
        hidden = rnd.attack_grade.passed
        visible = _visible_passed(rnd.attack_grade)
        forged = list(rnd.attack_grade.labels)
    elif diff == "" and rnd.gates is not None:
        hidden = False
        visible = _visible_passed(rnd.gates.empty)
    recorded = rnd.holes
    exposure = rnd.exposure
    attack = rnd.attack or {}
    return {
        "hidden_passed": hidden,
        "visible_passed": visible,
        "grader_labels": forged,
        "no_attempt": rnd.no_attempt is not None,
        "recorded": None
        if recorded is None
        else {
            "labels": list(recorded.labels),
            "attempted": list(recorded.attempted),
            "primary": recorded.primary,
            "exploited": recorded.exploited,
        },
        # T49: the inputs of the legit_fix rule and of classify's exposure_refs, as harden had them for this round.
        "exposure": {
            "future_git": exposure is not None and bool(exposure.future_git),
            "network": exposure is not None and bool(exposure.network),
            "refs": [] if exposure is None else [str(ref) for ref in exposure.future_git_evidence],
            # T53: digests of the lines future commits add (None: the scan could not list them).
            "future_added": {
                "digests": None if exposure is None else exposure.future_added_digests,
                "complete": exposure is not None and bool(exposure.future_added_complete),
            },
        },
        "attack": {"auto_submitted": bool(attack.get("auto_submitted")), "outcome": attack.get("outcome")},
    }


def _write_attacks(stem: str, traces_dir: Path, results: list[Any], inputs: list[Any | None]) -> list[str]:
    """Write the raw diffs and rounds.json for attack results in order (before first). inputs[i] is the round report
    of results[i], or None when the grade is unknown. Each round records the trace segment it owns (its attack
    index), so a round whose inputs fail still maps to the right segment. Returns notes; may raise."""
    notes: list[str] = []
    meta: dict[str, Any] = {}
    last: str | None = None
    for index, (name, result) in enumerate(zip(ROUND_NAMES, results)):
        diff = getattr(result, "final_diff", None) if getattr(result, "diff_ok", False) else None
        entry: dict[str, Any] = {
            "segment": index,
            "has_diff": diff is not None,
            "hidden_passed": None,
            "visible_passed": None,
            "grader_labels": [],
            "no_attempt": False,
            "recorded": None,
        }
        rnd = inputs[index]
        if rnd is not None:
            try:
                entry.update(_round_inputs(rnd, result))
            except Exception as exc:  # noqa: BLE001 - the diff and trace are kept all the same
                notes.append(f"the {name} grade inputs were not kept: {type(exc).__name__}")
        meta[name] = entry
        if diff is not None:
            _write(traces_dir, f"{stem}.{name}.diff", diff)
            last = diff
    if last is not None:
        _write(traces_dir, f"{stem}.diff", last)
    _write(traces_dir, f"{stem}.rounds.json", _json({"schema": SCHEMA, "rounds": meta}))
    return notes


def _finish(stem: str, traces_dir: Path, results: list[Any], inputs: list[Any | None]) -> list[str]:
    try:
        notes = _write_attacks(stem, traces_dir, results, inputs)
        secure_trace(traces_dir, stem)
        return notes
    except Exception as exc:  # noqa: BLE001 - never raises after a paid run; the class name only, no text
        return [f"raw run files were not kept: {type(exc).__name__}"]


def keep_raw(report: Any, stem: str, traces_dir: Path) -> list[str]:
    """Keep the raw attack diffs and the per-round grade inputs. Never raises. Returns notes (no diff text)."""
    try:
        rounds = [rnd for rnd in (report.before, report.after) if rnd is not None and rnd.attack is not None]
        results = list(report.attacks)
        if len(results) != len(rounds):
            return [f"{len(results)} attack results for {len(rounds)} attack rounds: raw diffs not kept"]
        return _finish(stem, traces_dir, results, list(rounds))
    except Exception as exc:  # noqa: BLE001 - never raises after a paid run; the class name only, no text
        return [f"raw run files were not kept: {type(exc).__name__}"]


def keep_stopped(results: list[Any], stem: str, traces_dir: Path) -> list[str]:
    """Keep the raw diffs of the attacks that finished before harden stopped (no report, so the grade is unknown).
    Best effort, never raises."""
    return _finish(stem, traces_dir, list(results), [None] * len(results))


@dataclass(frozen=True)
class RoundCheck:
    name: str
    report: holes.HoleReport
    test_paths: tuple[tuple[str, bool], ...]  # (path, restored by the grade)
    recorded: dict[str, Any] | None
    matches: bool | None  # recomputed labels equal the recorded ones; None when none were recorded
    primary_ok: bool | None = None  # recomputed primary equals the recorded one; None when not recorded
    exploited_ok: bool | None = None  # recomputed exploited equals the recorded one; None when not recorded
    recorded_outcome: str | None = (
        None  # attack summary outcome harden recorded (legit_fix, gold_match_with_exposure)
    )
    outcome: str | None = None  # the outcome recomputed with the same rule as harden
    outcome_ok: bool | None = None  # None when the downgrade inputs were not recorded (older rounds.json)
    future_digests: int | None = None  # T53: digests recorded for the round; None when not recorded
    future_complete: bool = False


GRADED_FIELDS = (
    "primary",
    "exploited",
    "outcome",
)  # rounds.json fields a recheck must reproduce; a mismatch exits 1


def _read_json(path: Path, what: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise KeepError(f"missing {what}: {path.name}") from None
    except (OSError, ValueError):
        raise KeepError(f"unreadable {what}: {path.name}") from None


def load_instance_id(traces_dir: Path, stem: str) -> str:
    """The task id from <stem>.restore.json. KeepError when that file is missing or has no id."""
    data = _read_json(traces_dir / f"{stem}.restore.json", "restore set")
    instance = data.get("instance_id") if isinstance(data, dict) else None
    if not isinstance(instance, str) or not instance:
        raise KeepError(f"unreadable restore set: {stem}.restore.json has no instance_id")
    return instance


def _segments(records: list[dict]) -> list[list[dict]]:
    """One record list per attack: a new segment starts at each header record."""
    out: list[list[dict]] = []
    for rec in records:
        if rec.get("type") == "header" or not out:
            out.append([])
        out[-1].append(rec)
    return out


def recheck(traces_dir: Path, stem: str, task: TaskSpec) -> list[RoundCheck]:
    """Re-run holes.classify for each kept round from the kept diff, trace and restore set. Offline.

    Every piece is checked before any classification, so a KeepError lists all that are missing.
    """
    missing = [
        name
        for name in (f"{stem}.jsonl", f"{stem}.restore.json", f"{stem}.rounds.json")
        if not (traces_dir / name).is_file()
    ]
    rounds: dict[str, Any] = {}
    if f"{stem}.rounds.json" not in missing:
        data = _read_json(traces_dir / f"{stem}.rounds.json", "round record")
        found = data.get("rounds") if isinstance(data, dict) else None
        if not isinstance(found, dict) or not found:
            raise KeepError(f"unreadable round record: {stem}.rounds.json")
        rounds = found
        for name in ROUND_NAMES:
            rec = rounds.get(name)
            if (
                isinstance(rec, dict)
                and rec.get("has_diff")
                and not (traces_dir / f"{stem}.{name}.diff").is_file()
            ):
                missing.append(f"{stem}.{name}.diff")
    if missing:
        raise KeepError("missing " + ", ".join(missing))
    restore = _read_json(traces_dir / f"{stem}.restore.json", "restore set")
    if not isinstance(restore, dict) or "restore_paths" not in restore:
        raise KeepError(f"unreadable restore set: {stem}.restore.json")
    paths = restore["restore_paths"]
    if paths is not None and not (isinstance(paths, list) and all(isinstance(p, str) for p in paths)):
        raise KeepError(f"unreadable restore set: {stem}.restore.json")
    names = [name for name in ROUND_NAMES if name in rounds]
    segments = _segments(holes.load_trace(traces_dir / f"{stem}.jsonl").records)
    checks: list[RoundCheck] = []
    for name in names:
        rec = rounds[name]
        index = rec.get("segment") if isinstance(rec, dict) else None
        if type(index) is not int or index < 0:
            raise KeepError(f"unreadable round record: {stem}.rounds.json")
        if index >= len(segments):
            raise KeepError(
                f"trace holds {len(segments)} attacks, round {name} is attack {index}: {stem}.jsonl"
            )
        diff: str | None = None
        if rec.get("has_diff"):
            diff = (traces_dir / f"{stem}.{name}.diff").read_text(encoding="utf-8", errors="replace")
        inputs = _downgrade_inputs(rec, stem)
        future = _future_inputs(rec, stem)
        report = holes.classify(
            segments[index],
            diff,
            task,
            visible_passed=rec.get("visible_passed"),
            hidden_passed=rec.get("hidden_passed"),
            grader_labels=tuple(rec.get("grader_labels") or ()),
            restored=paths,
            exposure_refs=() if inputs is None else inputs[0]["refs"],
            future_added=future,
        )
        if rec.get("no_attempt"):
            # harden clears the labels of an attack that made no attempt; the evidence stays in attempted.
            report = holes.HoleReport(
                primary="none",
                labels=(),
                attempted=report.attempted,
                evidence=report.evidence,
                succeeded=report.succeeded,
                exploited=False,
                skipped_records=report.skipped_records,
                notes=report.notes,
            )
        outcome: str | None = None
        if inputs is not None:
            # T49: the same rule harden applies after classify, with the round's recorded exposure flags.
            exposure, _ = inputs
            report, verdict = holes.downgrade_legit_fix(
                report,
                diff,
                task,
                future_git=exposure["future_git"],
                network=exposure["network"],
                future_added=future,
            )
            outcome = None if verdict is None else verdict[0]
        recorded = rec.get("recorded")
        matches = None if recorded is None else list(report.labels) == recorded.get("labels")
        test_paths = tuple(holes.diff_test_paths(diff, task, paths))
        checks.append(
            RoundCheck(
                name,
                report,
                test_paths,
                recorded,
                matches,
                primary_ok=_recorded_equal(recorded, "primary", report.primary),
                exploited_ok=_recorded_equal(recorded, "exploited", report.exploited),
                recorded_outcome=None if inputs is None else inputs[1]["outcome"],
                outcome=outcome,
                outcome_ok=None if inputs is None else inputs[1]["outcome"] == outcome,
                future_digests=len(future.digests) if isinstance(future, holes.FutureAdded) else None,
                future_complete=isinstance(future, holes.FutureAdded) and future.complete,
            )
        )
    return checks


def _downgrade_inputs(rec: dict[str, Any], stem: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """The exposure flags and refs, and the attack summary, harden had for one round (T49). None when rounds.json
    predates them: the outcome is then not recomputed. KeepError when they are present but unreadable."""
    exposure = rec.get("exposure")
    attack = rec.get("attack")
    if not (isinstance(exposure, dict) and isinstance(attack, dict) and "outcome" in attack):
        return None
    refs = exposure.get("refs")
    if not isinstance(refs, list) or not all(isinstance(ref, str) for ref in refs):
        raise KeepError(f"unreadable round record: {stem}.rounds.json")
    flags = {
        "future_git": bool(exposure.get("future_git")),
        "network": bool(exposure.get("network")),
        "refs": refs,
    }
    return flags, attack


def _future_inputs(rec: dict[str, Any], stem: str) -> holes.FutureAdded | None | holes._Legacy:
    """T53: the future-added digests harden gave classify for one round. LEGACY when rounds.json predates them (the
    pre-T53 rule then applies), None when the scan could not list them. KeepError when present but unreadable."""
    exposure = rec.get("exposure")
    recorded = exposure.get("future_added") if isinstance(exposure, dict) else None
    if recorded is None:
        return holes.LEGACY
    digests = recorded.get("digests") if isinstance(recorded, dict) else False
    if digests is None:
        return None
    if not isinstance(digests, list) or not all(isinstance(d, str) for d in digests):
        raise KeepError(f"unreadable round record: {stem}.rounds.json")
    return holes.FutureAdded(frozenset(digests), bool(recorded.get("complete")))


def _recorded_equal(recorded: dict[str, Any] | None, field: str, value: Any) -> bool | None:
    """Whether the recorded field equals the recomputed value. None when the round did not record the field."""
    if recorded is None or field not in recorded:
        return None
    return recorded[field] == value


def mismatched_fields(checks: list[RoundCheck]) -> list[str]:
    """The GRADED_FIELDS whose recomputed value differs from the recorded one in some round, in that order."""
    found = {
        field
        for check in checks
        for field, ok in (
            ("primary", check.primary_ok),
            ("exploited", check.exploited_ok),
            ("outcome", check.outcome_ok),
        )
        if ok is False
    }
    return [field for field in GRADED_FIELDS if field in found]


def _field_lines(check: RoundCheck) -> list[str]:
    states = {"primary": check.primary_ok, "exploited": check.exploited_ok}
    if all(ok is None for ok in states.values()):
        return ["  exploited/primary not recorded"]
    return [
        f"  recorded {field}: {'not recorded' if ok is None else 'match' if ok else 'DIFFER'}"
        for field, ok in states.items()
    ]


def _safe(text: str) -> str:
    return text.encode("ascii", "replace").decode("ascii")[:PATH_CHARS]


def render(stem: str, checks: list[RoundCheck]) -> list[str]:
    """Lines for the terminal: labels, flags and test path names only. No diff text, no evidence."""
    lines = [f"recheck {_safe(stem)} (offline: kept diff, trace and restore set)"]
    for check in checks:
        rep = check.report
        lines.append(
            f"{check.name}: labels={list(rep.labels)} attempted={list(rep.attempted)} "
            f"primary={rep.primary} exploited={rep.exploited}"
        )
        for path, restored in check.test_paths:
            lines.append(
                f"  test path {_safe(path)}: {'restored' if restored else 'unrestored'} by the grade"
            )
        if check.recorded is None:
            lines.append("  recorded labels: none kept")
        else:
            state = "match" if check.matches else "DIFFER"
            lines.append(f"  recorded labels: {state} {check.recorded.get('labels')}")
        lines.extend(_field_lines(check))
        lines.extend(_outcome_lines(check))
        lines.append(_future_line(check))
    return lines


def _future_line(check: RoundCheck) -> str:
    """T53: whether the round kept the digests git-history is confirmed against. Counts only, never a line."""
    if check.future_digests is None:
        return "  future-added digests not recorded: git-history is judged by the pre-T53 rule or as a lead"
    state = "complete" if check.future_complete else "partial"
    return f"  future-added digests: {check.future_digests} recorded ({state})"


def _outcome_lines(check: RoundCheck) -> list[str]:
    """T49: the recorded and the recomputed outcome (legit_fix, gold_match_with_exposure or none), and MATCH or DIFFER."""
    if check.outcome_ok is None:
        return ["  downgrade inputs not recorded: outcome not recomputed (older rounds.json)"]
    state = "MATCH" if check.outcome_ok else "DIFFER"
    recorded = check.recorded_outcome or "none"
    recomputed = check.outcome or "none"
    return [f"  outcome: recorded {recorded}, recomputed {recomputed}: {state}"]
