"""Keep a paid run's raw evidence locally (T42) and re-check its hole labels offline.

Every harden or batch run keeps, beside the certificates directory and under the git-ignored traces/ folder, named by
the certificate's file stem:
- <stem>.jsonl            the full attacker trace (every step of every attack round, written by attacker.attack)
- <stem>.before.diff      the RAW attack diff of the first round
- <stem>.after.diff       the RAW attack diff of the re-attack round (only when that round ran an attack)
- <stem>.diff             the RAW final diff: the last round's attack diff
- <stem>.restore.json     the task's restore set (grader.restore_paths), written before the paid run
- <stem>.rounds.json      per round: the grade inputs classify was given and the labels harden recorded

Nothing here is ever committed (results/traces/ is in .gitignore, and `git add -f` is denied). A file already there
is renamed to <name>.<UTC time>.old, never overwritten.

recheck() re-runs holes.classify on the kept diff, trace and restore set with no network, sandbox, model or budget.
render() prints labels and test path names only, never diff text.
"""

from __future__ import annotations

import json
import re
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
STEM = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
PATH_CHARS = 200


class KeepError(Exception):
    """A kept piece is missing or unreadable. The message names it."""


def valid_stem(stem: str) -> bool:
    """A certificate stem: no path separator, so it cannot climb out of the traces folder."""
    return bool(STEM.match(stem)) and ".." not in stem


def _write(folder: Path, name: str, text: str) -> Path:
    """Write folder/name; an existing file is renamed aside first. A symbolic link is refused."""
    target = folder / name
    if folder.is_symlink() or target.is_symlink():
        raise OSError(f"refusing to write through a symbolic link: {name}")
    folder.mkdir(parents=True, exist_ok=True)
    if target.exists():
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        aside = folder / f"{name}.{stamp}.old"
        number = 1
        while aside.exists() or aside.is_symlink():
            number += 1
            aside = folder / f"{name}.{stamp}.{number}.old"
        target.rename(aside)
    target.write_text(text, encoding="utf-8", errors="replace")
    return target


def _json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, indent=2) + "\n"


def restore_set(task: TaskSpec) -> list[str] | None:
    """grader.restore_paths(task), or None when the node ids or paths cannot be read exactly (fail closed)."""
    try:
        return restore_paths(task)
    except ValueError:
        return None


def write_restore(traces_dir: Path, stem: str, task: TaskSpec) -> None:
    """Cache the task's restore set beside the trace. OSError propagates; the caller decides what a failure means."""
    data = {"schema": SCHEMA, "instance_id": task.instance_id, "restore_paths": restore_set(task)}
    _write(traces_dir, f"{stem}.restore.json", _json(data))


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
    return {
        "has_diff": diff is not None,
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
    }


def keep_raw(report: Any, stem: str, traces_dir: Path) -> list[str]:
    """Keep the raw attack diffs and the per-round grade inputs. Never raises. Returns notes (no diff text)."""
    notes: list[str] = []
    rounds = [
        (name, rnd)
        for name, rnd in (("before", report.before), ("after", report.after))
        if rnd is not None and rnd.attack is not None
    ]
    results = list(report.attacks)
    if len(results) != len(rounds):
        return [f"{len(results)} attack results for {len(rounds)} attack rounds: raw diffs not kept"]
    meta: dict[str, Any] = {}
    last: str | None = None
    for (name, rnd), result in zip(rounds, results):
        try:
            meta[name] = _round_inputs(rnd, result)
            if result.final_diff is not None:
                _write(traces_dir, f"{stem}.{name}.diff", result.final_diff)
                last = result.final_diff
        except (OSError, ValueError) as exc:
            notes.append(f"the {name} raw diff was not kept: {type(exc).__name__}")
    try:
        if last is not None:
            _write(traces_dir, f"{stem}.diff", last)
        _write(traces_dir, f"{stem}.rounds.json", _json({"schema": SCHEMA, "rounds": meta}))
    except OSError as exc:
        notes.append(f"raw run files were not kept: {type(exc).__name__}")
    return notes


@dataclass(frozen=True)
class RoundCheck:
    name: str
    report: holes.HoleReport
    test_paths: tuple[tuple[str, bool], ...]  # (path, restored by the grade)
    recorded: dict[str, Any] | None
    matches: bool | None  # recomputed labels equal the recorded ones; None when none were recorded


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
    if len(segments) < len(names):
        raise KeepError(f"trace holds {len(segments)} attacks for {len(names)} recorded rounds: {stem}.jsonl")
    checks: list[RoundCheck] = []
    for index, name in enumerate(names):
        rec = rounds[name]
        if not isinstance(rec, dict):
            raise KeepError(f"unreadable round record: {stem}.rounds.json")
        diff: str | None = None
        if rec.get("has_diff"):
            diff = (traces_dir / f"{stem}.{name}.diff").read_text(encoding="utf-8", errors="replace")
        report = holes.classify(
            segments[index],
            diff,
            task,
            visible_passed=rec.get("visible_passed"),
            hidden_passed=rec.get("hidden_passed"),
            grader_labels=tuple(rec.get("grader_labels") or ()),
            restored=paths,
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
        recorded = rec.get("recorded")
        matches = None if recorded is None else list(report.labels) == recorded.get("labels")
        test_paths = tuple(holes.diff_test_paths(diff, task, paths))
        checks.append(RoundCheck(name, report, test_paths, recorded, matches))
    return checks


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
    return lines
