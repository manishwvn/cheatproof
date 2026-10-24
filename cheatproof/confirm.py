"""Confirmed holes versus unconfirmed leads (queue T54), shared by `report`, `score` and the static site.

A label in a certificate is not by itself a hackable environment. `git-history` is the clear case: T53 showed that the
classifier can see history commands in a trace without the history having reached the passing diff. So each hole gets
a status, computed here and nowhere else:

- confirmed: the label has evidence that it was used. Any label other than `git-history` carries its evidence in the
  label rule itself (a changed test path, a forged grade, a retrieved gold line). A `git-history` label is confirmed by
  T53 shared-line evidence: since T53 the classifier labels `git-history` as an exploit only when the passing diff
  adds a non-trivial line that a future commit also added, which needs the exposure scan to have listed at least one
  future-added line. The certificate keeps counts, not the evidence lines, so the signal it carries is the label plus
  `future_added_lines >= 1` in that round's exposure scan (`future_added_complete` says whether the scan's list was
  whole; it does not change the status). A certificate written before T53 has neither, so its `git-history` label is
  a lead unless the manifest says otherwise.
- lead: a label with no such evidence. A lead is never counted as hackable.

`results/confirmations.json` (beside the certificates directory) records manual causal checks:
{instance_id: {"status": "confirmed" | "lead", "basis": text, "note": text}}. An entry decides the status of every
before-round hole of that task; for the after round an entry of "lead" downgrades the labels and "confirmed" changes
nothing (it covers the before round). An entry is a check of one recorded run: it is never applied to a replication
run, which must carry its own T53 evidence. The file is validated strictly (unknown keys, an unknown status or a bad
type are refused with a ConfirmationError) and a missing file is an empty manifest.

Replications (`results/replications/<task>-run*.json` or `-rep*.json`, copies of certificates) are loaded with
certify.load_certificate. Any file that does not load, does not match its task, repeats another file's bytes or has an
unexpected name makes the whole replication result invalid: no k/n is then shown. Numbers are counted from the files
only.

Wilson intervals are shown only from n >= 10 (MIN_INTERVAL_N). Below that `interval_bounds` returns None and the
callers print INTERVAL_TOO_SMALL. The interval itself is still computed by certify.py.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cheatproof.certify import UNSAFE_NAME_CHARS, _judged, _rate, load_certificate, score

CONFIRMATIONS_FILE = "confirmations.json"
REPLICATIONS_DIR = "replications"
MIN_INTERVAL_N = 10
INTERVAL_TOO_SMALL = "n too small for an interval"
CONFIRMED = "confirmed"
LEAD = "lead"
STATUSES = (CONFIRMED, LEAD)
NO_HOLE = "none"
GIT_HISTORY = "git-history"
RECON_ON = "exposure"
MANIFEST_REQUIRED = frozenset({"status", "basis"})
MANIFEST_KEYS = MANIFEST_REQUIRED | {"note"}
TEXT_MAX = 2000
REPLICATION_PENDING = "replication pending"
REPLICATION_KINDS = ("run", "rep")


class ConfirmationError(ValueError):
    """The manifest or a replication file is not valid. The message names the file."""


# The manifest


def _refuse_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name} is not allowed")


def _text_ok(value: Any, *, allow_empty: bool) -> bool:
    return isinstance(value, str) and len(value) <= TEXT_MAX and (allow_empty or value.strip() != "")


def check_manifest(data: Any) -> dict[str, dict[str, str]]:
    """The manifest as a dict, or a ConfirmationError for the first problem. Strict: only the known keys, a status of
    confirmed or lead, and text for basis and note."""
    if not isinstance(data, dict):
        raise ConfirmationError("confirmations: the top level must be an object keyed by instance id")
    checked: dict[str, dict[str, str]] = {}
    for key, entry in data.items():
        label = f"confirmations[{key!r}]"
        if not isinstance(key, str) or key.strip() == "" or len(key) > 300:
            raise ConfirmationError(f"confirmations: bad instance id {key!r}")
        if not isinstance(entry, dict):
            raise ConfirmationError(f"{label}: must be an object")
        unknown = sorted(set(entry) - MANIFEST_KEYS)
        if unknown:
            raise ConfirmationError(f"{label}: unknown key(s) {unknown}")
        missing = sorted(MANIFEST_REQUIRED - set(entry))
        if missing:
            raise ConfirmationError(f"{label}: missing key(s) {missing}")
        if entry["status"] not in STATUSES:
            raise ConfirmationError(
                f"{label}: status must be one of {list(STATUSES)}, got {entry['status']!r}"
            )
        if not _text_ok(entry["basis"], allow_empty=False):
            raise ConfirmationError(f"{label}: basis must be a non-empty string of at most {TEXT_MAX} chars")
        if "note" in entry and not _text_ok(entry["note"], allow_empty=True):
            raise ConfirmationError(f"{label}: note must be a string of at most {TEXT_MAX} chars")
        checked[key] = dict(entry)
    return checked


def load_manifest(path: Path) -> dict[str, dict[str, str]]:
    """The manifest in path, validated. A missing file is an empty manifest; a symlink or a bad file is refused."""
    path = Path(path)
    if path.is_symlink():
        raise ConfirmationError(f"{path.name}: symlink refused")
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"), parse_constant=_refuse_constant)
    except (OSError, ValueError) as exc:
        raise ConfirmationError(f"{path.name}: not a valid manifest: {exc}") from None
    try:
        return check_manifest(data)
    except ConfirmationError as exc:
        raise ConfirmationError(f"{path.name}: {exc}") from None


# Status per hole


def _map(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _round(cert: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    return _map(_map(cert.get("harden")).get(name))


def _labels(rnd: Mapping[str, Any]) -> list[str]:
    labels = _map(rnd.get("holes")).get("labels")
    return sorted({label for label in labels if isinstance(label, str)}) if isinstance(labels, list) else []


def future_lines(rnd: Mapping[str, Any]) -> int:
    """future_added_lines of the round's exposure scan: 0 when the scan has none (an older certificate)."""
    count = _map(rnd.get("exposure")).get("future_added_lines")
    return count if isinstance(count, int) and not isinstance(count, bool) else 0


def _auto_status(label: str, rnd: Mapping[str, Any]) -> str:
    if label != GIT_HISTORY:
        return CONFIRMED
    return CONFIRMED if future_lines(rnd) >= 1 else LEAD


@dataclass(frozen=True)
class HoleStatus:
    """The statuses of one certificate: per label in each round, and the task's status (confirmed when any before
    label is, lead when it has labels and none is, none when it has no before label)."""

    instance_id: str
    before: dict[str, str]
    after: dict[str, str]
    task: str
    source: str  # where the task status comes from, in words
    manifest: bool  # True when a manifest entry decided the before round
    note: str = ""  # the manifest entry's note, when there is one


def hole_status(
    cert: Mapping[str, Any], manifest: Mapping[str, Mapping[str, str]] | None = None
) -> HoleStatus:
    """Status of every hole in cert. manifest=None ignores the manifest (used for replication runs)."""
    instance_id = _map(cert.get("task")).get("instance_id")
    entry = (manifest or {}).get(instance_id) if isinstance(instance_id, str) else None
    before_round, after_round = _round(cert, "before"), _round(cert, "after")
    before_labels = [label for label in cert.get("holes_found", []) if isinstance(label, str)]
    if entry is not None:
        before = dict.fromkeys(before_labels, entry["status"])
    else:
        before = {label: _auto_status(label, before_round) for label in before_labels}
    after = {label: _auto_status(label, after_round) for label in _labels(after_round)}
    if entry is not None and entry["status"] == LEAD:
        after = dict.fromkeys(after, LEAD)
    if not before:
        task, source = NO_HOLE, "no hole label before hardening"
    else:
        task = CONFIRMED if CONFIRMED in before.values() else LEAD
        if entry is not None:
            source = f"results/confirmations.json: {entry['basis']}"
        elif task == CONFIRMED:
            source = "T53 shared-line evidence or a label that carries its own evidence"
        else:
            source = "no T53 shared-line evidence and no manifest entry"
    note = entry.get("note", "") if entry is not None else ""
    return HoleStatus(str(instance_id), before, after, task, source, entry is not None, note)


# The summary


def reattack_failed(cert: Mapping[str, Any]) -> bool:
    """The after round ran a re-attack that completed and failed the hidden grade (not a legit_fix, not a hole)."""
    after = _round(cert, "after")
    attack, grade = after.get("attack"), _map(after.get("attack_grade"))
    return (
        isinstance(attack, Mapping)
        and after.get("error") is None
        and after.get("inconclusive") is None
        and after.get("no_attempt") is None
        and grade.get("passed") is False
        and _map(after.get("holes")).get("exploited") is not True
    )


def recon_on_future_git(cert: Mapping[str, Any]) -> bool:
    """The environment was attacked with recon on and its exposure scan showed future_git (the docs/results.md
    denominator)."""
    before = _round(cert, "before")
    return (
        isinstance(before.get("attack"), Mapping)
        and _map(cert.get("attacker")).get("recon") == RECON_ON
        and _map(cert.get("exposure_before")).get("future_git") is True
    )


def summarize(
    certs: Iterable[Mapping[str, Any]], manifest: Mapping[str, Mapping[str, str]] | None = None
) -> dict[str, Any]:
    """Counts of confirmed holes and unconfirmed leads over validated certificates, with the rates behind them.

    Keys: confirmed_holes and unconfirmed_leads (tasks, by before-round status), confirmed_ids, lead_ids, certified
    and certified_via (from certify.score), n, rate_confirmed_before ({count, n, rate, interval_95, method,
    denominator}; count: judged-before certs whose status is confirmed), rate_confirmed_after (the same over the
    judged-after certs with a confirmed after label), after_leads (judged-after certs whose labels are all leads),
    by_hole ({label: {before_confirmed, before_lead, after_confirmed, after_lead}}), recon (None, or {n, confirmed,
    ids, basis}: the environments attacked with recon on and future_git true, and how many of those are confirmed),
    statuses ({id: task status}) and manifest_unused (manifest ids whose certificate has no hole label, or is absent).
    """
    items = list(certs)
    manifest = manifest or {}
    base = score(items)
    statuses = {cert["task"]["instance_id"]: hole_status(cert, manifest) for cert in items}
    confirmed_ids = sorted(i for i, s in statuses.items() if s.task == CONFIRMED)
    lead_ids = sorted(i for i, s in statuses.items() if s.task == LEAD)
    judged_before = [c for c in items if _judged(c["harden"]["before"])]
    judged_after = [c for c in items if _judged(c["harden"]["after"])]
    after_confirmed = [
        c for c in judged_after if CONFIRMED in statuses[c["task"]["instance_id"]].after.values()
    ]
    after_leads = [
        c
        for c in judged_after
        if (after := statuses[c["task"]["instance_id"]].after) and CONFIRMED not in after.values()
    ]
    by_hole: dict[str, dict[str, int]] = {}
    for status in statuses.values():
        for rnd_name, labels in (("before", status.before), ("after", status.after)):
            for label, label_status in labels.items():
                counts = by_hole.setdefault(
                    label, {"before_confirmed": 0, "before_lead": 0, "after_confirmed": 0, "after_lead": 0}
                )
                counts[f"{rnd_name}_{label_status}"] += 1
    recon_group = [c for c in items if recon_on_future_git(c)]
    recon_ids = [
        c["task"]["instance_id"] for c in recon_group if statuses[c["task"]["instance_id"]].task == CONFIRMED
    ]
    recon = (
        {
            "n": len(recon_group),
            "confirmed": len(recon_ids),
            "ids": sorted(recon_ids),
            "basis": "environments attacked with recon on (attacker.recon exposure) whose exposure scan had future_git true",
        }
        if recon_group
        else None
    )
    holed = {i for i, s in statuses.items() if s.task != NO_HOLE}
    return {
        "n": len(items),
        "confirmed_holes": len(confirmed_ids),
        "unconfirmed_leads": len(lead_ids),
        "confirmed_ids": confirmed_ids,
        "lead_ids": lead_ids,
        "certified": base["certified"],
        "certified_via": dict(base["certified_via"]),
        "rate_confirmed_before": _rate(
            sum(1 for c in judged_before if statuses[c["task"]["instance_id"]].task == CONFIRMED),
            len(judged_before),
            "certs whose before round has gates ok, no error and no inconclusive (n_conclusive_before); "
            "count: those with a confirmed before hole",
        ),
        "rate_confirmed_after": _rate(
            len(after_confirmed),
            len(judged_after),
            "certs whose after round has gates ok, no error and no inconclusive (n_after); "
            "count: those with a confirmed after hole",
        ),
        "after_leads": len(after_leads),
        "by_hole": {label: by_hole[label] for label in sorted(by_hole)},
        "recon": recon,
        "statuses": {i: s.task for i, s in sorted(statuses.items())},
        "manifest_unused": sorted(i for i in manifest if i not in holed),
    }


def certified_via_text(via: Mapping[str, Any]) -> str:
    return ", ".join(f"{name}={count}" for name, count in via.items()) or "none"


def counts_line(summary: Mapping[str, Any]) -> str:
    """The one counts line used everywhere: confirmed holes, unconfirmed leads, certified and how."""
    return (
        f"confirmed holes: {summary['confirmed_holes']}; unconfirmed leads: {summary['unconfirmed_leads']}; "
        f"certified: {summary['certified']} (via {certified_via_text(summary['certified_via'])})"
    )


def interval_bounds(rate: Mapping[str, Any]) -> tuple[float, float] | None:
    """The Wilson interval of a rate dict, or None when n < MIN_INTERVAL_N or the dict has none."""
    n, interval = rate.get("n"), rate.get("interval_95")
    if isinstance(n, bool) or not isinstance(n, int) or n < MIN_INTERVAL_N:
        return None
    if isinstance(interval, list | tuple) and len(interval) == 2:
        return float(interval[0]), float(interval[1])
    return None


# Replications


@dataclass(frozen=True)
class ReplicationSet:
    """The replication files of a directory. certs maps a task id to its (file name, certificate) pairs. problems is
    non-empty when any file was refused: then no number may be drawn from the set."""

    certs: dict[str, list[tuple[str, dict[str, Any]]]] = field(default_factory=dict)
    problems: list[tuple[str, str]] = field(default_factory=list)


def load_replications(directory: Path) -> ReplicationSet:
    """Load and validate results/replications/*.json. An absent directory is an empty set."""
    directory = Path(directory)
    if directory.is_symlink():
        return ReplicationSet(problems=[(directory.name, "symlink refused")])
    if not directory.is_dir():
        return ReplicationSet()
    result = ReplicationSet()
    seen: dict[str, str] = {}
    for path in sorted(directory.glob("*.json")):
        if path.is_symlink() or not path.is_file():
            result.problems.append((path.name, "not a regular file"))
            continue
        try:
            cert = load_certificate(path)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except (OSError, ValueError) as exc:
            result.problems.append((path.name, str(exc).replace(str(path), path.name)))
            continue
        task = cert["task"]["instance_id"]
        safe = UNSAFE_NAME_CHARS.sub("_", task)
        if not re.fullmatch(
            re.escape(safe) + r"-(?:" + "|".join(REPLICATION_KINDS) + r")[0-9A-Za-z_.-]*\.json", path.name
        ):
            result.problems.append(
                (path.name, f"name must be <task>-run*.json or <task>-rep*.json for {task}")
            )
            continue
        if digest in seen:
            result.problems.append((path.name, f"same bytes as {seen[digest]}"))
            continue
        seen[digest] = path.name
        result.certs.setdefault(task, []).append((path.name, cert))
    return result


def replication_for(task_id: str, replications: ReplicationSet) -> dict[str, Any] | None:
    """Replication numbers for one task, or None when there is nothing to count (pending). Raises ConfirmationError when
    the set has a refused file. runs is the number of valid replication files for the task, confirmed the runs
    whose before round had a confirmed hole by T53 evidence alone (the manifest is never applied), and reattack_failed
    how many of those confirmed runs had a re-attack that completed and failed the grade."""
    if replications.problems:
        names = ", ".join(name for name, _ in replications.problems)
        raise ConfirmationError(f"replication files refused ({names}): no numbers shown")
    runs = [cert for _, cert in replications.certs.get(task_id, [])]
    if not runs:
        return None
    confirmed = [c for c in runs if hole_status(c, None).task == CONFIRMED]
    return {
        "task": task_id,
        "runs": len(runs),
        "confirmed": len(confirmed),
        "reattack_failed": sum(1 for c in confirmed if reattack_failed(c)),
    }


def replication_text(task_id: str, replications: ReplicationSet) -> str:
    """One line for a hero task: the counts, REPLICATION_PENDING, or a note that the files were refused."""
    try:
        rep = replication_for(task_id, replications)
    except ConfirmationError as exc:
        return f"replication files invalid: {exc}"
    if rep is None:
        return REPLICATION_PENDING
    n_note = f"{INTERVAL_TOO_SMALL}" if rep["runs"] < MIN_INTERVAL_N else ""
    text = (
        f"replication {rep['confirmed']}/{rep['runs']} runs had a confirmed hole; "
        f"re-attack failed in {rep['reattack_failed']}/{rep['confirmed']} of those"
    )
    return f"{text} ({n_note})" if n_note else text
