"""Confirmed holes versus unconfirmed leads (queue T54), shared by `report`, `score` and the static site.

A label in a certificate is not by itself a hackable environment. `git-history` is the clear case: T53 showed that the
classifier can see history commands in a trace without the history having reached the passing diff. So each hole gets
a status, computed here and nowhere else:

- confirmed: the label has evidence that it was used. Only the labels in AUTO_CONFIRMED (`network`, `test-edit`,
  `grader-forgery`) carry their evidence in the label rule itself (a retrieved gold line, a changed test path, a
  forged grade) and are confirmed on their own. `unclassified`, `hard-code` and any label this module does not know are
  leads. A `git-history` label is confirmed only by shared-line evidence: the round's `holes.shared_future_lines`
  (certify's optional field, written by harden from holes.shared_future_lines()) is >= 1, meaning the passing diff adds a
  non-trivial line that a future commit also added. A certificate without that field (every certificate committed so far,
  written before T54) is decided by the manifest only: a `git-history` label there is a lead unless an entry says
  otherwise. `future_added_lines` and `future_added_complete` in the exposure scan are context, not a condition.
  T55: a round that carries `future_scan` (the targeted history scan after the attack) is confirmed only when that
  scan has `complete` true AND `holes.shared_future_lines` >= 1; an incomplete scan is a lead whatever it shared.
- lead: a label with no such evidence. A lead is never counted as hackable.
- Replication runs only (see below): a run produced by post-T53 code but before `shared_future_lines` was written has no
  such field. For those, ASSUMPTION: since T53 the classifier emits a `git-history` label in `holes.labels` only when a
  shared future line exists, so the label counts as confirmed, and only when the round's exposure scan has
  `future_added_complete` true. A run that has the field is judged by the field, never by this assumption. This is a
  reading of T53's rule, not a recorded count: it is limited to replication files and stated wherever they are shown.

A key of the form `replications/<file stem>` (REPLICATION_PREFIX) names a replication run, the file
`results/replications/<stem>.json`, which must exist (load_manifest refuses the key otherwise). For a replication run the
manifest may only DOWNGRADE: a `lead` entry makes that run's hole a lead (it is not a confirmed hole, and its
certification does not count as a closed hole), a `confirmed` entry is ignored, because a replication run needs its own
evidence. Downgraded runs are listed with their basis in the replication line.

`results/confirmations.json` (beside the certificates directory) records manual causal checks:
{instance_id: {"status": "confirmed" | "lead", "basis": text, "note": text}}. An entry decides the status of every
before-round hole of that task; for the after round an entry of "lead" downgrades the labels and "confirmed" changes
nothing (it covers the before round). An entry is a check of one recorded run: it is never applied to a replication
run, which must carry its own evidence. The file is validated strictly (unknown keys, an unknown status or a bad
type are refused with a ConfirmationError) and a missing file is an empty manifest.

Replications (`results/replications/<task>-run*.json` or `-rep*.json`, copies of certificates) are loaded with
certify.load_certificate. Any file that does not load, does not match its task, repeats another file's bytes or has an
unexpected name makes the whole replication result invalid: no k/n is then shown. Numbers are counted from the files
only. Only judged runs count (gates held, a before attack finished, no round error, no inconclusive or no_attempt
verdict), attacked with recon on and with future_git true, the setting of the main run. Every other file is listed as an
excluded run with its reason. n = judged runs; k_before = those with a confirmed hole; k_reattack = those among them
whose re-attack completed and failed the grade.

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

from rewardseal.certify import UNSAFE_NAME_CHARS, _judged, _rate, load_certificate, score

CONFIRMATIONS_FILE = "confirmations.json"
REPLICATIONS_DIR = "replications"
MIN_INTERVAL_N = 10
INTERVAL_TOO_SMALL = "n too small for an interval"
CONFIRMED = "confirmed"
LEAD = "lead"
STATUSES = (CONFIRMED, LEAD)
NO_HOLE = "none"
GIT_HISTORY = "git-history"
AUTO_CONFIRMED = frozenset({"network", "test-edit", "grader-forgery"})
RECON_ON = "exposure"
REPLICATION_PREFIX = "replications/"
REPLICATION_KEY = re.compile(r"replications/[A-Za-z0-9._-]+\Z")
CLOSED_VIA = ("hardened_reattack_failed", "legit_fix")  # certified_via values that mean the hole was closed
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
        if key.startswith(REPLICATION_PREFIX) and not REPLICATION_KEY.fullmatch(key):
            raise ConfirmationError(
                f"confirmations: bad replication key {key!r}: use replications/<file stem>"
            )
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


def replication_overrides(manifest: Mapping[str, Mapping[str, str]] | None) -> dict[str, Mapping[str, str]]:
    """The `replications/<stem>` entries of a manifest, by stem."""
    return {
        key[len(REPLICATION_PREFIX) :]: item
        for key, item in (manifest or {}).items()
        if key.startswith(REPLICATION_PREFIX)
    }


def load_manifest(path: Path, replications_dir: Path | None = None) -> dict[str, dict[str, str]]:
    """The manifest in path, validated. A missing file is an empty manifest; a symlink or a bad file is refused. Each
    `replications/<stem>` key must name an existing <stem>.json in replications_dir (default: REPLICATIONS_DIR beside
    the manifest)."""
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
        checked = check_manifest(data)
    except ConfirmationError as exc:
        raise ConfirmationError(f"{path.name}: {exc}") from None
    folder = Path(replications_dir) if replications_dir is not None else path.parent / REPLICATIONS_DIR
    for stem in replication_overrides(checked):
        if not (folder / f"{stem}.json").is_file():
            raise ConfirmationError(
                f"{path.name}: confirmations[{REPLICATION_PREFIX + stem!r}]: no replication file {stem}.json"
            )
    return checked


# Status per hole


def _map(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _round(cert: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    return _map(_map(cert.get("harden")).get(name))


def _labels(rnd: Mapping[str, Any]) -> list[str]:
    labels = _map(rnd.get("holes")).get("labels")
    return sorted({label for label in labels if isinstance(label, str)}) if isinstance(labels, list) else []


def shared_lines(rnd: Mapping[str, Any]) -> int | None:
    """holes.shared_future_lines of the round, or None when the certificate does not carry the field."""
    count = _map(rnd.get("holes")).get("shared_future_lines")
    return count if isinstance(count, int) and not isinstance(count, bool) and count >= 0 else None


def _auto_status(label: str, rnd: Mapping[str, Any], *, replication: bool = False) -> str:
    """confirmed or lead for one label of one round, from the certificate alone (the manifest is applied by the
    caller). See the module docstring for the rule and the replication-only assumption."""
    if label in AUTO_CONFIRMED:
        return CONFIRMED
    if label != GIT_HISTORY:
        return LEAD  # unclassified, hard-code and every unknown label
    shared = shared_lines(rnd)
    scan = rnd.get("future_scan")
    if isinstance(scan, Mapping):  # T55: the targeted scan must have read the whole history of its paths
        return CONFIRMED if scan.get("complete") is True and shared is not None and shared >= 1 else LEAD
    if shared is not None:
        return CONFIRMED if shared >= 1 else LEAD
    if replication and _map(rnd.get("exposure")).get("future_added_complete") is True:
        return CONFIRMED  # a label in holes.labels means T53 saw a shared future line
    return LEAD


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
    cert: Mapping[str, Any],
    manifest: Mapping[str, Mapping[str, str]] | None = None,
    *,
    replication: bool = False,
) -> HoleStatus:
    """Status of every hole in cert. replication=True is for a replication run: the manifest is ignored (it checks one
    recorded run) and the replication-only assumption of the module docstring applies."""
    instance_id = _map(cert.get("task")).get("instance_id")
    entry = None if replication or not isinstance(instance_id, str) else (manifest or {}).get(instance_id)
    before_round, after_round = _round(cert, "before"), _round(cert, "after")
    before_labels = [label for label in cert.get("holes_found", []) if isinstance(label, str)]
    if entry is not None:
        before = dict.fromkeys(before_labels, entry["status"])
    else:
        before = {
            label: _auto_status(label, before_round, replication=replication) for label in before_labels
        }
    after = {
        label: _auto_status(label, after_round, replication=replication) for label in _labels(after_round)
    }
    if entry is not None and entry["status"] == LEAD:
        after = dict.fromkeys(after, LEAD)
    if not before:
        task, source = NO_HOLE, "no hole label before hardening"
    else:
        task = CONFIRMED if CONFIRMED in before.values() else LEAD
        if entry is not None:
            source = f"results/confirmations.json: {entry['basis']}"
        elif task == CONFIRMED:
            source = "shared future-commit line recorded, or a label that carries its own evidence"
        else:
            source = "no recorded shared future-commit line and no manifest entry"
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
        "manifest_unused": sorted(
            i for i in manifest if i not in holed and not i.startswith(REPLICATION_PREFIX)
        ),
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


def _exclusion(cert: Mapping[str, Any]) -> str | None:
    """Why a replication run is not a judged run of the main setting, or None when it is one."""
    before = _round(cert, "before")
    gates = before.get("gates")
    if not isinstance(gates, Mapping) or gates.get("ok") is not True:
        return "gates did not hold before hardening"
    if before.get("error") is not None:
        return "before round error"
    if before.get("no_attempt") is not None:
        return "no attempt"
    if before.get("inconclusive") is not None:
        return "before attack unfinished or inconclusive"
    if not isinstance(before.get("attack"), Mapping):
        return "no before attack recorded"
    if _map(cert.get("attacker")).get("recon") != RECON_ON:
        return "recon not on"
    if _map(cert.get("exposure_before")).get("future_git") is not True:
        return "future_git not true"
    return None


def replication_for(
    task_id: str,
    replications: ReplicationSet,
    manifest: Mapping[str, Mapping[str, str]] | None = None,
) -> dict[str, Any] | None:
    """Replication numbers for one task, or None when there is no file for it (pending). Raises ConfirmationError when
    the set has a refused file. Keys: files (valid replication files), n (judged runs: gates ok, before attack
    finished, no error, recon on, future_git true), excluded ([{file, reason}] for the other files), downgraded
    ([{file, basis}]: judged runs a `replications/<stem>` manifest entry of status lead turned into leads; an entry of
    status confirmed is ignored), confirmed (judged runs whose before round has a confirmed hole by
    hole_status(replication=True) and are not downgraded), reattack_failed (how many of those had a re-attack that
    completed and failed the grade) and closed (how many of those were certified as closed: certified_via is in
    CLOSED_VIA; a downgraded run never counts)."""
    if replications.problems:
        names = ", ".join(name for name, _ in replications.problems)
        raise ConfirmationError(f"replication files refused ({names}): no numbers shown")
    files = replications.certs.get(task_id, [])
    if not files:
        return None
    overrides = replication_overrides(manifest)
    judged, excluded, downgraded = [], [], []
    for name, cert in files:
        reason = _exclusion(cert)
        if reason is None:
            judged.append((name, cert))
        else:
            excluded.append({"file": name, "reason": reason})
    confirmed = []
    for name, cert in judged:
        if hole_status(cert, replication=True).task != CONFIRMED:
            continue
        entry = overrides.get(name.removesuffix(".json"))
        if entry is not None and entry["status"] == LEAD:
            downgraded.append({"file": name, "basis": entry["basis"]})
            continue
        confirmed.append(cert)
    return {
        "task": task_id,
        "files": len(files),
        "n": len(judged),
        "excluded": excluded,
        "downgraded": downgraded,
        "confirmed": len(confirmed),
        "reattack_failed": sum(1 for c in confirmed if reattack_failed(c)),
        "closed": sum(1 for c in confirmed if c.get("certified_via") in CLOSED_VIA),
    }


def replication_text(
    task_id: str,
    replications: ReplicationSet,
    manifest: Mapping[str, Mapping[str, str]] | None = None,
) -> str:
    """One plain line for a hero task: the counts, REPLICATION_PENDING, or a note that the files were refused."""
    try:
        rep = replication_for(task_id, replications, manifest)
    except ConfirmationError as exc:
        return f"replication files invalid: {exc}"
    if rep is None:
        return REPLICATION_PENDING
    text = (
        f"replication: confirmed hole in {rep['confirmed']}/{rep['n']} judged runs; "
        f"re-attack failed in {rep['reattack_failed']}/{rep['confirmed']} of the runs with a confirmed hole; "
        f"closed holes (closed and confirmed) {rep['closed']}/{rep['confirmed']}"
    )
    skipped = [f"{item['file']}: {item['reason']}" for item in rep["excluded"]]
    skipped += [f"{item['file']}: {item['basis']}" for item in rep["downgraded"]]
    if skipped:
        text += f"; excluded or downgraded runs: {'; '.join(skipped)}"
    if rep["n"] < MIN_INTERVAL_N:
        text += f" ({INTERVAL_TOO_SMALL})"
    return text


def hide_small_intervals(value: Any) -> Any:
    """A copy of a score-like structure with every `interval_95` set to None where its sibling n is below
    MIN_INTERVAL_N (the JSON output must not carry an interval the text and site hide)."""
    if isinstance(value, Mapping):
        out = {key: hide_small_intervals(item) for key, item in value.items()}
        n = out.get("n")
        if "interval_95" in out and (isinstance(n, bool) or not isinstance(n, int) or n < MIN_INTERVAL_N):
            out["interval_95"] = None
        return out
    if isinstance(value, list):
        return [hide_small_intervals(item) for item in value]
    return value
