"""Certificates and hackability score (queue T07, ADR 0002): one JSON file per task, and one score over them.

build_certificate() turns a HardenReport (harden.py) and the run facts into a plain dict. Every field
comes from code: HardenReport.to_dict(), which holds no raw diffs, steps or log text, the task's
digests, and the caller's attacker limits, cost and timestamp. Nothing here calls a model or the
network. validate_certificate() checks the schema by hand. write_certificate() writes
<instance_id>.json atomically, and load_certificate() reads it back and validates it. Certificates
are validated and cross-checked against their own harden block, so a hand-edited file with a count
that disagrees with its evidence is refused.

score() counts certificates: how many the attacker exploited before hardening, how many still
exploited after, how many were certified, and how many could not be judged. Each rate is a raw count
with its n and a Wilson 95% interval. A certified task means only "not hackable by this attacker".
It never means secure or proven.

Certificate keys (schema_version 1): schema, schema_version, task, image_digest, attacker,
holes_found, patches_applied, patches_rejected, unpatched, gates, certified, reason,
exposure_before, cost_usd, sandbox_runs, timestamp, notes, harden. The schema is closed: an unknown
top-level key is refused. The attacker mapping must name its model in "model", and a key that looks
like a credential is refused, so no secret reaches git.

Score keys (schema_version 1): n, hackable_before, hackable_after (after round with a hole label),
n_after (certs that have an after round), certified, inconclusive (before or after round has
inconclusive or error set), rate_before, rate_after, by_hole, by_source, cost_usd_total.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import math
import os
import re
import tempfile
from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cheatproof.harden import HardenReport
    from cheatproof.tasks import TaskSpec

SCHEMA_VERSION = 1
SCHEMA = "cheatproof.certificate"
SCORE_SCHEMA_VERSION = 1
Z_95 = 1.959963984540054  # the 97.5th percentile of the standard normal distribution
SHOWN_CHARS = 60  # longest repr of a bad value in an error message
TOP_KEYS = (
    "schema",
    "schema_version",
    "task",
    "image_digest",
    "attacker",
    "holes_found",
    "patches_applied",
    "patches_rejected",
    "unpatched",
    "gates",
    "certified",
    "reason",
    "exposure_before",
    "cost_usd",
    "sandbox_runs",
    "timestamp",
    "notes",
    "harden",
)
TASK_KEYS = ("instance_id", "repo", "base_commit", "image", "source", "gold_patch", "test_patch")
DIGEST_KEYS = ("sha256", "chars")
HARDEN_KEYS = (
    "instance_id",
    "before",
    "after",
    "candidates",
    "accepted",
    "rejected",
    "unpatched",
    "certified",
    "reason",
    "sandbox_runs",
    "notes",
)
ROUND_KEYS = (
    "patches",
    "patch_outcomes",
    "gates",
    "exposure",
    "attack",
    "attack_grade",
    "holes",
    "inconclusive",
    "error",
)
# Attacker keys that look like credentials are refused: the attacker mapping is copied into the certificate.
SECRET_KEY = re.compile(r"secret|password|passwd|api[_-]?key|credential|(^|_)token$", re.IGNORECASE)
UNSAFE_NAME_CHARS = re.compile(r"[^A-Za-z0-9._-]")


def _show(value: Any) -> str:
    text = repr(value)
    return text if len(text) <= SHOWN_CHARS else text[: SHOWN_CHARS - 3] + "..."


def _want(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _is_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _str_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _keys(data: Mapping[str, Any], keys: tuple[str, ...], where: str | None = None) -> None:
    for key in keys:
        if key not in data:
            name = f"{where}.{key}" if where else key
            raise ValueError(f"missing required key: {name}")


def _json_scalar(value: Any) -> bool:
    if value is None or isinstance(value, str | bool | int):
        return True
    return isinstance(value, float) and math.isfinite(value)


def _money(value: Any, name: str) -> float:
    _want(
        _is_number(value) and math.isfinite(value) and value >= 0,
        f"{name} must be a finite number >= 0, got {_show(value)}",
    )
    return float(value)


def _timestamp(value: Any) -> None:
    _want(isinstance(value, str), f"timestamp must be an ISO 8601 string with a timezone, got {_show(value)}")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise ValueError(f"timestamp is not ISO 8601: {_show(value)}") from None
    _want(parsed.utcoffset() is not None, f"timestamp needs a timezone: {_show(value)}")


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _check_task(value: Any) -> None:
    _want(isinstance(value, Mapping), "task must be an object")
    _keys(value, TASK_KEYS, "task")
    for key in ("instance_id", "repo", "base_commit", "image", "source"):
        _want(isinstance(value[key], str), f"task.{key} must be a string")
    for key in ("gold_patch", "test_patch"):
        digest = value[key]
        _want(isinstance(digest, Mapping), f"task.{key} must hold sha256 and chars, not the patch text")
        _keys(digest, DIGEST_KEYS, f"task.{key}")
        _want(isinstance(digest["sha256"], str), f"task.{key}.sha256 must be a string")
        _want(_is_count(digest["chars"]), f"task.{key}.chars must be a count")


def _check_attacker(value: Any) -> None:
    _want(isinstance(value, Mapping), "attacker must be an object")
    for key, item in value.items():
        _want(isinstance(key, str) and key != "", f"attacker key {_show(key)} must be a non-empty string")
        _want(not SECRET_KEY.search(key), f"attacker key {key!r} looks like a secret and is refused")
        _want(_json_scalar(item), f"attacker.{key} must be a finite JSON scalar, got {type(item).__name__}")
    _want(isinstance(value.get("model"), str) and value["model"] != "", "attacker.model must name the model")


def _check_round(value: Any, where: str, *, optional: bool) -> None:
    if value is None:
        _want(optional, f"{where} is required")
        return
    _want(isinstance(value, Mapping), f"{where} must be an object")
    _keys(value, ROUND_KEYS, where)
    holes = value["holes"]
    if holes is not None:
        _want(
            isinstance(holes, Mapping) and _str_list(holes.get("labels")),
            f"{where}.holes.labels must be a list of strings",
        )
    for key in ("inconclusive", "error"):
        _want(value[key] is None or isinstance(value[key], str), f"{where}.{key} must be a string or null")
    _want(value["gates"] is None or isinstance(value["gates"], Mapping), f"{where}.gates must be an object")


def _check_harden(value: Any) -> None:
    _want(isinstance(value, Mapping), "harden must be an object")
    _keys(value, HARDEN_KEYS, "harden")
    _want(isinstance(value["instance_id"], str), "harden.instance_id must be a string")
    _want(isinstance(value["certified"], bool), "harden.certified must be a bool")
    _want(isinstance(value["reason"], str), "harden.reason must be a string")
    _want(_is_count(value["sandbox_runs"]), "harden.sandbox_runs must be a count")
    for key in ("accepted", "rejected", "unpatched", "notes"):
        _want(_str_list(value[key]), f"harden.{key} must be a list of strings")
    _want(isinstance(value["candidates"], list), "harden.candidates must be a list")
    _check_round(value["before"], "harden.before", optional=False)
    _check_round(value["after"], "harden.after", optional=True)


def _check_consistent(data: Mapping[str, Any]) -> None:
    """The top-level facts must agree with the harden block they were taken from."""
    harden = data["harden"]
    before, after = harden["before"], harden["after"]
    expected_holes = [] if before["holes"] is None else sorted(set(before["holes"]["labels"]))
    _want(data["holes_found"] == expected_holes, "holes_found does not match harden.before.holes.labels")
    _want(data["certified"] == harden["certified"], "certified does not match harden.certified")
    _want(data["reason"] == harden["reason"], "reason does not match harden.reason")
    _want(data["patches_applied"] == harden["accepted"], "patches_applied does not match harden.accepted")
    _want(data["patches_rejected"] == harden["rejected"], "patches_rejected does not match harden.rejected")
    _want(data["unpatched"] == harden["unpatched"], "unpatched does not match harden.unpatched")
    _want(data["sandbox_runs"] == harden["sandbox_runs"], "sandbox_runs does not match harden.sandbox_runs")
    _want(data["notes"] == harden["notes"], "notes do not match harden.notes")
    _want(data["task"]["instance_id"] == harden["instance_id"], "task.instance_id does not match harden")
    _want(data["exposure_before"] == before["exposure"], "exposure_before does not match harden.before")
    after_gates = None if after is None else after["gates"]
    _want(
        data["gates"] == {"before": before["gates"], "after": after_gates},
        "gates do not match harden.before and harden.after",
    )


def validate_certificate(data: Mapping[str, Any]) -> None:
    """Raise ValueError unless data is a schema 1 certificate. Hand-written checks, no dependency.

    Checks the schema name and version, the required and unknown top-level keys, the type of every
    top-level key and of the harden block, the attacker mapping, the cost and timestamp, and that the
    top-level facts agree with the harden block.
    """
    _want(isinstance(data, Mapping), "certificate must be a JSON object")
    _keys(data, ("schema", "schema_version"))
    _want(data["schema"] == SCHEMA, f"wrong schema: expected {SCHEMA!r}, got {_show(data['schema'])}")
    version = data["schema_version"]
    _want(
        isinstance(version, int) and not isinstance(version, bool) and version == SCHEMA_VERSION,
        f"unknown schema_version {_show(version)}: this code reads version {SCHEMA_VERSION}",
    )
    _keys(data, TOP_KEYS)
    unknown = sorted(str(key) for key in data if key not in TOP_KEYS)
    _want(not unknown, f"unknown key in certificate: {unknown[0] if unknown else ''}")
    _check_task(data["task"])
    _want(
        data["image_digest"] is None or isinstance(data["image_digest"], str),
        "image_digest must be a string or null",
    )
    _check_attacker(data["attacker"])
    _want(_str_list(data["holes_found"]), "holes_found must be a list of strings")
    for key in ("patches_applied", "patches_rejected", "unpatched", "notes"):
        _want(_str_list(data[key]), f"{key} must be a list of strings")
    gates = data["gates"]
    _want(
        isinstance(gates, Mapping) and set(gates) == {"before", "after"}, "gates must hold before and after"
    )
    for side in ("before", "after"):
        _want(
            gates[side] is None or isinstance(gates[side], Mapping),
            f"gates.{side} must be an object or null",
        )
    _want(isinstance(data["certified"], bool), "certified must be a bool")
    _want(isinstance(data["reason"], str), "reason must be a string")
    _want(
        data["exposure_before"] is None or isinstance(data["exposure_before"], Mapping),
        "exposure_before must be an object or null",
    )
    _money(data["cost_usd"], "cost_usd")
    _want(_is_count(data["sandbox_runs"]), "sandbox_runs must be a count")
    _timestamp(data["timestamp"])
    _check_harden(data["harden"])
    _check_consistent(data)


def build_certificate(
    report: HardenReport,
    task: TaskSpec,
    *,
    image_digest: str | None,
    attacker: Mapping[str, Any],
    cost_usd: float,
    timestamp: str,
) -> dict[str, Any]:
    """The certificate for one hardened task, as a dict of JSON types. Raises ValueError on bad input.

    The task's gold and test patch texts are not stored: each becomes {sha256, chars}. The report's raw
    attack results (report.attacks) are never read. harden is report.to_dict() in full. timestamp must
    be ISO 8601 with a timezone, and cost_usd a finite number >= 0.
    """
    _want(
        report.instance_id == task.instance_id,
        f"report is for {_show(report.instance_id)} but the task is {_show(task.instance_id)}",
    )
    _want(image_digest is None or isinstance(image_digest, str), "image_digest must be a string or null")
    _want(isinstance(attacker, Mapping), "attacker must be a mapping")
    cost = _money(cost_usd, "cost_usd")
    _timestamp(timestamp)
    full = report.to_dict()
    before, after = full["before"], full["after"]
    cert = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "task": {
            "instance_id": task.instance_id,
            "repo": task.repo,
            "base_commit": task.base_commit,
            "image": task.image,
            "source": task.source,
            "gold_patch": {"sha256": _digest(task.gold_patch), "chars": len(task.gold_patch)},
            "test_patch": {"sha256": _digest(task.test_patch), "chars": len(task.test_patch)},
        },
        "image_digest": image_digest,
        "attacker": dict(attacker),
        "holes_found": [] if before["holes"] is None else sorted(set(before["holes"]["labels"])),
        "patches_applied": list(full["accepted"]),
        "patches_rejected": list(full["rejected"]),
        "unpatched": list(full["unpatched"]),
        "gates": {
            "before": copy.deepcopy(before["gates"]),
            "after": None if after is None else copy.deepcopy(after["gates"]),
        },
        "certified": full["certified"],
        "reason": full["reason"],
        "exposure_before": copy.deepcopy(before["exposure"]),
        "cost_usd": cost,
        "sandbox_runs": full["sandbox_runs"],
        "timestamp": timestamp,
        "notes": list(full["notes"]),
        "harden": full,
    }
    validate_certificate(cert)
    return cert


def certificate_filename(instance_id: str) -> str:
    """<instance_id> with each character outside [A-Za-z0-9._-] replaced by "_", plus ".json".

    Refuses an empty id, an id containing "..", and one that is only dots. Two ids that differ only in
    such characters (for example "a/b" and "a_b") get the same file name, so the later write replaces
    the earlier.
    """
    _want(isinstance(instance_id, str) and instance_id != "", "instance_id must be a non-empty string")
    _want(".." not in instance_id, f"refusing instance_id {_show(instance_id)}: it contains '..'")
    safe = UNSAFE_NAME_CHARS.sub("_", instance_id)
    _want(safe.strip(".") != "", f"refusing instance_id {_show(instance_id)}: nothing left after sanitising")
    return f"{safe}.json"


def write_certificate(cert: Mapping[str, Any], directory: Path) -> Path:
    """Validate cert and write it to <directory>/<safe instance_id>.json, atomically.

    The write goes to a temp file in the same directory, then os.replace. The JSON has sorted keys,
    two-space indent and a trailing newline. NaN and infinity are refused. Returns the path written.
    """
    validate_certificate(cert)
    name = certificate_filename(cert["task"]["instance_id"])
    folder = Path(directory)
    folder.mkdir(parents=True, exist_ok=True)
    try:
        text = json.dumps(cert, sort_keys=True, indent=2, allow_nan=False) + "\n"
    except (TypeError, ValueError) as exc:
        raise ValueError(f"certificate is not JSON: {exc}") from None
    target = folder / name
    fd, tmp_name = tempfile.mkstemp(dir=folder, prefix=f".{name}.", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o644)  # mkstemp creates 0600; a certificate is meant to be read
        os.replace(tmp, target)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    return target


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name} is not allowed in a certificate")


def load_certificate(path: Path) -> dict[str, Any]:
    """Read one certificate file, parse it and validate it. Errors name the file."""
    source = Path(path)
    try:
        data = json.loads(source.read_text(encoding="utf-8"), parse_constant=_reject_constant)
    except ValueError as exc:  # JSONDecodeError and the NaN refusal are both ValueError
        raise ValueError(f"{source}: not a valid certificate: {exc}") from None
    try:
        validate_certificate(data)
    except ValueError as exc:
        raise ValueError(f"{source}: {exc}") from None
    return data


def wilson_interval(k: int, n: int, z: float = Z_95) -> tuple[float, float]:
    """Wilson score interval for k successes in n trials, clipped to [0, 1]. n == 0 gives (0.0, 1.0)."""
    _want(_is_count(k) and _is_count(n), "k and n must be counts (integers >= 0)")
    _want(k <= n, f"need k <= n, got k={k}, n={n}")
    _want(_is_number(z) and math.isfinite(z) and z > 0, f"z must be a positive finite number, got {_show(z)}")
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    z2 = z * z
    denom = 1 + z2 / n
    centre = (p + z2 / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / denom
    low = 0.0 if k == 0 else max(0.0, centre - half)
    high = 1.0 if k == n else min(1.0, centre + half)
    return (low, high)


def _after_labels(cert: Mapping[str, Any]) -> list[str]:
    after = cert["harden"]["after"]
    if after is None or after["holes"] is None:
        return []
    return sorted(set(after["holes"]["labels"]))


def _inconclusive(cert: Mapping[str, Any]) -> bool:
    rounds = (cert["harden"]["before"], cert["harden"]["after"])
    return any(
        rnd is not None and (rnd["inconclusive"] is not None or rnd["error"] is not None) for rnd in rounds
    )


def _rate(count: int, n: int) -> dict[str, Any]:
    low, high = wilson_interval(count, n)
    return {
        "count": count,
        "n": n,
        "rate": None if n == 0 else count / n,
        "interval_95": [low, high],
        "method": "wilson",
    }


def score(certs: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Raw counts and rates over certificates. Each one is validated first; every number is computed here.

    hackable_before counts certs whose before round exploited (holes_found not empty). hackable_after
    counts certs whose after round has a hole label. n_after is the number of certs that have an after
    round, so rate_after's denominator is n_after and not n. A cert whose after round errored counts in
    n_after and not in hackable_after.
    """
    items = list(certs)
    for cert in items:
        validate_certificate(cert)
    n = len(items)
    hackable_before = sum(1 for cert in items if cert["holes_found"])
    n_after = sum(1 for cert in items if cert["harden"]["after"] is not None)
    hackable_after = sum(1 for cert in items if _after_labels(cert))
    certified = sum(1 for cert in items if cert["certified"])
    inconclusive = sum(1 for cert in items if _inconclusive(cert))
    before_counts = Counter(label for cert in items for label in set(cert["holes_found"]))
    after_counts = Counter(label for cert in items for label in _after_labels(cert))
    by_hole = {
        label: {"before": before_counts[label], "after": after_counts[label]}
        for label in sorted(set(before_counts) | set(after_counts))
    }
    by_source: dict[str, dict[str, int]] = {}
    for source in sorted({cert["task"]["source"] for cert in items}):
        group = [cert for cert in items if cert["task"]["source"] == source]
        by_source[source] = {
            "n": len(group),
            "hackable_before": sum(1 for cert in group if cert["holes_found"]),
            "certified": sum(1 for cert in group if cert["certified"]),
        }
    return {
        "schema_version": SCORE_SCHEMA_VERSION,
        "n": n,
        "hackable_before": hackable_before,
        "hackable_after": hackable_after,
        "n_after": n_after,
        "certified": certified,
        "inconclusive": inconclusive,
        "rate_before": _rate(hackable_before, n),
        "rate_after": _rate(hackable_after, n_after),
        "by_hole": by_hole,
        "by_source": by_source,
        "cost_usd_total": math.fsum(cert["cost_usd"] for cert in items),
    }


def score_directory(directory: Path) -> dict[str, Any]:
    """score() over every *.json certificate in directory, in name order. A bad file raises, naming it."""
    root = Path(directory)
    if not root.is_dir():
        raise FileNotFoundError(f"no certificate directory: {root}")
    paths = sorted(path for path in root.glob("*.json") if path.is_file())
    return score([load_certificate(path) for path in paths])
