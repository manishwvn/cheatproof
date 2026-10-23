"""Batch planning for T38: task order, chunking and the dry-run plan. No model, sandbox, network or ledger access.

The exposure scan needs a sandbox, so "expected to show future_git" can only come from earlier evidence: a certificate
in the output folder whose exposure_before.future_git is true. Such a task that is not certified is revisited first.
An explicit id list, --first and --rerun cover the rest. Everything here reads the task cache and certificates only.
The caps in the dry-run warning come from the environment (or the .env values the caller passes), never the ledger.
"""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

from cheatproof.budget import (
    DEFAULT_REAL_SPEND_CAP_USD,
    DEFAULT_SANDBOX_COST_CAP_USD,
    MAX_REAL_SPEND_CAP_USD,
)

if TYPE_CHECKING:
    from cheatproof.tasks import TaskSpec

MAX_CHUNK = 10  # the most tasks one batch call may run
DEFAULT_CHUNK = 3  # the first paid run goes in chunks of at most 3
# Ledger-measured averages (docs/autopilot/HANDOFF.md): a hardened task costs about this much in trial credit, and
# about this much in the Sandboxes counter (an estimate: Sandboxes are not billed). The collect-only preflight adds one
# more sandbox start per task; its share is an estimate too.
TOKEN_COST_PER_TASK = 0.056
SANDBOX_COST_PER_TASK = 0.09
PREFLIGHT_SANDBOX_COST = 0.03
SANDBOX_ESTIMATE_PER_TASK = SANDBOX_COST_PER_TASK + PREFLIGHT_SANDBOX_COST  # about 0.12


class PlanError(ValueError):
    """A usage error in the plan: an unknown id or a bad chunk size. Found before any paid call."""


class Ordered(NamedTuple):
    tasks: list[TaskSpec]
    rerun: frozenset[str]  # ids whose existing certificate is ignored (the task is attacked again)


@dataclass(frozen=True)
class Caps:
    sandbox: float  # SANDBOX_COST_CAP_USD
    real: float  # REAL_SPEND_CAP_USD
    trial: float | None  # TRIAL_CREDIT_CAP_USD, an extra stricter cap when set


def check_chunk_size(value: int | None) -> int:
    size = DEFAULT_CHUNK if value is None else value
    if not 1 <= size <= MAX_CHUNK:
        raise PlanError(f"--chunk-size must be 1..{MAX_CHUNK}, got {size}")
    return size


def _number(raw: object) -> float | None:
    try:
        value = float(str(raw).strip())
    except ValueError:
        return None
    return value if math.isfinite(value) and value > 0 else None


def read_caps(*sources: Mapping[str, str | None]) -> Caps:
    """The three caps from the first source that sets each name (the process environment first, then the .env values).
    An unset or invalid value gives the budget's default, a too-high real cap its ceiling. Reads no ledger."""

    def pick(name: str) -> float | None:
        for source in sources:
            if source.get(name):
                return _number(source[name])
        return None

    sandbox = pick("SANDBOX_COST_CAP_USD") or DEFAULT_SANDBOX_COST_CAP_USD
    real = min(pick("REAL_SPEND_CAP_USD") or DEFAULT_REAL_SPEND_CAP_USD, MAX_REAL_SPEND_CAP_USD)
    return Caps(sandbox=sandbox, real=real, trial=pick("TRIAL_CREDIT_CAP_USD"))


def future_git_revisits(out: Path, tasks: Sequence[TaskSpec]) -> list[str]:
    """Ids of tasks whose certificate in out shows future_git evidence and is not certified (worth another try)."""
    from cheatproof.certify import certificate_filename  # lazy: only a batch needs the file names

    found: list[str] = []
    for task in tasks:
        try:
            cert = json.loads((out / certificate_filename(task.instance_id)).read_text(encoding="utf-8"))
            exposure = cert.get("exposure_before")
            hit = isinstance(exposure, dict) and exposure.get("future_git") is True
            if hit and cert.get("certified") is not True:
                found.append(task.instance_id)
        except (OSError, ValueError, AttributeError):
            continue  # no readable certificate: no evidence
    return found


def order_tasks(
    tasks: Sequence[TaskSpec],
    *,
    lookup: Callable[[str], Sequence[TaskSpec]],
    out: Path,
    instance_ids: Sequence[str] | None = None,
    first: Sequence[str] | None = None,
    prefer_future_git: bool = False,
    rerun: bool = False,
) -> Ordered:
    """The run order. instance_ids replaces the selection (exactly those, in that order, from the cache). first ids go
    to the front, then future_git revisits (when asked), then the rest in selection order. A task not in the selection
    is looked up in the cache; PlanError when it is not there. rerun makes the first ids ignore their certificate; the
    future_git revisits always do (they are not certified, by construction)."""
    chosen = {t.instance_id: t for t in tasks}

    def get(iid: str) -> TaskSpec:
        if iid not in chosen:
            found = lookup(iid)
            if not found:
                raise PlanError(f"no cached task {iid!r}: run python -m cheatproof.tasks fetch first")
            chosen[iid] = found[0]
        return chosen[iid]

    base = [get(i) for i in dict.fromkeys(instance_ids)] if instance_ids else list(tasks)
    front_ids = list(dict.fromkeys(first or ()))
    revisit = future_git_revisits(out, base) if prefer_future_git else []
    front = [*front_ids, *(i for i in revisit if i not in front_ids)]
    ordered = [get(i) for i in front]
    front_set = set(front)
    ordered += [t for t in base if t.instance_id not in front_set]
    return Ordered(ordered, frozenset(revisit) | (frozenset(front_ids) if rerun else frozenset()))


def estimate(runs: int) -> tuple[float, float]:
    """(trial USD, Sandboxes USD estimate incl. the preflight start) for this many hardened tasks."""
    return runs * TOKEN_COST_PER_TASK, runs * SANDBOX_ESTIMATE_PER_TASK


def cap_warnings(trial: float, sandbox: float, caps: Caps) -> list[str]:
    """Warnings for a plan whose estimate alone passes a cap. The ledger is not read, so spend already counted is not
    in the comparison: the remaining headroom is smaller than the cap shown."""
    warnings = []
    if sandbox > caps.sandbox:
        warnings.append(
            f"WARNING: estimated Sandboxes ${sandbox:.2f} is above SANDBOX_COST_CAP_USD ${caps.sandbox:g}: "
            "the budget would halt this batch before it ends"
        )
    real = min(caps.real, caps.trial) if caps.trial is not None else caps.real
    if trial > real:
        name = (
            "TRIAL_CREDIT_CAP_USD"
            if caps.trial is not None and caps.trial < caps.real
            else "REAL_SPEND_CAP_USD"
        )
        warnings.append(
            f"WARNING: estimated trial spend ${trial:.3f} is above {name} ${real:g}: "
            "the budget would halt this batch before it ends"
        )
    return warnings


def render_plan(
    tasks: Sequence[TaskSpec],
    certified: Collection[str],
    rerun: Collection[str],
    chunk_size: int,
    *,
    caps: Caps | None = None,
    skip: Collection[str] = (),
) -> list[str]:
    """The dry-run text: ids in order with their chunk, boundaries, the estimated cost and cap warnings. No calls were
    made. skip are ids an earlier chunk found env-broken: not retried."""
    lines: list[str] = []
    runs = 0
    for task in tasks:
        iid = task.instance_id
        if iid in skip:
            lines.append(f"  -      {iid}: env-broken in an earlier chunk, not retried")
            continue
        if iid in certified and iid not in rerun:
            lines.append(f"  -      {iid}: already has a certificate, skipped")
            continue
        if runs and runs % chunk_size == 0:
            lines.append(
                f"  --- chunk boundary after {runs} tasks: check the console, then run the same command again ---"
            )
        note = "run (existing certificate is replaced, a copy is kept)" if iid in certified else "run"
        lines.append(f"  chunk {runs // chunk_size + 1}  {iid}: {note}")
        runs += 1
    trial, sandbox = estimate(runs)
    head = (
        f"batch plan (dry run, no calls made): {len(tasks)} selected, {runs} to run, chunk size {chunk_size}"
    )
    tail = [
        (
            f"estimated cost: trial ${trial:.3f} (${TOKEN_COST_PER_TASK} per task), Sandboxes ${sandbox:.2f} "
            f"(about ${SANDBOX_ESTIMATE_PER_TASK:.2f} per task: ${SANDBOX_COST_PER_TASK} measured + the "
            "collect-only preflight start, an estimate; Sandboxes are not billed, the counter is a guard)"
        )
    ]
    if caps is not None:
        trial_cap = "" if caps.trial is None else f", TRIAL_CREDIT_CAP_USD ${caps.trial:g}"
        tail.append(
            f"caps (ledger not read, so spend already counted is not subtracted): SANDBOX_COST_CAP_USD "
            f"${caps.sandbox:g}, REAL_SPEND_CAP_USD ${caps.real:g}{trial_cap}"
        )
        tail += cap_warnings(trial, sandbox, caps)
    return [head, *lines, *tail]
