"""Batch planning for T38: task order, chunking and the dry-run plan. No model, sandbox, network or ledger access.

The exposure scan needs a sandbox, so "expected to show future_git" can only come from earlier evidence: a certificate
in the output folder whose exposure_before.future_git is true. Such a task that is not certified is revisited first.
An explicit id list, --first and --rerun cover the rest. Everything here reads the task cache and certificates only.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Collection, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from cheatproof.tasks import TaskSpec

MAX_CHUNK = 10  # the most tasks one batch call may run; the default
# Ledger-measured averages (docs/autopilot/HANDOFF.md): a hardened task costs about this much, trial and Sandboxes.
TOKEN_COST_PER_TASK = 0.056
SANDBOX_COST_PER_TASK = 0.09


class PlanError(ValueError):
    """A usage error in the plan: an unknown id or a bad chunk size. Found before any paid call."""


class Ordered(NamedTuple):
    tasks: list[TaskSpec]
    rerun: frozenset[str]  # ids whose existing certificate is ignored (the task is attacked again)


def check_chunk_size(value: int | None) -> int:
    size = MAX_CHUNK if value is None else value
    if not 1 <= size <= MAX_CHUNK:
        raise PlanError(f"--chunk-size must be 1..{MAX_CHUNK}, got {size}")
    return size


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
    """(trial USD, Sandboxes USD estimate) for this many hardened tasks, from the ledger-measured averages."""
    return runs * TOKEN_COST_PER_TASK, runs * SANDBOX_COST_PER_TASK


def render_plan(
    tasks: Sequence[TaskSpec], certified: Collection[str], rerun: Collection[str], chunk_size: int
) -> list[str]:
    """The dry-run text: ids in order with their chunk, boundaries, and the estimated cost. No calls were made."""
    lines: list[str] = []
    runs = 0
    for task in tasks:
        iid = task.instance_id
        if iid in certified and iid not in rerun:
            lines.append(f"  -      {iid}: already has a certificate, skipped")
            continue
        if runs and runs % chunk_size == 0:
            lines.append(
                f"  --- chunk boundary after {runs} tasks: check the console, then run the next chunk ---"
            )
        note = "run (existing certificate is replaced)" if iid in certified else "run"
        lines.append(f"  chunk {runs // chunk_size + 1}  {iid}: {note}")
        runs += 1
    trial, sandbox = estimate(runs)
    head = (
        f"batch plan (dry run, no calls made): {len(tasks)} selected, {runs} to run, chunk size {chunk_size}"
    )
    tail = (
        f"estimated cost: trial ${trial:.3f} (${TOKEN_COST_PER_TASK} per task), Sandboxes ${sandbox:.2f} "
        f"(${SANDBOX_COST_PER_TASK} per task, an estimate-only counter); the collect-only preflight adds a "
        "sandbox start per task"
    )
    return [head, *lines, tail]
