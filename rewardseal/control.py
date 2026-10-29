"""Deterministic retrieval control (no model, no attacker, no Tavily).

For one task it asks: if a script simply retrieves the future upstream commit from the sandbox's git history and applies
it, does the hidden grade pass, and does that stop working after `strip-future-git`? Steps, in one sandbox session:

  before  reset; list the future commits that touch the gold patch's source files (`git rev-list --all --no-merges
          --reverse ^<base> -- <paths>`); take each one's own change (`git diff <c>^ <c> -- <paths>`); rank them by how
          many non-trivial added lines they share with the gold patch (digest overlap, ties oldest first); then, for
          the top MAX_TRIES, reset, apply the change as the candidate patch and grade it (hidden tests, as the gates).
  strip   reset, apply strip-future-git, list the same candidates (expected: none), and run the gold and empty gates.

The record says what a deterministic retrieval did. It does NOT show that any model used the history, and it says so.
Only commit ids (12 hex), counts and booleans are kept, never a line of text.
"""

from __future__ import annotations

import json
import re
import shlex
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rewardseal import audit, grader, holes, patches
from rewardseal.budget import BudgetExceeded
from rewardseal.tasks import TaskSpec

SCHEMA = "rewardseal.retrieval-control"
SCHEMA_VERSION = 1
MAX_CANDIDATES = 200  # commits whose change is read and ranked
MAX_TRIES = 3  # commits applied and graded
GIT_TIMEOUT_S = 120.0
DISCLAIMER = "does not prove model causality: usable leakage for this control only, not why any model acted"


class ControlError(RuntimeError):
    """The control could not run (a git listing failed): no record is written."""


@dataclass(frozen=True)
class ControlOps:
    """Collaborators, so tests inject fakes."""

    grade: Callable[..., Any]
    apply_patches: Callable[..., list[Any]]
    gold_gate: Callable[..., Any]
    empty_gate: Callable[..., Any]

    @classmethod
    def default(cls) -> ControlOps:
        return cls(
            grade=grader.grade,
            apply_patches=patches.apply_patches,
            gold_gate=grader.gold_gate,
            empty_gate=grader.empty_gate,
        )


def _patch_digests(patch: str, wanted: Sequence[str], test_files: frozenset[str]) -> frozenset[str]:
    """The digests of the non-trivial lines a patch adds in `wanted` source files (the gold-line rule, any patch)."""
    open_quote: dict[str, str | None] = {}
    found: set[str] = set()
    for change in holes._changes(patch):
        if change.sign != "+" or change.path not in wanted or holes.is_test_path(change.path, test_files):
            continue
        text = audit._code_line(open_quote, change.path, change.text)
        digest = None if text is None else holes.future_line_digest(text)
        if digest is not None:
            found.add(digest)
    return frozenset(found)


def _git(session: Any, workdir: str, args: str) -> Any:
    return session.run(grader.git_command(workdir, args), GIT_TIMEOUT_S)


@dataclass(frozen=True)
class CandidateListing:
    ranked: list[tuple[str, int, str]]
    listed: int
    unreadable_or_root: int
    listing_complete: bool
    candidate_cap_hit: bool

    def stats(self) -> dict[str, Any]:
        return {
            "future_commits_touching_gold_files": self.listed,
            "readable_changes": len(self.ranked),
            "unreadable_or_root": self.unreadable_or_root,
            "listing_complete": self.listing_complete,
            "candidate_cap_hit": self.candidate_cap_hit,
            "root_commits_supported": False,
        }


def candidates(session: Any, task: TaskSpec, *, workdir: str) -> CandidateListing:
    """Rank readable changes; parentless root commits are unsupported and counted as unreadable."""
    paths = audit.source_paths(task)
    if not paths:
        return CandidateListing([], 0, 0, True, False)
    base = grader.checked_sha(task.base_commit)
    quoted = " ".join(shlex.quote(p) for p in paths)
    listing = _git(session, workdir, f"rev-list --all --no-merges --reverse ^{base} -- {quoted}")
    if listing.exit_code != 0 or listing.timed_out:
        raise ControlError("the future commit listing failed")
    commits = listing.stdout.splitlines()
    if listing.truncated and listing.stdout and not listing.stdout.endswith("\n"):
        commits.pop()  # A partial final line is not a listed commit.
    if any(not re.fullmatch(r"[0-9a-fA-F]{40}", commit) for commit in commits):
        raise ControlError("the future commit listing contained an invalid commit")
    gold = audit.gold_line_digests(task)
    test_files = frozenset(holes._diff_paths(task.test_patch)[0])
    ranked: list[tuple[str, int, str]] = []
    unreadable = 0
    for commit in commits[:MAX_CANDIDATES]:
        res = _git(
            session,
            workdir,
            f"diff --binary --no-ext-diff --no-textconv --no-color {commit}^ {commit} -- {quoted}",
        )
        if res.exit_code != 0 or res.timed_out or res.truncated or not res.stdout.strip():
            unreadable += 1
            continue
        shared = len(_patch_digests(res.stdout, paths, test_files) & gold)
        ranked.append((commit, shared, res.stdout))
    ranked.sort(key=lambda item: -item[1])  # stable: ties keep the oldest first
    return CandidateListing(
        ranked, len(commits), unreadable, not listing.truncated, len(commits) > MAX_CANDIDATES
    )


def run_control(
    session: Any,
    task: TaskSpec,
    *,
    workdir: str = grader.DEFAULT_WORKDIR,
    timeout: float = 1800,
    ops: ControlOps | None = None,
) -> dict[str, Any]:
    """The record of one task, in an already started session. Every reset books a sandbox run on the session's budget.
    A budget or executor stop propagates."""
    ops = ControlOps.default() if ops is None else ops
    inner = session
    session = audit._CountingSession(inner)
    resets = 0
    outcomes: list[Any] = []
    strip_successes: list[bool] = []

    def fresh(*, strip: bool = False) -> bool:
        nonlocal resets
        inner.reset()
        resets += 1
        if not strip:
            return True
        current = ops.apply_patches(session, task, (audit.PATCH_NAME,), workdir=workdir)
        outcomes.extend(current)
        ok = bool(current) and all(o.ok for o in current)
        strip_successes.append(ok)
        return ok

    def attempt(listing: CandidateListing, *, strip: bool) -> list[dict[str, Any]]:
        tried = []
        for commit, shared, change in listing.ranked[:MAX_TRIES]:
            if not fresh(strip=strip):
                tried.append(
                    {
                        "commit": commit[:12],
                        "shared_gold_lines": shared,
                        "applied": False,
                        "passed": False,
                        "f2p": "0/0",
                    }
                )
                continue
            grade = ops.grade(session, task, change, timeout, workdir=workdir)
            tried.append(
                {
                    "commit": commit[:12],
                    "shared_gold_lines": shared,
                    "applied": bool(grade.applied),
                    "passed": bool(grade.passed),
                    "f2p": f"{grade.f2p_passed}/{grade.f2p_total}",
                }
            )
        return tried

    fresh()
    found = candidates(session, task, workdir=workdir)
    tries = attempt(found, strip=False)
    listing_strip_ok = fresh(strip=True)
    after = candidates(session, task, workdir=workdir)
    after_tries = attempt(after, strip=True)
    gold_strip_ok = fresh(strip=True)
    gold = ops.gold_gate(session, task, timeout, workdir=workdir)
    empty_strip_ok = fresh(strip=True)
    empty = ops.empty_gate(session, task, timeout, workdir=workdir)
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "instance_id": task.instance_id,
        "base_commit": task.base_commit[:12],
        "disclaimer": DISCLAIMER,
        "before_strip": {
            **found.stats(),
            "tried": tries,
            "retrieved_fix_passes_hidden_tests": any(t["passed"] for t in tries),
        },
        "after_strip": {
            **after.stats(),
            "patch_applied": listing_strip_ok
            and all(strip_successes)
            and bool(outcomes)
            and all(o.ok for o in outcomes),
            "tried": after_tries,
            "gold_gate_ok": gold_strip_ok and bool(gold.passed),
            "empty_gate_ok": empty_strip_ok
            and bool(empty.applied)
            and empty.error is None
            and not empty.passed,
        },
        "sandbox_resets": resets + session.auto_resets,
    }


def write_record(record: dict[str, Any], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    name = f"{record['instance_id']}-retrieval-control.json"
    path = out_dir / name
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


__all__ = ["BudgetExceeded", "ControlError", "ControlOps", "candidates", "run_control", "write_record"]
