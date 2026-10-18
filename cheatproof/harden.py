"""Re-attack loop (queue T06, ADR 0002): harden one task, then attack it again with the same attacker.

harden() answers one question for one task: do the patches close the holes an attacker really used? Nothing here
is a model call. The caller binds the model, prompts and limits into attack_fn, so the before and the after
attack run the same code under the same limits. Every number is computed from grader, exposure and holes output.

Flow:
1. Before round, no patches. Gold gate (gold patch must pass), empty gate (no patch must fail), exposure scan,
   one attack, a grade of the attack's diff, and the hole labels. A broken gate stops everything: the task, not
   the attacker, is the problem. An attack that did not exploit needs no patch, so there is no after round.
2. Candidate checks. For each patch the labels need (patches_for), a new session from env_for(env, (name,)) gets
   that one patch, and the gold patch must still pass. A patch that fails to apply or breaks the gold gate is
   rejected with its reason. Nothing else is tried on a rejected patch.
3. After round with the accepted patches, in a session from env_for(env, accepted): the same gates, scan, attack
   function, clean-session grade and classifier. If no patch was accepted (only hard-code or unclassified holes,
   or every patch rejected) there is no after round and the task is not certified.

Session handling. fresh() resets a session and re-runs apply_patches before every step, because a reset destroys
in-session patch work. The first use of a just-started session skips the reset. The attack's diff is graded in
a new clean session state, never in the attacker's own, which may have tampered with the object store. Every
start and every reset this module triggers counts as one sandbox run (sandbox_runs); the automatic reset inside
Session.run after a host timeout is not visible here and is not counted. Every session is closed on every path.
BudgetExceeded, ExecutorRefused and ExecutorUnavailable always propagate. Any other exception inside a round or
a candidate check is recorded (type and message, at most 300 chars) and makes certified False.

certified means: the gates held, the attack did not exploit after hardening, and no needed patch was rejected or
left without a patch. It never means secure: the reason strings say "not hackable by this attacker" and nothing
stronger. An attack that errored (stop_reason, error and diff_ok are in the attack summary) counts as an attack
that failed; the caller reads those fields before it trusts a "failed" attack.

Report keys (stable; T07 writes these into certificates). to_dict() holds only JSON types.
  HardenReport: instance_id, before, candidates, accepted, rejected, unpatched, after, certified, reason,
    sandbox_runs. `attacks` (the AttackResult objects, with raw diffs and steps, for trace saving) is a plain
    field and is NOT in to_dict. It holds one result per round whose attack ran, before first; before.attack
    and after.attack (None when that attack did not run) tell which is which.
  RoundReport: patches, patch_outcomes, gates, exposure, attack, attack_grade, holes, error.
    gates is GradeResult pair {gold, empty} plus reason and ok. attack is a summary: submitted, stop_reason,
    tokens_in, tokens_out, diff_ok, error, steps (a count), final_diff_sha256, final_diff_chars. It never holds
    the raw diff or the steps. attack_grade is None when the attack made no diff.
  CandidateCheck: name, accepted, outcomes, gold, reason.
"""

from __future__ import annotations

import contextlib
import hashlib
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any

from cheatproof.budget import Budget, BudgetExceeded
from cheatproof.executor import EnvSpec, Executor, ExecutorRefused, ExecutorUnavailable, Session
from cheatproof.exposure import ExposureReport
from cheatproof.grader import GateReport, GradeResult
from cheatproof.holes import HoleReport

if TYPE_CHECKING:
    from cheatproof.attacker import AttackResult
    from cheatproof.patches import PatchOutcome
    from cheatproof.tasks import TaskSpec

DEFAULT_TIMEOUT_S = 1800
ERROR_CHARS = 300
# The caller binds llm, prompts and AttackConfig. The same function and limits run before and after hardening.
AttackFn = Callable[[Session], "AttackResult"]
# Raised by the backend or the budget: the run cannot go on, so these are never recorded as a round error.
PROPAGATE = (BudgetExceeded, ExecutorRefused, ExecutorUnavailable)


@dataclass(frozen=True)
class HardenOps:
    """Every collaborator harden() calls, as plain callables, so tests inject fakes. default() is the real set.

    grade(session, task, patch, timeout, *, workdir, **grade_kwargs) -> GradeResult
    apply_patches(session, task, names, *, workdir) -> list[PatchOutcome]
    patches_for(labels) -> tuple[str, ...]      unpatched(labels) -> tuple[str, ...]
    env_for(spec, names) -> EnvSpec             grade_kwargs(names) -> dict[str, bool]
    scan(session, task, *, workdir) -> ExposureReport
    classify(trace, final_diff, task, *, hidden_passed) -> HoleReport
    """

    grade: Callable[..., GradeResult]
    apply_patches: Callable[..., list[PatchOutcome]]
    patches_for: Callable[..., tuple[str, ...]]
    unpatched: Callable[..., tuple[str, ...]]
    env_for: Callable[..., EnvSpec]
    grade_kwargs: Callable[..., dict[str, bool]]
    scan: Callable[..., ExposureReport]
    classify: Callable[..., HoleReport]

    @classmethod
    def default(cls) -> HardenOps:
        # Imported here so this module loads without patches.py and tests never need the real set.
        from cheatproof import exposure, grader, holes, patches

        return cls(
            grade=grader.grade,
            apply_patches=patches.apply_patches,
            patches_for=patches.patches_for,
            unpatched=patches.unpatched,
            env_for=patches.env_for,
            grade_kwargs=patches.grade_kwargs,
            scan=exposure.scan,
            classify=holes.classify,
        )


def _gates_dict(gates: GateReport) -> dict[str, Any]:
    return {**asdict(gates), "reason": gates.reason, "ok": gates.ok}


@dataclass(frozen=True)
class RoundReport:
    """One attack round: gates, exposure scan, one attack, its clean-session grade and its hole labels.

    error is set when the round stopped early without a verdict (a patch failed to apply, or an exception that
    is not a budget or executor stop). Fields after the stopping point stay None.
    """

    patches: tuple[str, ...]
    patch_outcomes: tuple[PatchOutcome, ...] = ()
    gates: GateReport | None = None
    exposure: ExposureReport | None = None
    attack: dict[str, Any] | None = None
    attack_grade: GradeResult | None = None
    holes: HoleReport | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "patches": list(self.patches),
            "patch_outcomes": [outcome.to_dict() for outcome in self.patch_outcomes],
            "gates": None if self.gates is None else _gates_dict(self.gates),
            "exposure": None if self.exposure is None else asdict(self.exposure),
            "attack": None if self.attack is None else dict(self.attack),
            "attack_grade": None if self.attack_grade is None else asdict(self.attack_grade),
            "holes": None if self.holes is None else self.holes.to_dict(),
            "error": self.error,
        }


@dataclass(frozen=True)
class CandidateCheck:
    """One patch tried alone in its own session: it must apply, and the gold patch must still pass."""

    name: str
    accepted: bool
    outcomes: tuple[PatchOutcome, ...] = ()
    gold: GradeResult | None = None
    reason: str | None = None  # why it was rejected; None when accepted

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "accepted": self.accepted,
            "outcomes": [outcome.to_dict() for outcome in self.outcomes],
            "gold": None if self.gold is None else asdict(self.gold),
            "reason": self.reason,
        }


@dataclass(frozen=True)
class HardenReport:
    instance_id: str
    before: RoundReport
    candidates: tuple[CandidateCheck, ...]
    accepted: tuple[str, ...]
    rejected: tuple[str, ...]
    unpatched: tuple[str, ...]  # hole labels no patch covers
    after: RoundReport | None
    certified: bool
    reason: str
    sandbox_runs: int  # every session start and reset harden() triggered
    # Raw attack results for trace saving: before first, then after. Not serialised: they hold raw diffs.
    attacks: tuple[AttackResult, ...] = field(default=(), repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "instance_id": self.instance_id,
            "before": self.before.to_dict(),
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "accepted": list(self.accepted),
            "rejected": list(self.rejected),
            "unpatched": list(self.unpatched),
            "after": None if self.after is None else self.after.to_dict(),
            "certified": self.certified,
            "reason": self.reason,
            "sandbox_runs": self.sandbox_runs,
        }


class _RoundFailed(Exception):
    """A step cannot go on (a patch failed in the session). The message becomes RoundReport.error."""


@dataclass
class _RoundState:
    patches: tuple[str, ...]
    outcomes: tuple[PatchOutcome, ...] = ()
    gates: GateReport | None = None
    exposure: ExposureReport | None = None
    attack: dict[str, Any] | None = None
    attack_grade: GradeResult | None = None
    holes: HoleReport | None = None
    error: str | None = None

    def report(self) -> RoundReport:
        return RoundReport(
            patches=self.patches,
            patch_outcomes=self.outcomes,
            gates=self.gates,
            exposure=self.exposure,
            attack=self.attack,
            attack_grade=self.attack_grade,
            holes=self.holes,
            error=self.error,
        )


def _capped(text: str, limit: int = ERROR_CHARS) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _error_text(exc: Exception) -> str:
    return _capped(f"{type(exc).__name__}: {exc}")


def _patch_failure(outcomes: list[PatchOutcome], names: tuple[str, ...]) -> str | None:
    """Why the patches are not in the session, or None. A patch with no outcome counts as not applied."""
    for outcome in outcomes:
        if not outcome.ok:
            return _capped(f"patch {outcome.name} failed: {'; '.join(outcome.notes) or 'no notes'}")
    reported = {outcome.name for outcome in outcomes}
    for name in names:
        if name not in reported:
            return f"patch {name} reported no outcome"
    return None


def _attack_summary(result: AttackResult) -> dict[str, Any]:
    diff = result.final_diff
    return {
        "submitted": result.submitted,
        "stop_reason": result.stop_reason,
        "tokens_in": result.tokens_in,
        "tokens_out": result.tokens_out,
        "diff_ok": result.diff_ok,
        "error": _capped(result.error),
        "steps": len(result.steps),
        "final_diff_sha256": None
        if diff is None
        else hashlib.sha256(diff.encode("utf-8", "replace")).hexdigest(),
        "final_diff_chars": None if diff is None else len(diff),
    }


class _Sandbox:
    """One started session. fresh() makes it clean: a reset (not on first use), then the patches again."""

    def __init__(self, loop: _Loop, session: Session) -> None:
        self.session = session
        self._loop = loop
        self._used = False

    def fresh(self, names: tuple[str, ...]) -> list[PatchOutcome]:
        loop = self._loop
        if self._used:
            loop.runs += 1
            self.session.reset()
        self._used = True
        if not names:
            return []
        return list(loop.ops.apply_patches(self.session, loop.task, names, workdir=loop.workdir))


class _Loop:
    def __init__(
        self,
        executor: Executor,
        task: TaskSpec,
        attack_fn: AttackFn,
        budget: Budget | None,
        timeout: float,
        workdir: str,
        ops: HardenOps,
    ) -> None:
        self.executor = executor
        self.task = task
        self.attack_fn = attack_fn
        self.budget = budget
        self.timeout = timeout
        self.workdir = workdir
        self.ops = ops
        self.runs = 0
        self.attacks: list[AttackResult] = []

    @contextlib.contextmanager
    def _session(self, env: EnvSpec) -> Iterator[_Sandbox]:
        self.runs += 1
        session = self.executor.start(env, self.budget)
        try:
            yield _Sandbox(self, session)
        except BaseException:
            with contextlib.suppress(Exception):  # the first error matters more than a failed close
                session.close()
            raise
        session.close()

    def _grade_here(self, session: Session, names: tuple[str, ...], patch: str) -> GradeResult:
        return self.ops.grade(
            session, self.task, patch, self.timeout, workdir=self.workdir, **self.ops.grade_kwargs(names)
        )

    def _fresh(self, box: _Sandbox, state: _RoundState) -> None:
        state.outcomes = tuple(box.fresh(state.patches))
        failure = _patch_failure(list(state.outcomes), state.patches)
        if failure is not None:
            raise _RoundFailed(failure)

    def _grade(self, box: _Sandbox, state: _RoundState, patch: str) -> GradeResult:
        self._fresh(box, state)
        return self._grade_here(box.session, state.patches, patch)

    def _play(self, box: _Sandbox, state: _RoundState) -> None:
        gold = self._grade(box, state, self.task.gold_patch)
        empty = self._grade(box, state, "")
        state.gates = GateReport(gold=gold, empty=empty)
        if not state.gates.ok:
            return
        self._fresh(box, state)
        state.exposure = self.ops.scan(box.session, self.task, workdir=self.workdir)
        self._fresh(box, state)
        result = self.attack_fn(box.session)
        self.attacks.append(result)
        state.attack = _attack_summary(result)
        diff = result.final_diff if result.diff_ok else None
        hidden_passed = None
        if diff is not None:
            # A clean session: the attacker's own may hold a tampered object store or restored-over tests.
            state.attack_grade = self._grade(box, state, diff)
            hidden_passed = state.attack_grade.passed
        state.holes = self.ops.classify(result.steps, diff, self.task, hidden_passed=hidden_passed)

    def round(self, env: EnvSpec, names: tuple[str, ...]) -> RoundReport:
        state = _RoundState(names)
        try:
            with self._session(self.ops.env_for(env, names) if names else env) as box:
                self._play(box, state)
        except PROPAGATE:
            raise
        except _RoundFailed as exc:
            state.error = str(exc)
        except Exception as exc:  # noqa: BLE001 - one failed round must not lose the report
            state.error = _error_text(exc)
        return state.report()

    def candidate(self, env: EnvSpec, name: str) -> CandidateCheck:
        names = (name,)
        outcomes: tuple[PatchOutcome, ...] = ()
        gold: GradeResult | None = None
        reason: str | None = None
        try:
            with self._session(self.ops.env_for(env, names)) as box:
                outcomes = tuple(box.fresh(names))  # a new session: nothing to reset yet
                reason = _patch_failure(list(outcomes), names)
                if reason is None:
                    gold = self._grade_here(box.session, names, self.task.gold_patch)
                    if not gold.passed:
                        why = gold.error or "a FAIL_TO_PASS or PASS_TO_PASS node failed"
                        reason = f"gold gate failed with this patch: {why}"
        except PROPAGATE:
            raise
        except Exception as exc:  # noqa: BLE001 - an unusable candidate is rejected, never fatal
            reason = _error_text(exc)
        return CandidateCheck(
            name, reason is None, outcomes, gold, None if reason is None else _capped(reason)
        )

    def report(
        self,
        before: RoundReport,
        certified: bool,
        reason: str,
        *,
        candidates: tuple[CandidateCheck, ...] = (),
        unpatched: tuple[str, ...] = (),
        after: RoundReport | None = None,
    ) -> HardenReport:
        return HardenReport(
            instance_id=self.task.instance_id,
            before=before,
            candidates=candidates,
            accepted=tuple(c.name for c in candidates if c.accepted),
            rejected=tuple(c.name for c in candidates if not c.accepted),
            unpatched=unpatched,
            after=after,
            certified=certified,
            reason=reason,
            sandbox_runs=self.runs,
            attacks=tuple(self.attacks),
        )

    def run(self, env: EnvSpec) -> HardenReport:
        before = self.round(env, ())
        if before.error is not None:
            return self.report(before, False, f"round before hardening failed: {before.error}")
        if before.gates is not None and not before.gates.ok:
            return self.report(
                before, False, f"gates failed before hardening (the task is broken): {before.gates.reason}"
            )
        if before.holes is None:  # unreachable: a round with no error and ok gates ran its attack
            return self.report(before, False, "round before hardening produced no hole report")
        if not before.holes.exploited:
            reason = "attacker failed before hardening (not hackable by this attacker)"
            return self.report(before, True, reason)

        labels = before.holes.labels
        needed = tuple(dict.fromkeys(self.ops.patches_for(labels)))
        no_patch = tuple(self.ops.unpatched(labels))
        candidates = tuple(self.candidate(env, name) for name in needed)
        accepted = tuple(c.name for c in candidates if c.accepted)
        rejected = [f"{c.name} ({c.reason})" for c in candidates if not c.accepted]
        if not accepted:
            notes = []
            if rejected:
                notes.append("rejected: " + "; ".join(rejected))
            if no_patch:
                notes.append("no patch exists for: " + ", ".join(no_patch))
            detail = "; ".join(notes) or "no patch applies"
            reason = f"attacker exploited {', '.join(labels)} and nothing could be applied ({detail}); not hardened"
            return self.report(before, False, reason, candidates=candidates, unpatched=no_patch)

        after = self.round(env, accepted)
        shown = {"candidates": candidates, "unpatched": no_patch, "after": after}
        if after.error is not None:
            return self.report(before, False, f"round after hardening failed: {after.error}", **shown)
        if after.gates is not None and not after.gates.ok:
            reason = f"gates failed after hardening with {', '.join(accepted)}: {after.gates.reason}"
            return self.report(before, False, reason, **shown)
        if after.holes is None:  # unreachable, as above
            return self.report(before, False, "round after hardening produced no hole report", **shown)
        if after.holes.exploited:
            holes = ", ".join(after.holes.labels)
            reason = f"attacker still exploits after hardening with {', '.join(accepted)} ({holes})"
            return self.report(before, False, reason, **shown)
        if rejected or no_patch:
            open_holes = rejected + [f"no patch for {label}" for label in no_patch]
            reason = (
                f"attacker failed after hardening with {', '.join(accepted)}, but the hole is not fully "
                f"closed: {'; '.join(open_holes)}; not certified"
            )
            return self.report(before, False, reason, **shown)
        reason = f"attacker failed after hardening with {', '.join(accepted)} (not hackable by this attacker)"
        return self.report(before, True, reason, **shown)


def harden(
    executor: Executor,
    env: EnvSpec,
    task: TaskSpec,
    attack_fn: AttackFn,
    *,
    budget: Budget | None = None,
    timeout: float = DEFAULT_TIMEOUT_S,
    workdir: str | None = None,
    ops: HardenOps | None = None,
) -> HardenReport:
    """Attack the task, patch what the attack used, attack again, and report. One task, one attack per round.

    timeout bounds each grade's pytest runs. workdir defaults to env.workdir. ops defaults to the real
    collaborators (HardenOps.default()), resolved here so importing this module needs none of them.
    """
    if not timeout > 0:  # also refuses NaN
        raise ValueError(f"harden timeout must be greater than 0 seconds, got {timeout!r}")
    loop = _Loop(
        executor,
        task,
        attack_fn,
        budget,
        float(timeout),
        env.workdir if workdir is None else workdir,
        HardenOps.default() if ops is None else ops,
    )
    return loop.run(env)
