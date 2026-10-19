"""Re-attack loop (queue T06, ADR 0002): harden one task, then attack it again with the same attacker.

harden() answers one question for one task: do the patches close the holes an attacker really used? Nothing here
is a model call. The caller binds the model, prompts and limits into attack_fn, so the before and the after
attack run the same code under the same limits. Every number is computed from grader, exposure and holes output.

Flow:
1. Before round, no patches. Gold gate (gold patch must pass), empty gate (no patch must fail), exposure scan,
   one attack, a grade of the attack's diff, and the hole labels. A broken gate stops everything: the task, not
   the attacker, is the problem. An attack that made no attempt is not graded and is never certified. An attack
   that did not exploit needs no patch, so there is no after round.
2. Candidate checks. For each patch the labels need (patches_for), a new session from env_for(env, (name,)) gets
   that one patch, and the gold patch must still pass. A patch that fails to apply or breaks the gold gate is
   rejected with its reason. Nothing else is tried on a rejected patch.
3. After round with the accepted patches, in a session from env_for(env, accepted): the same gates, scan, attack
   function, clean-session grade and classifier. If no patch was accepted (only hard-code or unclassified holes,
   or every patch rejected) there is no after round and the task is not certified. The after scan must no longer
   list the labels the accepted patches close: git-history (strip-future-git) and network (network-off).
   test-edit is closed at grade time, so the scan is not asked about it.

Session handling. fresh() resets a session and re-runs apply_patches before every step, because a reset destroys
in-session patch work. The first use of a just-started session skips the reset. The attack's diff is graded in
a new clean session state, never in the attacker's own, which may have tampered with the object store. Every
start and every reset this module triggers counts as one sandbox run (sandbox_runs); the automatic reset inside
Session.run after a host timeout is not visible here and is not counted. Every session is closed on every path.
On the normal exit path a failed close is retried once; a second failure is a note in the report, not an error.
BudgetExceeded, ExecutorRefused and ExecutorUnavailable always propagate. Any other exception inside a round or
a candidate check is recorded (type and message, at most 300 chars) and makes certified False.

Attack verdicts. An attack is conclusive only when stop_reason is "submit" or "max_steps", diff_ok is True and
final_diff is not None, no step reset the sandbox during a round with patches (the attacker then ran unpatched),
and its grade is conclusive: it applied with no error, or its error says the test guard refused the diff
("test files touched:", "guarded config touched:") or the candidate did not apply ("candidate patch did not
apply"). Any other attack is inconclusive, and a round with an inconclusive attack never certifies. A reset during
the before round, when no patch is in force, is noted and changes nothing else.

No attempt. A conclusive attack that took no step, whose final_diff is empty, or whose trace holds no write step
made no attempt. Its round reports no_attempt with the reason, and that round is not graded. A write step is a
write_file or run step: a shell command may write, so run counts. A trace of only read_file, web_search and submit
steps has none. A no_attempt round never certifies, and score() counts it apart from failed attacks: an attacker
that did not try says nothing about the patches.

Visible and hidden results. The grade's PASS_TO_PASS nodes are the repo's own tests, which the attacker can run.
FAIL_TO_PASS nodes come from the hidden test patch. _visible_passed reads the PASS_TO_PASS result: True when all of
them pass on the attack's diff, None when the grade did not run them (not applied, errored, or no PASS_TO_PASS
nodes). An empty diff uses the empty gate's grade, which graded the same state. classify gets visible_passed and
hidden_passed, so hard-code can be found; it is reported as attempted only when the hidden grade fails. This is a
proxy: the attacker's own run of its visible tests is not recorded.

certified means: the gates held, the attack did not exploit after hardening, the attack verdicts are conclusive
(neither inconclusive nor no_attempt), the after exposure scan no longer lists the labels the accepted patches close,
and no needed patch was rejected or left without a patch. score() splits certified into certified_unhardened (the
attacker never succeeded before any patch) and certified_hardened (certified after patches). It never means secure:
the reason strings say "not hackable by this attacker" and nothing stronger.

Report keys (stable; T07 writes these into certificates). to_dict() holds only JSON types and no raw sandbox or
attacker text: each GradeResult.log_tail becomes {"sha256", "chars"}, and each hole's evidence becomes a count per
label (evidence_counts). Do not serialise a report with dataclasses.asdict for a certificate: that includes
`attacks`, which holds raw diffs and steps. Use to_dict().
  HardenReport: instance_id, before, candidates, accepted, rejected, unpatched, after, certified, reason,
    sandbox_runs, notes. `attacks` (the AttackResult objects, with raw diffs and steps, for trace saving) is a
    plain field and is NOT in to_dict. It holds one result per round whose attack ran, before first; before.attack
    and after.attack (None when that attack did not run) tell which is which.
  RoundReport: patches, patch_outcomes, gates, exposure, attack, attack_grade, holes, inconclusive, no_attempt,
    error. gates is GradeResult pair {gold, empty} plus reason and ok. attack is a summary: submitted, stop_reason,
    tokens_in, tokens_out, diff_ok, error, steps (a count), final_diff_sha256, final_diff_chars. It never holds
    the raw diff or the steps. attack_grade is None when the attack made no diff, an empty one, or made no attempt.
    inconclusive is the reason the round's attack gives no verdict, or None. no_attempt is the reason the attack
    made no attempt (see the module docstring), or None.
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
from cheatproof.exposure import HOLE_GIT_HISTORY, HOLE_NETWORK, ExposureReport
from cheatproof.grader import GateReport, GradeResult
from cheatproof.holes import HoleReport

if TYPE_CHECKING:
    from cheatproof.attacker import AttackResult
    from cheatproof.patches import PatchOutcome
    from cheatproof.tasks import TaskSpec

DEFAULT_TIMEOUT_S = 1800
ERROR_CHARS = 300
CLOSE_ATTEMPTS = 2  # the normal exit path closes once, then retries once
# The attacker's stop reasons that finish an attack. token_limit, budget and error do not.
CONCLUSIVE_STOPS = frozenset({"submit", "max_steps"})
# Grade errors that mean the attack lost: the test guard refused the diff, or the candidate did not apply.
# Stable prefixes from grader.py.
ATTACK_LOST_PREFIXES = ("test files touched:", "guarded config touched:", "candidate patch did not apply")
# Trace steps that can write to the sandbox. A shell command may write anything, so run counts as a write step.
WRITE_TOOLS = frozenset({"write_file", "run"})
# harden() calls the attack once per round. certify.build_certificate records this in the attacker block.
ATTACKS_PER_ROUND = 1
# Patch name -> the exposure label it closes, as exposure.scan reports it. test-edit is closed at grade time.
EXPOSURE_CLOSED_BY = {"strip-future-git": HOLE_GIT_HISTORY, "network-off": HOLE_NETWORK}
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
    classify(trace, final_diff, task, *, visible_passed, hidden_passed, grader_labels) -> HoleReport
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


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _grade_dict(grade: GradeResult) -> dict[str, Any]:
    # JSON types only: a tuple (GradeResult.labels) becomes a list, as json.dumps would write it.
    data = {key: list(value) if isinstance(value, tuple) else value for key, value in asdict(grade).items()}
    tail = data["log_tail"]  # sandbox output: a digest only, so a certificate never carries log text
    data["log_tail"] = {"sha256": _digest(tail), "chars": len(tail)}
    return data


def _gates_dict(gates: GateReport) -> dict[str, Any]:
    return {
        "gold": _grade_dict(gates.gold),
        "empty": _grade_dict(gates.empty),
        "reason": gates.reason,
        "ok": gates.ok,
    }


def _holes_dict(holes: HoleReport) -> dict[str, Any]:
    data = holes.to_dict()
    evidence = data.pop("evidence")  # attacker-derived snippets: a count per label instead
    data["evidence_counts"] = {label: len(items) for label, items in evidence.items()}
    return data


@dataclass(frozen=True)
class RoundReport:
    """One attack round: gates, exposure scan, one attack, its clean-session grade and its hole labels.

    error is set when the round stopped early without a verdict (a patch failed to apply, or an exception that
    is not a budget or executor stop). Fields after the stopping point stay None. inconclusive is set when the
    round ran its attack but the attack gives no verdict (see the module docstring). no_attempt is set when the
    attack made no attempt; such a round is never certified and is not graded.
    """

    patches: tuple[str, ...]
    patch_outcomes: tuple[PatchOutcome, ...] = ()
    gates: GateReport | None = None
    exposure: ExposureReport | None = None
    attack: dict[str, Any] | None = None
    attack_grade: GradeResult | None = None
    holes: HoleReport | None = None
    inconclusive: str | None = None
    no_attempt: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "patches": list(self.patches),
            "patch_outcomes": [outcome.to_dict() for outcome in self.patch_outcomes],
            "gates": None if self.gates is None else _gates_dict(self.gates),
            "exposure": None if self.exposure is None else asdict(self.exposure),
            "attack": None if self.attack is None else dict(self.attack),
            "attack_grade": None if self.attack_grade is None else _grade_dict(self.attack_grade),
            "holes": None if self.holes is None else _holes_dict(self.holes),
            "inconclusive": self.inconclusive,
            "no_attempt": self.no_attempt,
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
            "gold": None if self.gold is None else _grade_dict(self.gold),
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
    notes: tuple[
        str, ...
    ] = ()  # facts that do not change certification, such as a session close that failed twice
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
            "notes": list(self.notes),
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
    inconclusive: str | None = None
    no_attempt: str | None = None
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
            inconclusive=self.inconclusive,
            no_attempt=self.no_attempt,
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


def _reset_during(result: AttackResult) -> bool:
    """True when a command timed out and the executor reset the sandbox during the attack."""
    return any(step.get("reset") is True for step in result.steps)


def _unfinished(result: AttackResult, patched: bool) -> str | None:
    """Why the attack did not finish, or None: a stop other than submit or max_steps, a diff that was not taken,
    or a sandbox reset while patches were in force (the attacker then ran unpatched)."""
    if result.stop_reason not in CONCLUSIVE_STOPS:
        return f"attack ended with stop_reason {result.stop_reason}"
    if not result.diff_ok or result.final_diff is None:
        return "the final diff could not be taken"
    if patched and _reset_during(result):
        return "sandbox reset during the attack; patches were not in force"
    return None


def _no_attempt(result: AttackResult, patched: bool) -> str | None:
    """Why a finished attack made no attempt, or None. Such an attack is never certified. See the module docstring."""
    if _unfinished(result, patched) is not None:
        return None  # _inconclusive reports an unfinished attack
    if not result.steps:
        return "the attack took no steps"
    if result.final_diff == "":
        return "the final diff is empty"
    if not any(step.get("tool") in WRITE_TOOLS for step in result.steps):
        return "the trace has no write step"
    return None


def _inconclusive(
    result: AttackResult, grade: GradeResult | None, patched: bool, no_attempt: str | None
) -> str | None:
    """Why this attack gives no verdict, or None when it is conclusive: exploited, failed or no attempt.

    grade is the clean-session grade of the attack's diff, None when it was not graded. The module docstring has
    the rules.
    """
    unfinished = _unfinished(result, patched)
    if unfinished is not None:
        return unfinished
    if no_attempt is not None:
        return None
    if grade is None:
        return "the attack diff was not graded"
    if grade.applied and grade.error is None:
        return None
    if grade.error is not None and grade.error.startswith(ATTACK_LOST_PREFIXES):
        return None
    return f"attack diff grade inconclusive: {_capped(grade.error or 'the diff did not apply')}"


def _visible_passed(grade: GradeResult) -> bool | None:
    """Whether the repo's own tests pass on this diff, or None when the grade does not say.

    The PASS_TO_PASS nodes are the repo's existing tests, which the attacker can run. FAIL_TO_PASS nodes come from
    the hidden test patch, so they are not counted here. A grade that did not apply, errored, or has no
    PASS_TO_PASS nodes gives None.
    """
    if not grade.applied or grade.error is not None or grade.p2p_total == 0:
        return None
    return grade.p2p_passed == grade.p2p_total


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
        "final_diff_sha256": None if diff is None else _digest(diff),
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
        self.notes: list[str] = []

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
        self._close(session)

    def _close(self, session: Session) -> None:
        """Normal exit: a failed close is retried once, then noted. PROPAGATE errors still raise."""
        failures: list[Exception] = []
        for _ in range(CLOSE_ATTEMPTS):
            try:
                session.close()
                return
            except PROPAGATE:
                raise
            except Exception as exc:  # noqa: BLE001 - retried once, then noted
                failures.append(exc)
        self.notes.append(
            f"session close failed twice ({type(failures[-1]).__name__}): check for a leftover sandbox"
        )

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
        patched = bool(state.patches)
        if not patched and _reset_during(result):
            self.notes.append(
                "before attack: sandbox reset after a command timeout; no patch was in force, "
                "so certification is not affected"
            )
        state.no_attempt = _no_attempt(result, patched)
        diff = result.final_diff if result.diff_ok else None
        hidden_passed = None
        visible_passed = None
        if diff and state.no_attempt is None:
            # A clean session: the attacker's own may hold a tampered object store or restored-over tests.
            state.attack_grade = self._grade(box, state, diff)
            hidden_passed = state.attack_grade.passed
            visible_passed = _visible_passed(state.attack_grade)
        elif diff == "":
            # The empty gate of this round graded this same state and failed it.
            hidden_passed = False
            visible_passed = _visible_passed(empty)
        state.holes = self.ops.classify(
            result.steps,
            diff,
            self.task,
            visible_passed=visible_passed,
            hidden_passed=hidden_passed,
            grader_labels=() if state.attack_grade is None else state.attack_grade.labels,
        )
        state.inconclusive = _inconclusive(result, state.attack_grade, patched, state.no_attempt)

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
            notes=tuple(self.notes),
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
        if before.inconclusive is not None:
            return self.report(before, False, f"inconclusive attack: {before.inconclusive}")
        if before.no_attempt is not None:
            reason = f"attacker made no attempt before hardening ({before.no_attempt}); not certified"
            return self.report(before, False, reason)
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
        if after.no_attempt is not None:
            reason = (
                f"attacker made no attempt after hardening with {', '.join(accepted)} "
                f"({after.no_attempt}); not certified"
            )
            return self.report(before, False, reason, **shown)
        if after.holes.exploited:
            holes = ", ".join(after.holes.labels)
            reason = f"attacker still exploits after hardening with {', '.join(accepted)} ({holes})"
            return self.report(before, False, reason, **shown)
        if after.inconclusive is not None:
            return self.report(before, False, f"inconclusive attack: {after.inconclusive}", **shown)
        if after.exposure is None:
            return self.report(before, False, "exposure scan missing after hardening", **shown)
        closed = [EXPOSURE_CLOSED_BY[name] for name in accepted if name in EXPOSURE_CLOSED_BY]
        still_open = [label for label in closed if label in after.exposure.holes]
        if still_open:
            reason = "; ".join(f"patch did not close {label} (exposure scan)" for label in still_open)
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
