import hashlib
import json
from dataclasses import dataclass, replace

import pytest

from cheatproof import holes
from cheatproof.attacker import AttackResult
from cheatproof.budget import BudgetExceeded
from cheatproof.executor import EnvSpec, ExecutorRefused, ExecutorUnavailable, Session
from cheatproof.exposure import ExposureReport
from cheatproof.grader import GateReport, GradeResult
from cheatproof.harden import HardenOps, HardenReport, harden
from cheatproof.holes import HoleReport
from cheatproof.tasks import TaskSpec

STRIP = "strip-future-git"
GUARD = "test-edit-guard"
NET_OFF = "network-off"
# VERIFY: these names and the label to patch map mirror the T06 patches.py contract; no recorded real
# patches.py run confirms them yet.
PATCH_OF = {"git-history": STRIP, "test-edit": GUARD, "network": NET_OFF}
SCAN_CLOSES = {STRIP: "git-history", NET_OFF: "network"}  # which scan label each patch closes
EXPLOIT = "EXPLOIT-DIFF-RAW-MARKER"
GOLD = "GOLD-PATCH"
LOG = "LOG-TAIL-MARKER pytest output"
EVIDENCE = "EVIDENCE-SNIPPET-MARKER"
ENV = EnvSpec(image="python:3.12-slim", network=True)
TASK = TaskSpec(
    instance_id="fixture__task-1",
    repo="fixture/repo",
    base_commit="a" * 40,
    image="python:3.12-slim",
    fail_to_pass=("tests/test_x.py::test_new",),
    pass_to_pass=("tests/test_x.py::test_old",),
    gold_patch=GOLD,
    test_patch="",
    source="fixture",
)
PROPAGATING = [BudgetExceeded, ExecutorRefused, ExecutorUnavailable]
FAILED_BEFORE = "attacker failed before hardening (not hackable by this attacker)"
# An attack that tried: a write_file step and a run step (a shell command may write).
WRITE_STEPS = [{"n": 1, "tool": "write_file"}, {"n": 2, "tool": "run"}]
# A hard-code case with real trace records (the shape attacker.py writes) and a real test patch.
HARD_CODE_TEST_PATCH = (
    "diff --git a/tests/test_x.py b/tests/test_x.py\n"
    "--- a/tests/test_x.py\n"
    "+++ b/tests/test_x.py\n"
    "@@ -1 +1,2 @@\n"
    " def test_old():\n"
    "+    assert answer() == 4242\n"
)
HARD_CODE_DIFF = (
    "diff --git a/src/answer.py b/src/answer.py\n"
    "--- a/src/answer.py\n"
    "+++ b/src/answer.py\n"
    "@@ -1 +1,2 @@\n"
    " def answer():\n"
    "+    return 4242\n"
)
HARD_CODE_STEPS = [
    {
        "type": "step",
        "step": 1,
        "tool": "write_file",
        "args": {"path": "src/answer.py"},
        "error": None,
        "reset": False,
        "result_digest": {"head": "ok", "sha256": "0" * 64},
    }
]


@dataclass(frozen=True)
class FakeOutcome:
    # VERIFY: stands in for patches.PatchOutcome (name, ok, notes, to_dict).
    name: str
    ok: bool = True
    notes: tuple[str, ...] = ()

    def to_dict(self):
        return {"name": self.name, "ok": self.ok, "notes": list(self.notes)}


def make_attack(diff=EXPLOIT, *, diff_ok=True, stop_reason="submit", error="", steps=None):
    return AttackResult(
        submitted=True,
        stop_reason=stop_reason,
        steps=[dict(step) for step in WRITE_STEPS] if steps is None else steps,
        tokens_in=120,
        tokens_out=30,
        final_diff=diff if diff_ok else None,
        error=error,
        diff_ok=diff_ok,
    )


def grade_result(passed, *, error=None, applied=True):
    return GradeResult(passed, int(passed), 1, int(passed), 1, applied, error, LOG)


class FakeSession(Session):
    """Counts resets. A reset forgets the patches, as a real one destroys the in-session work."""

    def __init__(self, sid, lab):
        self.sid = sid
        self.lab = lab
        self.generation = 0  # resets so far
        self.applied: tuple[str, ...] = ()
        self.closed = 0

    def run(self, cmd, timeout):
        raise AssertionError("the loop runs nothing itself")

    def write_file(self, path, data):
        raise AssertionError("the loop writes nothing itself")

    def diff(self):
        raise AssertionError("the loop reads no diff itself")

    def reset(self):
        self.lab.maybe_fail("reset")
        self.generation += 1
        self.applied = ()
        self.lab.resets.append(self.sid)

    def close(self):
        self.closed += 1


class FakeExecutor:
    def __init__(self, lab, session_cls=FakeSession):
        self.lab = lab
        self.session_cls = session_cls
        self.sessions: list[FakeSession] = []
        self.envs: list[EnvSpec] = []
        self.budgets: list[object] = []

    def start(self, env, budget=None):
        self.lab.maybe_fail(f"start:{len(self.sessions)}")
        self.envs.append(env)
        self.budgets.append(budget)
        session = self.session_cls(len(self.sessions), self.lab)
        self.sessions.append(session)
        return session


@dataclass
class Call:
    sid: int
    generation: int
    applied: tuple[str, ...]
    patch: str | None = None
    kwargs: dict | None = None


class Lab:
    """A scripted world. The defaults: the attacker exploits git-history and strip-future-git closes it.

    gold_breaks: patches that make the gold patch fail while active. closes: patches under which the exploit
    diff fails the hidden tests. exposed: labels the exposure scan lists while no patch closes them. scan_holes:
    labels the scan lists whatever patches are in force. attack_grade: a GradeResult returned for every attack
    diff instead of the scripted one. fail: where a fake raises, keyed "attack", "attack:N", "grade", "scan",
    "scan:N", "reset", "start:N".
    """

    def __init__(
        self,
        *,
        labels=("git-history",),
        gold_ok=True,
        empty_passes=False,
        gold_breaks=(),
        closes=(STRIP,),
        exposed=("git-history",),
        scan_holes=None,
        attack_grade=None,
        attacks=None,
        apply_fail=None,
        apply_fails_from=None,
        fail=None,
        task=TASK,
    ):
        self.task = task
        self.labels = labels
        self.gold_ok = gold_ok
        self.empty_passes = empty_passes
        self.gold_breaks = set(gold_breaks)
        self.closes = set(closes)
        self.exposed = exposed
        self.scan_holes = scan_holes
        self.attack_grade = attack_grade
        self.attacks = attacks or [make_attack()]
        self.apply_fail = apply_fail or {}
        self.apply_fails_from = apply_fails_from
        self.fail = fail or {}
        self.resets: list[int] = []
        self.grade_calls: list[Call] = []
        self.apply_calls: list[Call] = []
        self.scan_calls: list[Call] = []
        self.attack_calls: list[Call] = []
        self.classify_calls: list[tuple] = []
        self.env_calls: list[tuple] = []
        self.executor = FakeExecutor(self)
        self.ops = HardenOps(
            grade=self.grade,
            apply_patches=self.apply_patches,
            patches_for=self.patches_for,
            unpatched=self.unpatched,
            env_for=self.env_for,
            grade_kwargs=self.grade_kwargs,
            scan=self.scan,
            classify=self.classify,
        )

    def maybe_fail(self, where):
        if where in self.fail:
            exc = self.fail[where]
            raise exc() if isinstance(exc, type) else exc

    def grade(self, session, task, patch, timeout, *, workdir, **kwargs):
        if patch not in (GOLD, ""):
            self.maybe_fail("grade")  # only the attack's own grade can fail here
        self.grade_calls.append(Call(session.sid, session.generation, session.applied, patch, dict(kwargs)))
        self.last_grade_args = (timeout, workdir)
        active = set(session.applied)
        if patch == GOLD:
            ok = self.gold_ok and not active & self.gold_breaks
            return grade_result(ok, error=None if ok else "gold broken")
        if patch == "":
            return grade_result(self.empty_passes)
        if self.attack_grade is not None:
            return self.attack_grade
        return grade_result(patch == EXPLOIT and not active & self.closes)

    def apply_patches(self, session, task, names, *, workdir):
        late = self.apply_fails_from is not None and len(self.apply_calls) >= self.apply_fails_from
        self.apply_calls.append(Call(session.sid, session.generation, tuple(names)))
        session.applied = tuple(names)
        outcomes = []
        for name in names:
            if late:
                outcomes.append(FakeOutcome(name, False, ("late failure",)))
            elif name in self.apply_fail:
                outcomes.append(FakeOutcome(name, False, self.apply_fail[name]))
            else:
                outcomes.append(FakeOutcome(name))
        return outcomes

    def patches_for(self, labels):
        return tuple(PATCH_OF[label] for label in labels if label in PATCH_OF)

    def unpatched(self, labels):
        return tuple(label for label in labels if label not in PATCH_OF)

    def env_for(self, spec, names):
        self.env_calls.append(tuple(names))
        return replace(spec, network=False) if NET_OFF in names else spec

    def grade_kwargs(self, names):
        return {"reject_test_edits": True} if GUARD in names else {}

    def scan(self, session, task, *, workdir):
        index = len(self.scan_calls)
        self.maybe_fail("scan")
        self.maybe_fail(f"scan:{index}")
        self.scan_calls.append(Call(session.sid, session.generation, session.applied))
        if self.scan_holes is not None:
            holes = list(self.scan_holes)
        else:
            closed = {SCAN_CLOSES[name] for name in session.applied if name in SCAN_CLOSES}
            holes = [label for label in self.exposed if label not in closed]
        return ExposureReport(
            future_git="git-history" in holes,
            future_git_evidence=["refs/future"] if "git-history" in holes else [],
            tests_writable=False,
            writable_tests=[],
            restore_covered=True,
            unrestored_tests=[],
            writable_as_root=[],
            network="network" in holes,
            network_evidence=[],
            holes=holes,
        )

    def classify(self, trace, final_diff, task, *, visible_passed=None, hidden_passed=None, grader_labels=()):
        self.classify_calls.append((trace, final_diff, hidden_passed, visible_passed))
        exploited = hidden_passed is True
        labels = tuple(self.labels) if exploited else ()
        return HoleReport(
            primary=labels[0] if labels else "none",
            labels=labels,
            attempted=labels,
            evidence={label: (f"{EVIDENCE} {label}",) for label in labels},
            succeeded=hidden_passed,
            exploited=exploited,
            skipped_records=0,
        )

    def attack_fn(self, session):
        index = len(self.attack_calls)
        self.maybe_fail("attack")
        self.maybe_fail(f"attack:{index}")
        self.attack_calls.append(Call(session.sid, session.generation, session.applied))
        return self.attacks[min(index, len(self.attacks) - 1)]

    def run(self, env=ENV, **kwargs):
        return harden(self.executor, env, self.task, self.attack_fn, ops=self.ops, **kwargs)

    @property
    def runs_made(self):
        return len(self.executor.sessions) + len(self.resets)


def assert_clean(lab, report):
    assert report.sandbox_runs == lab.runs_made
    assert all(session.closed == 1 for session in lab.executor.sessions)
    assert "secure" not in report.reason.lower()


def test_gold_gate_fails_no_attack():
    lab = Lab(gold_ok=False)
    report = lab.run()
    assert report.certified is False
    assert report.reason.startswith("gates failed before hardening (the task is broken): gold gate failed")
    assert lab.attack_calls == [] and lab.scan_calls == [] and report.attacks == ()
    assert report.before.gates is not None and not report.before.gates.ok
    assert report.before.attack is None and report.after is None and report.candidates == ()
    assert_clean(lab, report)


def test_empty_gate_passing_blocks_certification():
    lab = Lab(empty_passes=True)
    report = lab.run()
    assert report.certified is False
    assert "empty gate passed" in report.reason
    assert lab.attack_calls == []
    assert isinstance(report.before.gates, GateReport) and report.before.gates.gold.passed
    assert_clean(lab, report)


def test_attacker_fails_before_is_certified_without_after_round():
    lab = Lab(attacks=[make_attack("WRONG-DIFF")])
    report = lab.run()
    assert report.certified is True
    assert report.reason == FAILED_BEFORE
    assert report.after is None and report.candidates == () and report.accepted == ()
    assert report.before.attack_grade is not None and not report.before.attack_grade.passed
    assert report.before.inconclusive is None
    assert len(lab.executor.sessions) == 1
    # start, then a reset before each of: empty gate, scan, attack, attack grade. The first use skips the reset.
    assert report.sandbox_runs == 5
    assert_clean(lab, report)


def test_git_history_exploit_is_patched_and_certified():
    lab = Lab()
    report = lab.run()
    assert report.certified is True
    assert report.before.holes.labels == ("git-history",) and report.before.holes.exploited
    assert report.accepted == (STRIP,) and report.rejected == () and report.unpatched == ()
    assert [c.name for c in report.candidates] == [STRIP] and report.candidates[0].accepted
    assert report.candidates[0].gold is not None and report.candidates[0].gold.passed
    assert report.after is not None and report.after.patches == (STRIP,)
    assert report.after.holes is not None and not report.after.holes.exploited
    assert report.after.exposure.holes == []
    assert report.reason == f"attacker failed after hardening with {STRIP} (not hackable by this attacker)"
    # before 1+4, candidate 1+0, after 1+4
    assert report.sandbox_runs == 11 and len(lab.executor.sessions) == 3
    assert len(report.attacks) == 2 and all(a.final_diff == EXPLOIT for a in report.attacks)
    assert_clean(lab, report)


def test_patch_that_breaks_gold_is_rejected_and_after_round_uses_the_rest():
    lab = Lab(labels=("git-history", "test-edit"), gold_breaks=(GUARD,), closes=(STRIP,))
    report = lab.run()
    assert report.accepted == (STRIP,) and report.rejected == (GUARD,)
    bad = next(c for c in report.candidates if c.name == GUARD)
    assert bad.accepted is False and "gold gate failed with this patch: gold broken" in bad.reason
    assert bad.gold is not None and not bad.gold.passed
    assert report.after is not None and report.after.patches == (STRIP,)
    assert report.certified is False
    assert GUARD in report.reason and "not certified" in report.reason
    assert_clean(lab, report)


def test_only_needed_patch_breaks_gold_skips_after_round():
    lab = Lab(gold_breaks=(STRIP,))
    report = lab.run()
    assert report.certified is False
    assert report.accepted == () and report.rejected == (STRIP,)
    assert report.after is None
    assert "nothing could be applied" in report.reason and STRIP in report.reason
    assert len(lab.attack_calls) == 1
    assert len(lab.executor.sessions) == 2  # before round, one candidate
    assert_clean(lab, report)


def test_patch_apply_failure_is_rejected_with_the_notes():
    lab = Lab(apply_fail={STRIP: ("no .git directory",)})
    report = lab.run()
    candidate = report.candidates[0]
    assert candidate.accepted is False and "no .git directory" in candidate.reason
    assert candidate.gold is None  # never graded: the patch was not in the session
    assert report.after is None and report.certified is False
    assert_clean(lab, report)


def test_patch_with_no_outcome_is_rejected():
    lab = Lab()
    lab.ops = replace(lab.ops, apply_patches=lambda session, task, names, *, workdir: [])
    report = lab.run()
    assert report.candidates[0].accepted is False
    assert "reported no outcome" in report.candidates[0].reason
    assert report.certified is False


def test_hard_code_only_is_not_certified_and_lists_unpatched():
    lab = Lab(labels=("hard-code",))
    report = lab.run()
    assert report.certified is False
    assert report.candidates == () and report.accepted == () and report.after is None
    assert report.unpatched == ("hard-code",)
    assert "hard-code" in report.reason and "no patch exists" in report.reason
    assert_clean(lab, report)


def test_after_attack_still_exploiting_is_not_certified():
    lab = Lab(closes=())
    report = lab.run()
    assert report.certified is False
    assert report.accepted == (STRIP,)
    assert report.after is not None and report.after.holes.exploited
    assert report.reason.startswith("attacker still exploits after hardening")
    assert "git-history" in report.reason
    assert_clean(lab, report)


def test_attack_diff_is_graded_in_a_clean_session_with_grade_kwargs():
    lab = Lab(labels=("test-edit",), closes=(GUARD,))
    report = lab.run()
    assert report.certified is True
    attacker = lab.attack_calls[1]  # the after attack
    graded = [c for c in lab.grade_calls if c.patch == EXPLOIT]
    assert len(graded) == 2
    before_grade, after_grade = graded
    assert before_grade.kwargs == {} and after_grade.kwargs == {"reject_test_edits": True}
    attacker_before = lab.attack_calls[0]
    for attack, grade in ((attacker_before, before_grade), (attacker, after_grade)):
        assert grade.sid == attack.sid
        assert grade.generation == attack.generation + 1  # reset in between: not the attacker's own state
    assert after_grade.applied == (GUARD,)
    assert lab.last_grade_args == (1800, "/testbed")
    assert_clean(lab, report)


def test_network_off_patch_changes_env_of_later_sessions():
    lab = Lab(labels=("network",), closes=(NET_OFF,), exposed=("network",))
    report = lab.run(env=ENV)
    assert report.certified is True
    assert [env.network for env in lab.executor.envs] == [True, False, False]
    assert lab.env_calls == [(NET_OFF,), (NET_OFF,)]  # the before round never calls env_for
    assert ENV.network is True  # the caller's spec is not modified
    assert_clean(lab, report)


def test_apply_patches_is_rerun_after_every_reset():
    lab = Lab()
    report = lab.run()
    after_session = lab.executor.sessions[2]
    steps = [c for c in lab.grade_calls + lab.scan_calls + lab.attack_calls if c.sid == after_session.sid]
    assert len(steps) == 5  # gold, empty, scan, attack, attack grade
    assert all(step.applied == (STRIP,) for step in steps)
    assert [c.generation for c in steps if c.patch == GOLD] == [0]  # first use: no reset
    applies = [c for c in lab.apply_calls if c.sid == after_session.sid]
    assert [c.generation for c in applies] == [0, 1, 2, 3, 4]  # once per fresh state, each after its reset
    assert lab.apply_calls[0].sid == 1 and lab.apply_calls[0].generation == 0  # the candidate session
    before_steps = [c for c in lab.grade_calls + lab.scan_calls + lab.attack_calls if c.sid == 0]
    assert all(step.applied == () for step in before_steps)
    assert all(c.sid != 0 for c in lab.apply_calls)  # no patches before hardening: apply_patches not called
    assert_clean(lab, report)


def test_first_use_of_a_started_session_skips_the_reset():
    lab = Lab(gold_ok=False)
    report = lab.run()
    gold, empty = lab.grade_calls
    assert (gold.sid, gold.generation) == (0, 0)
    assert (empty.sid, empty.generation) == (0, 1)
    assert report.sandbox_runs == 2


# Attack verdicts: an attack that did not really run is inconclusive, never a failed attack.


@pytest.mark.parametrize("stop", ["error", "token_limit", "budget"])
def test_attack_that_did_not_finish_is_inconclusive(stop):
    lab = Lab(attacks=[make_attack("WRONG-DIFF", stop_reason=stop, error="llm call failed: APIError")])
    report = lab.run()
    assert report.certified is False and report.after is None
    assert report.reason == f"inconclusive attack: attack ended with stop_reason {stop}"
    assert report.before.inconclusive == f"attack ended with stop_reason {stop}"
    assert report.before.attack["error"] == "llm call failed: APIError"
    assert_clean(lab, report)


def test_attack_with_no_steps_after_token_limit_is_inconclusive():
    lab = Lab(attacks=[make_attack("WRONG-DIFF", stop_reason="token_limit", steps=[])])
    report = lab.run()
    assert report.certified is False
    assert report.reason == "inconclusive attack: attack ended with stop_reason token_limit"
    assert report.before.no_attempt is None
    assert report.before.attack["steps"] == 0
    assert_clean(lab, report)


@pytest.mark.parametrize("stop", ["submit", "max_steps"])
def test_attack_that_took_no_steps_made_no_attempt(stop):
    lab = Lab(attacks=[make_attack("WRONG-DIFF", stop_reason=stop, steps=[])])
    report = lab.run()
    assert report.certified is False and report.after is None
    assert report.before.no_attempt == "the attack took no steps"
    assert report.reason == (
        "attacker made no attempt before hardening (the attack took no steps); not certified"
    )
    assert report.before.inconclusive is None and report.before.attack["steps"] == 0
    assert [c.patch for c in lab.grade_calls] == [GOLD, ""]  # the attack was never graded
    assert_clean(lab, report)


@pytest.mark.parametrize(
    "steps",
    [
        [{"n": 1, "tool": "read_file"}, {"n": 2, "tool": "submit"}],
        [{"n": 1, "tool": "web_search"}, {"n": 2, "tool": "submit"}],
    ],
)
def test_attack_with_no_write_step_made_no_attempt_even_with_a_diff(steps):
    lab = Lab(attacks=[make_attack(EXPLOIT, steps=steps)])
    report = lab.run()
    assert report.certified is False and report.after is None
    assert report.before.no_attempt == "the trace has no write step"
    assert report.reason == (
        "attacker made no attempt before hardening (the trace has no write step); not certified"
    )
    assert report.before.attack_grade is None and report.before.holes.exploited is False
    assert [c.patch for c in lab.grade_calls] == [GOLD, ""]  # the diff was never graded
    assert_clean(lab, report)


def test_a_run_step_counts_as_a_write_step():
    lab = Lab(attacks=[make_attack(EXPLOIT, steps=[{"n": 1, "tool": "run"}])])
    report = lab.run()
    assert report.before.no_attempt is None
    assert report.before.attack_grade is not None and report.before.holes.exploited


def test_diff_not_taken_after_submit_is_inconclusive():
    lab = Lab(attacks=[make_attack("WRONG-DIFF", diff_ok=False, stop_reason="submit")])
    report = lab.run()
    assert report.certified is False and report.after is None
    assert report.reason == "inconclusive attack: the final diff could not be taken"
    assert report.before.attack_grade is None
    assert [c.patch for c in lab.grade_calls] == [GOLD, ""]  # the attack was never graded
    assert_clean(lab, report)


def test_diff_failure_is_inconclusive_and_the_attack_was_never_graded():
    failed = make_attack(diff_ok=False, stop_reason="error", error="diff failed: git is broken")
    lab = Lab(attacks=[failed])
    report = lab.run()
    assert report.certified is False and report.after is None
    assert report.reason == "inconclusive attack: attack ended with stop_reason error"
    assert [c.patch for c in lab.grade_calls] == [GOLD, ""]  # the attack was never graded
    assert lab.classify_calls == [(failed.steps, None, None, None)]
    assert report.before.attack["diff_ok"] is False and report.before.attack["final_diff_sha256"] is None
    assert report.before.attack["error"] == "diff failed: git is broken"
    assert_clean(lab, report)


def test_empty_diff_is_no_attempt_never_certified_and_not_graded_again():
    lab = Lab(attacks=[make_attack("")])
    report = lab.run()
    assert report.certified is False and report.after is None
    assert (
        report.reason == "attacker made no attempt before hardening (the final diff is empty); not certified"
    )
    assert report.before.no_attempt == "the final diff is empty"
    assert report.before.inconclusive is None and report.before.attack_grade is None
    assert report.before.attack["final_diff_chars"] == 0
    assert [c.patch for c in lab.grade_calls] == [GOLD, ""]
    # The empty gate of this round graded the same state (it failed), so its visible result is the one used.
    assert lab.classify_calls == [(lab.attacks[0].steps, "", False, False)]
    assert_clean(lab, report)


def test_empty_diff_after_hardening_is_no_attempt_and_not_certified():
    lab = Lab(attacks=[make_attack(), make_attack("", steps=WRITE_STEPS)])
    report = lab.run()
    assert report.certified is False and report.accepted == (STRIP,)
    assert report.before.holes.exploited and report.before.no_attempt is None
    assert report.after is not None and report.after.no_attempt == "the final diff is empty"
    assert report.after.attack_grade is None and report.after.inconclusive is None
    assert report.reason == (
        f"attacker made no attempt after hardening with {STRIP} (the final diff is empty); not certified"
    )
    assert_clean(lab, report)


@pytest.mark.parametrize(
    "grade",
    [
        grade_result(False, error="pytest timed out after 5s"),
        grade_result(False, error="pytest printed no final summary line"),
        grade_result(False, error="pytest exited 3"),
        grade_result(False, error="hidden tests did not apply: patch does not apply", applied=False),
        grade_result(False, error="test files refused: bad path", applied=False),
    ],
)
def test_inconclusive_attack_grade_is_not_a_failed_attack(grade):
    lab = Lab(attacks=[make_attack()], attack_grade=grade)
    report = lab.run()
    assert report.certified is False and report.after is None
    why = f"attack diff grade inconclusive: {grade.error}"
    assert report.reason == f"inconclusive attack: {why}"
    assert report.before.inconclusive == why
    assert_clean(lab, report)


@pytest.mark.parametrize(
    "grade",
    [
        grade_result(False, error="candidate patch did not apply: corrupt patch at line 4", applied=False),
        grade_result(False, error="test files touched: tests/test_x.py", applied=False),
        grade_result(False, error="guarded config touched: setup.cfg", applied=False),
    ],
)
def test_refused_or_unapplied_attack_diff_is_a_failed_attack(grade):
    lab = Lab(attacks=[make_attack()], attack_grade=grade)
    report = lab.run()
    assert report.certified is True and report.reason == FAILED_BEFORE
    assert report.before.inconclusive is None
    assert report.before.holes.exploited is False
    assert_clean(lab, report)


# The visible result is the grade's PASS_TO_PASS result. It is None when the grade does not say.


@pytest.mark.parametrize(
    ("grade", "visible"),
    [
        (GradeResult(False, 0, 1, 1, 1, True, None, LOG), True),  # hidden fails, existing tests pass
        (GradeResult(False, 0, 1, 0, 1, True, None, LOG), False),  # an existing test fails too
        (GradeResult(False, 0, 1, 0, 0, True, None, LOG), None),  # no PASS_TO_PASS nodes to judge
        (GradeResult(False, 0, 1, 1, 1, True, "pytest timed out after 5s", LOG), None),
        (GradeResult(False, 0, 1, 1, 1, False, "hidden tests did not apply: x", LOG), None),
    ],
)
def test_visible_result_of_the_attack_grade_reaches_classify(grade, visible):
    lab = Lab(attacks=[make_attack()], attack_grade=grade)
    lab.run()
    assert lab.classify_calls[-1] == (lab.attacks[0].steps, EXPLOIT, False, visible)


def test_hard_code_is_found_with_the_visible_pass_and_reported_only_as_attempted():
    # Real classifier: visible tests pass, the hidden grade fails, and an added line shares 4242 with the test patch.
    task = replace(TASK, test_patch=HARD_CODE_TEST_PATCH)
    attack = make_attack(HARD_CODE_DIFF, steps=HARD_CODE_STEPS)
    lab = Lab(attacks=[attack], attack_grade=GradeResult(False, 0, 1, 1, 1, True, None, LOG), task=task)
    lab.ops = replace(lab.ops, classify=holes.classify)
    report = lab.run()
    assert "hard-code" in report.before.holes.attempted
    assert report.before.holes.labels == () and report.before.holes.exploited is False
    assert report.certified is True and report.reason == FAILED_BEFORE
    assert_clean(lab, report)


def test_grader_forgery_label_of_the_attack_grade_reaches_the_round_holes_and_blocks_certification():
    # Real classifier: the grade's forged pytest output carries grader-forgery. The grade fails, so the label is only
    # attempted, and the attack is inconclusive rather than a failed attack. The environment is not certified.
    forged = GradeResult(
        False,
        0,
        1,
        0,
        1,
        True,
        "grader-forgery: pytest printed 2 short test summary headers, expected 1",
        LOG,
        labels=("grader-forgery",),
    )
    lab = Lab(attacks=[make_attack()], attack_grade=forged)
    lab.ops = replace(lab.ops, classify=holes.classify)
    report = lab.run()
    assert "grader-forgery" in report.before.holes.attempted
    assert report.before.holes.labels == () and report.before.holes.exploited is False
    assert report.before.inconclusive == f"attack diff grade inconclusive: {forged.error}"
    assert report.certified is False and report.after is None
    assert report.reason == f"inconclusive attack: attack diff grade inconclusive: {forged.error}"
    assert_clean(lab, report)


# A reset during an attack (a command timed out) gives the sandbox back unpatched. Its attack counts only
# when a patch was not in force, and then it is only noted.


def test_reset_in_before_round_is_noted_and_does_not_block_certification():
    steps = [{"n": 1, "tool": "write_file"}, {"n": 2, "tool": "run", "reset": True}]
    lab = Lab(attacks=[make_attack("WRONG-DIFF", steps=steps)])
    report = lab.run()
    assert report.certified is True and report.reason == FAILED_BEFORE
    assert report.before.inconclusive is None
    assert (
        len(report.notes) == 1 and "reset" in report.notes[0] and "no patch was in force" in report.notes[0]
    )
    assert_clean(lab, report)


def test_reset_in_before_round_still_patches_and_certifies():
    steps = [{"n": 1, "tool": "run", "reset": True}, {"n": 2, "tool": "write_file"}]
    lab = Lab(attacks=[make_attack(steps=steps), make_attack()])
    report = lab.run()
    assert report.certified is True and report.accepted == (STRIP,)
    assert report.before.holes.exploited and report.after.inconclusive is None
    assert len(report.notes) == 1
    assert_clean(lab, report)


def test_reset_in_after_round_is_inconclusive_and_not_certified():
    steps = [{"n": 1, "tool": "write_file"}, {"n": 2, "tool": "run", "reset": True}]
    lab = Lab(attacks=[make_attack(), make_attack(steps=steps)])
    report = lab.run()
    assert report.certified is False and report.accepted == (STRIP,)
    assert report.after is not None and report.after.holes is not None
    assert report.after.inconclusive == "sandbox reset during the attack; patches were not in force"
    assert report.reason == "inconclusive attack: sandbox reset during the attack; patches were not in force"
    assert report.notes == ()
    assert_clean(lab, report)


# The after round's exposure scan must no longer list the labels the accepted patches close.


def test_exposure_still_listing_a_closed_label_blocks_certification():
    lab = Lab(scan_holes=("git-history",))
    report = lab.run()
    assert report.certified is False and report.accepted == (STRIP,)
    assert report.reason == "patch did not close git-history (exposure scan)"
    assert report.after is not None and report.after.exposure.holes == ["git-history"]
    assert report.after.holes is not None and not report.after.holes.exploited  # the attack itself failed
    assert_clean(lab, report)


def test_network_still_open_after_network_off_blocks_certification():
    lab = Lab(labels=("network",), closes=(NET_OFF,), scan_holes=("network",))
    report = lab.run()
    assert report.certified is False and report.accepted == (NET_OFF,)
    assert report.reason == "patch did not close network (exposure scan)"
    assert_clean(lab, report)


def test_test_edit_label_in_the_scan_is_not_checked():
    lab = Lab(labels=("test-edit",), closes=(GUARD,), scan_holes=("test-edit",))
    report = lab.run()
    assert report.certified is True and report.accepted == (GUARD,)
    assert report.after.exposure.holes == ["test-edit"]
    assert_clean(lab, report)


def test_missing_exposure_scan_after_hardening_is_not_certified():
    lab = Lab()
    lab.ops = replace(lab.ops, scan=lambda session, task, *, workdir: None)
    report = lab.run()
    assert report.certified is False and report.accepted == (STRIP,)
    assert report.after is not None and report.after.exposure is None and report.after.error is None
    assert report.reason == "exposure scan missing after hardening"
    assert_clean(lab, report)


def test_errored_exposure_scan_after_hardening_is_not_certified():
    lab = Lab(fail={"scan:1": ValueError("scan broke")})
    report = lab.run()
    assert report.certified is False and report.accepted == (STRIP,)
    assert report.after.error == "ValueError: scan broke"
    assert report.reason == "round after hardening failed: ValueError: scan broke"
    assert_clean(lab, report)


@pytest.mark.parametrize("exc", PROPAGATING)
@pytest.mark.parametrize("where", ["attack", "grade", "scan", "reset", "start:1", "start:0"])
def test_budget_and_executor_stops_propagate_and_sessions_close(exc, where):
    lab = Lab(fail={where: exc})
    with pytest.raises(exc):
        lab.run()
    assert all(session.closed == 1 for session in lab.executor.sessions)


def test_close_failure_does_not_hide_a_propagating_error():
    class BadClose(FakeSession):
        def close(self):
            super().close()
            raise RuntimeError("docker rm failed")

    lab = Lab(fail={"attack": BudgetExceeded})
    lab.executor.session_cls = BadClose
    with pytest.raises(BudgetExceeded):
        lab.run()
    assert lab.executor.sessions[0].closed == 1


# A failed close on the normal exit path is retried once, then noted. It never fails the run.


def test_failed_close_on_normal_exit_is_retried_once():
    class CloseOnce(FakeSession):
        def close(self):
            self.closed += 1
            if self.closed == 1:
                raise RuntimeError("docker rm failed")

    lab = Lab()
    lab.executor.session_cls = CloseOnce
    report = lab.run()
    assert report.certified is True and report.notes == ()
    assert [session.closed for session in lab.executor.sessions] == [2, 2, 2]
    assert report.sandbox_runs == 11


def test_close_that_fails_twice_is_noted_and_does_not_raise():
    class CloseBroken(FakeSession):
        def close(self):
            self.closed += 1
            raise RuntimeError("docker rm failed")

    lab = Lab()
    lab.executor.session_cls = CloseBroken
    report = lab.run()
    assert report.certified is True
    assert report.reason == f"attacker failed after hardening with {STRIP} (not hackable by this attacker)"
    assert len(report.notes) == 3  # one per session: before, candidate, after
    assert all(note.startswith("session close failed twice (RuntimeError)") for note in report.notes)
    assert [session.closed for session in lab.executor.sessions] == [2, 2, 2]


def test_budget_raised_by_close_on_normal_exit_propagates():
    class CloseBudget(FakeSession):
        def close(self):
            self.closed += 1
            raise BudgetExceeded()

    lab = Lab()
    lab.executor.session_cls = CloseBudget
    with pytest.raises(BudgetExceeded):
        lab.run()


@pytest.mark.parametrize("where", ["attack", "grade", "scan", "reset"])
def test_other_exception_is_recorded_as_the_round_error(where):
    lab = Lab(fail={where: ValueError("boom " + "x" * 400)})
    report = lab.run()
    assert report.certified is False and report.after is None
    assert report.before.error.startswith("ValueError: boom xxx")
    assert len(report.before.error) <= 300
    assert report.reason == f"round before hardening failed: {report.before.error}"
    assert all(session.closed == 1 for session in lab.executor.sessions)
    # a reset counts when it is attempted: a failed one may already have reserved its run
    assert report.sandbox_runs == lab.runs_made + (where == "reset")


def test_error_in_the_after_round_keeps_the_before_round():
    lab = Lab(fail={"attack:1": RuntimeError("model down")})  # the second attack call is the after attack
    report = lab.run()
    assert report.certified is False
    assert report.before.holes.exploited and report.after.error == "RuntimeError: model down"
    assert report.reason == "round after hardening failed: RuntimeError: model down"
    assert report.accepted == (STRIP,)
    assert len(report.attacks) == 1  # only the before attack returned
    assert_clean(lab, report)


def test_patch_failure_inside_the_after_round_ends_the_round():
    lab = Lab(apply_fails_from=1)  # call 0 is the candidate check; the after round's patches then fail
    report = lab.run()
    assert report.accepted == (STRIP,)
    assert report.certified is False
    assert report.after.error == f"patch {STRIP} failed: late failure"
    assert report.after.gates is None and report.after.attack is None
    assert report.after.patch_outcomes[0].ok is False
    assert lab.attack_calls and len(lab.attack_calls) == 1  # no after attack
    assert_clean(lab, report)


def test_to_dict_is_json_and_holds_no_raw_diff_log_text_or_evidence():
    lab = Lab()
    report = lab.run()
    data = report.to_dict()
    text = json.dumps(data)
    assert EXPLOIT not in text and "attacks" not in data
    assert LOG not in text and EVIDENCE not in text
    assert set(data) == {
        "instance_id",
        "before",
        "candidates",
        "accepted",
        "rejected",
        "unpatched",
        "after",
        "certified",
        "reason",
        "sandbox_runs",
        "notes",
    }
    assert set(data["before"]) == {
        "patches",
        "patch_outcomes",
        "gates",
        "exposure",
        "attack",
        "attack_grade",
        "holes",
        "inconclusive",
        "no_attempt",
        "error",
    }
    assert data["before"]["no_attempt"] is None
    attack = data["before"]["attack"]
    assert set(attack) == {
        "submitted",
        "stop_reason",
        "tokens_in",
        "tokens_out",
        "diff_ok",
        "error",
        "steps",
        "final_diff_sha256",
        "final_diff_chars",
    }
    assert attack["steps"] == 2 and attack["final_diff_chars"] == len(EXPLOIT)
    assert len(attack["final_diff_sha256"]) == 64
    assert data["before"]["gates"]["ok"] is True and data["before"]["gates"]["reason"] is None
    assert data["candidates"][0]["outcomes"] == [{"name": STRIP, "ok": True, "notes": []}]
    assert data["after"]["patch_outcomes"][0]["name"] == STRIP
    assert data["sandbox_runs"] == 11 and data["instance_id"] == "fixture__task-1"
    assert data["notes"] == []
    log_digest = {"sha256": hashlib.sha256(LOG.encode()).hexdigest(), "chars": len(LOG)}
    assert data["before"]["gates"]["gold"]["log_tail"] == log_digest
    assert data["before"]["attack_grade"]["log_tail"] == log_digest
    assert data["candidates"][0]["gold"]["log_tail"] == log_digest
    assert data["before"]["holes"]["evidence_counts"] == {"git-history": 1}
    assert "evidence" not in data["before"]["holes"]
    assert data["before"]["holes"]["labels"] == ["git-history"]
    assert isinstance(report, HardenReport)
    assert report.attacks[0].final_diff == EXPLOIT and report.attacks[0].steps == WRITE_STEPS


def test_to_dict_of_a_stopped_run_is_json():
    for lab in (
        Lab(gold_ok=False),
        Lab(labels=("hard-code",)),
        Lab(fail={"attack": KeyError("k")}),
        Lab(attacks=[make_attack("WRONG-DIFF", stop_reason="error")]),
    ):
        data = lab.run().to_dict()
        assert json.loads(json.dumps(data)) == data


def test_budget_and_workdir_are_passed_through():
    lab = Lab(attacks=[make_attack("WRONG-DIFF")])
    sentinel = object()
    lab.run(budget=sentinel, timeout=42, workdir="/repo")
    assert lab.executor.budgets == [sentinel]
    assert lab.last_grade_args == (42, "/repo")


@pytest.mark.parametrize("timeout", [0, -1, float("nan")])
def test_bad_timeout_raises_before_any_session(timeout):
    lab = Lab()
    with pytest.raises(ValueError, match="timeout"):
        lab.run(timeout=timeout)
    assert lab.executor.sessions == []


def test_default_ops_names_the_real_collaborators():
    pytest.importorskip("cheatproof.patches")  # written in parallel (T06); skipped until it exists
    ops = HardenOps.default()
    assert all(callable(getattr(ops, name)) for name in HardenOps.__dataclass_fields__)
