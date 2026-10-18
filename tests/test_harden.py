import json
from dataclasses import dataclass, replace

import pytest

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
EXPLOIT = "EXPLOIT-DIFF-RAW-MARKER"
GOLD = "GOLD-PATCH"
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
        steps=[{"n": 1}, {"n": 2}] if steps is None else steps,
        tokens_in=120,
        tokens_out=30,
        final_diff=diff if diff_ok else None,
        error=error,
        diff_ok=diff_ok,
    )


def grade_result(passed, *, error=None, applied=True):
    return GradeResult(passed, int(passed), 1, int(passed), 1, applied, error, "log")


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
    diff fails the hidden tests. fail: where a fake raises, keyed "attack", "grade", "scan", "reset", "start:N".
    """

    def __init__(
        self,
        *,
        labels=("git-history",),
        gold_ok=True,
        empty_passes=False,
        gold_breaks=(),
        closes=(STRIP,),
        attacks=None,
        apply_fail=None,
        apply_fails_from=None,
        fail=None,
    ):
        self.labels = labels
        self.gold_ok = gold_ok
        self.empty_passes = empty_passes
        self.gold_breaks = set(gold_breaks)
        self.closes = set(closes)
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
        self.maybe_fail("scan")
        self.scan_calls.append(Call(session.sid, session.generation, session.applied))
        return ExposureReport(True, ["refs/future"], False, [], True, [], False, [], ["git-history"])

    def classify(self, trace, final_diff, task, *, hidden_passed=None):
        self.classify_calls.append((trace, final_diff, hidden_passed))
        exploited = hidden_passed is True
        labels = tuple(self.labels) if exploited else ()
        return HoleReport(
            primary=labels[0] if labels else "none",
            labels=labels,
            attempted=labels,
            evidence={label: () for label in labels},
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
        return harden(self.executor, env, TASK, self.attack_fn, ops=self.ops, **kwargs)

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
    assert report.reason == "attacker failed before hardening (not hackable by this attacker)"
    assert report.after is None and report.candidates == () and report.accepted == ()
    assert report.before.attack_grade is not None and not report.before.attack_grade.passed
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
    lab = Lab(labels=("network",), closes=(NET_OFF,))
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


def test_diff_ok_false_counts_as_a_failed_attack():
    failed = make_attack(diff_ok=False, stop_reason="error", error="diff failed: git is broken")
    lab = Lab(attacks=[failed])
    report = lab.run()
    assert report.certified is True and report.after is None
    assert report.before.attack_grade is None
    assert [c.patch for c in lab.grade_calls] == [GOLD, ""]  # the attack was never graded
    assert lab.classify_calls == [(failed.steps, None, None)]
    assert report.before.attack["diff_ok"] is False and report.before.attack["final_diff_sha256"] is None
    assert report.before.attack["error"] == "diff failed: git is broken"
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


def test_to_dict_is_json_and_holds_no_raw_diff():
    lab = Lab()
    report = lab.run()
    data = report.to_dict()
    text = json.dumps(data)
    assert EXPLOIT not in text and "attacks" not in data
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
    }
    assert set(data["before"]) == {
        "patches",
        "patch_outcomes",
        "gates",
        "exposure",
        "attack",
        "attack_grade",
        "holes",
        "error",
    }
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
    assert isinstance(report, HardenReport)
    assert report.attacks[0].final_diff == EXPLOIT and report.attacks[0].steps == [{"n": 1}, {"n": 2}]


def test_to_dict_of_a_stopped_run_is_json():
    for lab in (Lab(gold_ok=False), Lab(labels=("hard-code",)), Lab(fail={"attack": KeyError("k")})):
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
