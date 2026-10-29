"""control.py: the deterministic retrieval control, with fake sessions and fake grading (no sandbox, no model)."""

from __future__ import annotations

from types import SimpleNamespace

from rewardseal import control
from rewardseal.executor import Result
from rewardseal.tasks import TaskSpec

BASE = "a" * 40
C1, C2 = "1" * 40, "2" * 40
GOLD = """diff --git a/pkg/core.py b/pkg/core.py
--- a/pkg/core.py
+++ b/pkg/core.py
@@ -1,1 +1,2 @@
 x = 1
+value = compute_the_answer(parameter_one, parameter_two)
"""
OTHER = """diff --git a/pkg/core.py b/pkg/core.py
--- a/pkg/core.py
+++ b/pkg/core.py
@@ -1,1 +1,2 @@
 x = 1
+unrelated_helper = build_something_else(argument_alpha, argument_beta)
"""
TESTS = """diff --git a/tests/test_core.py b/tests/test_core.py
--- a/tests/test_core.py
+++ b/tests/test_core.py
@@ -1,1 +1,2 @@
 import pytest
+def test_it(): assert True
"""


def make_task() -> TaskSpec:
    return TaskSpec(
        instance_id="org__repo-1",
        repo="org/repo",
        base_commit=BASE,
        problem_statement="fix",
        gold_patch=GOLD,
        test_patch=TESTS,
        fail_to_pass=("tests/test_core.py::test_it",),
        pass_to_pass=(),
        image="img",
        source="swe-rebench",
    )


class FakeSession:
    """Answers the two git commands. `history` is what rev-list lists; stripped sessions list nothing."""

    def __init__(self, history: list[str], changes: dict[str, str]):
        self.history, self.changes, self.resets, self.stripped = history, changes, 0, False

    def reset(self) -> None:
        self.resets += 1
        self.stripped = False

    def run(self, cmd: str, timeout: float) -> Result:
        if "rev-list" in cmd:
            out = "" if self.stripped or not self.history else "\n".join(self.history) + "\n"
            return Result(0, out, "", 0.0)
        for commit, text in self.changes.items():
            if commit in cmd:
                return Result(0, text, "", 0.0)
        return Result(1, "", "unknown", 0.0)


def ops(session: FakeSession, passing: set[str]):
    def grade(sess, task, patch, timeout, workdir):
        ok = patch in passing
        return SimpleNamespace(passed=ok, applied=True, f2p_passed=int(ok), f2p_total=1, error=None)

    def strip(sess, task, names, workdir):
        sess._inner.stripped = True
        return [SimpleNamespace(ok=True)]

    def gate(*args, **kwargs):
        return SimpleNamespace(passed=True, applied=True, error=None)

    def empty(*args, **kwargs):
        return SimpleNamespace(passed=False, applied=True, error=None)

    return control.ControlOps(grade=grade, apply_patches=strip, gold_gate=gate, empty_gate=empty)


def test_the_best_overlapping_future_commit_is_tried_first_and_the_retrieval_passes():
    session = FakeSession([C1, C2], {C1: OTHER, C2: GOLD})
    rec = control.run_control(session, make_task(), ops=ops(session, passing={GOLD}))
    first = rec["before_strip"]["tried"][0]
    assert first["commit"] == C2[:12] and first["shared_gold_lines"] == 1 and first["passed"] is True
    assert rec["before_strip"]["retrieved_fix_passes_hidden_tests"] is True
    assert rec["before_strip"]["future_commits_touching_gold_files"] == 2


def test_after_the_strip_nothing_can_be_retrieved_and_the_gates_are_recorded():
    session = FakeSession([C1, C2], {C1: OTHER, C2: GOLD})
    rec = control.run_control(session, make_task(), ops=ops(session, passing={GOLD}))
    after = rec["after_strip"]
    assert after["future_commits_touching_gold_files"] == 0 and after["patch_applied"] is True
    assert after["gold_gate_ok"] is True and after["empty_gate_ok"] is True
    assert rec["disclaimer"].startswith("does not prove model causality")


def test_no_candidate_means_no_retrieval_and_a_failed_listing_raises():
    session = FakeSession([], {})
    rec = control.run_control(session, make_task(), ops=ops(session, passing=set()))
    assert rec["before_strip"]["tried"] == []
    assert rec["before_strip"]["retrieved_fix_passes_hidden_tests"] is False

    class Broken(FakeSession):
        def run(self, cmd, timeout):
            return Result(128, "", "fatal", 0.0)

    import pytest

    with pytest.raises(control.ControlError):
        control.run_control(Broken([], {}), make_task(), ops=ops(session, passing=set()))


def test_the_record_holds_only_ids_counts_and_flags(tmp_path):
    session = FakeSession([C2], {C2: GOLD})
    rec = control.run_control(session, make_task(), ops=ops(session, passing={GOLD}))
    path = control.write_record(rec, tmp_path)
    text = path.read_text(encoding="utf-8")
    assert "compute_the_answer" not in text and path.name == "org__repo-1-retrieval-control.json"


def test_listing_counts_unreadable_changes_and_disables_diff_drivers():
    ids = [f"{i:040x}" for i in range(1, 6)]

    class Mixed(FakeSession):
        def run(self, cmd, timeout):
            if "rev-list" in cmd:
                return Result(0, "\n".join(ids) + "\n", "", 0, truncated=True)
            assert all(flag in cmd for flag in ("--binary", "--no-ext-diff", "--no-textconv", "--no-color"))
            idx = next(i for i, commit in enumerate(ids) if commit in cmd)
            return [
                Result(0, GOLD, "", 0),
                Result(1, "", "", 0),
                Result(0, GOLD, "", 0, truncated=True),
                Result(0, "", "", 0),
                Result(128, "", "no parent", 0),
            ][idx]

    listing = control.candidates(Mixed([], {}), make_task(), workdir="/repo")
    assert listing.stats() == {
        "future_commits_touching_gold_files": 5,
        "readable_changes": 1,
        "unreadable_or_root": 4,
        "listing_complete": False,
        "candidate_cap_hit": False,
        "root_commits_supported": False,
    }


def test_rank_up_to_200_and_report_cap():
    ids = [f"{i:040x}" for i in range(1, 202)]
    session = FakeSession(ids, {commit: GOLD if i == 199 else OTHER for i, commit in enumerate(ids)})
    listing = control.candidates(session, make_task(), workdir="/repo")
    assert listing.listed == 201 and listing.candidate_cap_hit
    assert len(listing.ranked) == 200 and listing.ranked[0][0] == ids[199]


def test_truncated_listing_discards_only_the_incomplete_final_line():
    class Partial(FakeSession):
        def run(self, cmd, timeout):
            if "rev-list" in cmd:
                return Result(0, C1 + "\n123", "", 0, truncated=True)
            return super().run(cmd, timeout)

    listing = control.candidates(Partial([C1], {C1: GOLD}), make_task(), workdir="/repo")
    assert listing.listed == 1 and not listing.listing_complete


def test_strip_failures_are_accumulated_and_gates_require_their_own_strip():
    for failing in (0, 1, 2):
        session = FakeSession([], {})
        base_ops = ops(session, set())
        calls = []

        def strip(sess, task, names, workdir, calls=calls, failing=failing):
            calls.append(True)
            return [SimpleNamespace(ok=len(calls) - 1 != failing)]

        changed = control.ControlOps(base_ops.grade, strip, base_ops.gold_gate, base_ops.empty_gate)
        after = control.run_control(session, make_task(), ops=changed)["after_strip"]
        assert not after["patch_applied"]
        assert after["gold_gate_ok"] is (failing != 1)
        assert after["empty_gate_ok"] is (failing != 2)


def test_remaining_candidates_are_graded_after_strip_and_resets_are_counted():
    class Remaining(FakeSession):
        def run(self, cmd, timeout):
            result = super().run(cmd, timeout)
            if "rev-list" in cmd and self.stripped:
                return Result(0, C2 + "\n", "", 0, reset=True)
            return result

    session = Remaining([C1, C2], {C1: OTHER, C2: GOLD})
    rec = control.run_control(session, make_task(), ops=ops(session, {GOLD}))
    assert rec["after_strip"]["tried"][0]["passed"] is True
    assert rec["sandbox_resets"] == session.resets + 1


def test_failed_post_strip_attempt_is_recorded_and_affects_patch_result():
    session = FakeSession([C2], {C2: GOLD})
    base_ops = ops(session, {GOLD})
    calls = []

    def strip(sess, task, names, workdir):
        calls.append(True)
        return [SimpleNamespace(ok=len(calls) != 2)]

    changed = control.ControlOps(base_ops.grade, strip, base_ops.gold_gate, base_ops.empty_gate)
    after = control.run_control(session, make_task(), ops=changed)["after_strip"]
    assert after["tried"][0]["passed"] is False
    assert after["patch_applied"] is False
