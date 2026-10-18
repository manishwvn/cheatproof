import shlex

import pytest

from cheatproof.executor import Result, Session
from cheatproof.grader import (
    LOG_TAIL_CHARS,
    GateReport,
    GradeResult,
    diff_files,
    empty_gate,
    gold_gate,
    grade,
    node_outcomes,
    run_gates,
)
from cheatproof.tasks import TaskSpec

BASE = "71fb12cefda5a3e1e223ed837bca468f8bdab874"
F2P = "tests/test_x.py::test_new"
P2P = "tests/test_x.py::test_old"
GOLD_MARK = "GOLD-FIX"
GOLD = f"diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-bug\n+{GOLD_MARK}\n"
TEST_PATCH = "diff --git a/tests/test_x.py b/tests/test_x.py\n--- a/tests/test_x.py\n+++ b/tests/test_x.py\n@@ -1 +1 @@\n-a\n+b\n"
TEST_NEW = "diff --git a/tests/test_new.py b/tests/test_new.py\nnew file mode 100644\n--- /dev/null\n+++ b/tests/test_new.py\n@@ -0,0 +1 @@\n+x\n"
OK = Result(0, "", "", 0.0)
SUMMARY_HEADER = "=== short test summary info ==="


def make_task(**overrides) -> TaskSpec:
    fields = {
        "instance_id": "fixture__task-1",
        "repo": "fixture/repo",
        "base_commit": BASE,
        "image": "python:3.12-slim",
        "fail_to_pass": (F2P,),
        "pass_to_pass": (P2P,),
        "gold_patch": GOLD,
        "test_patch": TEST_PATCH,
        "source": "fixture",
    }
    fields.update(overrides)
    return TaskSpec(**fields)


class FakeSession(Session):
    """Stands in for a sandbox. Records commands, writes and resets; runs nothing.

    rules are (needle, answer) pairs and the first match wins. An answer is a Result, or a callable
    (session, cmd) -> Result. A command no rule matches exits 0 with no output. A cleanup rm -rf removes the
    files it names, as the real sandbox would.
    """

    def __init__(self, rules=()):
        self.rules = list(rules)
        self.commands: list[tuple[str, float]] = []
        self.writes: dict[str, str | bytes] = {}
        self.events: list[str] = []
        self.resets = 0

    def run(self, cmd, timeout):
        self.commands.append((cmd, timeout))
        self.events.append("run")
        if cmd.startswith("rm -rf -- "):
            gone = cmd.removeprefix("rm -rf -- ")
            self.writes = {
                path: data for path, data in self.writes.items() if not path.startswith(gone + "/")
            }
            return OK
        for needle, answer in self.rules:
            if needle in cmd:
                return answer(self, cmd) if callable(answer) else answer
        return OK

    def write_file(self, path, data):
        self.writes[path] = data

    def diff(self):
        raise NotImplementedError("the grader does not read a diff")

    def reset(self):
        self.resets += 1
        self.writes.clear()
        self.events.append("reset")

    def close(self):
        pass

    def cmds(self, needle):
        return [cmd for cmd, _ in self.commands if needle in cmd]


def summary(*lines: str) -> str:
    return "\n".join(["collected 2 items", "", SUMMARY_HEADER, *lines, "=== 2 tests in 0.01s ==="]) + "\n"


def pytest_nodes(cmd: str) -> list[str]:
    tokens = shlex.split(cmd)
    return tokens[tokens.index("-rA") + 1 :]


def all_pass(session, cmd):
    return Result(0, summary(*(f"PASSED {node}" for node in pytest_nodes(cmd))), "", 0.1)


def pytest_says(statuses: dict[str, str]):
    """Answer for one pytest run: each node gets its status, a node not in statuses gets no line."""

    def answer(session, cmd):
        lines = []
        for node in pytest_nodes(cmd):
            if node in statuses:
                status = statuses[node]
                lines.append(f"{status} {node}" + ("" if status == "PASSED" else " - boom"))
        code = 0 if all(status == "PASSED" for status in statuses.values()) else 1
        return Result(code, summary(*lines), "", 0.1)

    return answer


def fixed_only(session, cmd):
    """Passes F2P only when the candidate patch holds the gold fix. P2P always passes."""
    fixed = any(
        GOLD_MARK in str(data) for path, data in session.writes.items() if path.endswith("candidate.diff")
    )
    return pytest_says(
        {node: ("PASSED" if fixed or node == P2P else "FAILED") for node in pytest_nodes(cmd)}
    )(session, cmd)


def fake_result(passed: bool) -> GradeResult:
    return GradeResult(passed, 0, 0, 0, 0, True, None, "")


# node_outcomes: reading the -rA summary


def test_node_outcomes_reads_each_status():
    out = summary("PASSED a", "FAILED b - assert 1 == 2", "ERROR c - fixture broke", "SKIPPED e - no gpu")
    assert node_outcomes(out, ["a", "b", "c", "d", "e"]) == {
        "a": True,
        "b": False,
        "c": False,
        "d": False,
        "e": False,
    }


def test_node_outcomes_ignores_lines_outside_the_summary():
    out = "PASSED t.py::b\n" + summary("FAILED t.py::b - boom") + "PASSED t.py::b\n"
    assert node_outcomes(out, ["t.py::b"]) == {"t.py::b": False}


def test_node_outcomes_teardown_error_blocks_a_pass():
    out = summary("PASSED t.py::a", "ERROR t.py::a - teardown broke")
    assert node_outcomes(out, ["t.py::a"]) == {"t.py::a": False}


def test_node_outcomes_accepts_parametrized_ids_that_contain_a_separator():
    out = summary("PASSED t.py::test[a - b]", "FAILED t.py::test[c] - boom")
    assert node_outcomes(out, ["t.py::test[a - b]", "t.py::test[c]"]) == {
        "t.py::test[a - b]": True,
        "t.py::test[c]": False,
    }


def test_node_outcomes_without_a_summary_fails_every_node():
    assert node_outcomes("Traceback (most recent call last):\n", ["t.py::a"]) == {"t.py::a": False}


# grade: the pass rule and the apply steps


def test_passes_when_every_node_passes():
    session = FakeSession([("pytest", all_pass)])
    result = grade(session, make_task(), GOLD)
    assert result.passed is True
    assert (result.f2p_passed, result.f2p_total) == (1, 1)
    assert (result.p2p_passed, result.p2p_total) == (1, 1)
    assert result.applied is True
    assert result.error is None


def test_fail_to_pass_failure_fails_the_grade():
    session = FakeSession([("pytest", pytest_says({F2P: "FAILED", P2P: "PASSED"}))])
    result = grade(session, make_task(), GOLD)
    assert result.passed is False
    assert (result.f2p_passed, result.p2p_passed) == (0, 1)
    assert result.applied is True


def test_pass_to_pass_error_fails_the_grade():
    session = FakeSession([("pytest", pytest_says({F2P: "PASSED", P2P: "ERROR"}))])
    result = grade(session, make_task(), GOLD)
    assert result.passed is False
    assert (result.f2p_passed, result.p2p_passed) == (1, 0)


def test_node_missing_from_the_output_counts_as_a_failure():
    session = FakeSession([("pytest", pytest_says({F2P: "PASSED"}))])
    result = grade(session, make_task(), GOLD)
    assert result.passed is False
    assert (result.f2p_passed, result.p2p_passed, result.p2p_total) == (1, 0, 1)


def test_a_test_that_prints_a_pass_line_still_fails():
    printed = f"PASSED {F2P}\n"
    answer = Result(1, printed + summary(f"FAILED {F2P} - boom", f"PASSED {P2P}"), "", 0.0)
    result = grade(FakeSession([("pytest", answer)]), make_task(), GOLD)
    assert result.passed is False
    assert result.f2p_passed == 0


@pytest.mark.parametrize("patch", ["", "  \n"])
def test_blank_patch_skips_the_candidate_apply(patch):
    session = FakeSession([("pytest", all_pass)])
    result = grade(session, make_task(), patch)
    assert session.cmds("candidate.diff") == []
    assert not any(path.endswith("candidate.diff") for path in session.writes)
    assert session.cmds("hidden-tests.diff")
    assert result.applied is True


def test_candidate_that_does_not_apply_stops_before_any_test_runs():
    session = FakeSession(
        [("candidate.diff", Result(1, "", "error: patch failed: calc.py:3", 0.0)), ("pytest", all_pass)]
    )
    result = grade(session, make_task(), GOLD)
    assert result.applied is False
    assert result.passed is False
    assert result.error == "candidate patch did not apply: error: patch failed: calc.py:3"
    assert session.cmds("pytest") == []
    assert session.commands[-1][0].startswith("rm -rf -- /tmp/cheatproof-")  # cleanup still ran


def test_hidden_tests_that_clash_are_restored_to_base_then_retried():
    attempts = []

    def first_clash(session, cmd):
        attempts.append(cmd)
        if len(attempts) == 1:
            return Result(1, "", "error: patch failed: tests/test_x.py", 0.0)
        return OK

    session = FakeSession([("hidden-tests.diff", first_clash), ("pytest", all_pass)])
    result = grade(session, make_task(), GOLD)
    restore = session.cmds(" checkout ")
    assert len(restore) == 1
    assert BASE in restore[0] and "tests/test_x.py" in restore[0]
    assert len(attempts) == 2
    assert result.applied is True
    assert result.passed is True


def test_test_file_the_candidate_created_is_removed_before_the_retry():
    attempts = []

    def first_clash(session, cmd):
        attempts.append(cmd)
        return Result(1, "", "already exists", 0.0) if len(attempts) == 1 else OK

    session = FakeSession([("hidden-tests.diff", first_clash), ("pytest", all_pass)])
    result = grade(session, make_task(test_patch=TEST_NEW), GOLD)
    assert session.cmds("rm -f -- tests/test_new.py")
    assert session.cmds(" checkout ") == []
    assert result.applied is True
    assert result.passed is True


def test_hidden_tests_that_still_do_not_apply_fail_the_grade():
    session = FakeSession([("hidden-tests.diff", Result(1, "", "error: nope", 0.0)), ("pytest", all_pass)])
    result = grade(session, make_task(), GOLD)
    assert result.applied is False
    assert result.passed is False
    assert result.error == "hidden tests did not apply: error: nope"
    assert session.cmds("pytest") == []


def test_timed_out_run_fails_and_says_so():
    session = FakeSession([("pytest", Result(124, "", "[timed out]", 1.0, timed_out=True))])
    result = grade(session, make_task(), GOLD)
    assert result.passed is False
    assert result.applied is True
    assert result.error is not None and result.error.startswith("pytest timed out")


def test_task_without_fail_to_pass_fails_closed_without_touching_the_session():
    session = FakeSession()
    result = grade(session, make_task(fail_to_pass=()), GOLD)
    assert result.passed is False
    assert result.error == "task has no FAIL_TO_PASS tests"
    assert session.commands == []


def test_log_tail_keeps_only_the_end():
    noisy = "x" * 20_000
    answer = Result(1, noisy + summary(f"FAILED {F2P} - boom"), "", 0.0)
    result = grade(FakeSession([("pytest", answer)]), make_task(), GOLD)
    assert len(result.log_tail) <= LOG_TAIL_CHARS
    assert "short test summary info" in result.log_tail


# grade: quoting, hardening and ordering


def test_hostile_node_id_reaches_pytest_as_one_argument():
    hostile = "t.py::x; rm -rf /; echo $(id)"
    session = FakeSession([("pytest", all_pass)])
    result = grade(session, make_task(fail_to_pass=(hostile,), pass_to_pass=()), GOLD)
    (cmd,) = session.cmds("pytest")
    assert hostile in pytest_nodes(cmd)
    assert shlex.quote(hostile) in cmd
    assert result.passed is True


@pytest.mark.parametrize("node", ["--help", "-x", "t.py::a\nb", "t.py::a\0", ""])
def test_node_ids_that_read_as_options_or_break_lines_are_refused(node):
    session = FakeSession()
    with pytest.raises(ValueError):
        grade(session, make_task(fail_to_pass=(node,)), GOLD)
    assert session.commands == []


def test_long_node_lists_run_in_batches_and_every_node_counts():
    p2p = tuple(f"tests/test_big.py::test_case_{i:05d}" + "x" * 50 for i in range(3000))
    session = FakeSession([("pytest", all_pass)])
    result = grade(session, make_task(pass_to_pass=p2p), GOLD)
    runs = session.cmds("pytest")
    assert len(runs) > 1
    assert max(len(cmd) for cmd in runs) < 128 * 1024
    assert [node for cmd in runs for node in pytest_nodes(cmd)] == [F2P, *p2p]
    assert result.passed is True
    assert result.p2p_total == result.p2p_passed == 3000


def test_caches_are_cleared_before_the_candidate_is_applied():
    session = FakeSession([("pytest", all_pass)])
    grade(session, make_task(), GOLD)
    cleanup = next(i for i, (cmd, _) in enumerate(session.commands) if "__pycache__" in cmd)
    apply = next(i for i, (cmd, _) in enumerate(session.commands) if "candidate.diff" in cmd)
    assert cleanup < apply
    assert "-name '*.pyc'" in session.commands[cleanup][0]
    assert "-name .git -prune" in session.commands[cleanup][0]


def test_every_git_call_ignores_repo_config():
    session = FakeSession([("pytest", all_pass)])
    grade(session, make_task(), GOLD)
    git_cmds = [cmd for cmd, _ in session.commands if " git " in cmd]
    assert len(git_cmds) == 2  # the candidate apply and the hidden-tests apply
    for cmd in git_cmds:
        for flag in (
            "GIT_CONFIG_GLOBAL=/dev/null",
            "core.hooksPath=/dev/null",
            "core.attributesFile=/dev/null",
            "core.fsmonitor=false",
            "diff.external=",
            "--literal-pathspecs",
        ):
            assert flag in cmd, (flag, cmd)


def test_pytest_runs_in_testbed_without_bytecode_or_cache_writes():
    session = FakeSession([("pytest", all_pass)])
    grade(session, make_task(), GOLD)
    (cmd,) = session.cmds("pytest")
    assert cmd.startswith("cd /testbed && PYTHONDONTWRITEBYTECODE=1 python -m pytest ")
    assert "-p no:cacheprovider" in cmd and "-rA" in cmd


def test_workdir_can_be_overridden():
    session = FakeSession([("pytest", all_pass)])
    grade(session, make_task(), GOLD, workdir="/work tree")
    assert session.cmds("pytest")[0].startswith("cd '/work tree' && ")


@pytest.mark.parametrize("timeout", [0, -1, float("nan")])
def test_non_positive_timeout_is_refused(timeout):
    with pytest.raises(ValueError):
        grade(FakeSession(), make_task(), GOLD, timeout)


def test_base_commit_must_be_a_hex_id():
    with pytest.raises(ValueError):
        grade(FakeSession(), make_task(base_commit="main; rm -rf /"), GOLD)


def test_test_patch_paths_must_stay_inside_the_workdir():
    bad = "diff --git a/../evil.py b/../evil.py\n--- a/../evil.py\n+++ b/../evil.py\n@@ -1 +1 @@\n-a\n+b\n"
    with pytest.raises(ValueError):
        grade(FakeSession(), make_task(test_patch=bad), GOLD)


def test_diff_files_lists_changed_and_new_files():
    assert diff_files(TEST_PATCH + TEST_NEW) == [("tests/test_x.py", False), ("tests/test_new.py", True)]


def test_diff_files_of_a_removed_file_uses_its_old_path():
    removed = (
        "diff --git a/tests/old.py b/tests/old.py\n--- a/tests/old.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n"
    )
    assert diff_files(removed) == [("tests/old.py", False)]


def test_diff_files_of_an_empty_patch_is_empty():
    assert diff_files("") == []


# gates


def test_gold_gate_passes_and_empty_gate_fails_on_the_same_session():
    session = FakeSession([("pytest", fixed_only)])
    assert gold_gate(session, make_task()).passed is True
    assert empty_gate(session, make_task()).passed is False


def test_run_gates_resets_before_each_grade_and_reports_ok():
    session = FakeSession([("pytest", fixed_only)])
    report = run_gates(session, make_task())
    assert report.gold.passed is True
    assert report.empty.passed is False
    assert report.ok is True
    assert session.resets == 2
    assert session.events[0] == "reset"
    second_reset = session.events.index("reset", 1)
    assert "run" in session.events[:second_reset]


@pytest.mark.parametrize(
    ("gold", "empty", "ok"),
    [(True, False, True), (False, False, False), (True, True, False), (False, True, False)],
)
def test_gate_report_ok_needs_gold_to_pass_and_empty_to_fail(gold, empty, ok):
    assert GateReport(gold=fake_result(gold), empty=fake_result(empty)).ok is ok
