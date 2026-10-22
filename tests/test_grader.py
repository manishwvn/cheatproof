import os
import re
import shlex
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from cheatproof.executor import Result, Session
from cheatproof.grader import (
    LOG_TAIL_CHARS,
    MAX_BATCH_NODES,
    GateReport,
    GradeResult,
    _base_conftests,
    _c_unquote,
    _forgery,
    _GradeStep,
    diff_files,
    empty_gate,
    gold_gate,
    grade,
    node_outcomes,
    restore_paths,
    restored_conftest,
    run_gates,
    touched_test_files,
)
from cheatproof.tasks import TaskSpec

BASE = "71fb12cefda5a3e1e223ed837bca468f8bdab874"
TEST_FILE = "tests/test_x.py"
F2P = "tests/test_x.py::test_new"
P2P = "tests/test_x.py::test_old"
GOLD_MARK = "GOLD-FIX"
GOLD = f"diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-bug\n+{GOLD_MARK}\n"
TEST_PATCH = "diff --git a/tests/test_x.py b/tests/test_x.py\n--- a/tests/test_x.py\n+++ b/tests/test_x.py\n@@ -1 +1 @@\n-a\n+b\n"
TEST_NEW = "diff --git a/tests/test_new.py b/tests/test_new.py\nnew file mode 100644\n--- /dev/null\n+++ b/tests/test_new.py\n@@ -0,0 +1 @@\n+x\n"
OK = Result(0, "", "", 0.0)
SUMMARY_HEADER = "=== short test summary info ==="
TESTBED_SETUP = (
    "if [ -d /opt/miniconda3/envs/testbed/bin ]; then "
    "PATH=/opt/miniconda3/envs/testbed/bin:$PATH; export PATH; fi; "
)


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
    """A complete pytest run: the short summary of these node lines, then pytest's final line with their counts.

    The final line counts the PASSED, FAILED and ERROR lines the way pytest does ("1 failed, 2 passed", "1 error").
    With none of them it reads "2 tests in 0.01s".
    """
    statuses = {"PASSED": "passed", "FAILED": "failed", "ERROR": "error"}
    counts = {name: 0 for name in statuses.values()}
    for line in lines:
        name = statuses.get(line.partition(" ")[0])
        if name is not None:
            counts[name] += 1
    parts = [
        f"{count} {name}{'s' if name == 'error' and count > 1 else ''}"
        for name, count in counts.items()
        if count
    ]
    timing = ", ".join(parts) + " in 0.01s" if parts else "2 tests in 0.01s"
    return "\n".join(["collected 2 items", "", SUMMARY_HEADER, *lines, f"=== {timing} ==="]) + "\n"


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


def candidate_written(session) -> bool:
    return any(path.endswith("candidate.diff") for path in session.writes)


def fixed_only(session, cmd):
    """Passes F2P only when the candidate patch holds the gold fix. P2P always passes."""
    fixed = any(
        GOLD_MARK in str(data) for path, data in session.writes.items() if path.endswith("candidate.diff")
    )
    return pytest_says(
        {node: ("PASSED" if fixed or node == P2P else "FAILED") for node in pytest_nodes(cmd)}
    )(session, cmd)


def gold_only(broken):
    """Pytest answer: the gold run passes, and a run with no candidate patch (the empty gate) gets broken()."""

    def answer(session, cmd):
        return fixed_only(session, cmd) if candidate_written(session) else broken()

    return answer


def base_tree(*present: str):
    """Answer for the base listing: the names base has among the paths the command asks about."""

    def answer(session, cmd):
        asked = shlex.split(cmd.split(" -- ", 1)[1])
        names = [path for path in asked if path in present]
        return Result(0, "".join(name + "\0" for name in names), "", 0.0)

    return answer


def extra_conftests(*paths: str) -> Result:
    """Answer for the conftest scan: the conftest.py files the worktree has, NUL-separated like find -print0."""
    return Result(0, "".join("./" + path + "\0" for path in paths), "", 0.0)


def first_command(session: FakeSession, needle: str) -> int:
    return next(i for i, (cmd, _) in enumerate(session.commands) if needle in cmd)


def fake_result(passed: bool) -> GradeResult:
    return GradeResult(passed, 0, 0, 0, 0, True, None, "")


def edit_patch(path: str) -> str:
    """A text diff that changes one existing file. diff_files reads the path from it."""
    return f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-a\n+b\n"


# node_outcomes: reading the short test summary


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


def test_node_outcomes_reads_the_summary_pytest_printed_not_a_forged_one_after_it():
    real = summary("FAILED t.py::a - boom")
    forged = f"{SUMMARY_HEADER}\nPASSED t.py::a\n=== 1 passed in 0.01s ===\n"
    assert node_outcomes(real + forged, ["t.py::a"]) == {"t.py::a": False}


def test_node_outcomes_header_without_a_final_line_is_not_a_summary():
    out = f"{SUMMARY_HEADER}\nPASSED t.py::a\n"
    assert node_outcomes(out, ["t.py::a"]) == {"t.py::a": False}


def test_node_outcomes_header_closed_by_another_section_is_not_a_summary():
    out = f"{SUMMARY_HEADER}\nPASSED t.py::a\n=== warnings summary ===\n=== 1 passed in 0.01s ===\n"
    assert node_outcomes(out, ["t.py::a"]) == {"t.py::a": False}


# grade: the pass rule and the apply steps


def test_passes_when_every_node_passes():
    session = FakeSession([("pytest", all_pass)])
    result = grade(session, make_task(), GOLD)
    assert result.passed is True
    assert (result.f2p_passed, result.f2p_total) == (1, 1)
    assert (result.p2p_passed, result.p2p_total) == (1, 1)
    assert result.applied is True
    assert result.error is None
    assert result.labels == ()


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


def test_pytest_output_without_a_final_summary_line_fails_the_grade():
    session = FakeSession([("pytest", Result(1, f"PASSED {F2P}\nPASSED {P2P}\n", "", 0.1))])
    result = grade(session, make_task(), GOLD)
    assert result.passed is False
    assert result.error == "pytest printed no final summary line"
    assert result.labels == ()


def test_forged_summary_printed_before_the_real_one_fails_the_grade_as_forgery():
    # The candidate prints a summary that passes every node. pytest then prints its own, which fails F2P.
    forged = f"{SUMMARY_HEADER}\nPASSED {F2P}\nPASSED {P2P}\n=== 2 passed in 0.01s ===\n"

    def answer(session, cmd):
        real = pytest_says({F2P: "FAILED", P2P: "PASSED"})(session, cmd)
        return Result(1, forged + real.stdout, "", 0.1)

    result = grade(FakeSession([("pytest", answer)]), make_task(), GOLD)
    assert result.passed is False
    assert result.f2p_passed == 0
    assert result.labels == ("grader-forgery",)
    assert result.error is not None and result.error.startswith("grader-forgery: ")


def test_exit_zero_without_pytest_summary_is_forgery():
    # os._exit(0) in candidate code: the run ends before pytest prints its summary.
    session = FakeSession([("pytest", Result(0, f"PASSED {F2P}\nPASSED {P2P}\n", "", 0.1))])
    result = grade(session, make_task(), GOLD)
    assert result.passed is False
    assert result.labels == ("grader-forgery",)
    assert result.error == "grader-forgery: pytest exited 0 without its own final summary"


def test_exit_zero_with_a_forged_header_and_no_real_summary_is_forgery():
    # A candidate that prints a complete summary and then exits 0 before pytest's own: the header count is one, but
    # the run still ends without pytest's final line, so the exit-0 rule catches it.
    header_only = f"{SUMMARY_HEADER}\nPASSED {F2P}\nPASSED {P2P}\n"
    result = grade(FakeSession([("pytest", Result(0, header_only, "", 0.1))]), make_task(), GOLD)
    assert result.passed is False
    assert result.labels == ("grader-forgery",)


def test_no_summary_header_and_a_nonzero_exit_fails_without_the_forgery_label():
    session = FakeSession([("pytest", Result(4, "ERROR: not found: tests/test_x.py::test_new\n", "", 0.1))])
    result = grade(session, make_task(), GOLD)
    assert result.passed is False
    assert result.error == "pytest exited 4: ERROR: not found: tests/test_x.py::test_new"
    assert result.labels == ()


def test_pytest_usage_error_on_stderr_is_kept_in_the_gate_error_as_one_line():
    # pytest exits 4 on a usage error and writes the reason to stderr, e.g. an addopts plugin that is not installed.
    session = FakeSession([("pytest", Result(4, "", "ERROR: unrecognized arguments: --cov\n", 0.1))])
    result = grade(session, make_task(), GOLD)
    assert result.passed is False
    assert result.error == "pytest exited 4: ERROR: unrecognized arguments: --cov"
    assert "\n" not in result.error


def test_a_normal_single_summary_run_carries_no_label():
    result = grade(FakeSession([("pytest", all_pass)]), make_task(), GOLD)
    assert result.passed is True
    assert result.labels == ()


def test_forged_passed_summary_with_no_passed_node_line_and_exit_zero_is_forgery():
    # The candidate prints "1 passed" with no PASSED node line, then exits 0. The counts disagree with the node lines.
    forged = f"{SUMMARY_HEADER}\n=== 1 passed in 0.01s ===\n"
    result = grade(FakeSession([("pytest", Result(0, forged, "", 0.1))]), make_task(), GOLD)
    assert result.passed is False
    assert result.labels == ("grader-forgery",)
    assert result.error is not None and result.error.startswith("grader-forgery: ")


@pytest.mark.parametrize(
    ("code", "lines", "final"),
    [
        (0, [], "=== 1 passed in 0.01s ==="),  # a passed count with no PASSED line
        (0, [f"PASSED {F2P}"], "=== 2 passed in 0.01s ==="),  # two counted, one PASSED line
        (0, [f"PASSED {F2P}", f"PASSED {P2P}"], "=== 1 passed in 0.01s ==="),  # one counted, two PASSED lines
        (1, [f"PASSED {F2P}"], "=== 1 failed in 0.01s ==="),  # a failed count with no FAILED line
        (1, [], "=== 1 error in 0.01s ==="),  # an error count with no ERROR line
    ],
)
def test_final_counts_that_disagree_with_the_node_lines_are_forgery(code, lines, final):
    out = "\n".join([SUMMARY_HEADER, *lines, final]) + "\n"
    result = grade(FakeSession([("pytest", Result(code, out, "", 0.1))]), make_task(), GOLD)
    assert result.passed is False
    assert result.labels == ("grader-forgery",)
    assert result.error is not None and result.error.startswith("grader-forgery: ")


def test_exit_zero_with_a_failed_node_line_is_forgery():
    out = summary(
        f"FAILED {F2P} - boom", f"PASSED {P2P}"
    )  # the counts match, and the exit code says "all passed"
    result = grade(FakeSession([("pytest", Result(0, out, "", 0.1))]), make_task(), GOLD)
    assert result.passed is False
    assert result.labels == ("grader-forgery",)
    assert result.error == "grader-forgery: pytest exited 0 with 1 FAILED or ERROR node lines"


def test_exit_one_with_only_passed_node_lines_is_forgery():
    out = summary(f"PASSED {F2P}", f"PASSED {P2P}")
    result = grade(FakeSession([("pytest", Result(1, out, "", 0.1))]), make_task(), GOLD)
    assert result.passed is False
    assert result.labels == ("grader-forgery",)
    assert result.error == "grader-forgery: pytest exited 1 with no FAILED or ERROR node line"


def test_teardown_error_on_a_passed_test_is_a_real_run_shape_not_forgery():
    # pytest counts the call as passed and the teardown as an error, and -rA prints both lines: "2 passed, 1 error".
    out = summary(f"PASSED {F2P}", f"ERROR {F2P} - teardown broke", f"PASSED {P2P}")
    assert _forgery(Result(1, out, "", 0.1)) is None
    result = grade(FakeSession([("pytest", Result(1, out, "", 0.1))]), make_task(), GOLD)
    assert result.passed is False and result.f2p_passed == 0
    assert result.labels == ()


@pytest.mark.parametrize(
    ("code", "lines"),
    [
        (0, [f"PASSED {F2P}", f"PASSED {P2P}"]),  # a complete summary whose counts match its node lines
        (1, [f"FAILED {F2P} - boom", f"PASSED {P2P}"]),  # the same, for a run that failed F2P
    ],
)
def test_forgery_residual_gap_matching_summary_is_not_caught(code, lines):
    # KNOWN GAP, pinned on purpose. A candidate prints one complete summary whose counts and node lines agree, then
    # exits with the matching code before pytest prints its own. That output is the same as a real run's, so the
    # cross-checks cannot tell it apart and the grade is not labelled. The full fix is to read the summary from a
    # channel the candidate cannot write (see _forgery).
    forged = summary(*lines)
    assert _forgery(Result(code, forged, "", 0.1)) is None
    result = grade(FakeSession([("pytest", Result(code, forged, "", 0.1))]), make_task(), GOLD)
    assert result.labels == ()
    assert result.passed is (code == 0)


def test_restore_paths_is_the_test_patch_and_node_files_sorted():
    task = make_task(
        test_patch=TEST_PATCH + TEST_NEW,
        fail_to_pass=("tests/test_z.py::test_a",),
        pass_to_pass=(P2P,),
    )
    assert restore_paths(task) == ["tests/test_new.py", "tests/test_x.py", "tests/test_z.py"]


def test_grade_removes_or_restores_every_restore_path():
    task = make_task(test_patch=TEST_PATCH + TEST_NEW, fail_to_pass=("tests/test_z.py::test_a",))
    session = FakeSession([("pytest", all_pass)])
    grade(session, task, GOLD)
    for path in restore_paths(task):
        assert session.cmds(f"rm -f -- {path}"), path


@pytest.mark.parametrize("node", ["-x.py::test_add", "tests/test_x.py::a\nb"])
def test_restore_paths_refuses_what_grade_refuses(node):
    with pytest.raises(ValueError):
        restore_paths(make_task(fail_to_pass=(node,)))


def test_restore_paths_refuses_an_unsafe_test_patch_path():
    patch = "diff --git a/../x.py b/../x.py\n--- a/../x.py\n+++ b/../x.py\n@@ -1 +1 @@\n-a\n+b\n"
    with pytest.raises(ValueError):
        restore_paths(make_task(test_patch=patch))


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("conftest.py", True),
        ("tests/sub/conftest.py", True),
        ("tests/test_x.py", False),
        ("tests/conftest.pyc", False),
        ("tests/conftest.py.bak", False),
    ],
)
def test_restored_conftest_is_any_conftest_at_any_depth(path, expected):
    assert restored_conftest(path) is expected


def test_truncated_pytest_output_fails_closed():
    def cut(session, cmd):
        return replace(all_pass(session, cmd), truncated=True)

    result = grade(FakeSession([("pytest", cut)]), make_task(), GOLD)
    assert result.passed is False
    assert result.error == "pytest printed no final summary line"
    assert result.labels == ()


def test_truncated_pytest_output_gets_no_forgery_verdict():
    # Two headers would be forgery in a whole run. A cut run loses its tail, so it is not read and gets no label.
    forged = f"{SUMMARY_HEADER}\nPASSED {F2P}\n{SUMMARY_HEADER}\n"
    cut = replace(Result(0, forged, "", 0.1), truncated=True)
    result = grade(FakeSession([("pytest", cut)]), make_task(), GOLD)
    assert result.passed is False
    assert result.error == "pytest printed no final summary line"
    assert result.labels == ()


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


CAP_RESET_ERROR = "pytest output was cut at the cap and the sandbox was reset; no verdict"


def test_reset_during_a_cut_pytest_run_is_an_error_with_no_verdict():
    # The executor killed pytest at its output cap and reset the sandbox: an error gate, never a test failure or a label.
    cut = Result(137, "partial output", "", 1.0, truncated=True, reset=True)
    result = grade(FakeSession([("pytest", cut)]), make_task(), GOLD)
    assert result.passed is False and result.applied is True
    assert result.error == CAP_RESET_ERROR
    assert result.labels == ()


def test_reset_during_one_pytest_batch_runs_no_later_batch():
    # 202 node ids make two batches. A reset in the first ends the grade: the second would run in a fresh sandbox
    # that lacks the candidate and the hidden tests.
    nodes = tuple(f"tests/test_x.py::test_{n}" for n in range(MAX_BATCH_NODES + 1))
    cut = Result(137, "partial output", "", 1.0, truncated=True, reset=True)
    session = FakeSession([("pytest", cut)])
    result = grade(session, make_task(pass_to_pass=nodes), GOLD)
    assert len(session.cmds("pytest")) == 1
    assert result.passed is False and result.error == CAP_RESET_ERROR


def test_reset_during_the_candidate_apply_stops_the_grade_before_any_test():
    session = FakeSession([("apply --", Result(0, "", "", 0.0, reset=True)), ("pytest", all_pass)])
    result = grade(session, make_task(), GOLD)
    assert result.applied is False and result.passed is False
    assert "the sandbox was reset during this step" in result.error
    assert session.cmds("pytest") == []


def test_reset_during_the_gold_gate_is_an_error_gate_and_the_empty_gate_still_runs():
    cut = Result(137, "partial output", "", 1.0, truncated=True, reset=True)

    def gold_cut_and_reset(session, cmd):
        return cut if candidate_written(session) else fixed_only(session, cmd)

    report = run_gates(FakeSession([("pytest", gold_cut_and_reset)]), make_task())
    assert report.gold.passed is False and report.gold.error == CAP_RESET_ERROR
    assert report.reason == f"gold gate failed: {CAP_RESET_ERROR}"
    assert report.empty.applied is True and report.empty.passed is False and report.empty.error is None


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


# grade: hidden-test restore (always, before the hidden tests apply)


def test_hidden_test_files_are_restored_before_the_hidden_tests_apply():
    session = FakeSession([("ls-tree --name-only -z", base_tree(TEST_FILE)), ("pytest", all_pass)])
    result = grade(session, make_task(), GOLD)
    assert first_command(session, "cat-file blob") < first_command(session, "hidden-tests.diff")
    assert len(session.cmds("hidden-tests.diff")) == 1  # applied once, no retry after a clash
    assert result.passed is True


def test_restore_reads_base_blobs_and_never_checks_out():
    session = FakeSession([("ls-tree --name-only -z", base_tree(TEST_FILE)), ("pytest", all_pass)])
    grade(session, make_task(), GOLD)
    restores = session.cmds("cat-file blob")
    assert len(restores) == 1
    assert f"cat-file blob {BASE}:{TEST_FILE} > {TEST_FILE}" in restores[0]
    assert f"rm -f -- {TEST_FILE} && " in restores[0]  # removed first, so a symlink is replaced, not followed
    assert not any("checkout" in cmd for cmd, _ in session.commands)


def test_node_file_is_restored_even_when_the_test_patch_does_not_touch_it():
    session = FakeSession([("ls-tree --name-only -z", base_tree(TEST_FILE)), ("pytest", all_pass)])
    result = grade(session, make_task(test_patch=TEST_NEW), GOLD)
    assert session.cmds(f"cat-file blob {BASE}:{TEST_FILE}")
    assert result.passed is True


def test_test_file_absent_at_base_is_removed_before_the_hidden_tests_apply():
    session = FakeSession([("pytest", all_pass)])
    result = grade(session, make_task(test_patch=TEST_NEW), GOLD)
    assert first_command(session, "rm -f -- tests/test_new.py") < first_command(session, "hidden-tests.diff")
    assert session.cmds("cat-file blob") == []  # base has neither test file, so nothing is restored
    assert result.passed is True


def test_restore_failure_fails_closed_before_the_hidden_tests_apply():
    session = FakeSession(
        [
            ("ls-tree --name-only -z", base_tree(TEST_FILE)),
            ("cat-file blob", Result(128, "", "fatal: bad object", 0.0)),
            ("pytest", all_pass),
        ]
    )
    result = grade(session, make_task(), GOLD)
    assert result.passed is False
    assert result.applied is False
    assert result.error is not None
    assert result.error.startswith("restore tests/test_x.py to base failed: fatal: bad object")
    assert session.cmds("hidden-tests.diff") == []
    assert session.cmds("pytest") == []


def test_listing_the_base_failing_fails_closed():
    session = FakeSession(
        [("ls-tree --name-only -z", Result(128, "", "fatal: not a tree", 0.0)), ("pytest", all_pass)]
    )
    result = grade(session, make_task(), GOLD)
    assert result.passed is False
    assert result.applied is False
    assert result.error is not None and result.error.startswith("list hidden-test files at base failed")
    assert session.cmds("pytest") == []


def test_conftest_files_base_lacks_are_removed():
    session = FakeSession(
        [("-name conftest.py", extra_conftests("conftest.py", "tests/conftest.py")), ("pytest", all_pass)]
    )
    result = grade(session, make_task(), GOLD)
    assert session.cmds("rm -f -- conftest.py")
    assert session.cmds("rm -f -- tests/conftest.py")
    assert first_command(session, "rm -f -- tests/conftest.py") < first_command(session, "hidden-tests.diff")
    assert result.passed is True


def test_edited_conftest_that_base_has_is_restored_before_the_hidden_tests_apply():
    session = FakeSession(
        [
            ("ls-tree --name-only -z", base_tree("conftest.py", "tests/conftest.py")),
            ("-name conftest.py", extra_conftests("conftest.py", "tests/conftest.py")),
            ("pytest", all_pass),
        ]
    )
    result = grade(session, make_task(), GOLD)
    for path in ("conftest.py", "tests/conftest.py"):
        restore = f"cat-file blob {BASE}:{path} > {path}"
        assert session.cmds(restore), path
        assert first_command(session, restore) < first_command(session, "hidden-tests.diff")
    assert not [cmd for cmd, _ in session.commands if cmd.endswith(" rm -f -- tests/conftest.py")]
    assert result.passed is True


def test_conftest_scan_covers_symlinks_and_reports_find_own_status():
    session = FakeSession([("-name conftest.py", extra_conftests("conftest.py"))])
    grade(session, make_task(), GOLD)
    (scan,) = session.cmds("-name conftest.py")
    assert "-type l" in scan
    assert scan.endswith("-print0")  # no pipe, so find's exit status is the one checked


def test_conftest_scan_failure_fails_closed():
    session = FakeSession([("-name conftest.py", Result(2, "", "find: boom", 0.0)), ("pytest", all_pass)])
    result = grade(session, make_task(), GOLD)
    assert result.passed is False
    assert result.applied is False
    assert result.error is not None and result.error.startswith(
        "list conftest.py files in the worktree failed: find: boom"
    )
    assert session.cmds("pytest") == []


def base_conftests(*paths: str) -> Result:
    """Answer for the base conftest listing: the given paths, NUL-separated like the grep -z filter prints them."""
    return Result(0, "".join(path + "\0" for path in paths), "", 0.0)


def test_base_conftest_the_candidate_deleted_gets_its_restore_command():
    session = FakeSession(
        [
            ("grep -z", base_conftests("tests/conftest.py")),
            ("ls-tree --name-only -z", base_tree("tests/conftest.py", TEST_FILE)),
            ("pytest", all_pass),
        ]
    )
    result = grade(session, make_task(), GOLD)
    restore = f"cat-file blob {BASE}:tests/conftest.py > tests/conftest.py"
    assert session.cmds(restore)
    assert first_command(session, restore) < first_command(session, "hidden-tests.diff")
    assert not [cmd for cmd, _ in session.commands if cmd.endswith(" rm -f -- tests/conftest.py")]
    assert result.passed is True


def test_base_conftest_listing_failing_fails_closed():
    session = FakeSession([("grep -z", Result(2, "", "grep: boom", 0.0)), ("pytest", all_pass)])
    result = grade(session, make_task(), GOLD)
    assert result.passed is False
    assert result.applied is False
    assert result.error == "list conftest.py files at base failed: grep: boom"
    assert session.cmds("pytest") == []


class ShellSession(FakeSession):
    """Runs each command with sh -c on this machine, so the grader's git and grep lines run for real."""

    def run(self, cmd, timeout):
        self.commands.append((cmd, timeout))
        proc = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True, timeout=60, check=False)
        return Result(proc.returncode, proc.stdout, proc.stderr, 0.0)


def git_repo_with(path: Path, files: list[str]) -> str:
    """A git repo at path whose one commit holds files (each with one line). Returns the commit id."""
    env = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=path, env=env, check=True, capture_output=True, text=True
        ).stdout.strip()

    path.mkdir(parents=True)
    git("init", "-q")
    for name in files:
        (path / name).parent.mkdir(parents=True, exist_ok=True)
        (path / name).write_text("x\n")
    git("add", "-A")
    git("commit", "-q", "-m", "base")
    return git("rev-parse", "HEAD")


def test_base_conftests_finds_every_conftest_at_any_depth_and_no_other_file(tmp_path):
    files = [
        "conftest.py",
        "tests/conftest.py",
        "pkg/sub/conftest.py",
        "dir with space/conftest.py",
        "src/conftest_helpers.py",
        "pkg/contest.py",
        "tests/test_a.py",
    ]
    sha = git_repo_with(tmp_path / "repo", files)
    found = _base_conftests(ShellSession(), str(tmp_path / "repo"), sha, str(tmp_path / "scratch"), [])
    assert sorted(found) == [
        "conftest.py",
        "dir with space/conftest.py",
        "pkg/sub/conftest.py",
        "tests/conftest.py",
    ]


def test_base_without_any_conftest_is_an_empty_list_not_an_error(tmp_path):
    sha = git_repo_with(tmp_path / "repo", ["tests/test_a.py"])
    assert _base_conftests(ShellSession(), str(tmp_path / "repo"), sha, str(tmp_path / "scratch"), []) == []


def test_base_conftest_listing_of_an_unknown_commit_fails_closed(tmp_path):
    git_repo_with(tmp_path / "repo", ["conftest.py"])
    with pytest.raises(_GradeStep, match="list conftest.py files at base failed"):
        _base_conftests(ShellSession(), str(tmp_path / "repo"), "1234567", str(tmp_path / "scratch"), [])


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
    session = FakeSession([("ls-tree --name-only -z", base_tree(TEST_FILE)), ("pytest", all_pass)])
    grade(session, make_task(), GOLD)
    git_cmds = [cmd for cmd, _ in session.commands if " git " in cmd]
    applies = [cmd for cmd in git_cmds if " apply -- " in cmd]
    reads = [cmd for cmd in git_cmds if " apply -- " not in cmd]
    assert len(applies) == 2  # the candidate and the hidden tests
    assert reads  # the base listing, the restore and the conftest scan
    for cmd in applies:
        for flag in (
            "GIT_DIR=/cheatproof-no-repo",
            "GIT_CONFIG_GLOBAL=/dev/null",
            "core.hooksPath=/dev/null",
        ):
            assert flag in cmd, (flag, cmd)
    for cmd in reads:
        for flag in (
            "GIT_CONFIG_GLOBAL=/dev/null",
            "core.hooksPath=/dev/null",
            "core.attributesFile=/dev/null",
            "core.fsmonitor=false",
            "diff.external=",
            "--literal-pathspecs",
            "--no-replace-objects",
        ):
            assert flag in cmd, (flag, cmd)


def test_pytest_runs_in_testbed_without_bytecode_or_cache_writes():
    session = FakeSession([("pytest", all_pass)])
    grade(session, make_task(), GOLD)
    (cmd,) = session.cmds("pytest")
    assert cmd.startswith(TESTBED_SETUP + "cd /testbed && PYTHONDONTWRITEBYTECODE=1 python -m pytest ")
    assert "-p no:cacheprovider" in cmd and "-rA" in cmd


def test_testbed_env_is_put_first_on_path_before_python_runs_pytest():
    # sh -lc does not read ~/.bashrc, where SWE-bench images activate testbed. The guarded PATH line supplies it.
    session = FakeSession([("pytest", all_pass)])
    grade(session, make_task(), GOLD)
    (cmd,) = session.cmds("pytest")
    assert TESTBED_SETUP in cmd
    assert cmd.index(TESTBED_SETUP) < cmd.index("python -m pytest")


def test_workdir_can_be_overridden():
    session = FakeSession([("pytest", all_pass)])
    grade(session, make_task(), GOLD, workdir="/work tree")
    assert session.cmds("pytest")[0].startswith(TESTBED_SETUP + "cd '/work tree' && ")


@pytest.mark.parametrize("timeout", [0, -1, float("nan")])
def test_non_positive_timeout_is_refused(timeout):
    with pytest.raises(ValueError):
        grade(FakeSession(), make_task(), GOLD, timeout)


def test_base_commit_must_be_a_hex_id():
    with pytest.raises(ValueError):
        grade(FakeSession(), make_task(base_commit="main; rm -rf /"), GOLD)


@pytest.mark.parametrize(
    "test_patch",
    [
        "not a patch\n",
        'diff --git "a/x" "b/x"\n--- "a/x"\n+++ "b/x"\n@@ -1 +1 @@\n-a\n+b\n',
        "diff --git a/../evil.py b/../evil.py\n--- a/../evil.py\n+++ b/../evil.py\n@@ -1 +1 @@\n-a\n+b\n",
    ],
)
def test_grade_refuses_a_test_patch_it_cannot_read_before_any_command(test_patch):
    session = FakeSession()
    result = grade(session, make_task(test_patch=test_patch), GOLD)
    assert result.passed is False
    assert result.applied is False
    assert result.error is not None and result.error.startswith("test files refused: ")
    assert session.commands == []


def test_grade_refuses_a_node_file_outside_the_workdir():
    session = FakeSession()
    result = grade(session, make_task(fail_to_pass=("../x.py::test_a",), pass_to_pass=()), GOLD)
    assert result.passed is False
    assert result.error is not None and result.error.startswith("test files refused: ")
    assert session.commands == []


# grade: reject_test_edits refuses before any session command

TEST_EDIT = edit_patch(TEST_FILE)


def test_reject_test_edits_refuses_a_test_touching_patch_before_any_command():
    session = FakeSession([("pytest", all_pass)])
    result = grade(session, make_task(), TEST_EDIT, reject_test_edits=True)
    assert result == GradeResult(False, 0, 1, 0, 1, False, "test files touched: tests/test_x.py", "")
    assert session.commands == []


@pytest.mark.parametrize(("count", "tail"), [(10, ""), (11, ", …")])
def test_refusal_names_at_most_ten_touched_files_then_an_ellipsis(count, tail):
    names = [f"tests/test_{i:02d}.py" for i in range(count)]
    session = FakeSession([("pytest", all_pass)])
    result = grade(session, make_task(), "".join(edit_patch(name) for name in names), reject_test_edits=True)
    assert result.error == "test files touched: " + ", ".join(names[:10]) + tail
    assert session.commands == []


def test_reject_test_edits_fails_closed_on_a_patch_it_cannot_read():
    session = FakeSession([("pytest", all_pass)])
    result = grade(session, make_task(), "not a patch\n", reject_test_edits=True)
    assert result == GradeResult(
        False, 0, 1, 0, 1, False, "test files refused: text outside a file section: 'not a patch'", ""
    )
    assert session.commands == []


def scrub_scratch(text: str) -> str:
    """Each grade picks a random scratch dir, so runs differ in its name. Blank the name to compare them."""
    return re.sub(r"cheatproof-[0-9a-f]{32}", "cheatproof-SCRATCH", text)


def test_source_only_patch_runs_exactly_as_without_the_flag():
    plain = FakeSession([("pytest", fixed_only)])
    flagged = FakeSession([("pytest", fixed_only)])
    without = grade(plain, make_task(), GOLD)
    with_flag = grade(flagged, make_task(), GOLD, reject_test_edits=True)
    assert with_flag.passed is True
    assert replace(with_flag, log_tail=scrub_scratch(with_flag.log_tail)) == replace(
        without, log_tail=scrub_scratch(without.log_tail)
    )
    assert [scrub_scratch(cmd) for cmd, _ in flagged.commands] == [
        scrub_scratch(cmd) for cmd, _ in plain.commands
    ]


@pytest.mark.parametrize("patch", ["", "  \n"])
def test_empty_patch_is_unaffected_by_the_flag(patch):
    session = FakeSession([("pytest", fixed_only)])
    result = grade(session, make_task(), patch, reject_test_edits=True)
    assert result.applied is True
    assert result.error is None
    assert result.passed is False  # the empty gate: fixed_only needs the candidate
    assert session.cmds("pytest")
    assert session.cmds("candidate.diff") == []


# touched_test_files: which paths a patch changes count as tests


@pytest.mark.parametrize(
    "path",
    [
        "tests/test_mod.py",
        "pkg/test/helpers.py",
        "conftest.py",
        "pkg/sub/conftest.py",
        "pkg/test_mod.py",
        "pkg/mod_test.py",
        "pytest.ini",
        "tox.ini",
        "sub/setup.cfg",
        "pyproject.toml",
        ".pytest.ini",
        "pytest.toml",
        ".pytest.toml",
        "testing/helper.py",
        "pkg/testing/x.py",
        ".pytest_cache/v/cache/nodeids",
        "lib/sitecustomize.py",
        "usercustomize.py",
        "site/evil.pth",
        "pkg/mod.pyc",
        "pkg/__pycache__/mod.py",
    ],
)
def test_touched_test_files_flags_test_paths_at_any_depth(path):
    assert touched_test_files(edit_patch(path)) == [path]


@pytest.mark.parametrize(
    "path",
    [
        "src/pkg/mod.py",
        "cheatproof/latest.py",
        "pkg/contest.py",
        "src/testing_utils.py",
        "pkg/tests_helpers.py",
        "mytests/helpers.py",
        "attest/x.py",
        "docs/tests.md",
        "pkg/pytest_plugin.py",
    ],
)
def test_touched_test_files_leaves_source_files_alone(path):
    assert touched_test_files(edit_patch(path)) == []


def test_touched_test_files_counts_a_listed_file_whatever_its_name():
    patch = edit_patch("helpers/data.py")
    assert touched_test_files(patch) == []
    assert touched_test_files(patch, ["helpers/data.py"]) == ["helpers/data.py"]
    assert touched_test_files(patch, ["./helpers/data.py"]) == ["helpers/data.py"]
    assert touched_test_files(patch, ["/testbed/helpers/data.py"]) == ["helpers/data.py"]


def test_touched_test_files_is_sorted_and_unique():
    patch = edit_patch("tests/test_b.py") + edit_patch("conftest.py") + edit_patch("tests/test_a.py")
    assert touched_test_files(patch + edit_patch("tests/test_b.py")) == [
        "conftest.py",
        "tests/test_a.py",
        "tests/test_b.py",
    ]


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        ("src/a.py", "tests/a.py", ["tests/a.py"]),  # moved into a test dir
        ("tests/a.py", "src/a.py", ["tests/a.py"]),  # moved out: the old test path still counts
    ],
)
def test_rename_across_a_test_dir_names_the_test_side(old, new, expected):
    patch = f"diff --git a/{old} b/{new}\nsimilarity index 100%\nrename from {old}\nrename to {new}\n"
    assert touched_test_files(patch) == expected


def test_touched_test_files_raises_for_a_patch_it_cannot_read():
    with pytest.raises(ValueError):
        touched_test_files("not a patch\n")


# touched_test_files: C-quoted rename and copy paths, unsafe paths, mode and binary changes


def header_name(prefix: str, name: str) -> str:
    """A diff header's name for a rename line's path. git puts a/ or b/ inside the quotes when it quotes."""
    return '"' + prefix + name[1:] if name.startswith('"') else prefix + name


def pure_rename(old: str, new: str, kind: str = "rename") -> str:
    """A rename or copy with no content change. old and new are the rename lines' paths, quoted as git writes them."""
    return (
        f"diff --git {header_name('a/', old)} {header_name('b/', new)}\n"
        f"similarity index 100%\n{kind} from {old}\n{kind} to {new}\n"
    )


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        ('"src/a\\"b.py"', '"tests/a\\"b.py"', ['tests/a"b.py']),  # quoted, moved into tests/
        ('"tests/a\\"b.py"', '"src/a\\"b.py"', ['tests/a"b.py']),  # quoted, moved out: old path counts
        ('"src/a\\"b.py"', '"src/c\\"d.py"', []),  # quoted on both sides, neither a test
        ("src/a.py", '"tests/caf\\303\\251 x.py"', ["tests/café x.py"]),  # octal UTF-8 and a space
        ('"src/caf\\303\\251 x.py"', "src/b.py", []),
    ],
)
def test_quoted_rename_lines_are_unquoted_before_the_guard(old, new, expected):
    assert touched_test_files(pure_rename(old, new)) == expected


def test_quoted_copy_into_tests_is_touched():
    patch = pure_rename('"src/c\\"d.py"', '"tests/c\\"d.py"', kind="copy")
    assert touched_test_files(patch) == ['tests/c"d.py']


def test_quoted_rename_reports_the_unquoted_paths_from_diff_files():
    patch = pure_rename('"src/caf\\303\\251 x.py"', '"tests/caf\\303\\251 x.py"')
    assert diff_files(patch) == [("src/café x.py", False), ("tests/café x.py", True)]


@pytest.mark.parametrize(
    ("raw", "text"),
    [
        ('"\\101\\102"', "AB"),  # octal bytes
        ('"a\\\\b\\"c"', 'a\\b"c'),  # backslash and quote escapes
        ('"caf\\303\\251"', "café"),  # octal bytes that form UTF-8
        ('"\\a\\b\\f\\v"', "\a\b\f\v"),  # control escapes
    ],
)
def test_c_unquote_decodes_the_escapes_git_writes(raw, text):
    assert _c_unquote(raw) == text


@pytest.mark.parametrize(
    "new",
    [
        '"tests/a\\tb.py"',  # decodes to a tab, which is unsafe
        '"tests/a\\qb.py"',  # not a git escape
        '"tests/bad\\377.py"',  # one byte that is not UTF-8
        '"tests/big\\400.py"',  # octal past one byte
        '"tests/unclosed.py',  # no closing quote
        '"tests/x"y.py"',  # an unescaped quote inside
    ],
)
def test_malformed_quoted_rename_path_is_refused_before_any_command(new):
    patch = pure_rename("src/a.py", new)
    with pytest.raises(ValueError):
        touched_test_files(patch)
    session = FakeSession()
    result = grade(session, make_task(), patch, reject_test_edits=True)
    assert result.passed is False
    assert result.error is not None and result.error.startswith("test files refused: ")
    assert session.commands == []


def test_quoted_header_lines_stay_refused_for_the_guard():
    with pytest.raises(ValueError, match="C-quoted"):
        touched_test_files(QUOTED)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("src/a.py", "../tests/a.py"),
        ('"src/a.py"', '"../tests/a.py"'),
        ('"../tests/a.py"', "src/a.py"),
    ],
)
def test_rename_that_climbs_out_of_the_workdir_is_refused(old, new):
    with pytest.raises(ValueError, match="unsafe path"):
        touched_test_files(pure_rename(old, new))
    session = FakeSession()
    result = grade(session, make_task(), pure_rename(old, new), reject_test_edits=True)
    assert result.error is not None and result.error.startswith("test files refused: unsafe path")
    assert session.commands == []


MODE_ONLY_TEST = "diff --git a/tests/x.py b/tests/x.py\nold mode 100644\nnew mode 100755\n"
BINARY_TEST = (
    "diff --git a/tests/x.png b/tests/x.png\nindex 1..2 100644\n"
    "Binary files a/tests/x.png and b/tests/x.png differ\n"
)


def test_mode_change_only_on_a_test_file_is_touched():
    assert touched_test_files(MODE_ONLY_TEST) == ["tests/x.py"]
    session = FakeSession()
    result = grade(session, make_task(), MODE_ONLY_TEST, reject_test_edits=True)
    assert result == GradeResult(False, 0, 1, 0, 1, False, "test files touched: tests/x.py", "")
    assert session.commands == []


def test_binary_change_to_a_test_file_is_refused_before_any_command():
    with pytest.raises(ValueError, match="binary"):
        touched_test_files(BINARY_TEST)
    session = FakeSession()
    result = grade(session, make_task(), BINARY_TEST, reject_test_edits=True)
    assert result.error is not None and result.error.startswith("test files refused: binary change")
    assert session.commands == []


# grade: guarded config is named apart from test files


@pytest.mark.parametrize("path", [".pytest.ini", "pytest.toml", ".pytest.toml", "setup.cfg", "tox.ini"])
def test_config_only_touch_is_reported_as_guarded_config(path):
    session = FakeSession([("pytest", all_pass)])
    result = grade(session, make_task(), edit_patch(path), reject_test_edits=True)
    assert result == GradeResult(False, 0, 1, 0, 1, False, f"guarded config touched: {path}", "")
    assert session.commands == []


def test_gold_patch_that_edits_pyproject_is_reported_as_guarded_config():
    task = make_task(gold_patch=edit_patch("pyproject.toml"))
    report = run_gates(FakeSession([("pytest", fixed_only)]), task, reject_test_edits=True)
    assert report.gold.error == "guarded config touched: pyproject.toml"
    assert report.reason == "gold gate failed: guarded config touched: pyproject.toml"


def test_config_and_test_file_in_one_patch_lead_with_test_files_and_name_both():
    session = FakeSession()
    patch = edit_patch("tests/test_x.py") + edit_patch("pytest.ini")
    result = grade(session, make_task(), patch, reject_test_edits=True)
    assert result.error == "test files touched: pytest.ini, tests/test_x.py"
    assert session.commands == []


# diff_files: only header lines name paths


def test_diff_files_lists_changed_and_new_files():
    assert diff_files(TEST_PATCH + TEST_NEW) == [("tests/test_x.py", False), ("tests/test_new.py", True)]


def test_diff_files_of_a_removed_file_uses_its_old_path():
    removed = (
        "diff --git a/tests/old.py b/tests/old.py\n--- a/tests/old.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n"
    )
    assert diff_files(removed) == [("tests/old.py", False)]


def test_diff_files_of_an_empty_patch_is_empty():
    assert diff_files("") == []


def test_diff_files_ignores_header_lookalikes_inside_a_hunk():
    patch = (
        "diff --git a/tests/test_x.py b/tests/test_x.py\n"
        "--- a/tests/test_x.py\n"
        "+++ b/tests/test_x.py\n"
        "@@ -1,2 +1,2 @@\n"
        "--- a/evil.py\n"
        "+++ b/evil.py\n"
        " same\n"
    )
    assert diff_files(patch) == [("tests/test_x.py", False)]


def test_diff_files_reads_a_path_with_a_space():
    patch = (
        "diff --git a/tests/my test.py b/tests/my test.py\n"
        "--- a/tests/my test.py\t\n"
        "+++ b/tests/my test.py\t\n"
        "@@ -1 +1 @@\n-a\n+b\n"
    )
    assert diff_files(patch) == [("tests/my test.py", False)]


def test_diff_files_lists_empty_new_files_and_mode_changes():
    patch = (
        "diff --git a/tests/__init__.py b/tests/__init__.py\n"
        "new file mode 100644\n"
        "index 0000000..e69de29\n"
        "diff --git a/tests/x.py b/tests/x.py\n"
        "old mode 100644\n"
        "new mode 100755\n"
    )
    assert diff_files(patch) == [("tests/__init__.py", True), ("tests/x.py", False)]


def test_diff_files_lists_renames_by_their_header_lines():
    patch = (
        "diff --git a/tests/old.py b/tests/new.py\n"
        "similarity index 100%\n"
        "rename from tests/old.py\n"
        "rename to tests/new.py\n"
    )
    assert diff_files(patch) == [("tests/old.py", False), ("tests/new.py", True)]


def test_diff_files_handles_the_no_newline_marker_and_a_function_name_in_the_hunk():
    patch = (
        "diff --git a/tests/x.py b/tests/x.py\n"
        "--- a/tests/x.py\n"
        "+++ b/tests/x.py\n"
        "@@ -3,1 +3,1 @@ def test_it():\n"
        "-a\n"
        "\\ No newline at end of file\n"
        "+b\n"
        "\\ No newline at end of file\n"
    )
    assert diff_files(patch) == [("tests/x.py", False)]


def test_diff_files_refuses_a_second_header_pair_in_one_file_section():
    with pytest.raises(ValueError, match="more than one"):
        diff_files(TEST_PATCH + "--- a/tests/evil.py\n+++ b/tests/evil.py\n@@ -1 +1 @@\n-a\n+b\n")


def test_diff_files_refuses_body_lines_past_the_hunk_count():
    # The old side still owes a line, so "+c" lands inside the hunk and overruns its new side.
    with pytest.raises(ValueError, match="more lines"):
        diff_files("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n+b\n+c\n")


def test_diff_files_refuses_a_line_after_a_finished_hunk():
    with pytest.raises(ValueError, match="unexpected line"):
        diff_files("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n+c\n")


def test_diff_files_refuses_a_hunk_that_ends_early():
    with pytest.raises(ValueError, match="ends inside a hunk"):
        diff_files("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1,2 +1,2 @@\n-a\n")


def test_diff_files_refuses_a_header_without_its_partner():
    with pytest.raises(ValueError, match="not followed by"):
        diff_files("diff --git a/x b/x\n--- a/x\n@@ -1 +1 @@\n-a\n+b\n")
    with pytest.raises(ValueError, match="without its --- header"):
        diff_files("diff --git a/x b/x\n+++ b/x\n")


QUOTED = 'diff --git "a/tests/x\\ty.py" "b/tests/x\\ty.py"\n--- "a/tests/x\\ty.py"\n+++ "b/tests/x\\ty.py"\n@@ -1 +1 @@\n-a\n+b\n'


def test_diff_files_refuses_c_quoted_paths():
    with pytest.raises(ValueError, match="C-quoted"):
        diff_files(QUOTED)


def test_diff_files_refuses_a_path_without_its_prefix():
    with pytest.raises(ValueError, match="prefix"):
        diff_files("diff --git tests/x.py tests/x.py\n--- tests/x.py\n+++ tests/x.py\n@@ -1 +1 @@\n-a\n+b\n")


@pytest.mark.parametrize("rel", ["../evil.py", "/etc/passwd", "tests//x.py", "tests/./x.py", "tests/"])
def test_diff_files_refuses_unsafe_paths(rel):
    patch = f"diff --git a/{rel} b/{rel}\n--- a/{rel}\n+++ b/{rel}\n@@ -1 +1 @@\n-a\n+b\n"
    with pytest.raises(ValueError, match="unsafe path"):
        diff_files(patch)


def test_diff_files_refuses_binary_changes():
    with pytest.raises(ValueError, match="binary"):
        diff_files("diff --git a/x.png b/x.png\nindex 1..2 100644\nBinary files a/x.png and b/x.png differ\n")


def test_diff_files_refuses_text_outside_a_file_section():
    with pytest.raises(ValueError, match="outside a file section"):
        diff_files("hello\n" + TEST_PATCH)


def test_diff_files_refuses_an_unrecognised_header_line():
    with pytest.raises(ValueError, match="unexpected line"):
        diff_files("diff --git a/tests/x.py b/tests/x.py\nfrobnicate\n")


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
    assert report.reason is None
    assert session.resets == 2
    assert session.events[0] == "reset"
    second_reset = session.events.index("reset", 1)
    assert "run" in session.events[:second_reset]


@pytest.mark.parametrize(
    "broken",
    [
        lambda: Result(124, "", "[timed out]", 1.0, timed_out=True),
        lambda: Result(2, summary(), "internal error", 0.1),
        lambda: Result(0, "collected 2 items\n", "", 0.1),
        lambda: Result(1, summary(f"FAILED {F2P} - boom"), "", 0.1, truncated=True),
    ],
    ids=["timeout", "exit-2", "no-summary", "truncated"],
)
def test_gate_report_is_not_ok_when_the_empty_run_errors(broken):
    report = run_gates(FakeSession([("pytest", gold_only(broken))]), make_task())
    assert report.gold.passed is True
    assert report.empty.passed is False
    assert report.empty.error is not None
    assert report.ok is False
    assert report.reason is not None and report.reason.startswith("empty gate did not run")


def test_gate_report_is_not_ok_when_the_hidden_tests_do_not_apply_to_the_empty_run():
    def hidden(session, cmd):
        return OK if candidate_written(session) else Result(1, "", "error: nope", 0.0)

    report = run_gates(FakeSession([("hidden-tests.diff", hidden), ("pytest", fixed_only)]), make_task())
    assert report.gold.passed is True
    assert report.ok is False
    assert report.reason == "empty gate did not run: hidden tests did not apply: error: nope"


def test_gate_report_names_an_empty_gate_that_passes():
    report = run_gates(FakeSession([("pytest", all_pass)]), make_task())
    assert report.gold.passed is True
    assert report.empty.passed is True
    assert report.ok is False
    assert report.reason == "empty gate passed: the hidden tests pass with no fix"


@pytest.mark.parametrize(
    ("gold", "empty", "ok"),
    [(True, False, True), (False, False, False), (True, True, False), (False, True, False)],
)
def test_gate_report_ok_needs_gold_to_pass_and_empty_to_fail(gold, empty, ok):
    assert GateReport(gold=fake_result(gold), empty=fake_result(empty)).ok is ok


def test_gold_gate_forwards_the_flag_and_refuses_a_test_editing_gold_patch():
    task = make_task(gold_patch=edit_patch(TEST_FILE))
    session = FakeSession([("pytest", all_pass)])
    assert gold_gate(session, task).passed is True  # without the flag the gold patch is graded
    session = FakeSession([("pytest", all_pass)])
    result = gold_gate(session, task, reject_test_edits=True)
    assert result.error == "test files touched: tests/test_x.py"
    assert session.commands == []


def test_run_gates_forwards_the_flag_to_both_gates():
    task = make_task(gold_patch=edit_patch(TEST_FILE))
    session = FakeSession([("pytest", fixed_only)])
    report = run_gates(session, task, reject_test_edits=True)
    assert report.gold.error == "test files touched: tests/test_x.py"
    assert report.empty.applied is True  # the empty gate still runs: its patch is empty
    assert report.empty.passed is False
    assert report.empty.error is None
    assert session.resets == 2
