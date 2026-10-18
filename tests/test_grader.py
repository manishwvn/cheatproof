import re
import shlex
from dataclasses import replace

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
    session = FakeSession([("pytest", Result(0, f"PASSED {F2P}\nPASSED {P2P}\n", "", 0.1))])
    result = grade(session, make_task(), GOLD)
    assert result.passed is False
    assert result.error == "pytest printed no final summary line"


def test_truncated_pytest_output_fails_closed():
    def cut(session, cmd):
        return replace(all_pass(session, cmd), truncated=True)

    result = grade(FakeSession([("pytest", cut)]), make_task(), GOLD)
    assert result.passed is False
    assert result.error is not None and "cut at the executor cap" in result.error


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
