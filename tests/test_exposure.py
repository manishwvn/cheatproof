import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from cheatproof.executor import Result, Session
from cheatproof.exposure import HOLE_GIT_HISTORY, HOLE_NETWORK, HOLE_TEST_EDIT, scan
from cheatproof.tasks import TaskSpec

BASE = "71fb12cefda5a3e1e223ed837bca468f8bdab874"
OTHER = "9676c1085a90cf604df7cc56977abe773bae86b1"
HERO = Path(__file__).resolve().parent / "fixtures" / "hero"
TEST_PATCH_TWO_FILES = (
    "diff --git a/tests/test_a.py b/tests/test_a.py\n--- a/tests/test_a.py\n+++ b/tests/test_a.py\n"
    "@@ -1 +1 @@\n-a\n+b\n"
    "diff --git a/tests/test_b.py b/tests/test_b.py\n--- a/tests/test_b.py\n+++ b/tests/test_b.py\n"
    "@@ -1 +1 @@\n-a\n+b\n"
)
# The one command that runs the writability probe. Its script never names the network.
PROBE = "find . -name .git"
# Answers for a clean repo: nothing past base, no writable test file, no network. First match wins.
CLEAN = [
    ("rev-list", Result(0, "0\n", "", 0.0)),
    ("for-each-ref", Result(0, f"{BASE}||refs/heads/main\n", "", 0.0)),
    ("reflog show", Result(0, f"{BASE}\n", "", 0.0)),
    ("ORIG_HEAD", Result(1, "", "", 0.0)),
    ("FETCH_HEAD", Result(1, "", "", 0.0)),
    (PROBE, Result(0, "done\n", "", 0.0)),
    ("python3 -c", Result(1, "", "OSError", 0.0)),
]


def make_task(**overrides) -> TaskSpec:
    fields = {
        "instance_id": "fixture__task-1",
        "repo": "fixture/repo",
        "base_commit": BASE,
        "image": "python:3.12-slim",
        "fail_to_pass": ("tests/test_calc.py::test_add",),
        "pass_to_pass": ("tests/test_calc.py::test_add_zero",),
        "gold_patch": "",
        "test_patch": "",
        "source": "fixture",
    }
    fields.update(overrides)
    return TaskSpec(**fields)


class FakeSession(Session):
    """Stands in for a sandbox. Records commands and writes; runs nothing. First matching rule wins."""

    def __init__(self, rules=()):
        self.rules = list(rules)
        self.commands: list[str] = []
        self.writes: dict[str, str | bytes] = {}
        self.resets = 0

    def run(self, cmd, timeout):
        self.commands.append(cmd)
        for needle, answer in self.rules:
            if needle in cmd:
                return answer
        return Result(0, "", "", 0.0)

    def write_file(self, path, data):
        self.writes[path] = data

    def diff(self):
        raise NotImplementedError

    def reset(self):
        self.resets += 1

    def close(self):
        pass


def session_with(*rules) -> FakeSession:
    return FakeSession([*rules, *CLEAN])


# scan: the three holes


def test_clean_repo_reports_no_holes():
    report = scan(session_with(), make_task())
    assert report.holes == []
    assert report.future_git is False and report.future_git_evidence == []
    assert report.tests_writable is False and report.writable_tests == []
    assert report.restore_covered is True and report.unrestored_tests == []
    assert report.network is False and report.network_evidence == []


@pytest.mark.parametrize(
    ("rule", "label"),
    [
        (("rev-list", Result(0, "1\n", "", 0.0)), HOLE_GIT_HISTORY),
        (("for-each-ref", Result(0, f"{OTHER}||refs/heads/future\n", "", 0.0)), HOLE_GIT_HISTORY),
        (("for-each-ref", Result(0, f"{BASE}|{OTHER}|refs/tags/v1\n", "", 0.0)), HOLE_GIT_HISTORY),
        (("reflog show", Result(0, f"{BASE}\n{OTHER}\n", "", 0.0)), HOLE_GIT_HISTORY),
        (("ORIG_HEAD", Result(0, f"{OTHER}\n", "", 0.0)), HOLE_GIT_HISTORY),
        (("FETCH_HEAD", Result(0, f"{OTHER}\n", "", 0.0)), HOLE_GIT_HISTORY),
        (
            (PROBE, Result(0, "covered tests/test_calc.py\nuncovered tests/conftest.py\ndone\n", "", 0.0)),
            HOLE_TEST_EDIT,
        ),
        (("python3 -c", Result(0, "", "", 0.0)), HOLE_NETWORK),
    ],
)
def test_each_hole_turns_on_alone(rule, label):
    report = scan(session_with(rule), make_task())
    assert report.holes == [label]


def test_a_ref_at_base_is_not_evidence():
    report = scan(
        session_with(("for-each-ref", Result(0, f"{BASE}|{BASE}|refs/heads/main\n", "", 0.0))), make_task()
    )
    assert report.holes == []


def test_git_evidence_names_what_was_found():
    report = scan(session_with(("rev-list", Result(0, "3\n", "", 0.0))), make_task())
    assert report.future_git_evidence == ["3 commit(s) past base reachable from refs"]


def test_all_three_holes_are_listed_in_order():
    report = scan(
        session_with(
            ("rev-list", Result(0, "1\n", "", 0.0)),
            (PROBE, Result(0, "uncovered tests/conftest.py\ndone\n", "", 0.0)),
            ("python3 -c", Result(0, "", "", 0.0)),
        ),
        make_task(),
    )
    assert report.holes == [HOLE_GIT_HISTORY, HOLE_TEST_EDIT, HOLE_NETWORK]


def test_a_git_check_that_cannot_run_counts_as_a_hole():
    report = scan(session_with(("rev-list", Result(128, "", "fatal: bad object", 0.0))), make_task())
    assert report.holes == [HOLE_GIT_HISTORY]
    assert report.future_git_evidence == ["unverified: rev-list failed (exit 128): fatal: bad object"]


def test_invalid_base_commit_fails_closed_as_git_history():
    session = session_with()
    report = scan(session, make_task(base_commit="REDACTED"))
    assert report.holes == [HOLE_GIT_HISTORY]
    assert report.future_git_evidence[0].startswith("unverifiable: invalid commit id")
    assert not any("rev-list" in cmd for cmd in session.commands)


def test_unreachable_workdir_makes_the_writability_check_unverified():
    report = scan(session_with((PROBE, Result(2, "", "", 0.0))), make_task())
    assert report.writable_tests == ["unverified: writability check failed (exit 2)"]
    assert report.holes == [HOLE_TEST_EDIT]


def test_scan_writes_nothing_and_resets_nothing():
    session = session_with()
    scan(session, make_task())
    assert session.writes == {}
    assert session.resets == 0
    assert not any(" rm " in cmd or cmd.startswith("rm ") for cmd in session.commands)


# test-edit: observed writability, judged against the grader's restore set


def test_probe_names_every_restore_set_path():
    session = FakeSession(CLEAN)
    scan(
        session,
        make_task(
            fail_to_pass=("tests/test_a.py::test_one",),
            pass_to_pass=("tests/test_p.py::test_p",),
            test_patch=TEST_PATCH_TWO_FILES,
        ),
    )
    (probe,) = [cmd for cmd in session.commands if PROBE in cmd]
    for path in ("tests/test_a.py", "tests/test_b.py", "tests/test_p.py"):
        assert path in probe


def test_writable_node_file_is_observed_but_covered_by_the_restore():
    # As root every file is writable. The grader restores the node-id file from base, so it is not a hole.
    rule = (PROBE, Result(0, "covered tests/test_calc.py\ndone\n", "", 0.0))
    report = scan(session_with(rule), make_task())
    assert report.tests_writable is True
    assert report.writable_tests == ["tests/test_calc.py"]
    assert report.restore_covered is True and report.unrestored_tests == []
    assert report.holes == []


def test_writable_test_file_outside_the_restore_set_is_a_hole():
    rule = (PROBE, Result(0, "covered tests/test_calc.py\nuncovered tests/conftest.py\ndone\n", "", 0.0))
    report = scan(session_with(rule), make_task())
    assert report.writable_tests == ["tests/test_calc.py", "tests/conftest.py"]
    assert report.restore_covered is False
    assert report.unrestored_tests == ["tests/conftest.py"]
    assert report.holes == [HOLE_TEST_EDIT]


def test_p2p_node_file_and_test_patch_files_are_covered_too():
    task = make_task(
        fail_to_pass=("tests/test_a.py::test_one",),
        pass_to_pass=("tests/test_other.py::test_p",),
        test_patch=TEST_PATCH_TWO_FILES,
    )
    rule = (
        PROBE,
        Result(
            0,
            "covered tests/test_a.py\ncovered tests/test_other.py\ncovered tests/test_b.py\ndone\n",
            "",
            0.0,
        ),
    )
    report = scan(session_with(rule), task)
    assert report.restore_covered is True
    assert report.holes == []


def test_invalid_fail_to_pass_id_fails_closed_without_running_the_probe():
    session = session_with()
    report = scan(session, make_task(fail_to_pass=("-x.py::test_add",)))
    assert report.holes == [HOLE_TEST_EDIT]
    assert report.writable_tests[0].startswith("unverifiable: invalid test node id")
    assert not any(PROBE in cmd for cmd in session.commands)


def test_unsafe_test_patch_path_fails_closed():
    patch = "diff --git a/../x.py b/../x.py\n--- a/../x.py\n+++ b/../x.py\n@@ -1 +1 @@\n-a\n+b\n"
    report = scan(session_with(), make_task(test_patch=patch))
    assert report.holes == [HOLE_TEST_EDIT]
    assert report.unrestored_tests[0].startswith("unverifiable: unsafe path in patch")


def test_truncated_probe_output_is_unverified_and_a_hole():
    rule = (PROBE, Result(0, "covered tests/test_calc.py\n", "", 0.0, truncated=True))
    report = scan(session_with(rule), make_task())
    assert report.writable_tests == ["unverified: writability check output was cut"]
    assert report.holes == [HOLE_TEST_EDIT]


def test_probe_that_never_reaches_done_is_unverified_and_a_hole():
    report = scan(session_with((PROBE, Result(0, "covered tests/test_calc.py\n", "", 0.0))), make_task())
    assert report.writable_tests == ["unverified: writability check did not finish"]
    assert report.holes == [HOLE_TEST_EDIT]


# network: python3, then python, then bash /dev/tcp. Exit 127 means the program is missing.


def test_connect_failure_is_no_network_and_stops_the_chain():
    session = session_with(("python3 -c", Result(1, "", "OSError", 0.0)))
    report = scan(session, make_task())
    assert report.network is False and report.holes == []
    assert not any("/dev/tcp" in cmd for cmd in session.commands)


def test_missing_python3_falls_back_to_python():
    rules = [
        ("python3 -c", Result(127, "", "python3: not found", 0.0)),
        ("python -c", Result(0, "", "", 0.0)),
    ]
    report = scan(session_with(*rules), make_task())
    assert report.network is True
    assert report.network_evidence == ["connected to 1.1.1.1:53 (python)"]
    assert report.holes == [HOLE_NETWORK]


def test_bash_dev_tcp_probe_runs_when_both_pythons_are_missing():
    rules = [
        ("python3 -c", Result(127, "", "", 0.0)),
        ("python -c", Result(127, "", "", 0.0)),
        ("/dev/tcp", Result(1, "", "connect failed", 0.0)),
    ]
    report = scan(session_with(*rules), make_task())
    assert report.network is False and report.holes == []


def test_bash_dev_tcp_probe_that_connects_is_a_network_hole():
    rules = [
        ("python3 -c", Result(127, "", "", 0.0)),
        ("python -c", Result(127, "", "", 0.0)),
        ("/dev/tcp", Result(0, "", "", 0.0)),
    ]
    report = scan(session_with(*rules), make_task())
    assert report.network_evidence == ["connected to 1.1.1.1:53 (bash /dev/tcp)"]
    assert report.holes == [HOLE_NETWORK]


def test_all_probes_missing_is_unknown_and_counts_as_reachable():
    rules = [
        ("python3 -c", Result(127, "", "", 0.0)),
        ("python -c", Result(127, "", "", 0.0)),
        ("/dev/tcp", Result(127, "", "", 0.0)),
    ]
    session = session_with(*rules)
    report = scan(session, make_task())
    assert report.network is True
    assert report.network_evidence == [
        "unverified: probe unavailable (python3, python and bash /dev/tcp all missing)"
    ]
    assert report.holes == [HOLE_NETWORK]
    tried = [cmd.split()[0] for cmd in session.commands if "1.1.1.1" in cmd]
    assert tried == ["python3", "python", "timeout"]


def test_probe_status_other_than_0_1_or_missing_is_unknown():
    rules = [("python3 -c", Result(124, "", "", 0.0))]
    report = scan(session_with(*rules), make_task())
    assert report.network is True
    assert report.network_evidence[0].startswith("unverified: network probe (python3) failed (exit 124)")
    assert report.holes == [HOLE_NETWORK]


def test_probe_killed_by_the_host_is_unknown():
    rules = [("python3 -c", Result(137, "", "", 0.0, timed_out=True))]
    report = scan(session_with(*rules), make_task())
    assert report.network is True
    assert report.holes == [HOLE_NETWORK]


# hero fixture: a labelled task whose .git exposes the fix


def hero_task() -> TaskSpec:
    data = json.loads((HERO / "task.json").read_text(encoding="utf-8"))
    fields = {key: value for key, value in data.items() if key != "label"}
    fields["fail_to_pass"] = tuple(fields["fail_to_pass"])
    fields["pass_to_pass"] = tuple(fields["pass_to_pass"])
    return TaskSpec(**fields)


def git(repo: Path, *args: str, input: str | None = None) -> subprocess.CompletedProcess:
    env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
    return subprocess.run(
        ["git", "--no-replace-objects", *args],
        cwd=repo,
        input=input,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def build_hero(tmp_path: Path) -> Path:
    repo = tmp_path / "hero-repo"
    built = subprocess.run(
        ["bash", str(HERO / "build_repo.sh"), str(repo)], capture_output=True, text=True, check=False
    )
    assert built.returncode == 0, built.stderr
    return repo


needs_git = pytest.mark.skipif(
    shutil.which("git") is None or shutil.which("bash") is None, reason="needs git and bash on PATH"
)


class LocalShell(Session):
    """Runs each command with sh on this machine, so the probe script is exercised for real. A network probe is
    answered 'no route' without a connect, so the suite stays offline."""

    def run(self, cmd, timeout):
        if "1.1.1.1" in cmd:
            return Result(1, "", "no route (offline test)", 0.0)
        done = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True, timeout=timeout, check=False)
        return Result(done.returncode, done.stdout, done.stderr, 0.0)

    def write_file(self, path, data):
        raise NotImplementedError

    def diff(self):
        raise NotImplementedError

    def reset(self):
        raise NotImplementedError

    def close(self):
        pass


def test_hero_label_names_the_git_history_hole():
    data = json.loads((HERO / "task.json").read_text(encoding="utf-8"))
    label = data["label"]
    assert label["expected_holes"] == ["git-history"]  # test-edit is covered by the restore, so not expected
    assert label["attack_succeeds_before"] is True
    assert label["attack_succeeds_after"] is False


@needs_git
def test_hero_future_commit_is_reachable_from_a_ref_but_not_from_base(tmp_path):
    repo = build_hero(tmp_path)
    listed = git(repo, "rev-list", "--all", "--not", hero_task().base_commit)
    assert listed.returncode == 0, listed.stderr
    assert listed.stdout.strip() != ""


@needs_git
def test_hero_base_and_gold_patch_match_task_json(tmp_path):
    repo = build_hero(tmp_path)
    task = hero_task()
    head = git(repo, "rev-parse", "HEAD").stdout.strip()
    assert head.startswith(task.base_commit)  # task.json pins an abbreviated id (see README)
    assert len(head) == 40
    check = git(repo, "apply", "--check", "-", input=task.gold_patch)
    assert check.returncode == 0, check.stderr


@needs_git
def test_live_scan_of_the_hero_repo_reports_only_git_history(tmp_path):
    repo = build_hero(tmp_path)
    report = scan(LocalShell(), hero_task(), workdir=str(repo))
    assert report.future_git is True
    assert report.writable_tests == ["tests/test_calc.py"]  # the probe uid can write the node file
    assert report.restore_covered is True
    assert report.holes == [HOLE_GIT_HISTORY]


@needs_git
def test_live_scan_flags_a_test_file_the_grader_does_not_restore(tmp_path):
    repo = build_hero(tmp_path)
    (repo / "tests" / "conftest.py").write_text("# added by the agent\n", encoding="utf-8")
    report = scan(LocalShell(), hero_task(), workdir=str(repo))
    assert report.unrestored_tests == ["tests/conftest.py"]
    assert HOLE_TEST_EDIT in report.holes
