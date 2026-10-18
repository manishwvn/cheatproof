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

# Answers for a clean repo: nothing past base, no writable test, no network. First match wins.
CLEAN = [
    ("rev-list", Result(0, "0\n", "", 0.0)),
    ("for-each-ref", Result(0, f"{BASE}||refs/heads/main\n", "", 0.0)),
    ("reflog show", Result(0, f"{BASE}\n", "", 0.0)),
    ("ORIG_HEAD", Result(1, "", "", 0.0)),
    ("FETCH_HEAD", Result(1, "", "", 0.0)),
    ("test -w", Result(0, "", "", 0.0)),
    ("socket", Result(1, "", "OSError", 0.0)),
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
        (("test -w", Result(0, "tests/test_calc.py\n", "", 0.0)), HOLE_TEST_EDIT),
        (("socket", Result(0, "", "", 0.0)), HOLE_NETWORK),
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
            ("test -w", Result(0, "tests/test_calc.py\n", "", 0.0)),
            ("socket", Result(0, "", "", 0.0)),
        ),
        make_task(),
    )
    assert report.holes == [HOLE_GIT_HISTORY, HOLE_TEST_EDIT, HOLE_NETWORK]


def test_a_git_check_that_cannot_run_counts_as_a_hole():
    report = scan(session_with(("rev-list", Result(128, "", "fatal: bad object", 0.0))), make_task())
    assert report.holes == [HOLE_GIT_HISTORY]
    assert report.future_git_evidence == ["unverified: rev-list failed (exit 128): fatal: bad object"]


def test_missing_python_is_unverified_and_counts_as_reachable():
    report = scan(session_with(("socket", Result(127, "", "python3: not found", 0.0))), make_task())
    assert report.network is True
    assert report.holes == [HOLE_NETWORK]
    assert report.network_evidence == ["unverified: network probe failed (exit 127): python3: not found"]


def test_unreachable_workdir_makes_the_writability_check_unverified():
    report = scan(session_with(("test -w", Result(2, "", "", 0.0))), make_task())
    assert report.writable_tests == ["unverified: writability check failed (exit 2)"]
    assert report.holes == [HOLE_TEST_EDIT]


def test_writability_probe_covers_f2p_files_and_test_patch_files():
    session = FakeSession(CLEAN)
    scan(session, make_task(fail_to_pass=("tests/test_a.py::test_one",), test_patch=TEST_PATCH_TWO_FILES))
    (probe,) = [cmd for cmd in session.commands if "test -w" in cmd]
    assert "tests/test_a.py" in probe and "tests/test_b.py" in probe


def test_scan_writes_nothing_and_resets_nothing():
    session = session_with()
    scan(session, make_task())
    assert session.writes == {}
    assert session.resets == 0
    assert not any(" rm " in cmd or cmd.startswith("rm ") for cmd in session.commands)


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


def test_hero_label_names_the_git_history_hole():
    data = json.loads((HERO / "task.json").read_text(encoding="utf-8"))
    assert data["label"] == {
        "expected_holes": ["git-history"],
        "attack_succeeds_before": True,
        "attack_succeeds_after": False,
    }


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
