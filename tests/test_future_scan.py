"""T55: the targeted history scan after the attack (exposure.future_scan) replaces T53's global pre-attack digests.

Root cause of "future_added_complete is False on every live run": T53 digested the raw added lines of ALL future
commits and cut at 400 commits and 60 KB (`head -c 60000`). A repo with 378 future commits adds far more than 60 KB of
lines, so the cut was always hit and the list never counted as complete. The fix reads only the lines of the files
that matter (the final diff's and the gold patch's non-test files), after the attack, with sanity caps that are far
away and that make complete False when hit.

Fakes and throwaway local repositories only: no model, sandbox, network or paid call. The version control commands of
the scan run for real against a repo built in tmp_path (under sh and dash, with awk); everything else a sandbox would
answer (the writability and network probes) comes from a fake.
"""

import dataclasses
import hashlib
import json
import shutil
import subprocess

import pytest
import test_exposure as te
import test_git_history_evidence as tg
import test_harden as thd
import test_holes as th
import test_keep as tk

from rewardseal import certify, cli, confirm, exposure, holes, keep, site
from rewardseal.attacker import AttackResult
from rewardseal.executor import Result
from rewardseal.exposure import FutureScan, future_scan, scan
from rewardseal.harden import RoundReport
from rewardseal.holes import FutureAdded, classify, future_line_digest

FUTURE_LINE = tg.FUTURE_LINE
OTHER_LINE = tg.OTHER_LINE
SHELLS = [pytest.param("sh", id="sh"), pytest.param("dash", id="dash")]
GIT_MARK = "GIT_CONFIG_NOSYSTEM"  # every command built by grader.git_command carries this


def _need(shell):
    if shutil.which(shell) is None:
        pytest.skip(f"{shell} is not installed")
    if shutil.which("awk") is None:
        pytest.skip("awk is not installed")


class HybridSession(te.FakeSession):
    """Runs the scan's version control lines for real in a throwaway repo, through sh or dash. Everything else (the
    writability probe, the network probe) is answered by the fake rules: no network is ever touched. stdout is cut at
    the executor's per-stream cap and marked truncated, as the real executor does."""

    CAP = 64 * 1024

    def __init__(self, shell="sh", rules=te.CLEAN):
        super().__init__(rules)
        self.shell = shell

    def run(self, cmd, timeout):
        self.commands.append(cmd)
        if GIT_MARK not in cmd:
            return super().run(cmd, timeout)
        # Bytes, decoded without newline translation: a CR in a file must reach the scan as the sandbox gives it.
        done = subprocess.run([self.shell, "-c", cmd], check=False, capture_output=True, timeout=60)
        raw = done.stdout
        cut = "--no-walk" in cmd and len(raw) > self.CAP
        if cut:
            raw = raw[: self.CAP]
        return Result(
            done.returncode,
            raw.decode("utf-8", "replace"),
            done.stderr.decode("utf-8", "replace"),
            0.0,
            truncated=cut,
        )


class Repo:
    def __init__(self, path):
        self.path = path
        self.base = ""

    def git(self, *args, input=None):
        return subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
            cwd=self.path,
            capture_output=True,
            text=True,
            check=True,
            input=input,
        ).stdout.strip()

    def write(self, name, text):
        target = self.path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def commit_all(self, message):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD")

    def fast_import(self, branch, files_per_commit):
        """One commit per item on top of the current branch tip; each item is {path: text}. Fast: 600 commits at once."""
        tip = self.git("rev-parse", "HEAD")
        lines = []
        for index, files in enumerate(files_per_commit):
            lines += [
                f"commit refs/heads/{branch}",
                f"committer t <t@example.com> {1_700_000_000 + index} +0000",
            ]
            message = f"future {index}"
            lines += [f"data {len(message)}", message]
            if index == 0:
                lines.append(f"from {tip}")
            for path, text in files.items():
                lines += [f"M 100644 inline {path}", f"data {len(text.encode())}", text]
            lines.append("")
        self.git("fast-import", "--quiet", input="\n".join(lines) + "\n")


CORE_BASE = "def total(items):\n    value = old()\n    return 0\n"
CORE_FIXED = f"def total(items):\n{FUTURE_LINE}\n    return total\n"
GOLD_CORE = th._patch("pkg/core.py", ["    value = old()"], ["    gold_marker = compute_gold_value(items)"])


def make_repo(path):
    r = Repo(path)
    r.git("init", "-q", "-b", "main")
    r.write("pkg/core.py", CORE_BASE)
    r.write("pkg/other.py", "def other():\n    return 1\n")
    r.base = r.commit_all("base")
    return r


@pytest.fixture
def repo(tmp_path):
    return make_repo(tmp_path)


def task_for(r, **kwargs):
    fields = {"base_commit": r.base, "gold_patch": GOLD_CORE}
    fields.update(kwargs)
    return te.make_task(**fields)


def pre_scan(r, shell="sh", **kwargs):
    session = HybridSession(shell)
    return session, scan(session, task_for(r, **kwargs), workdir=str(r.path))


def docs(i):
    """About 3 KB of added lines that are not in any target file."""
    return {
        f"docs/page{i % 7}.md": "\n".join(
            f"entry {i} {j} written text for the documentation" for j in range(60)
        )
    }


# --- root cause and the fix at scale ------------------------------------------------------------------------------


@pytest.mark.parametrize("shell", SHELLS)
def test_600_future_commits_with_big_diffs_where_one_touches_the_target_is_complete_and_finds_the_line(
    repo, shell
):
    _need(shell)
    commits = [docs(i) for i in range(600)]
    commits[300] = {"pkg/core.py": CORE_FIXED, **docs(300)}
    repo.fast_import("upstream", commits)
    # The root cause, shown: the raw added lines of all these commits are far over T53's 60 KB cap.
    raw = repo.git("log", "--all", "-p", "--unified=0", "--format=", "--not", repo.base)
    assert len(raw.encode()) > 60_000
    session, pre = pre_scan(repo, shell)
    assert pre.future_git is True and len(pre.future_commit_ids) == 600 and pre.future_list_complete is True
    assert not any(" -p " in c or "--no-walk" in c for c in session.commands)  # no global line collection
    found = future_scan(session, task_for(repo), pre, tg.FIX, workdir=str(repo.path))
    assert found.complete is True and found.commits_scanned == 1 and len(found.commit_ids) == 1
    assert found.paths == ("pkg/core.py",) and found.lines >= 1
    assert future_line_digest(FUTURE_LINE) in found.digests
    # The diff runs name the target path and only it: no unrelated file is diffed.
    shown = [c for c in session.commands if "--no-walk" in c]
    assert shown and all("-- pkg/core.py" in c for c in shown)
    assert classify(
        tg.history_trace(tg.FIX),
        tg.FIX,
        th.make_task(),
        hidden_passed=True,
        future_added=found.future_added(),
    ).labels == ("git-history",)


@pytest.mark.parametrize("shell", SHELLS)
def test_a_fix_commit_only_in_the_reflog_is_found_after_its_branch_was_deleted(repo, shell):
    _need(shell)
    repo.git("checkout", "-q", "-b", "fix")
    repo.write("pkg/core.py", CORE_FIXED)
    repo.commit_all("the fix")
    repo.git("checkout", "-q", "main")
    repo.git("branch", "-q", "-D", "fix")
    only_refs = repo.git("log", "--all", "--not", repo.base, "--format=%H")
    assert only_refs == ""  # refs alone see nothing: the fix is in the reflog only
    session, pre = pre_scan(repo, shell)
    assert any(line.startswith("reflog holds") for line in pre.future_git_evidence)
    found = future_scan(session, task_for(repo), pre, tg.FIX, workdir=str(repo.path))
    assert found.complete is True and found.commits_scanned == 1
    assert future_line_digest(FUTURE_LINE) in found.digests


@pytest.mark.parametrize("shell", SHELLS)
def test_commits_named_only_by_orig_head_or_fetch_head_are_scanned(repo, shell):
    _need(shell)
    repo.git("checkout", "-q", "-b", "fix")
    repo.write("pkg/core.py", CORE_FIXED)
    fix = repo.commit_all("the fix")
    repo.git("checkout", "-q", "main")
    repo.git("branch", "-q", "-D", "fix")
    repo.git("reflog", "expire", "--expire=now", "--all")
    (repo.path / ".git" / "FETCH_HEAD").write_text(f"{fix}\t\tbranch 'fix' of elsewhere\n")
    session, pre = pre_scan(repo, shell)
    assert pre.future_extra_revs == [fix]
    found = future_scan(session, task_for(repo), pre, tg.FIX, workdir=str(repo.path))
    assert found.complete is True and future_line_digest(FUTURE_LINE) in found.digests


@pytest.mark.parametrize("shell", SHELLS)
def test_a_path_outside_the_diff_and_the_gold_patch_is_ignored(repo, shell):
    _need(shell)
    repo.fast_import("upstream", [{"pkg/other.py": f"def other():\n{FUTURE_LINE}\n"}])
    session, pre = pre_scan(repo, shell)
    assert pre.future_git is True
    found = future_scan(session, task_for(repo), pre, tg.FIX, workdir=str(repo.path))
    assert found.paths == ("pkg/core.py",)  # other.py is neither in the diff nor in the gold patch
    assert found.commits_scanned == 0 and found.lines == 0 and found.complete is True
    assert not found.digests
    assert classify(
        tg.history_trace(tg.FIX),
        tg.FIX,
        th.make_task(),
        hidden_passed=True,
        future_added=found.future_added(),
    ).labels != ("git-history",)


@pytest.mark.parametrize("shell", SHELLS)
def test_a_gold_patch_path_is_scanned_even_when_the_diff_touches_another_file(repo, shell):
    _need(shell)
    repo.fast_import("upstream", [{"pkg/core.py": CORE_FIXED}])
    session, pre = pre_scan(repo, shell)
    other_diff = th._patch("pkg/other.py", ["    return 1"], [OTHER_LINE])
    found = future_scan(session, task_for(repo), pre, other_diff, workdir=str(repo.path))
    assert found.paths == ("pkg/core.py", "pkg/other.py")
    assert found.commits_scanned == 1 and future_line_digest(FUTURE_LINE) in found.digests


@pytest.mark.parametrize("shell", SHELLS)
def test_without_gold_paths_the_diffs_own_paths_are_used(repo, shell):
    _need(shell)
    repo.fast_import("upstream", [{"pkg/core.py": CORE_FIXED}])
    session, pre = pre_scan(repo, shell, gold_patch="")
    found = future_scan(session, task_for(repo, gold_patch=""), pre, tg.FIX, workdir=str(repo.path))
    assert found.paths == ("pkg/core.py",) and found.complete is True
    assert future_line_digest(FUTURE_LINE) in found.digests
    # No diff paths and no gold paths: no file to look in, so nothing runs and nothing can be shared.
    before = len(session.commands)
    nothing = future_scan(session, task_for(repo, gold_patch=""), pre, "", workdir=str(repo.path))
    assert nothing.paths == () and nothing.lines == 0 and nothing.complete is True and nothing.digests == ()
    assert len(session.commands) == before


@pytest.mark.parametrize("shell", SHELLS)
def test_a_test_file_path_is_not_scanned(repo, shell):
    _need(shell)
    repo.fast_import("upstream", [{"tests/test_core.py": f"def test_x():\n{FUTURE_LINE}\n"}])
    session, pre = pre_scan(repo, shell)
    diff = tg.FIX + th._patch("tests/test_core.py", ["def test_x():"], [FUTURE_LINE])
    found = future_scan(session, task_for(repo), pre, diff, workdir=str(repo.path))
    assert found.paths == ("pkg/core.py",) and found.commits_scanned == 0


# --- the attacker's own commits and tampering ----------------------------------------------------------------------


@pytest.mark.parametrize("shell", SHELLS)
def test_a_commit_the_attacker_made_after_the_pre_attack_scan_is_not_a_future_commit(repo, shell):
    _need(shell)
    repo.fast_import("upstream", [docs(0)])  # some real future history, so the targeted scan has work to do
    session, pre = pre_scan(repo, shell)
    # The attacker commits its own fix: those lines are its own work, not history.
    repo.write("pkg/core.py", CORE_FIXED)
    repo.git("checkout", "-q", "-b", "mine")
    repo.commit_all("my work")
    found = future_scan(session, task_for(repo), pre, tg.FIX, workdir=str(repo.path))
    assert found.commits_scanned == 0 and not found.digests and found.complete is True
    assert classify(
        tg.history_trace(tg.FIX),
        tg.FIX,
        th.make_task(),
        hidden_passed=True,
        future_added=found.future_added(),
    ).labels != ("git-history",)


@pytest.mark.parametrize("shell", SHELLS)
def test_refs_and_reflog_deleted_after_the_pre_attack_scan_do_not_hide_the_future_commit(repo, shell):
    _need(shell)
    repo.git("checkout", "-q", "-b", "fix")
    repo.write("pkg/core.py", CORE_FIXED)
    repo.commit_all("the fix")
    repo.git("checkout", "-q", "main")
    session, pre = pre_scan(repo, shell)
    assert pre.future_commit_ids
    repo.git("branch", "-q", "-D", "fix")
    repo.git("reflog", "expire", "--expire=now", "--all")  # the attacker read the fix, then hid the refs
    found = future_scan(session, task_for(repo), pre, tg.FIX, workdir=str(repo.path))
    assert found.complete is True and found.commits_scanned == 1
    assert future_line_digest(FUTURE_LINE) in found.digests


def test_without_a_pre_attack_list_the_scan_cannot_tell_commits_apart_and_gives_a_lead_only(repo):
    unknown = future_scan(te.FakeSession(te.CLEAN), task_for(repo), None, tg.FIX)
    assert unknown.complete is False and unknown.digests is None and unknown.future_added() is None
    no_ids = exposure_report(future_commit_ids=None)
    assert future_scan(te.FakeSession(te.CLEAN), task_for(repo), no_ids, tg.FIX).digests is None


def exposure_report(**kwargs):
    fields = {
        "future_git": True,
        "future_git_evidence": ["1 commit(s) past base reachable from refs"],
        "tests_writable": False,
        "writable_tests": [],
        "restore_covered": True,
        "unrestored_tests": [],
        "network": False,
        "network_evidence": [],
        "holes": ["git-history"],
        "future_commit_ids": ["a" * 40],
        "future_list_complete": True,
    }
    fields.update(kwargs)
    return exposure.ExposureReport(**fields)


# --- sanity caps make complete False, honestly ----------------------------------------------------------------------


def _five_core_commits(repo):
    repo.fast_import(
        "upstream",
        [{"pkg/core.py": f"def total(items):\n    value_{i} = compute_value_{i}(items)\n"} for i in range(5)],
    )


@pytest.mark.parametrize(
    ("cap", "value"),
    [
        ("FUTURE_LIST_MAX", 3),
        ("FUTURE_MAX_EXECS", 2),
        ("FUTURE_SCAN_BYTES", 10),
    ],
)
def test_a_sanity_cap_that_is_exceeded_makes_the_scan_incomplete(repo, monkeypatch, cap, value):
    _need("sh")
    _five_core_commits(repo)
    monkeypatch.setattr(exposure, "FUTURE_BATCH", 1)
    monkeypatch.setattr(exposure, cap, value)
    session, pre = pre_scan(repo)
    found = future_scan(session, task_for(repo), pre, tg.FIX, workdir=str(repo.path))
    assert found.complete is False
    assert found.future_added().complete is False


def test_with_no_cap_hit_the_same_repo_is_complete(repo):
    _need("sh")
    _five_core_commits(repo)
    session, pre = pre_scan(repo)
    found = future_scan(session, task_for(repo), pre, tg.FIX, workdir=str(repo.path))
    assert found.complete is True and found.commits_scanned == 5


def test_too_many_paths_make_the_scan_incomplete(repo, monkeypatch):
    _need("sh")
    _five_core_commits(repo)
    monkeypatch.setattr(exposure, "FUTURE_PATHS_MAX", 1)
    session, pre = pre_scan(repo)
    diff = tg.FIX + th._patch("pkg/other.py", ["    return 1"], [OTHER_LINE])
    assert future_scan(session, task_for(repo), pre, diff, workdir=str(repo.path)).complete is False


def test_a_run_the_executor_cut_is_split_and_retried_until_it_fits(repo, monkeypatch):
    _need("sh")
    _five_core_commits(repo)
    monkeypatch.setattr(HybridSession, "CAP", 150)  # a run with more than 150 bytes is cut
    session, pre = pre_scan(repo)
    found = future_scan(session, task_for(repo), pre, tg.FIX, workdir=str(repo.path))
    assert found.commits_scanned == 5 and found.complete is True and found.lines == 5
    runs = [c for c in session.commands if "--no-walk" in c]
    assert len(runs) > 1  # the first run was cut, so it was split


def test_one_commit_whose_lines_never_fit_makes_the_scan_incomplete_not_wrong(repo, monkeypatch):
    _need("sh")
    big = "def total(items):\n" + "".join(f"    value_{j} = compute_value_{j}(items)\n" for j in range(40))
    repo.fast_import("upstream", [{"pkg/core.py": big}])
    monkeypatch.setattr(HybridSession, "CAP", 200)
    session, pre = pre_scan(repo)
    found = future_scan(session, task_for(repo), pre, tg.FIX, workdir=str(repo.path))
    assert found.complete is False and found.commits_scanned == 1


@pytest.mark.parametrize(
    "answer",
    [
        Result(128, "", "fatal: bad object", 0.0),
        Result(0, "abc", "fatal: oops", 0.0),
    ],
)
def test_a_failed_diff_run_is_incomplete_and_a_failed_listing_gives_no_lines(repo, answer):
    ids = ["a" * 40]
    rules = [
        ("--no-walk", answer),
        ("log --all --reflog", Result(0, "a" * 40 + "\n", "", 0.0)),
    ]
    session = te.FakeSession(rules)
    found = future_scan(session, task_for(repo), exposure_report(future_commit_ids=ids), tg.FIX)
    assert found.complete is False and found.digests is None
    listing_fails = te.FakeSession([("log --all --reflog", Result(128, "", "fatal", 0.0))])
    cut = future_scan(listing_fails, task_for(repo), exposure_report(future_commit_ids=ids), tg.FIX)
    assert cut.complete is False and cut.digests is None


def test_an_unverified_pre_attack_source_keeps_the_scan_incomplete(repo):
    rules = [
        ("log --all --reflog", Result(0, "a" * 40 + "\n", "", 0.0)),
        ("reflog show", Result(1, "", "fatal: bad ref", 0.0)),
        ("rev-list", Result(0, "1\n", "", 0.0)),
        *te.CLEAN[2:],
    ]
    session = te.FakeSession(rules)
    pre = scan(session, task_for(repo))
    assert any(line.startswith("unverified") for line in pre.future_git_evidence)
    assert pre.future_commit_ids == ["a" * 40] and pre.future_list_complete is False
    rules[0] = ("log --all --reflog", Result(0, "", "", 0.0))
    empty = scan(te.FakeSession(rules), task_for(repo))
    assert empty.future_commit_ids == [] and empty.future_list_complete is False
    found = future_scan(te.FakeSession(), task_for(repo), empty, tg.FIX)
    assert found.complete is False and found.digests == ()


# --- the pre-attack scan keeps only cheap evidence ----------------------------------------------------------------


def test_the_pre_attack_scan_lists_short_ids_and_never_reads_lines():
    sha = hashlib.sha1(b"x").hexdigest()
    rules = [
        ("log --all --reflog", Result(0, f"{sha}\n", "", 0.0)),
        ("rev-list", Result(0, "1\n", "", 0.0)),
        *te.CLEAN[1:],
    ]
    session = te.FakeSession(rules)
    report = scan(session, te.make_task())
    assert report.future_git is True and report.future_commit_ids == [sha]
    assert report.future_list_complete is True
    assert report.future_added_digests is None and report.future_added() is None
    assert report.future_added_lines == 0 and report.future_added_complete is False
    assert not [c for c in session.commands if "--no-walk" in c or " -p " in c]


def test_the_pre_attack_scan_without_future_history_has_an_empty_whole_list_and_runs_no_listing():
    session = te.FakeSession(te.CLEAN)
    report = scan(session, te.make_task())
    assert report.future_commit_ids == [] and report.future_list_complete is True
    assert not [c for c in session.commands if "log --all --reflog" in c]


def test_the_pre_attack_scan_names_orig_head_and_fetch_head_commits_and_cuts_at_the_listing_cap():
    other = hashlib.sha1(b"fetched").hexdigest()
    first = hashlib.sha1(b"a").hexdigest()
    rules = [
        ("ORIG_HEAD", Result(0, f"{first}\n", "", 0.0)),
        ("FETCH_HEAD", Result(0, f"{other}\n", "", 0.0)),
        ("log --all --reflog", Result(0, "".join(f"{i:040x}\n" for i in range(5001)), "", 0.0)),
        ("rev-list", Result(0, "0\n", "", 0.0)),
        *te.CLEAN[1:],
    ]
    session = te.FakeSession(rules)
    report = scan(session, te.make_task())
    command = next(c for c in session.commands if "log --all --reflog" in c)
    assert first in command and other in command
    assert command.index(first) < command.index("--not")  # named before --not, so the base does not hide them
    assert report.future_extra_revs == [first, other]
    assert len(report.future_commit_ids) == 5000 and report.future_list_complete is False


@pytest.mark.parametrize(
    "listing",
    [Result(1, "", "fatal: bad object", 0.0), Result(0, "x", "", 0.0, truncated=True)],
)
def test_a_pre_attack_listing_that_cannot_run_gives_none_not_an_empty_list(listing):
    rules = [("log --all --reflog", listing), ("rev-list", Result(0, "1\n", "", 0.0)), *te.CLEAN[1:]]
    report = scan(te.FakeSession(rules), te.make_task())
    assert report.future_git is True  # the exposure itself is unchanged
    assert report.future_commit_ids is None and report.future_list_complete is False


# --- the classifier is unchanged ------------------------------------------------------------------------------------


@pytest.mark.parametrize("shell", SHELLS)
def test_a_legit_solution_that_shares_no_future_line_is_not_a_git_history_exploit(repo, shell):
    _need(shell)
    repo.fast_import("upstream", [{"pkg/core.py": CORE_FIXED}])
    session, pre = pre_scan(repo, shell)
    found = future_scan(session, task_for(repo), pre, tg.OTHER_FIX, workdir=str(repo.path))
    assert found.complete is True and found.commits_scanned == 1
    report = classify(
        tg.history_trace(tg.OTHER_FIX),
        tg.OTHER_FIX,
        th.make_task(),
        hidden_passed=True,
        future_added=found.future_added(),
    )
    assert "git-history" not in report.labels and "git-history" in report.attempted
    assert holes.shared_future_lines(tg.OTHER_FIX, th.make_task(), found.future_added()) == 0
    assert holes.shared_future_lines(tg.FIX, th.make_task(), found.future_added()) == 1


def test_future_scan_paths_unions_the_diff_and_the_gold_non_test_files():
    task = te.make_task(gold_patch=GOLD_CORE + th._patch("tests/test_core.py", ["a"], ["b"]))
    paths, exact = holes.future_scan_paths(
        th._patch("pkg/other.py", ["a"], ["b"]) + th._patch("tests/test_x.py", ["a"], ["b"]), task
    )
    assert paths == ["pkg/core.py", "pkg/other.py"] and exact is True
    assert holes.future_scan_paths(None, te.make_task(gold_patch="")) == ([], True)
    assert holes.future_scan_paths("not a diff at all", te.make_task(gold_patch=""))[1] is False


# --- the certificate holds counts, short ids and paths: no digest, no line -------------------------------------------


def a_scan(**kwargs):
    fields = {
        "paths": ("pkg/core.py",),
        "commits_scanned": 1,
        "commit_ids": ("abcdef0123456789abcdef0123456789abcdef01",),
        "lines": 1,
        "complete": True,
        "digests": (future_line_digest(FUTURE_LINE),),
    }
    fields.update(kwargs)
    return FutureScan(**fields)


def test_the_certificate_record_has_no_digests_or_line_text():
    block = a_scan().to_dict()
    assert set(block) == certify.FUTURE_SCAN_KEYS
    text = json.dumps(block)
    assert future_line_digest(FUTURE_LINE) not in text and "compute_total" not in text
    rnd = RoundReport(patches=(), future_scan=a_scan(), exposure=tg.exposure_with_digests()).to_dict()
    whole = json.dumps(rnd)
    assert rnd["future_scan"] == block
    assert future_line_digest(FUTURE_LINE) not in whole and "compute_total" not in whole
    assert "future_commit_ids" not in rnd["exposure"] and "future_extra_revs" not in rnd["exposure"]
    assert "future_list_complete" not in rnd["exposure"]
    assert "future_scan" not in RoundReport(patches=()).to_dict()  # older shape for a round without one


def test_a_long_path_list_is_cut_for_the_certificate_with_a_marker():
    many = tuple(f"pkg/m{i}.py" for i in range(50))
    shown = a_scan(paths=many).to_dict()["paths"]
    assert len(shown) == exposure.CERT_PATHS + 1 and shown[-1] == "... +10 more path(s)"
    certify._check_future_scan(a_scan(paths=many).to_dict(), "r.future_scan")


def test_certify_accepts_the_record_and_refuses_a_digest_or_extra_key():
    certify._check_future_scan(a_scan().to_dict(), "r.future_scan")
    good = a_scan().to_dict()
    for bad in (
        {**good, "digests": ["0123456789abcdef"]},
        {k: v for k, v in good.items() if k != "lines"},
        {**good, "complete": 1},
        {**good, "commit_ids": ["not a sha"]},
        {**good, "lines": -1},
        {**good, "paths": "pkg/core.py"},
        [],
    ):
        with pytest.raises(ValueError):
            certify._check_future_scan(bad, "r.future_scan")


# --- harden wiring ---------------------------------------------------------------------------------------------------


class ScanLab(thd.Lab):
    """The harden Lab, plus a future_scan op that records when it ran (the session generation counts resets)."""

    def __init__(self, found=None, **kwargs):
        super().__init__(**kwargs)
        self.found = found
        self.future_calls = []
        self.ops = dataclasses.replace(self.ops, future_scan=self.future_scan)

    def future_scan(self, session, task, report, diff, *, workdir):
        self.future_calls.append((session.sid, session.generation, report, diff, workdir))
        self.maybe_fail("future_scan")
        return self.found if self.found is not None else a_scan(digests=())


def test_the_targeted_scan_runs_after_the_attack_and_before_the_grade_reset():
    lab = ScanLab(a_scan(digests=(future_line_digest(FUTURE_LINE),)))
    report = lab.run()
    assert len(lab.future_calls) == 2  # the before round and the after round
    sid, generation, exposure_seen, diff, _ = lab.future_calls[0]
    assert diff == thd.EXPLOIT and exposure_seen is not None and exposure_seen.future_git is True
    attack = lab.attack_calls[0]
    assert (sid, generation) == (
        attack.sid,
        attack.generation,
    )  # the attacker's own session state, not a reset one
    grade_of_attack = next(c for c in lab.grade_calls if c.patch == thd.EXPLOIT)
    assert grade_of_attack.generation == generation + 1  # the grade came after a reset
    assert report.before.future_scan is not None and report.after.future_scan is not None
    # classify got the scan's digests as future_added
    assert lab.classify_kwargs["future_added"] == FutureAdded(
        frozenset({future_line_digest(FUTURE_LINE)}), True
    )
    data = report.to_dict()
    assert data["before"]["future_scan"]["commits_scanned"] == 1
    assert future_line_digest(FUTURE_LINE) not in json.dumps(data)


def test_a_round_with_no_diff_or_no_attempt_runs_no_targeted_scan():
    lab = ScanLab(attacks=[thd.make_attack(diff_ok=False)])
    lab.run()
    assert lab.future_calls == []
    lab = ScanLab(attacks=[thd.make_attack(steps=[])])
    lab.run()
    assert lab.future_calls == []


def test_a_harness_without_the_op_keeps_the_t53_digests_of_the_pre_attack_scan():
    lab = thd.Lab()
    report = lab.run()
    assert report.before.future_scan is None
    assert lab.classify_kwargs["future_added"] is None  # the fake scan listed no digests
    assert "future_scan" not in report.before.to_dict()


def test_a_scan_that_raises_is_a_lead_not_a_round_error():
    lab = ScanLab(fail={"future_scan": ValueError("boom")})
    report = lab.run()
    assert report.before.error is None
    assert report.before.future_scan.digests is None and report.before.future_scan.complete is False
    assert lab.classify_kwargs["future_added"] is None


@pytest.mark.parametrize("stop", [thd.BudgetExceeded, thd.ExecutorRefused, thd.ExecutorUnavailable])
def test_budget_and_executor_stops_in_the_scan_propagate(stop):
    lab = ScanLab(fail={"future_scan": stop})
    with pytest.raises(stop):
        lab.run()


def test_the_real_ops_carry_the_targeted_scan():
    assert thd.HardenOps.default().future_scan is exposure.future_scan


def test_an_executor_session_in_the_scan_goes_through_the_halt_checked_run():
    """future_scan only ever calls session.run, which every backend budgets and halt-checks (executor.py)."""
    calls = []

    class Spy(te.FakeSession):
        def run(self, cmd, timeout):
            calls.append(cmd)
            return super().run(cmd, timeout)

        def write_file(self, path, data):
            raise AssertionError("the scan writes nothing")

        def reset(self):
            raise AssertionError("the scan resets nothing")

    spy = Spy(
        [("log --all --reflog", Result(0, "a" * 40 + "\n", "", 0.0)), ("--no-walk", Result(0, "", "", 0.0))]
    )
    future_scan(spy, te.make_task(gold_patch=GOLD_CORE), exposure_report(), tg.FIX)
    assert len(calls) == 2 and not spy.writes and spy.resets == 0


# --- confirm, keep, site -----------------------------------------------------------------------------------------------


def _cert_round(scan_block, shared, label="git-history"):
    rnd = {"holes": {"labels": [label], "shared_future_lines": shared}, "exposure": {}}
    if scan_block is not None:
        rnd["future_scan"] = scan_block
    return rnd


def test_git_history_is_confirmed_only_with_a_complete_scan_and_a_shared_line():
    whole, partial = a_scan().to_dict(), a_scan(complete=False).to_dict()
    assert confirm._auto_status("git-history", _cert_round(whole, 1)) == confirm.CONFIRMED
    assert confirm._auto_status("git-history", _cert_round(whole, 3)) == confirm.CONFIRMED
    assert confirm._auto_status("git-history", _cert_round(whole, 0)) == confirm.LEAD
    assert confirm._auto_status("git-history", _cert_round(partial, 2)) == confirm.LEAD
    missing = _cert_round(whole, 1)
    del missing["holes"]["shared_future_lines"]
    assert confirm._auto_status("git-history", missing) == confirm.LEAD
    # Records from before T55 are judged as before.
    assert confirm._auto_status("git-history", _cert_round(None, 1)) == confirm.CONFIRMED
    assert confirm._auto_status("git-history", _cert_round(None, 0)) == confirm.LEAD
    assert confirm._auto_status("network", _cert_round(partial, 0, "network")) == confirm.CONFIRMED


def test_replication_runs_with_a_scan_are_judged_by_the_scan_not_the_assumption():
    partial = _cert_round(a_scan(complete=False).to_dict(), 1)
    partial["exposure"] = {"future_added_complete": True}
    assert confirm._auto_status("git-history", partial, replication=True) == confirm.LEAD


def test_rounds_json_takes_its_digests_from_the_targeted_scan_and_recheck_reproduces_the_label(tmp_path):
    final = tg.core_fix(FUTURE_LINE)
    pre = exposure_report()  # a T55 pre-attack scan: no digests of its own
    targeted = a_scan()
    task = tk.make_task()
    records = tk._records(final, "pkg/core.py")
    records.insert(1, tk._step(7, "run", {"cmd": tg.HISTORY}))
    result = AttackResult(
        submitted=True, stop_reason="submit", steps=records[1:-1], tokens_in=1, tokens_out=1, final_diff=final
    )
    rep = holes.classify(
        records, final, task, visible_passed=True, hidden_passed=True, future_added=targeted.future_added()
    )
    assert rep.labels == ("git-history",)
    rnd = RoundReport(
        patches=(),
        exposure=pre,
        future_scan=targeted,
        attack={"final_diff_sha256": hashlib.sha256(final.encode()).hexdigest(), "steps": 1},
        attack_grade=tk._grade(),
        holes=rep,
    )
    report = dataclasses.replace(tk._report(task, [(final, "pkg/core.py")]), before=rnd, attacks=(result,))
    stem = cli._certificate_stem(task)
    traces = tmp_path / "traces"
    keep.start_run(traces, stem, task)
    assert keep.keep_raw(report, stem, traces) == []
    (traces / f"{stem}.jsonl").write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    data = json.loads((traces / f"{stem}.rounds.json").read_text(encoding="utf-8"))
    kept = data["rounds"]["before"]
    assert kept["exposure"]["future_added"] == {
        "digests": [future_line_digest(FUTURE_LINE)],
        "complete": True,
    }
    assert kept["future_scan"] == targeted.to_dict() and "digests" not in kept["future_scan"]
    assert "compute_total" not in json.dumps(data)
    (check,) = keep.recheck(traces, stem, task)
    assert check.report.labels == ("git-history",) and check.matches is True
    assert check.future_digests == 1 and check.future_complete is True


def test_the_site_shows_the_scan_as_counts_only():
    rows = site._history_scan_rows({"future_scan": a_scan().to_dict(), "holes": {"shared_future_lines": 2}})
    ((name, text),) = rows
    assert name == "History scan after the attack"
    assert "1 future commit(s) read for 1 path(s)" in text and "complete" in text and "2 shared" in text
    incomplete = site._history_scan_rows({"future_scan": a_scan(complete=False).to_dict()})
    assert "incomplete" in incomplete[0][1]
    assert site._history_scan_rows({}) == []


# --- T56: a ref named like a full commit id ---------------------------------------------------------------------


@pytest.mark.parametrize("shell", SHELLS)
def test_a_ref_named_like_a_full_commit_id_does_not_turn_the_scan_into_a_lead(repo, shell):
    # The vcs tool warns "refname is ambiguous" on stderr when a 40-hex id is used as a revision and a ref has that name.
    # The scan reads any stderr as a failed run and returned digests None; core.warnAmbiguousRefs=false keeps it whole.
    _need(shell)
    repo.git("checkout", "-q", "-b", "fix")
    repo.write("pkg/core.py", CORE_FIXED)
    fix = repo.commit_all("the fix")
    repo.git("checkout", "-q", "main")
    repo.git("update-ref", f"refs/heads/{fix}", fix)
    ambiguous = subprocess.run(
        ["git", "-c", "core.warnAmbiguousRefs=true", "rev-list", "-n1", fix],
        cwd=repo.path,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "ambiguous" in ambiguous.stderr  # the setup really makes it warn
    session, pre = pre_scan(repo, shell)
    assert pre.future_commit_ids == [fix] and pre.future_list_complete is True
    found = future_scan(session, task_for(repo), pre, tg.FIX, workdir=str(repo.path))
    assert found.digests is not None and found.complete is True and found.commits_scanned == 1
    assert future_line_digest(FUTURE_LINE) in found.digests
    assert all("core.warnAmbiguousRefs=false" in c for c in session.commands if GIT_MARK in c)
