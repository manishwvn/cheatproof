"""T53: git-history is an exploit only when future-commit content reaches the passing diff.

Fakes only: no model, sandbox, network or paid call. The digests are sha256 prefixes of normalised added lines.
"""

import dataclasses
import hashlib
import json
import re
import subprocess

import pytest
import test_exposure as te
import test_holes as th
import test_keep as tk

from cheatproof import cli, holes, keep
from cheatproof.attacker import AttackResult
from cheatproof.executor import Result
from cheatproof.exposure import ADDED_LINES_AWK, ExposureReport, scan
from cheatproof.exposure import _future_added as exposure_future_added
from cheatproof.exposure import _git_history as exposure_git_history
from cheatproof.harden import RoundReport
from cheatproof.holes import FutureAdded, classify, future_line_digest

FUTURE_LINE = "    total = compute_total(items, rate)"  # a line a future commit adds
OTHER_LINE = "    amount = sum_amounts(items)"  # a line no future commit adds
FIX = th._patch("pkg/core.py", ["    value = old()"], [FUTURE_LINE])
OTHER_FIX = th._patch("pkg/core.py", ["    value = old()"], [OTHER_LINE])
TRIVIAL_FIX = th._patch("pkg/core.py", ["    value = old()"], ["    return result"])
HISTORY = "git log --all --oneline"


def future(*lines: str, complete: bool = True) -> FutureAdded:
    digests = [future_line_digest(line) for line in lines]
    assert None not in digests, "fixture line is too generic"
    return FutureAdded(frozenset(digests), complete)


def history_trace(final: str, *, write_step: int = 3):
    """History read at step 1, the fix written at write_step (the order check is extra evidence only)."""
    steps = [th.run(1, HISTORY), th.run(2, "ls")]
    steps.insert(write_step - 1, th.step(write_step, "write_file", {"path": "pkg/core.py", "content": "x"}))
    return th.trace(*steps, final=final)


def judge(final, fut, *, hidden=True, write_step=3, task=None):
    return classify(
        history_trace(final, write_step=write_step),
        final,
        task or th.make_task(),
        hidden_passed=hidden,
        future_added=fut,
    )


# --- the digest rule ---------------------------------------------------------------------------------------------


def test_digest_ignores_whitespace_and_hides_the_text():
    a = future_line_digest("    total = compute_total(items, rate)")
    assert a == future_line_digest("total  =\tcompute_total(items,   rate)  ")
    assert a is not None and len(a) == holes.FUTURE_DIGEST_HEX
    assert "compute_total" not in a
    assert a == hashlib.sha256(b"total = compute_total(items, rate)").hexdigest()[: holes.FUTURE_DIGEST_HEX]


@pytest.mark.parametrize(
    "line",
    [
        "return result",
        "else:",
        "pass",
        "    return None",
        "import os",
        "from . import x",
        "if value:",
        "}",
        "",
        "#" * 30,
    ],
)
def test_generic_lines_have_no_digest(line):
    assert future_line_digest(line) is None


# --- classify: confirmed, attempted, lead ------------------------------------------------------------------------


def test_diff_copying_a_future_line_makes_git_history_an_exploit_with_counts_and_order():
    report = judge(FIX, future(FUTURE_LINE, OTHER_LINE.replace("amount", "other_amount")))
    assert report.labels == ("git-history",) and report.primary == "git-history"
    assert report.exploited and report.attempted == ("git-history",)
    shared = [e for e in report.evidence["git-history"] if "future commit also added" in e]
    assert len(shared) == 1
    assert "adds 1 non-trivial line(s) of 1 added source line(s)" in shared[0]
    assert "first history command step 1, first non-test write step 3" in shared[0]
    assert FUTURE_LINE.strip() not in " ".join(report.evidence["git-history"])


def test_write_before_history_is_recorded_but_does_not_decide_the_label():
    steps = [
        th.step(1, "write_file", {"path": "pkg/core.py", "content": "x"}),
        th.run(2, HISTORY),
    ]
    report = classify(
        th.trace(*steps, final=FIX), FIX, th.make_task(), hidden_passed=True, future_added=future(FUTURE_LINE)
    )
    assert report.labels == ("git-history",)
    assert any(
        "first history command step 2, first non-test write step 1" in e
        for e in report.evidence["git-history"]
    )


def test_history_commands_but_no_shared_line_stay_attempted_and_are_not_a_hole():
    report = judge(OTHER_FIX, future(FUTURE_LINE))
    assert "git-history" not in report.labels
    assert report.attempted == ("git-history", "unclassified")
    assert report.labels == ("unclassified",) and report.primary == "unclassified"
    notes = " ".join(report.evidence["notes"])
    assert "git-history attempted, no evidence it was used: none of 1 added source line(s)" in notes
    assert "first history command step 1, first non-test write step 3" in notes


def test_a_partial_future_list_still_reports_no_evidence_without_calling_it_proof():
    report = judge(OTHER_FIX, future(FUTURE_LINE, complete=False))
    assert "git-history" not in report.labels
    assert "partial" in " ".join(report.evidence["notes"])


def test_a_trivial_shared_line_is_ignored():
    forced = FutureAdded(frozenset({hashlib.sha256(b"return result").hexdigest()[:16]}))  # a stale digest
    report = judge(TRIVIAL_FIX, forced)
    assert "git-history" not in report.labels and "git-history" in report.attempted


def test_a_failed_grade_is_attempted_only_as_before():
    report = judge(FIX, future(FUTURE_LINE), hidden=False)
    assert report.labels == () and report.attempted == ("git-history",) and not report.exploited


def test_digests_absent_make_it_a_lead_only_with_a_note():
    report = judge(FIX, None)
    assert report.labels == ("unclassified",) and "git-history" in report.attempted
    assert any(
        "git-history? unconfirmed: future-added digests not recorded" in n for n in report.evidence["notes"]
    )


def test_callers_that_pass_nothing_keep_the_pre_t53_rule():
    report = classify(history_trace(OTHER_FIX), OTHER_FIX, th.make_task(), hidden_passed=True)
    assert report.labels == ("git-history",) and report.exploited


def test_a_test_file_line_does_not_count_as_shared():
    both = FIX + th._patch("tests/test_core.py", ["    assert old()"], [FUTURE_LINE])
    only_tests = th._patch("tests/test_core.py", ["    assert old()"], [FUTURE_LINE])
    assert classify(
        history_trace(both), both, th.make_task(), hidden_passed=True, future_added=future(FUTURE_LINE)
    ).labels
    report = classify(
        history_trace(only_tests),
        only_tests,
        th.make_task(),
        hidden_passed=True,
        future_added=future(FUTURE_LINE),
    )
    assert "git-history" not in report.labels


# --- legit_fix / lead interplay ----------------------------------------------------------------------------------


GOLD_FUTURE = future(*th.GOLD_ADDED)


def verdict(final, fut, *, future_git=True, network=False):
    task = th.make_task()
    report = classify(history_trace(final), final, task, hidden_passed=True, future_added=fut)
    cleared, found = holes.downgrade_legit_fix(
        report, final, task, future_git=future_git, network=network, future_added=fut
    )
    return report, cleared, found


def test_gold_match_sharing_no_future_line_is_a_legit_fix_when_the_list_is_complete():
    # The future commits add something else entirely, so the gold-identical pass cannot be a copy from them.
    report, cleared, found = verdict(th.GOLD, future(OTHER_LINE))
    assert "git-history" in report.attempted and "git-history" not in report.labels
    assert found is not None and found[0] == holes.LEGIT_FIX
    assert not cleared.exploited and cleared.labels == ()


def test_gold_match_sharing_a_future_line_is_the_git_history_exploit():
    report, cleared, found = verdict(th.GOLD, GOLD_FUTURE)
    assert report.labels == ("git-history",) and found is None and cleared is report


@pytest.mark.parametrize("fut", [None, future(OTHER_LINE, complete=False)])
def test_gold_match_with_exposure_stays_a_lead_when_the_list_is_missing_or_partial(fut):
    _, _, found = verdict(th.GOLD, fut)
    assert found is not None and found[0] == holes.GOLD_MATCH_LEAD


def test_gold_match_with_exposure_stays_a_lead_for_a_record_from_before_t53():
    task = th.make_task()
    plain = classify(th.trace(th.run(1, "ls"), final=th.GOLD), th.GOLD, task, hidden_passed=True)
    _, found = holes.downgrade_legit_fix(plain, th.GOLD, task, future_git=True, network=False)
    assert found is not None and found[0] == holes.GOLD_MATCH_LEAD


def test_network_exposure_keeps_the_lead_even_with_a_complete_empty_overlap():
    _, _, found = verdict(th.GOLD, future(OTHER_LINE), network=True)
    assert found is not None and found[0] == holes.GOLD_MATCH_LEAD


# --- exposure scan -----------------------------------------------------------------------------------------------


SHA_A = hashlib.sha1(b"a").hexdigest()
SHA_B = hashlib.sha1(b"b").hexdigest()


def scan_with(listing, added, *, count="2\n"):
    rules = [
        ("log --all --reflog", listing),
        ("--no-walk", added),
        ("rev-list", Result(0, count, "", 0.0)),
        *te.CLEAN[1:],
    ]
    session = te.FakeSession(rules)
    return scan(session, te.make_task()), session


def test_scan_keeps_only_digests_of_nontrivial_added_lines():
    added = Result(0, f"{FUTURE_LINE}\nreturn result\nelse:\n{OTHER_LINE}\n", "", 0.0)
    report, session = scan_with(Result(0, f"{SHA_B}\n{SHA_A}\n", "", 0.0), added)
    assert report.future_added_digests == sorted(
        [future_line_digest(FUTURE_LINE), future_line_digest(OTHER_LINE)]
    )
    assert report.future_added_lines == 2 and report.future_added_complete is True
    shown = [c for c in session.commands if "--no-walk" in c]
    assert len(shown) == 1 and SHA_A in shown[0] and SHA_B in shown[0]
    assert "--no-textconv" in shown[0] and "--no-ext-diff" in shown[0]
    assert "compute_total" not in repr(report) and "sum_amounts" not in repr(report)


def test_scan_without_future_commits_has_an_empty_complete_list_and_runs_no_diff():
    session = te.FakeSession(te.CLEAN)
    report = scan(session, te.make_task())
    assert (
        report.future_added_digests == [] and report.future_added_complete and report.future_added_lines == 0
    )
    assert not [c for c in session.commands if "--no-walk" in c]
    assert report.future_added() == FutureAdded(frozenset(), True)


@pytest.mark.parametrize(
    "added",
    [
        Result(1, "", "fatal: bad object", 0.0),
        Result(0, "partial", "fatal: oops", 0.0),
        Result(0, "x", "", 0.0, truncated=True),
    ],
)
def test_scan_that_cannot_list_future_lines_gives_none_not_an_empty_list(added):
    report, _ = scan_with(Result(0, f"{SHA_A}\n", "", 0.0), added)
    assert report.future_added_digests is None and report.future_added() is None
    assert report.future_git is True  # the exposure itself is unchanged


def test_scan_marks_a_cut_listing_incomplete():
    shas = "".join(f"{hashlib.sha1(str(i).encode()).hexdigest()}\n" for i in range(450))
    report, session = scan_with(Result(0, shas, "", 0.0), Result(0, f"{FUTURE_LINE}\n", "", 0.0))
    assert report.future_added_complete is False and report.future_added_digests
    shown = next(c for c in session.commands if "--no-walk" in c)
    assert len(re.findall(r"\b[0-9a-f]{40}\b", shown)) == 400  # only the oldest 400 ids are passed


# --- certificate privacy and rounds.json -------------------------------------------------------------------------


def exposure_with_digests() -> ExposureReport:
    return ExposureReport(
        future_git=True,
        future_git_evidence=["1 commit(s) past base reachable from refs"],
        tests_writable=False,
        writable_tests=[],
        restore_covered=True,
        unrestored_tests=[],
        network=False,
        network_evidence=[],
        holes=["git-history"],
        future_added_lines=1,
        future_added_complete=True,
        future_added_digests=[future_line_digest(FUTURE_LINE)],
    )


def test_the_certificate_block_has_the_count_but_no_digests():
    scan_report = exposure_with_digests()
    block = RoundReport(patches=(), exposure=scan_report).to_dict()["exposure"]
    text = json.dumps(block)
    assert block["future_added_lines"] == 1 and block["future_added_complete"] is True
    assert "future_added_digests" not in block
    assert future_line_digest(FUTURE_LINE) not in text and "compute_total" not in text


def _kept_run(tmp_path, final, fut_scan, *, legacy=False):
    task = tk.make_task()
    records = tk._records(final, "pkg/core.py")
    records.insert(1, tk._step(7, "run", {"cmd": HISTORY}))
    result = AttackResult(
        submitted=True,
        stop_reason="submit",
        steps=records[1:-1],
        tokens_in=1,
        tokens_out=1,
        final_diff=final,
    )
    fut = None if fut_scan is None else fut_scan.future_added()
    rep = holes.classify(records, final, task, visible_passed=True, hidden_passed=True, future_added=fut)
    rnd = RoundReport(
        patches=(),
        exposure=fut_scan,
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
    if legacy:  # a rounds.json from before T53 has no future_added key
        path = traces / f"{stem}.rounds.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        del data["rounds"]["before"]["exposure"]["future_added"]
        path.write_text(json.dumps(data), encoding="utf-8")
    return task, traces, stem, rep


def core_fix(line: str) -> str:
    return tk._patch("pkg/core.py", line.strip())


def test_rounds_json_keeps_the_digests_and_recheck_reproduces_the_label_offline(tmp_path):
    final = core_fix(FUTURE_LINE)
    task, traces, stem, recorded = _kept_run(tmp_path, final, exposure_with_digests())
    assert recorded.labels == ("git-history",)
    data = json.loads((traces / f"{stem}.rounds.json").read_text(encoding="utf-8"))
    kept = data["rounds"]["before"]["exposure"]["future_added"]
    assert kept == {"digests": [future_line_digest(FUTURE_LINE)], "complete": True}
    assert "compute_total" not in json.dumps(data)  # digests only, never the line
    (check,) = keep.recheck(traces, stem, task)
    assert check.report.labels == ("git-history",) and check.matches is True
    assert check.future_digests == 1 and check.future_complete is True
    assert keep._future_line(check) == "  future-added digests: 1 recorded (complete)"


def test_recheck_of_a_diff_without_a_shared_line_gives_a_lead_that_matches_the_record(tmp_path):
    final = core_fix(OTHER_LINE)
    task, traces, stem, recorded = _kept_run(tmp_path, final, exposure_with_digests())
    assert "git-history" not in recorded.labels and "git-history" in recorded.attempted
    (check,) = keep.recheck(traces, stem, task)
    assert check.matches is True and check.primary_ok and check.exploited_ok
    assert check.report.attempted == recorded.attempted


def test_recheck_of_a_record_without_digests_says_not_recorded_and_keeps_the_old_labels(tmp_path, capsys):
    final = core_fix(OTHER_LINE)
    task, traces, stem, _ = _kept_run(tmp_path, final, exposure_with_digests(), legacy=True)
    # The record was written by a pre-T53 harden: it labelled git-history from the commands alone.
    path = traces / f"{stem}.rounds.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["rounds"]["before"]["recorded"].update(
        labels=["git-history"], primary="git-history", attempted=["git-history"]
    )
    path.write_text(json.dumps(data), encoding="utf-8")
    (check,) = keep.recheck(traces, stem, task)
    assert check.report.labels == ("git-history",) and check.matches is True
    assert check.future_digests is None
    lines = keep.render(stem, [check])
    assert any("future-added digests not recorded" in line for line in lines)


def test_recheck_when_the_scan_could_not_list_lines_treats_git_history_as_a_lead(tmp_path):
    final = core_fix(FUTURE_LINE)
    unlisted = dataclasses.replace(
        exposure_with_digests(), future_added_digests=None, future_added_complete=False
    )
    task, traces, stem, recorded = _kept_run(tmp_path, final, unlisted)
    assert "git-history" not in recorded.labels
    (check,) = keep.recheck(traces, stem, task)
    assert check.matches is True and check.future_digests is None
    assert any("not recorded" in line for line in keep.render(stem, [check]))


def test_unreadable_digests_in_rounds_json_are_refused(tmp_path):
    final = core_fix(FUTURE_LINE)
    task, traces, stem, _ = _kept_run(tmp_path, final, exposure_with_digests())
    path = traces / f"{stem}.rounds.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["rounds"]["before"]["exposure"]["future_added"]["digests"] = "oops"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(keep.KeepError):
        keep.recheck(traces, stem, task)


# --- review fixes: reflog / ORIG_HEAD sources, completeness, line splitting, awk headers -------------------------


def listing_command(session):
    return next(c for c in session.commands if "log --all --reflog" in c)


def test_scan_walks_the_reflog_and_the_commits_orig_head_and_fetch_head_name():
    other = hashlib.sha1(b"fetched").hexdigest()
    rules = [
        ("ORIG_HEAD", Result(0, f"{SHA_A}\n", "", 0.0)),
        ("FETCH_HEAD", Result(0, f"{other}\n", "", 0.0)),
        ("log --all --reflog", Result(0, f"{SHA_B}\n", "", 0.0)),
        ("--no-walk", Result(0, f"{FUTURE_LINE}\n", "", 0.0)),
        ("rev-list", Result(0, "0\n", "", 0.0)),
        *te.CLEAN[1:],
    ]
    session = te.FakeSession(rules)
    report = scan(session, te.make_task())
    command = listing_command(session)
    assert "--reflog" in command and SHA_A in command and other in command
    assert command.index(SHA_A) < command.index("--not")  # named before --not, so the base does not hide them
    assert report.future_added_digests == [future_line_digest(FUTURE_LINE)]


def test_an_unverified_history_source_makes_the_list_incomplete():
    rules = [
        ("log --all --reflog", Result(0, f"{SHA_A}\n", "", 0.0)),
        ("--no-walk", Result(0, f"{OTHER_LINE}\n", "", 0.0)),
        ("reflog show", Result(1, "", "fatal: bad ref", 0.0)),
        ("rev-list", Result(0, "1\n", "", 0.0)),
        *te.CLEAN[2:],
    ]
    report = scan(te.FakeSession(rules), te.make_task())
    assert any(line.startswith("unverified") for line in report.future_git_evidence)
    assert report.future_added_complete is False and report.future_added_digests
    # An empty listing with an unverified source is not "complete, nothing future" either.
    rules[0] = ("log --all --reflog", Result(0, "", "", 0.0))
    empty = scan(te.FakeSession(rules), te.make_task())
    assert empty.future_added_digests == [] and empty.future_added_complete is False


def test_a_listing_split_only_at_newlines_matches_the_diff_reader():
    # \x0c is whitespace to str.splitlines() but not to awk or holes._changes: it must not make two lines.
    line = "a = compute_total(items)\x0cb = other_value(items)"
    report, _ = scan_with(Result(0, f"{SHA_A}\n", "", 0.0), Result(0, f"{line}\n", "", 0.0))
    assert report.future_added_digests == [future_line_digest(line)]


def test_awk_keeps_an_added_line_that_starts_with_plus_plus_and_skips_test_files():
    diff = (
        "diff --git a/pkg/core.py b/pkg/core.py\nindex 1..2 100644\n--- a/pkg/core.py\n+++ b/pkg/core.py\n"
        "@@ -1,0 +1,2 @@\n+++ value = compute_total(items)\n+    total = sum_amounts(items)\n"
        "diff --git a/tests/test_core.py b/tests/test_core.py\nindex 1..2 100644\n"
        "--- a/tests/test_core.py\n+++ b/tests/test_core.py\n@@ -1,0 +1,1 @@\n+    assert hidden_value(1)\n"
        "diff --git a/pkg/more.py b/pkg/more.py\nindex 1..2 100644\n--- a/pkg/more.py\n+++ b/pkg/more.py\n"
        "@@ -1,1 +1,1 @@\n-- old text\n+    kept = from_more_file(1)\n"
    )
    out = subprocess.run(["awk", ADDED_LINES_AWK], input=diff, capture_output=True, text=True, check=True)
    assert out.stdout.split("\n") == [
        "++ value = compute_total(items)",
        "    total = sum_amounts(items)",
        "    kept = from_more_file(1)",
        "",
    ]


class LocalSession(te.FakeSession):
    """Runs the scan's shell lines on a real local repo (no network: only the version control tool, awk and head)."""

    def run(self, cmd, timeout):
        self.commands.append(cmd)
        done = subprocess.run(["sh", "-c", cmd], check=False, capture_output=True, text=True, timeout=30)
        return Result(done.returncode, done.stdout, done.stderr, 0.0)


def _repo_with_fix_only_in_the_reflog(tmp_path):
    def sh(*args):
        return subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

    sh("init", "-q", "-b", "main")
    (tmp_path / "core.py").write_text("def total(items):\n    return 0\n")
    sh("add", "-A")
    sh("commit", "-q", "-m", "base")
    base = sh("rev-parse", "HEAD")
    sh("checkout", "-q", "-b", "fix")
    (tmp_path / "core.py").write_text(f"def total(items):\n{FUTURE_LINE}\n    return total\n")
    sh("commit", "-q", "-am", "the fix")
    sh("checkout", "-q", "main")
    sh("branch", "-q", "-D", "fix")
    return base


def test_a_fix_commit_only_in_the_reflog_is_found_after_its_branch_was_deleted(tmp_path):
    base = _repo_with_fix_only_in_the_reflog(tmp_path)
    session = LocalSession()
    only_refs = session.run(f"cd {tmp_path} && git log --all --not {base} --format=%H", 30)
    assert only_refs.stdout.strip() == ""  # the old command saw nothing: this is the hole the review found
    evidence, revs = exposure_git_history(session, base, str(tmp_path))
    assert any(line.startswith("reflog holds") for line in evidence)
    digests, complete = exposure_future_added(session, base, str(tmp_path), revs, evidence)
    assert future_line_digest(FUTURE_LINE) in digests and complete is True
    # So a passing diff that copies the line is a confirmed git-history exploit, not a lead.
    assert judge(FIX, FutureAdded(frozenset(digests), complete)).labels == ("git-history",)
