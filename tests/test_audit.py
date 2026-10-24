"""T57: the deterministic exposure audit (cheatproof/audit.py, `audit-exposure`, the summary in report and site).

Fakes and throwaway local repositories only: no model, attacker, sandbox, network, Tavily or paid call. The version
control lines of the scan, the targeted fix scan and the strip-future-git patch run for real (sh, git, awk) against a
repository built in tmp_path; the gates, the sandbox start and the budget are fakes.
"""

import dataclasses
import json
import os
import shutil
import subprocess
import types
from pathlib import Path

import pytest
import test_exposure as te
import test_future_scan as tf
import test_holes as th

from cheatproof import audit, certify, cli, exposure, holes, patches, site
from cheatproof.budget import BudgetExceeded
from cheatproof.executor import ExecutorRefused, Result
from cheatproof.grader import GradeResult
from cheatproof.patches import PatchOutcome

GOLD_LINE = "    gold_marker = compute_gold_value(items)"
GOLD_FIXED = f"def total(items):\n{GOLD_LINE}\n    return 0\n"
SHELLS = tf.SHELLS
GIT_ENV = {
    **{k: v for k, v in os.environ.items() if not k.startswith("GIT_")},
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
}


@pytest.fixture(autouse=True)
def _in_tmp_path(tmp_path, monkeypatch):
    # The CLI defaults are relative (results/exposure, runs/tasks): no test writes under the repo's results/ or runs/.
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("EXECUTOR", raising=False)
    monkeypatch.delenv("MIN_FREE_DISK_GB", raising=False)
    monkeypatch.setattr(cli, "_env_file_values", dict)  # never read the owner's .env


def _need(shell):
    tf._need(shell)
    if shutil.which("git") is None:
        pytest.skip("git is not installed")


class AuditSession(tf.HybridSession):
    """The scan's git lines run for real (HybridSession); so do the strip scripts (they all end with the marker
    'cheatproof-strip'). reset() only counts: the strip is applied right after it, as in a fresh sandbox."""

    def __init__(self, repo, shell="sh"):
        super().__init__(shell)
        self.repo = repo
        self.reset_calls = 0

    def run(self, cmd, timeout):
        if "cheatproof-strip" not in cmd:
            return super().run(cmd, timeout)
        self.commands.append(cmd)
        done = subprocess.run(
            [self.shell, "-c", cmd],
            cwd=self.repo.path,
            env=GIT_ENV,
            capture_output=True,
            timeout=60,
            check=False,
        )
        return Result(done.returncode, done.stdout.decode(), done.stderr.decode(), 0.0)

    def reset(self):
        self.reset_calls += 1


def grade(passed, *, applied=True, error=None):
    return GradeResult(passed, 1, 1, 1, 1, applied, error, "")


def ops(*, gold=True, empty=False, patch=None, empty_applied=True):
    """The real scans and the real strip patch, with fake gates. patch replaces apply_patches when given."""
    return audit.AuditOps(
        scan=exposure.scan,
        future_scan=exposure.future_scan,
        touched_paths=exposure.future_touched_paths,
        apply_patches=patch or patches.apply_patches,
        gold_gate=lambda session, task, timeout, workdir: grade(gold),
        empty_gate=lambda session, task, timeout, workdir: grade(empty, applied=empty_applied),
        shared_lines=holes.shared_future_lines,
    )


def measure(repo, shell="sh", **kwargs):
    session = AuditSession(repo, shell)
    task = tf.task_for(repo)
    measured = audit.measure(session, task, workdir=str(repo.path), ops=ops(**kwargs))
    return session, task, measured


def record_of(task, measured, runs=5):
    return audit.build_record(
        task, measured, executor="sandbox", timestamp="2026-10-24T00:00:00+00:00", sandbox_runs=runs
    )


# --- fix reachability ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("shell", SHELLS)
def test_a_fix_on_a_future_branch_is_reachable_and_the_strip_closes_it(tmp_path, shell):
    _need(shell)
    repo = tf.make_repo(tmp_path)
    repo.fast_import("upstream", [{"pkg/core.py": GOLD_FIXED}])
    session, task, m = measure(repo, shell)
    assert m.future_commits_before == 1 and m.refs_before >= 1
    assert m.gold_lines_in_future >= 1 and m.gold_paths_touched == 1
    assert m.scan.paths == ("pkg/core.py",) and m.scan.commits_scanned == 1 and m.scan.complete is True
    assert (m.patch_applied, m.gold_gate_ok, m.empty_gate_ok) == (True, True, True)
    assert m.future_commits_after == 0 and m.closed is True
    assert session.reset_calls == 3 == m.resets
    rec = record_of(task, m)
    assert rec["fix_reachable"] is True and rec["closed"] is True and rec["future_commits_after"] == 0
    assert rec["future_scan"]["gold_paths_touched_by_future_commits"] == 1
    assert len(rec["future_scan"]["commit_ids"][0]) == 12
    # the repository really lost its future history
    assert repo.git("for-each-ref") == ""


@pytest.mark.parametrize("shell", SHELLS)
def test_a_fix_only_in_the_reflog_is_reachable(tmp_path, shell):
    _need(shell)
    repo = tf.make_repo(tmp_path)
    repo.git("checkout", "-q", "-b", "fix")
    repo.write("pkg/core.py", GOLD_FIXED)
    repo.commit_all("the fix")
    repo.git("checkout", "-q", "main")
    repo.git("branch", "-q", "-D", "fix")
    assert repo.git("log", "--all", "--not", repo.base, "--format=%H") == ""  # refs alone see nothing
    _, task, m = measure(repo, shell)
    assert m.future_commits_before == 1 and m.refs_before == 0
    assert m.gold_lines_in_future >= 1
    assert m.future_commits_after == 0 and m.closed is True
    assert record_of(task, m)["fix_reachable"] is True


def test_future_commits_that_do_not_add_a_gold_line_leave_the_fix_unreachable(tmp_path):
    _need("sh")
    repo = tf.make_repo(tmp_path)
    other = f"def total(items):\n{tf.FUTURE_LINE}\n    return 0\n"  # touches core.py, adds another line
    repo.fast_import("upstream", [{"pkg/core.py": other}])
    _, task, m = measure(repo)
    assert m.future_commits_before == 1 and m.gold_paths_touched == 1 and m.gold_lines_in_future == 0
    rec = record_of(task, m)
    assert (
        rec["fix_reachable"] is False and rec["closed"] is True
    )  # still open before, closed after the strip


def test_a_future_commit_on_an_unrelated_file_touches_no_gold_path(tmp_path):
    _need("sh")
    repo = tf.make_repo(tmp_path)
    repo.fast_import("upstream", [{"pkg/other.py": f"def other():\n{GOLD_LINE}\n"}])
    _, task, m = measure(repo)
    assert m.future_commits_before == 1 and m.gold_paths_touched == 0 and m.gold_lines_in_future == 0
    assert record_of(task, m)["fix_reachable"] is False


def test_no_future_commit_at_all(tmp_path):
    _need("sh")
    repo = tf.make_repo(tmp_path)
    _, task, m = measure(repo)
    assert m.future_commits_before == 0 and m.gold_paths_touched == 0 and m.future_commits_after == 0
    rec = record_of(task, m)
    assert rec["fix_reachable"] is False and rec["refs_before"] == 0


# --- closed needs the patch, both gates and zero left ---------------------------------------------------------------


def test_a_gold_gate_that_fails_after_the_patch_is_not_closed(tmp_path):
    _need("sh")
    repo = tf.make_repo(tmp_path)
    repo.fast_import("upstream", [{"pkg/core.py": GOLD_FIXED}])
    _, task, m = measure(repo, gold=False)
    assert m.future_commits_after == 0 and m.gold_gate_ok is False and m.closed is False
    assert record_of(task, m)["closed"] is False


def test_an_empty_gate_that_passes_or_did_not_run_is_not_closed(tmp_path):
    _need("sh")
    repo = tf.make_repo(tmp_path)
    repo.fast_import("upstream", [{"pkg/core.py": GOLD_FIXED}])
    assert measure(repo, empty=True)[2].closed is False
    (tmp_path / "second").mkdir()
    repo2 = tf.make_repo(tmp_path / "second")
    repo2.fast_import("upstream", [{"pkg/core.py": GOLD_FIXED}])
    assert measure(repo2, empty_applied=False)[2].empty_gate_ok is False


def test_a_patch_that_did_not_apply_or_left_commits_is_not_closed(tmp_path):
    _need("sh")
    repo = tf.make_repo(tmp_path)
    repo.fast_import("upstream", [{"pkg/core.py": GOLD_FIXED}])
    noop = lambda session, task, names, *, workdir: [PatchOutcome(patches.PATCH_STRIP_GIT, True, ())]
    _, _, m = measure(
        repo, patch=noop
    )  # reports success but removed nothing: the rescan still sees the commit
    assert m.future_commits_after == 1 and m.closed is False
    failed = lambda session, task, names, *, workdir: [PatchOutcome(patches.PATCH_STRIP_GIT, False, ("x",))]
    (tmp_path / "second").mkdir()
    repo2 = tf.make_repo(tmp_path / "second")
    repo2.fast_import("upstream", [{"pkg/core.py": GOLD_FIXED}])
    _, _, m2 = measure(repo2, patch=failed)
    assert m2.patch_applied is False and m2.closed is False


def test_an_unlistable_history_has_no_record():
    session = te.FakeSession(
        [("log ", Result(1, "", "boom", 0.0)), ("rev-list", Result(0, "1\n", "", 0.0)), *te.CLEAN]
    )
    with pytest.raises(audit.AuditUnavailable):
        audit.measure(session, te.make_task(), ops=ops())


# --- the record: schema, validation, privacy -------------------------------------------------------------------------


@pytest.fixture(scope="module")
def good(tmp_path_factory):
    """One real record, built once from a throwaway repo (the strip is slow enough to matter)."""
    _need("sh")
    repo = tf.make_repo(tmp_path_factory.mktemp("good"))
    repo.fast_import("upstream", [{"pkg/core.py": GOLD_FIXED}])
    _, task, m = measure(repo)
    return task, record_of(task, m)


def test_the_record_has_the_schema_fields_and_no_line_text_or_digest(good):
    _task, rec = good
    assert set(rec) == audit.RECORD_KEYS
    assert (rec["schema"], rec["schema_version"]) == ("rewardseal.exposure-audit", 1)
    assert rec["patch"] == {
        "name": "strip-future-git",
        "applied": True,
        "gold_gate_ok": True,
        "empty_gate_ok": True,
    }
    text = json.dumps(rec)
    assert "compute_gold_value" not in text and "gold_marker" not in text
    digest = holes.future_line_digest(GOLD_LINE)
    assert digest not in text
    assert rec["sandbox_runs"] == 5 and rec["executor"] == "sandbox"
    audit.validate_record(rec)  # includes the leak guard (sanitize.assert_clean)


def test_a_record_is_written_atomically_under_the_certificate_file_name(tmp_path, good):
    task, rec = good
    out = tmp_path / "results" / "exposure"
    path = audit.write_record(rec, out)
    assert path == out / certify.certificate_filename(task.instance_id)
    assert json.loads(path.read_text()) == rec
    assert audit.load_record(path) == rec
    assert [p.name for p in out.iterdir()] == [path.name]  # no temp file left
    other = dict(rec, instance_id="another__task-1")
    path.write_text(json.dumps(dict(rec, instance_id="x__y-1")))
    with pytest.raises(ValueError, match="another instance id"):
        audit.write_record(other | {"instance_id": rec["instance_id"]}, out)


@pytest.mark.parametrize(
    "change",
    [
        lambda r: r.update(extra=1),
        lambda r: r.pop("closed"),
        lambda r: r.update(schema="other"),
        lambda r: r.update(schema_version=2),
        lambda r: r.update(schema_version=True),
        lambda r: r.update(future_commits_before=-1),
        lambda r: r.update(future_commits_before=True),
        lambda r: r.update(future_commits_after="0"),
        lambda r: r.update(base_commit="XYZ"),
        lambda r: r.update(fix_reachable=False),  # contradicts gold_lines_in_future
        lambda r: r.update(closed=False),  # contradicts gates ok and zero left
        lambda r: r["patch"].update(gold_gate_ok=False),  # closed would be false
        lambda r: r["patch"].update(extra=1),
        lambda r: r["future_scan"].update(commit_ids=["abc"]),
        lambda r: r["future_scan"].update(commit_ids=["a" * 40]),
        lambda r: r["future_scan"].update(lines="3"),
        lambda r: r["future_scan"].update(commits_scanned=99),
        lambda r: r["future_scan"].update(digests=["0123456789abcdef"]),
        lambda r: r.update(repo="ghp_abcdefghij0123456789"),  # the leak guard
        lambda r: r.update(timestamp=""),
    ],
)
def test_a_malformed_record_is_refused(good, change):
    _, rec = good
    bad = json.loads(json.dumps(rec))
    change(bad)
    with pytest.raises(audit.ExposureAuditError):
        audit.validate_record(bad)


# --- the summary ---------------------------------------------------------------------------------------------------


def synthetic(iid, *, before=3, fix=False, closed=True, after=0, complete=True):
    patch_ok = closed
    return {
        "schema": audit.SCHEMA,
        "schema_version": 1,
        "instance_id": iid,
        "repo": "org/repo",
        "base_commit": "a" * 40,
        "future_commits_before": before,
        "refs_before": 2,
        "fix_reachable": fix,
        "future_scan": {
            "list_complete": True,
            "paths": ["pkg/core.py"],
            "commits_scanned": min(before, 1),
            "commit_ids": ["0123456789ab"] * min(before, 1),
            "lines": 1,
            "complete": complete,
            "gold_paths_touched_by_future_commits": 1,
            "gold_lines_in_future": 1 if fix else 0,
        },
        "patch": {
            "name": "strip-future-git",
            "applied": patch_ok,
            "gold_gate_ok": patch_ok,
            "empty_gate_ok": patch_ok,
        },
        "future_commits_after": after,
        "closed": closed and after == 0,
        "executor": "sandbox",
        "timestamp": "2026-10-24T00:00:00+00:00",
        "sandbox_runs": 5,
    }


def write_all(directory, *records):
    for rec in records:
        audit.write_record(rec, directory)


def test_the_summary_is_computed_strictly_from_the_records(tmp_path):
    d = tmp_path / "results" / "exposure"
    write_all(
        d,
        synthetic("a__a-1", before=5, fix=True, closed=True),
        synthetic("b__b-2", before=2, fix=True, closed=False, after=2),
        synthetic("c__c-3", before=7, fix=False, closed=True),
        synthetic("d__d-4", before=0, fix=False, closed=True),  # nothing in the history: M only
        synthetic("e__e-5", before=1, fix=False, closed=False, after=None, complete=False),
    )
    s = audit.exposure_summary(d)
    assert (s["M"], s["N_future"], s["N_fix"], s["N_closed"]) == (5, 4, 2, 2)
    assert s["source"] == "audit" and s["n_incomplete_scans"] == 1
    assert s["fix_ids"] == ["a__a-1", "b__b-2"] and s["not_closed_ids"] == ["b__b-2", "e__e-5"]
    line = audit.summary_line(s)
    assert "4 of 5 audited" in line and "reachable in 2" in line and "closed 2 of the 4" in line
    assert "not an audit" not in line


def test_a_malformed_or_renamed_or_repeated_record_refuses_every_number(tmp_path):
    d = tmp_path / "exposure"
    write_all(d, synthetic("a__a-1"))
    (d / "broken.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(audit.ExposureAuditError, match="broken.json"):
        audit.exposure_summary(d)
    (d / "broken.json").unlink()
    bad = synthetic("b__b-2")
    bad["closed"] = "yes"
    (d / certify.certificate_filename("b__b-2")).write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(audit.ExposureAuditError):
        audit.exposure_summary(d)
    (d / certify.certificate_filename("b__b-2")).unlink()
    (d / "wrong-name.json").write_text(json.dumps(synthetic("c__c-3")), encoding="utf-8")
    with pytest.raises(audit.ExposureAuditError, match="file name"):
        audit.exposure_summary(d)


def test_without_records_the_summary_falls_back_to_the_certificates_and_says_so(tmp_path):
    certs = tmp_path / "results" / "certificates"
    certs.mkdir(parents=True)
    for iid, git in (("a__a-1", True), ("b__b-2", False), ("c__c-3", True)):
        (certs / f"{iid}.json").write_text(
            json.dumps({"exposure_before": {"future_git": git}}), encoding="utf-8"
        )
    (certs / "d.json").write_text(
        json.dumps({"exposure_before": None}), encoding="utf-8"
    )  # no scan: not counted
    (certs / "e.json").write_text("not json", encoding="utf-8")
    s = audit.exposure_summary(tmp_path / "results" / "exposure")
    assert (s["M"], s["N_future"], s["N_fix"], s["N_closed"]) == (3, 2, None, None)
    assert s["source"] == "certificates"
    assert "from attack certificates (not an audit)" in audit.summary_line(s)
    assert audit.exposure_summary(tmp_path / "nothing" / "exposure") is None


# --- the command -------------------------------------------------------------------------------------------------


class CountingBudget:
    """Counts reserve_sandbox_run like Budget does and can stop after a number of runs or when halted."""

    def __init__(self, stop_after=None, halted=None):
        self.runs = 0
        self.stop_after = stop_after
        self.halted = halted

    def reserve_sandbox_run(self):
        if self.halted:
            raise BudgetExceeded(f"budget halted: {self.halted}")
        if self.stop_after is not None and self.runs >= self.stop_after:
            raise BudgetExceeded("sandbox run cap reached")
        self.runs += 1

    def check_not_halted(self):
        if self.halted:
            raise BudgetExceeded(f"budget halted: {self.halted}")


class CountedSession:
    def __init__(self, budget):
        self.budget = budget

    def reset(self):
        self.budget.reserve_sandbox_run()

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class CountedExecutor:
    def __init__(self):
        self.starts = 0

    def start(self, env, budget=None):
        self.starts += 1
        budget.reserve_sandbox_run()  # every start books a run, like the real executors
        return CountedSession(budget)


def report_with(ids, *, complete=True):
    return exposure.ExposureReport(
        future_git=bool(ids),
        future_git_evidence=["ref refs/heads/up points at abcdef123456"] * (2 if ids else 0),
        tests_writable=False,
        writable_tests=[],
        restore_covered=True,
        unrestored_tests=[],
        network=False,
        network_evidence=[],
        holes=[],
        future_commit_ids=list(ids),
        future_list_complete=complete,
    )


class World:
    """Fake scans and gates for the command tests: three future commits before the strip, none after. The scan is
    called once before and once after the patch, so the Nth call decides."""

    def __init__(self, *, fix=True, gold=True, empty=False, after_left=0):
        self.calls = 0
        self.fix, self.gold, self.empty, self.after_left = fix, gold, empty, after_left
        self.patch_calls = 0

    def ops(self):
        def scan(session, task, *, workdir):
            self.calls += 1
            n = 3 if self.calls % 2 == 1 else self.after_left
            return report_with([f"{i:040x}" for i in range(1, n + 1)])

        def future_scan(session, task, report, final_diff, *, workdir):
            return exposure.FutureScan(("pkg/core.py",), 1, ("0" * 39 + "1",), 1, True, ("0123456789abcdef",))

        def apply(session, task, names, *, workdir):
            self.patch_calls += 1
            return [PatchOutcome(patches.PATCH_STRIP_GIT, True, ())]

        return audit.AuditOps(
            scan=scan,
            future_scan=future_scan,
            touched_paths=lambda *a, **k: 1,
            apply_patches=apply,
            gold_gate=lambda s, t, timeout, workdir: grade(self.gold),
            empty_gate=lambda s, t, timeout, workdir: grade(self.empty),
            shared_lines=lambda patch, task, added: 1 if self.fix else 0,
        )


def tasks_for(*ids):
    return [te.make_task(instance_id=i, repo="org/repo", base_commit="a" * 40) for i in ids]


def refuse(*args, **kwargs):
    raise AssertionError("a dry run makes no call")


def make_deps(tasks, world=None, *, budget=None, executor=None, preflight="ok", disk=100.0):
    budget = budget or CountingBudget()
    executor = executor or CountedExecutor()
    world = world or World()
    by_id = {t.instance_id: t for t in tasks}
    if preflight == "ok":
        pf = lambda session, task, *, workdir: types.SimpleNamespace(ok=True, error=None)
    elif preflight is None:
        pf = None
    else:
        pf = lambda session, task, *, workdir: types.SimpleNamespace(ok=False, error=preflight)
    return cli.Deps(
        find_tasks=lambda iid, source, cache_dir: [by_id[iid]] if iid in by_id else [],
        make_executor=lambda: executor,
        make_budget=lambda: budget,
        make_llm=refuse,
        harden=refuse,
        attack=refuse,
        build_certificate=refuse,
        write_certificate=refuse,
        score_directory=refuse,
        build_site=refuse,
        clock=lambda: "2026-10-24T00:00:00+00:00",
        load_selection=lambda source, n, cache_dir: types.SimpleNamespace(selected=list(tasks), skipped={}),
        disk_free_gb=lambda path: disk,
        preflight=pf,
        audit_ops=world.ops(),
    )


class CountedBudgetHolder:
    @staticmethod
    def fresh():
        return CountingBudget()


def audit_argv(*extra):
    return ["audit-exposure", "--source", "swe-rebench", "--n", "18", "--out", "results/exposure", *extra]


def test_a_dry_run_makes_no_call_and_estimates_about_five_sandbox_runs_a_task(capsys):
    deps = cli.Deps.for_dry_run()
    deps = dataclasses.replace(
        deps,
        load_selection=lambda source, n, cache_dir: types.SimpleNamespace(
            selected=tasks_for("a__a-1", "b__b-2")
        ),
    )
    rc = cli.main(audit_argv("--dry-run"), deps=deps)
    printed = capsys.readouterr().out
    assert rc == 0
    assert "dry run, no calls made" in printed and "2 to audit" in printed
    assert "estimated sandbox runs: 10 (about 5 per task" in printed
    assert "Sandboxes are not billed, the counter is a guard" in printed
    assert "$0 of trial credit" in printed
    assert not Path("results").exists()  # no file


def test_a_dry_run_never_builds_an_executor_or_a_budget(capsys):
    def boom():
        raise AssertionError("built in a dry run")

    deps = dataclasses.replace(make_deps(tasks_for("a__a-1")), make_executor=boom, make_budget=boom)
    assert cli.main(audit_argv("--dry-run"), deps=deps) == 0
    assert "1 to audit" in capsys.readouterr().out


def test_main_uses_the_cache_only_deps_for_a_dry_run(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        cli.Deps, "default", classmethod(lambda cls: refuse())
    )  # would load .env and the SDKs
    cache = tmp_path / "cache"
    cache.mkdir()
    rc = cli.main(audit_argv("--dry-run", "--cache-dir", str(cache)))
    assert rc == 2  # no current cache: a usage error, still with no call
    assert "no current cache" in capsys.readouterr().err


def test_the_command_writes_one_record_per_task_through_the_budget(capsys):
    budget = CountingBudget()
    executor = CountedExecutor()
    deps = make_deps(tasks_for("a__a-1"), World(), budget=budget, executor=executor)
    assert cli.main(audit_argv(), deps=deps) == 0
    out = Path("results/exposure")
    rec = json.loads((out / "a__a-1.json").read_text())
    audit.validate_record(rec)
    assert rec["sandbox_runs"] == 5 == budget.runs  # preflight start + audit start + 3 resets, all booked
    assert executor.starts == 2
    assert (
        rec["future_commits_before"],
        rec["fix_reachable"],
        rec["future_commits_after"],
        rec["closed"],
    ) == (
        3,
        True,
        0,
        True,
    )
    printed = capsys.readouterr().out
    assert "a__a-1: audited" in printed and "audit: audited 1" in printed
    assert "1 of 1 audited tasks have future commits" in printed


def test_a_task_with_a_record_is_skipped_unless_rerun(capsys):
    deps = make_deps(tasks_for("a__a-1"))
    assert cli.main(audit_argv(), deps=deps) == 0
    budget = CountingBudget()
    deps2 = make_deps(tasks_for("a__a-1"), budget=budget)
    assert cli.main(audit_argv(), deps=deps2) == 0
    assert budget.runs == 0 and "already has a record, skipped" in capsys.readouterr().out
    deps3 = make_deps(tasks_for("a__a-1"), budget=budget)
    assert cli.main(audit_argv("--rerun"), deps=deps3) == 0
    assert budget.runs == 5


def test_an_env_broken_task_is_skipped_by_the_preflight_and_has_no_record(capsys):
    budget = CountingBudget()
    deps = make_deps(tasks_for("a__a-1"), budget=budget, preflight="collect-only exited 4: ImportError")
    assert cli.main(audit_argv(), deps=deps) == 0
    printed = capsys.readouterr().out
    assert "a__a-1: not audited (env-broken)" in printed and "env-broken=1" in printed
    assert budget.runs == 1  # only the preflight start
    assert not list(Path("results/exposure").glob("*.json")) if Path("results/exposure").exists() else True


def test_no_preflight_skips_the_collect_only_start():
    budget = CountingBudget()
    deps = make_deps(tasks_for("a__a-1"), budget=budget)
    assert cli.main(audit_argv("--no-preflight"), deps=deps) == 0
    assert budget.runs == 4
    assert json.loads(Path("results/exposure/a__a-1.json").read_text())["sandbox_runs"] == 4


def test_a_budget_stop_ends_the_run_with_exit_1_and_no_record(capsys):
    budget = CountingBudget(stop_after=3)  # preflight, start, one reset, then refused
    deps = make_deps(tasks_for("a__a-1", "b__b-2"), budget=budget)
    assert cli.main(audit_argv(), deps=deps) == 1
    printed = capsys.readouterr().out
    assert "a__a-1: not audited (budget)" in printed
    assert "b__b-2" not in printed  # the run stopped at once
    assert not list(Path("results/exposure").glob("*.json")) if Path("results/exposure").exists() else True


def test_a_halted_budget_stops_before_the_first_exec(capsys):
    budget = CountingBudget(halted="HTTP 402")
    deps = make_deps(tasks_for("a__a-1"), budget=budget)
    assert cli.main(audit_argv(), deps=deps) == 1
    assert "budget halted" in capsys.readouterr().out
    assert budget.runs == 0


def test_an_executor_refusal_skips_that_task_and_goes_on(capsys):
    class Refusing(CountedExecutor):
        def start(self, env, budget=None):
            if self.starts == 0:
                self.starts += 1
                raise ExecutorRefused("no docker")
            return super().start(env, budget)

    deps = make_deps(tasks_for("a__a-1", "b__b-2"), executor=Refusing())
    assert cli.main(audit_argv(), deps=deps) == 0
    printed = capsys.readouterr().out
    assert "a__a-1: not audited (executor_refused)" in printed and "b__b-2: audited" in printed


def test_a_task_that_the_patch_does_not_close_is_recorded_as_open(capsys):
    deps = make_deps(tasks_for("a__a-1"), World(after_left=2))
    assert cli.main(audit_argv(), deps=deps) == 0
    rec = json.loads(Path("results/exposure/a__a-1.json").read_text())
    assert rec["future_commits_after"] == 2 and rec["closed"] is False
    assert "closed 0 of the 1" in capsys.readouterr().out


def test_instance_ids_pick_exactly_those_tasks_in_order(capsys):
    deps = make_deps(tasks_for("a__a-1", "b__b-2", "c__c-3"))
    assert cli.main(audit_argv("--instance-ids", "c__c-3", "a__a-1", "--dry-run"), deps=deps) == 0
    lines = [ln.strip() for ln in capsys.readouterr().out.splitlines() if ln.strip().startswith("audit  ")]
    assert lines == ["audit  c__c-3", "audit  a__a-1"]
    assert cli.main(audit_argv("--instance-ids", "nope__x-1", "--dry-run"), deps=deps) == 2


def test_usage_errors_exit_2(capsys):
    deps = make_deps(tasks_for("a__a-1"))
    assert cli.main(audit_argv("--timeout", "0"), deps=deps) == 2
    assert cli.main([*audit_argv(), "--n", "-1"], deps=deps) == 2


def test_a_bad_record_on_disk_stops_the_summary_with_exit_1(capsys):
    d = Path("results/exposure")
    d.mkdir(parents=True)
    (d / "junk.json").write_text("{}", encoding="utf-8")
    deps = make_deps(tasks_for("a__a-1"))
    assert cli.main(audit_argv(), deps=deps) == 1
    assert "junk.json" in capsys.readouterr().err


# --- report and site -----------------------------------------------------------------------------------------------


def _cert_dirs(tmp_path):
    certs = tmp_path / "results" / "certificates"
    certs.mkdir(parents=True)
    (certs / "x.json").write_text("{}", encoding="utf-8")
    return certs


def _report_deps(summary_fn):
    base = make_deps(tasks_for("a__a-1"))
    return dataclasses.replace(
        base,
        score_directory=lambda d: {"schema_version": 1, "n": 1, "certified": 1, "outcomes": {}},
        exposure_summary=summary_fn,
    )


def test_report_text_and_json_carry_the_summary(tmp_path, capsys):
    certs = _cert_dirs(tmp_path)
    write_all(tmp_path / "results" / "exposure", synthetic("a__a-1", fix=True), synthetic("b__b-2", before=0))
    deps = _report_deps(cli._exposure_summary)
    assert cli.main(["report", "--certs", str(certs)], deps=deps) == 0
    text = capsys.readouterr().out
    assert "history exposure audit" in text and "1 of 2 audited tasks have future commits" in text
    assert cli.main(["report", "--certs", str(certs), "--format", "json"], deps=deps) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["exposure_audit"]["M"] == 2 and data["exposure_audit"]["N_fix"] == 1
    assert data["exposure_audit"]["N_closed"] == 1 and data["exposure_audit"]["source"] == "audit"


def test_report_without_records_labels_the_certificate_fallback(tmp_path, capsys):
    certs = _cert_dirs(tmp_path)
    (certs / "x.json").write_text(json.dumps({"exposure_before": {"future_git": True}}), encoding="utf-8")
    assert cli.main(["report", "--certs", str(certs)], deps=_report_deps(cli._exposure_summary)) == 0
    text = capsys.readouterr().out
    assert "from attack certificates (not an audit)" in text and "1 of 1 certificates" in text


def test_report_refuses_a_malformed_record(tmp_path, capsys):
    certs = _cert_dirs(tmp_path)
    d = tmp_path / "results" / "exposure"
    d.mkdir()
    (d / "a.json").write_text("[]", encoding="utf-8")
    assert cli.main(["report", "--certs", str(certs)], deps=_report_deps(cli._exposure_summary)) == 2
    assert "exposure audit" in capsys.readouterr().err


def test_report_without_the_hook_is_unchanged(tmp_path, capsys):
    certs = _cert_dirs(tmp_path)
    assert cli.main(["report", "--certs", str(certs)], deps=_report_deps(None)) == 0
    assert "history exposure" not in capsys.readouterr().out


def test_the_site_hero_gets_one_new_paragraph(tmp_path):
    certs_src = Path(__file__).resolve().parents[1] / "results" / "certificates"
    certs = tmp_path / "results" / "certificates"
    certs.mkdir(parents=True)
    for name in ("12rambau__sepal_ui-518.json", "CycloneDX__cyclonedx-python-348-93d44b30.json"):
        shutil.copy(certs_src / name, certs / name)
    out = tmp_path / "site"
    result = site.build_site(certs, out)
    assert not [e for e in result.errors if e[0] == "exposure"]
    html = (out / "index.html").read_text(encoding="utf-8")
    assert "from attack certificates (not an audit)" in html  # no records yet: the labelled fallback
    assert html.count('class="exposure-audit"') == 1
    assert "Confirmed holes" in html and 'class="headline"' in html  # the T54 hero is still there
    write_all(tmp_path / "results" / "exposure", synthetic("a__a-1", fix=True, before=4))
    site.build_site(certs, out)
    html = (out / "index.html").read_text(encoding="utf-8")
    assert "history exposure audit" in html and "1 of 1 audited tasks" in html
    assert "not an audit" not in html


def test_the_site_lists_a_malformed_record_and_shows_no_number(tmp_path):
    certs_src = Path(__file__).resolve().parents[1] / "results" / "certificates"
    certs = tmp_path / "results" / "certificates"
    certs.mkdir(parents=True)
    shutil.copy(certs_src / "12rambau__sepal_ui-518.json", certs / "12rambau__sepal_ui-518.json")
    bad = tmp_path / "results" / "exposure"
    bad.mkdir()
    (bad / "z.json").write_text("{}", encoding="utf-8")
    result = site.build_site(certs, tmp_path / "site")
    assert any(name == "exposure" for name, _ in result.errors)
    assert 'class="exposure-audit"' not in (tmp_path / "site" / "index.html").read_text(encoding="utf-8")


# --- the exec path -------------------------------------------------------------------------------------------------


def test_the_audit_reaches_the_sandbox_only_through_session_run_start_and_reset():
    world = World()
    session = te.FakeSession(te.CLEAN)
    audit.measure(session, te.make_task(gold_patch=th._patch("pkg/core.py", ["a"], ["b"])), ops=world.ops())
    assert session.resets == 3 and world.patch_calls == 3
    assert not session.writes  # nothing is written into the sandbox by the audit itself


def test_touched_paths_reads_names_only_and_no_line():
    session = te.FakeSession([("--name-only", Result(0, "pkg/core.py\nelse.py\n", "", 0.0)), *te.CLEAN])
    report = report_with(["a" * 40])
    count = exposure.future_touched_paths(
        session, te.make_task(), report, ["pkg/core.py", "pkg/missing.py"], workdir="/testbed"
    )
    assert count == 1
    (cmd,) = [c for c in session.commands if "--name-only" in c]
    assert " -p " not in cmd and "--no-walk" not in cmd and "-- pkg/core.py pkg/missing.py" in cmd
    # unreadable results are unknown, never zero
    cut = te.FakeSession([("--name-only", Result(0, "x\n", "", 0.0, truncated=True)), *te.CLEAN])
    assert exposure.future_touched_paths(cut, te.make_task(), report, ["x"]) is None
    assert exposure.future_touched_paths(session, te.make_task(), None, ["x"]) is None
    assert exposure.future_touched_paths(session, te.make_task(), report_with([]), ["x"]) == 0


# --- review fixes -------------------------------------------------------------------------------------------------


def test_a_corrupt_existing_record_is_replaced_but_another_tasks_record_is_not(tmp_path):
    out = tmp_path / "exposure"
    rec = synthetic("a__a-1")
    out.mkdir()
    target = out / certify.certificate_filename("a__a-1")
    target.write_text("{truncated", encoding="utf-8")
    audit.write_record(rec, out)
    assert json.loads(target.read_text()) == rec
    target.write_text(json.dumps(synthetic("z__z-9")), encoding="utf-8")
    with pytest.raises(ValueError, match="another instance id"):
        audit.write_record(rec, out)


def test_an_empty_history_list_from_an_unverified_probe_has_no_record():
    class Unverified(World):
        def ops(self):
            real = super().ops()
            return dataclasses.replace(real, scan=lambda *a, **k: report_with([], complete=False))

    with pytest.raises(audit.AuditUnavailable, match="unknown"):
        audit.measure(te.FakeSession(te.CLEAN), te.make_task(), ops=Unverified().ops())


def test_an_incomplete_after_list_of_zero_is_not_a_zero():
    class Partial(World):
        def ops(self):
            real = super().ops()
            calls = []

            def scan(session, task, *, workdir):
                calls.append(1)
                return report_with(["1" * 40] if len(calls) == 1 else [], complete=len(calls) == 1)

            return dataclasses.replace(real, scan=scan)

    m = audit.measure(te.FakeSession(te.CLEAN), te.make_task(), ops=Partial().ops())
    assert m.future_commits_after is None and m.closed is False


def test_a_cut_pathspec_or_a_newline_in_a_path_makes_the_touched_count_unknown():
    session = te.FakeSession([("--name-only", Result(0, "a\n", "", 0.0)), *te.CLEAN])
    report = report_with(["a" * 40])
    many = [f"p{i}.py" for i in range(exposure.FUTURE_PATHS_MAX + 1)]
    assert exposure.future_touched_paths(session, te.make_task(), report, many) is None
    assert exposure.future_touched_paths(session, te.make_task(), report, ["a\nb.py"]) is None


def test_the_command_skips_a_task_whose_record_does_not_validate_and_goes_on(capsys):
    class Bad(World):
        def ops(self):
            real = super().ops()
            calls = []

            def future_scan(session, task, report, final_diff, *, workdir):
                calls.append(1)
                if len(calls) == 1:  # a commit id of the wrong shape: build_record refuses it
                    return exposure.FutureScan(
                        ("pkg/core.py",), 1, ("short",), 1, True, ("0123456789abcdef",)
                    )
                return real.future_scan(session, task, report, final_diff, workdir=workdir)

            return dataclasses.replace(real, future_scan=future_scan)

    deps = make_deps(tasks_for("a__a-1", "b__b-2"), Bad())
    assert cli.main(audit_argv(), deps=deps) == 0
    printed = capsys.readouterr().out
    assert "a__a-1: not audited (invalid_record)" in printed and "b__b-2: audited" in printed
    assert [p.name for p in Path("results/exposure").glob("*.json")] == ["b__b-2.json"]


def test_the_summary_line_flags_incomplete_listings(tmp_path):
    d = tmp_path / "exposure"
    rec = synthetic("a__a-1")
    rec["future_scan"]["list_complete"] = False
    write_all(d, rec)
    s = audit.exposure_summary(d)
    assert s["n_incomplete_lists"] == 1 and "lower bounds" in audit.summary_line(s)
