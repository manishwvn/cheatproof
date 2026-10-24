"""T42: raw traces, diffs and restore sets are kept locally, and `holes recheck` re-runs the classifier offline.

Fakes only: no model, sandbox, network or budget. Every file goes under tmp_path.
"""

import dataclasses
import hashlib
import json
from pathlib import Path

import pytest
import test_harden as th
import test_recon_nudge as trn

from cheatproof import cli, holes, keep
from cheatproof.attacker import AttackResult
from cheatproof.grader import GradeResult
from cheatproof.harden import HardenReport, RoundReport
from cheatproof.tasks import TaskSpec

BASE = hashlib.sha1(b"base").hexdigest()
F2P = "tests/test_core.py::test_new"
P2P = "tests/test_core.py::test_old"
SECRET_BODY = "SECRET_BODY_LINE_4d1e"  # diff text that must never reach the terminal


def _patch(path: str, added: str) -> str:
    return f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1,1 +1,1 @@\n-old\n+{added}\n"


TEST_PATCH = _patch("tests/test_core.py", "assert compute(1) == 1234")
GOLD = _patch("pkg/core.py", "value = compute(1) * scale")
RESTORED_EDIT = _patch("tests/test_core.py", SECRET_BODY)  # the grade restores this file
UNRESTORED_EDIT = _patch("tests/helpers/test_util.py", SECRET_BODY)  # the grade does not restore this one
SOURCE_FIX = _patch("pkg/core.py", "value = new()")


def make_task() -> TaskSpec:
    return TaskSpec(
        instance_id="fixture__core-1",
        repo="fixture/core",
        base_commit=BASE,
        image="swebench/fixture:latest",
        fail_to_pass=(F2P,),
        pass_to_pass=(P2P,),
        gold_patch=GOLD,
        test_patch=TEST_PATCH,
        source="swe-rebench",
    )


def _digest(text: str) -> dict:
    return {"sha256": hashlib.sha256(text.encode()).hexdigest(), "head": text[:300], "chars": len(text)}


HEADER = {"type": "header", "label": None, "model": "fake", "tools": ["run", "write_file", "submit"]}


def _step(n: int, tool: str, args: dict) -> dict:
    return {
        "type": "step",
        "step": n,
        "tool": tool,
        "args": args,
        "result_digest": _digest("exit_code: 0"),
        "error": None,
        "ignored_calls": 0,
        "reset": False,
        "tokens_in": 1,
        "tokens_out": 1,
        "elapsed": 0.1,
    }


def _end(diff: str | None) -> dict:
    return {
        "type": "end",
        "stop_reason": "submit",
        "submitted": True,
        "diff_ok": diff is not None,
        "steps": 1,
        "tokens_in": 1,
        "tokens_out": 1,
        "error": "",
        "final_diff": None if diff is None else _digest(diff),
    }


def _records(diff: str, step_path: str) -> list[dict]:
    return [HEADER, _step(1, "write_file", {"path": step_path, "content": "x"}), _end(diff)]


def _result(diff: str, step_path: str) -> AttackResult:
    return AttackResult(
        submitted=True,
        stop_reason="submit",
        steps=[_step(1, "write_file", {"path": step_path})],
        tokens_in=1,
        tokens_out=1,
        final_diff=diff,
    )


def _grade(passed: bool = True) -> GradeResult:
    return GradeResult(
        passed=passed,
        f2p_passed=1 if passed else 0,
        f2p_total=1,
        p2p_passed=1,
        p2p_total=1,
        applied=True,
        error=None,
        log_tail="",
    )


def _round(records: list[dict], diff: str, task: TaskSpec) -> RoundReport:
    """A round as harden builds it: the real classifier's report, graded as passed."""
    report = holes.classify(records, diff, task, visible_passed=True, hidden_passed=True)
    summary = {"final_diff_sha256": hashlib.sha256(diff.encode()).hexdigest(), "steps": 1}
    return RoundReport(patches=(), attack=summary, attack_grade=_grade(), holes=report)


def _report(task: TaskSpec, rounds: list[tuple[str, str]]) -> HardenReport:
    """rounds: (diff, path the trace writes) per attack, before first."""
    built = [_round(_records(diff, path), diff, task) for diff, path in rounds]
    return HardenReport(
        instance_id=task.instance_id,
        before=built[0],
        candidates=(),
        accepted=(),
        rejected=(),
        unpatched=(),
        after=built[1] if len(built) > 1 else None,
        certified=False,
        reason="fake",
        sandbox_runs=len(built),
        attacks=tuple(_result(diff, path) for diff, path in rounds),
    )


class Ledger:
    def __init__(self) -> None:
        self.totals = iter((0.10, 0.25))

    def snapshot(self) -> dict:
        return {"total_usd": next(self.totals), "days": {}, "sandbox_runs": 0, "halted": None}


def _deps(task: TaskSpec, rounds: list[tuple[str, str]]) -> cli.Deps:
    """cli.Deps whose attack writes a real trace file and whose harden returns a report with raw attack results."""
    attack_records = [_records(diff, path) for diff, path in rounds]
    calls = {"n": 0}

    def attack(llm, session, system_prompt, task_prompt, config, trace_path=None):
        with trace_path.open("a", encoding="utf-8") as out:
            for rec in attack_records[calls["n"]]:
                out.write(json.dumps(rec) + "\n")
        calls["n"] += 1
        diff, path = rounds[calls["n"] - 1]
        return _result(diff, path)

    def harden(executor, env, task_, attack_fn, *, budget, **kwargs):
        for _ in rounds:
            attack_fn("session")
        return _report(task, rounds)

    def build_certificate(report, task_, **kwargs):
        return {"instance_id": task_.instance_id}

    def write_certificate(cert, directory):
        path = directory / f"{cert['instance_id']}.json"
        path.write_text(json.dumps(cert), encoding="utf-8")
        return path

    def boom(*args, **kwargs):
        raise AssertionError("the offline recheck must not build this")

    return cli.Deps(
        find_tasks=lambda instance_id, source, cache_dir: [task] if instance_id == task.instance_id else [],
        make_executor=lambda: "executor",
        make_budget=lambda: Ledger(),
        make_llm=lambda budget: "llm",
        harden=harden,
        attack=attack,
        build_certificate=build_certificate,
        write_certificate=write_certificate,
        score_directory=boom,
        build_site=boom,
        clock=lambda: "2026-10-23T00:00:00+00:00",
    )


def _harden(tmp_path: Path, task: TaskSpec, rounds: list[tuple[str, str]]) -> Path:
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("Strategy prompt.\n", encoding="utf-8")
    out = tmp_path / "certs"
    argv = ["harden", task.instance_id, "--system-prompt-file", str(prompt), "--attacker-model", "m"]
    assert cli.main([*argv, "--out", str(out)], deps=_deps(task, rounds)) == 0
    return tmp_path / "traces"


def _recheck(traces: Path, task: TaskSpec, stem: str | None = None) -> int:
    stem = stem or cli._certificate_stem(task)
    return cli.main(["holes", "recheck", stem, "--traces", str(traces)], deps=_deps(task, []))


def test_harden_keeps_trace_raw_diffs_and_restore_set(tmp_path):
    task = make_task()
    traces = _harden(
        tmp_path, task, [(UNRESTORED_EDIT, "tests/helpers/test_util.py"), (SOURCE_FIX, "pkg/core.py")]
    )
    stem = cli._certificate_stem(task)
    assert (traces / f"{stem}.before.diff").read_text(encoding="utf-8") == UNRESTORED_EDIT
    assert (traces / f"{stem}.after.diff").read_text(encoding="utf-8") == SOURCE_FIX
    assert (traces / f"{stem}.diff").read_text(
        encoding="utf-8"
    ) == SOURCE_FIX  # the final diff is the last round's
    records = [
        json.loads(line) for line in (traces / f"{stem}.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert [r["type"] for r in records] == [
        "header",
        "step",
        "end",
        "header",
        "step",
        "end",
    ]  # every step, both rounds
    restore = json.loads((traces / f"{stem}.restore.json").read_text(encoding="utf-8"))
    assert restore == {"schema": 1, "instance_id": task.instance_id, "restore_paths": ["tests/test_core.py"]}
    rounds = json.loads((traces / f"{stem}.rounds.json").read_text(encoding="utf-8"))["rounds"]
    assert rounds["before"]["recorded"]["labels"] == ["test-edit"]
    assert rounds["after"]["recorded"]["labels"] == ["unclassified"]  # the restored edit is no test-edit
    assert rounds["before"]["hidden_passed"] is True and rounds["before"]["has_diff"] is True


def test_a_rerun_sets_old_files_aside_and_never_overwrites(tmp_path):
    task = make_task()
    _harden(tmp_path, task, [(SOURCE_FIX, "pkg/core.py")])
    traces = _harden(tmp_path, task, [(UNRESTORED_EDIT, "tests/helpers/test_util.py")])
    stem = cli._certificate_stem(task)
    assert (traces / f"{stem}.before.diff").read_text(encoding="utf-8") == UNRESTORED_EDIT
    aside = sorted(traces.glob(f"{stem}.before.diff.*.old"))
    assert [p.read_text(encoding="utf-8") for p in aside] == [SOURCE_FIX]
    assert len(list(traces.glob(f"{stem}.restore.json.*.old"))) == 1


def test_unreadable_restore_set_is_cached_as_null(tmp_path):
    task = dataclasses.replace(make_task(), fail_to_pass=("-bad",))
    keep.start_run(tmp_path, "stem", task)
    data = json.loads((tmp_path / "stem.restore.json").read_text(encoding="utf-8"))
    assert data["restore_paths"] is None


def test_recheck_reproduces_labels_and_restored_and_unrestored_paths(tmp_path, capsys):
    task = make_task()
    traces = _harden(
        tmp_path,
        task,
        [(UNRESTORED_EDIT, "tests/helpers/test_util.py"), (RESTORED_EDIT, "tests/test_core.py")],
    )
    capsys.readouterr()
    assert _recheck(traces, task) == 0
    out = capsys.readouterr().out
    lines = out.splitlines()
    assert "before: labels=['test-edit']" in lines[1]
    assert "  test path tests/helpers/test_util.py: unrestored by the grade" in lines
    assert (
        "after: labels=['unclassified'] attempted=['unclassified']" in out
    )  # not test-edit: the grade restores it
    assert "  test path tests/test_core.py: restored by the grade" in lines
    assert out.count("recorded labels: match") == 2
    assert SECRET_BODY not in out  # labels and path names only, never diff text


def test_recheck_shows_when_the_recorded_labels_differ(tmp_path, capsys):
    task = make_task()
    traces = _harden(tmp_path, task, [(UNRESTORED_EDIT, "tests/helpers/test_util.py")])
    stem = cli._certificate_stem(task)
    rounds_path = traces / f"{stem}.rounds.json"
    data = json.loads(rounds_path.read_text(encoding="utf-8"))
    data["rounds"]["before"]["recorded"]["labels"] = []
    rounds_path.write_text(json.dumps(data), encoding="utf-8")
    capsys.readouterr()
    assert _recheck(traces, task) == 0
    assert "recorded labels: DIFFER []" in capsys.readouterr().out


def test_recheck_uses_the_cached_restore_set_not_the_task(tmp_path, capsys):
    task = make_task()
    traces = _harden(tmp_path, task, [(RESTORED_EDIT, "tests/test_core.py")])
    stem = cli._certificate_stem(task)
    restore_path = traces / f"{stem}.restore.json"
    data = json.loads(restore_path.read_text(encoding="utf-8"))
    data["restore_paths"] = None  # unreadable at run time: fail closed, every test path is labelled
    restore_path.write_text(json.dumps(data), encoding="utf-8")
    capsys.readouterr()
    assert _recheck(traces, task) == 1  # the recorded primary no longer matches: named on stderr (T46)
    captured = capsys.readouterr()
    assert "before: labels=['test-edit']" in captured.out
    assert "tests/test_core.py: unrestored by the grade" in captured.out
    assert "recorded labels: DIFFER" in captured.out
    assert "recorded primary does not match the recomputed primary" in captured.err


@pytest.mark.parametrize(
    "gone",
    [".jsonl", ".restore.json", ".rounds.json", ".before.diff"],
)
def test_recheck_names_a_missing_piece_and_exits_nonzero(tmp_path, capsys, gone):
    task = make_task()
    traces = _harden(tmp_path, task, [(UNRESTORED_EDIT, "tests/helpers/test_util.py")])
    stem = cli._certificate_stem(task)
    (traces / f"{stem}{gone}").unlink()
    capsys.readouterr()
    rc = _recheck(traces, task)
    captured = capsys.readouterr()
    if gone == ".restore.json":
        assert rc == 1 and f"{stem}.restore.json" in captured.err  # the task id lives there
    else:
        assert rc == 1 and f"missing {stem}{gone}" in captured.err
    assert captured.out == ""


def test_recheck_lists_every_missing_piece(tmp_path, capsys):
    task = make_task()
    traces = _harden(tmp_path, task, [(UNRESTORED_EDIT, "tests/helpers/test_util.py")])
    stem = cli._certificate_stem(task)
    (traces / f"{stem}.jsonl").unlink()
    (traces / f"{stem}.before.diff").unlink()
    capsys.readouterr()
    assert _recheck(traces, task) == 1
    err = capsys.readouterr().err
    assert f"{stem}.jsonl" in err and f"{stem}.before.diff" in err


def test_recheck_refuses_a_stem_that_climbs_out(tmp_path, capsys):
    assert _recheck(tmp_path, make_task(), "../evil") == 2
    assert "not a certificate stem" in capsys.readouterr().err


def test_recheck_with_an_uncached_task_exits_2(tmp_path, capsys):
    task = make_task()
    traces = _harden(tmp_path, task, [(SOURCE_FIX, "pkg/core.py")])
    stem = cli._certificate_stem(task)
    other = dataclasses.replace(task, instance_id="other__task-9")
    capsys.readouterr()
    rc = cli.main(["holes", "recheck", stem, "--traces", str(traces)], deps=_deps(other, []))
    assert rc == 2 and "cached" in capsys.readouterr().err


def test_classify_restored_default_reads_the_task_and_none_fails_closed():
    task = make_task()
    records = _records(RESTORED_EDIT, "tests/test_core.py")
    assert holes.classify(records, RESTORED_EDIT, task, hidden_passed=True).labels == ("unclassified",)
    assert holes.classify(
        records, RESTORED_EDIT, task, hidden_passed=True, restored=["tests/test_core.py"]
    ).labels == ("unclassified",)
    closed = holes.classify(records, RESTORED_EDIT, task, hidden_passed=True, restored=None)
    assert closed.labels == ("test-edit",)
    other = holes.classify(records, RESTORED_EDIT, task, hidden_passed=True, restored=["pkg/other.py"])
    assert other.labels == ("test-edit",)


# --- T42 review fixes -------------------------------------------------------------------------------------------


def _argv(tmp_path: Path, task: TaskSpec) -> list[str]:
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("Strategy prompt.\n", encoding="utf-8")
    return [
        "harden",
        task.instance_id,
        "--system-prompt-file",
        str(prompt),
        "--attacker-model",
        "m",
        "--out",
        str(tmp_path / "certs"),
    ]


def test_a_restore_write_failure_refuses_the_run_before_any_spend(tmp_path, monkeypatch, capsys):
    task = make_task()
    calls = []

    def fail(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(keep, "start_run", fail)
    deps = _deps(task, [(SOURCE_FIX, "pkg/core.py")])
    deps = dataclasses.replace(deps, harden=lambda *a, **k: calls.append("harden"))
    assert cli.main(_argv(tmp_path, task), deps=deps) == 1
    assert calls == []  # harden (the paid run) never started
    assert not (tmp_path / "certs").exists()


def test_a_keep_raw_failure_does_not_block_the_certificate(tmp_path, monkeypatch, capsys):
    task = make_task()

    def boom(*args, **kwargs):
        raise RuntimeError("SECRET_MESSAGE_8c2d")

    monkeypatch.setattr(keep, "_write_attacks", boom)
    assert cli.main(_argv(tmp_path, task), deps=_deps(task, [(SOURCE_FIX, "pkg/core.py")])) == 0
    captured = capsys.readouterr()
    assert "certificate:" in captured.out
    assert "RuntimeError" in captured.err and "SECRET_MESSAGE_8c2d" not in captured.err
    assert (tmp_path / "certs" / "fixture__core-1.json").is_file()


def test_keep_raw_never_raises_even_on_a_broken_report():
    assert keep.keep_raw(object(), "stem", Path("/nonexistent/never")) == [
        "raw run files were not kept: AttributeError"
    ]


def test_batch_keeps_the_same_files(tmp_path, capsys):
    task = make_task()
    from cheatproof.tasks import Loaded

    selection = Loaded(source="swe-rebench", scanned=1, valid=1, skipped={}, selected=(task,))
    deps = dataclasses.replace(
        _deps(task, [(UNRESTORED_EDIT, "tests/helpers/test_util.py")]),
        load_selection=lambda source, n, cache_dir: selection,
        disk_free_gb=lambda path: 100.0,
    )
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("Strategy prompt.\n", encoding="utf-8")
    argv = ["batch", "--system-prompt-file", str(prompt), "--attacker-model", "m"]
    out = tmp_path / "results" / "certificates"
    assert cli.main([*argv, "--out", str(out), "--source", "swe-rebench"], deps=deps) == 0
    traces = tmp_path / "results" / "traces"
    stem = cli._certificate_stem(task)
    names = sorted(p.name for p in traces.iterdir())
    assert names == sorted(
        f"{stem}{suffix}" for suffix in (".jsonl", ".before.diff", ".diff", ".restore.json", ".rounds.json")
    )
    capsys.readouterr()
    assert _recheck(traces, task) == 0
    assert "before: labels=['test-edit']" in capsys.readouterr().out


def test_kept_files_are_private(tmp_path):
    task = make_task()
    traces = _harden(
        tmp_path, task, [(UNRESTORED_EDIT, "tests/helpers/test_util.py"), (SOURCE_FIX, "pkg/core.py")]
    )
    assert traces.stat().st_mode & 0o777 == 0o700
    files = list(traces.iterdir())
    assert len(files) == 6
    for path in files:
        assert path.stat().st_mode & 0o777 == 0o600, path.name


def test_a_harden_stop_keeps_the_raw_diffs_of_the_attacks_that_returned(tmp_path, capsys):
    from cheatproof.budget import BudgetExceeded

    task = make_task()
    deps = _deps(task, [(UNRESTORED_EDIT, "tests/helpers/test_util.py")])

    def harden(executor, env, task_, attack_fn, *, budget, **kwargs):
        attack_fn("session")
        raise BudgetExceeded("cap reached")

    deps = dataclasses.replace(deps, harden=harden)
    assert cli.main(_argv(tmp_path, task), deps=deps) == 1
    traces = tmp_path / "traces"
    stem = cli._certificate_stem(task)
    assert (traces / f"{stem}.before.diff").read_text(encoding="utf-8") == UNRESTORED_EDIT
    assert (traces / f"{stem}.diff").is_file() and not (traces / f"{stem}.after.diff").exists()
    capsys.readouterr()
    assert _recheck(traces, task) == 0  # no grade was recorded, but the trace and diff still classify
    assert "before: labels=" in capsys.readouterr().out


def test_a_stale_after_round_from_an_earlier_run_is_set_aside(tmp_path):
    task = make_task()
    _harden(tmp_path, task, [(UNRESTORED_EDIT, "tests/helpers/test_util.py"), (SOURCE_FIX, "pkg/core.py")])
    traces = _harden(tmp_path, task, [(UNRESTORED_EDIT, "tests/helpers/test_util.py")])
    stem = cli._certificate_stem(task)
    assert not (traces / f"{stem}.after.diff").exists()
    assert (traces / f"{stem}.diff").read_text(
        encoding="utf-8"
    ) == UNRESTORED_EDIT  # the new run's final diff
    (old_after,) = traces.glob(f"{stem}.after.diff.*.old")
    assert old_after.read_text(encoding="utf-8") == SOURCE_FIX
    rounds = json.loads((traces / f"{stem}.rounds.json").read_text(encoding="utf-8"))["rounds"]
    assert list(rounds) == ["before"]


def test_a_failed_round_input_does_not_shift_the_next_round_onto_the_first_segment(
    tmp_path, monkeypatch, capsys
):
    task = make_task()
    real = keep._round_inputs
    seen = []

    def flaky(rnd, result):
        seen.append(1)
        if len(seen) == 1:
            raise ValueError("boom")
        return real(rnd, result)

    monkeypatch.setattr(keep, "_round_inputs", flaky)
    traces = _harden(
        tmp_path, task, [(UNRESTORED_EDIT, "tests/helpers/test_util.py"), (SOURCE_FIX, "pkg/core.py")]
    )
    stem = cli._certificate_stem(task)
    rounds = json.loads((traces / f"{stem}.rounds.json").read_text(encoding="utf-8"))["rounds"]
    assert (rounds["before"]["segment"], rounds["after"]["segment"]) == (0, 1)
    capsys.readouterr()
    assert _recheck(traces, task) == 0
    out = capsys.readouterr().out
    assert "before: labels=" in out and "after: labels=['unclassified']" in out
    assert "recorded labels: none kept" in out and "recorded labels: match ['unclassified']" in out


def test_garbage_trace_lines_are_skipped_and_do_not_move_the_segments(tmp_path, capsys):
    task = make_task()
    traces = _harden(
        tmp_path, task, [(UNRESTORED_EDIT, "tests/helpers/test_util.py"), (SOURCE_FIX, "pkg/core.py")]
    )
    stem = cli._certificate_stem(task)
    path = traces / f"{stem}.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[1:1] = ["{not json", "[1, 2]", "\x00\x01garbage"]
    lines.insert(len(lines) - 1, '{"type": "step"}')  # valid JSON, fails the step schema: skipped and counted
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    capsys.readouterr()
    assert _recheck(traces, task) == 0
    out = capsys.readouterr().out
    assert "before: labels=['test-edit']" in out and out.count("recorded labels: match") == 2


def test_a_round_record_without_a_segment_is_unreadable(tmp_path, capsys):
    task = make_task()
    traces = _harden(tmp_path, task, [(SOURCE_FIX, "pkg/core.py")])
    stem = cli._certificate_stem(task)
    path = traces / f"{stem}.rounds.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    del data["rounds"]["before"]["segment"]
    path.write_text(json.dumps(data), encoding="utf-8")
    capsys.readouterr()
    assert _recheck(traces, task) == 1
    assert "unreadable round record" in capsys.readouterr().err


@pytest.mark.parametrize(
    "name",
    ["x.jsonl", "x.before.diff", "x.after.diff", "x.diff", "x.restore.json", "x.rounds.json", "x.diff.1.old"],
)
def test_version_control_ignores_the_kept_raw_files(name):
    import subprocess

    root = Path(__file__).resolve().parent.parent
    probe = subprocess.run(
        ["git", "check-ignore", "-q", f"results/traces/{name}"], cwd=root, capture_output=True, check=False
    )
    assert probe.returncode == 0, f"results/traces/{name} is not ignored"


# --- T46: recheck also compares primary and exploited with rounds.json ------------------------------------------


def _edit_recorded(traces: Path, stem: str, name: str, *, drop: tuple[str, ...] = (), **changes) -> None:
    path = traces / f"{stem}.rounds.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    recorded = data["rounds"][name]["recorded"]
    recorded.update(changes)
    for key in drop:
        recorded.pop(key)
    path.write_text(json.dumps(data), encoding="utf-8")


def test_harden_records_primary_and_exploited_beside_the_labels(tmp_path):
    task = make_task()
    traces = _harden(tmp_path, task, [(UNRESTORED_EDIT, "tests/helpers/test_util.py")])
    stem = cli._certificate_stem(task)
    rounds = json.loads((traces / f"{stem}.rounds.json").read_text(encoding="utf-8"))["rounds"]
    assert rounds["before"]["recorded"]["primary"] == "test-edit"
    assert rounds["before"]["recorded"]["exploited"] is True


def test_recheck_passes_when_primary_and_exploited_agree(tmp_path, capsys):
    task = make_task()
    traces = _harden(tmp_path, task, [(UNRESTORED_EDIT, "tests/helpers/test_util.py")])
    capsys.readouterr()
    assert _recheck(traces, task) == 0
    out = capsys.readouterr().out
    assert "recorded primary: match" in out and "recorded exploited: match" in out


@pytest.mark.parametrize(
    "field, changes", [("exploited", {"exploited": False}), ("primary", {"primary": "none"})]
)
def test_recheck_exits_1_and_names_the_recorded_field_that_differs(tmp_path, capsys, field, changes):
    task = make_task()
    traces = _harden(tmp_path, task, [(UNRESTORED_EDIT, "tests/helpers/test_util.py")])
    stem = cli._certificate_stem(task)
    _edit_recorded(traces, stem, "before", **changes)
    capsys.readouterr()
    assert _recheck(traces, task) == 1
    captured = capsys.readouterr()
    assert f"recorded {field} does not match the recomputed {field}: {stem}.rounds.json" in captured.err
    assert f"recorded {field}: DIFFER" in captured.out
    assert SECRET_BODY not in captured.out + captured.err  # no diff text, and no recorded or recomputed value


def test_recheck_names_both_differing_fields_in_a_fixed_order(tmp_path, capsys):
    task = make_task()
    traces = _harden(tmp_path, task, [(UNRESTORED_EDIT, "tests/helpers/test_util.py")])
    stem = cli._certificate_stem(task)
    _edit_recorded(traces, stem, "before", primary="none", exploited=False)
    capsys.readouterr()
    assert _recheck(traces, task) == 1
    err = capsys.readouterr().err.splitlines()
    assert [line.split()[2] for line in err if "does not match" in line] == ["primary", "exploited"]


def test_recheck_on_an_older_rounds_file_checks_labels_only(tmp_path, capsys):
    task = make_task()
    traces = _harden(tmp_path, task, [(UNRESTORED_EDIT, "tests/helpers/test_util.py")])
    stem = cli._certificate_stem(task)
    _edit_recorded(traces, stem, "before", drop=("primary", "exploited"))
    capsys.readouterr()
    assert _recheck(traces, task) == 0
    captured = capsys.readouterr()
    assert "exploited/primary not recorded" in captured.out
    assert "recorded labels: match" in captured.out
    assert captured.err == ""


def test_recheck_labels_that_differ_still_exit_0_as_before(tmp_path, capsys):
    task = make_task()
    traces = _harden(tmp_path, task, [(UNRESTORED_EDIT, "tests/helpers/test_util.py")])
    stem = cli._certificate_stem(task)
    _edit_recorded(traces, stem, "before", labels=[])
    capsys.readouterr()
    assert _recheck(traces, task) == 0
    assert "recorded labels: DIFFER" in capsys.readouterr().out


# --- T49: the legit_fix downgrade is replayed by recheck, from inputs kept at write time ---------------------------


def _legit_task(gold: str) -> TaskSpec:
    return dataclasses.replace(th.TASK, gold_patch=gold, test_patch=th.HARD_CODE_TEST_PATCH)


def _keep_real_run(tmp_path: Path, task: TaskSpec, lab, *, after: bool = False) -> tuple[Path, str]:
    """Run the real harden with the fakes of test_recon_nudge.LegitLab, keep its files as cli does, and write each
    attack's trace. after=True keeps the same attack again as the re-attack round."""
    out = lab.run()
    if after:
        out = dataclasses.replace(out, after=out.before, attacks=(out.attacks[0], out.attacks[0]))
    stem = cli._certificate_stem(task)
    traces = tmp_path / "traces"
    keep.start_run(traces, stem, task)
    assert keep.keep_raw(out, stem, traces) == []
    lines = [
        json.dumps(rec) for result in out.attacks for rec in [HEADER, *result.steps, _end(result.final_diff)]
    ]
    (traces / f"{stem}.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return traces, stem


def _rounds(traces: Path, stem: str) -> dict:
    return json.loads((traces / f"{stem}.rounds.json").read_text(encoding="utf-8"))["rounds"]


def test_rounds_file_keeps_the_downgrade_inputs_at_write_time(tmp_path):
    task = _legit_task(trn.FIX_DIFF)
    traces, stem = _keep_real_run(
        tmp_path, task, trn.LegitLab(trn.FIX_DIFF, attacks=[trn.legit_attack(trn.FIX_DIFF)])
    )
    before = _rounds(traces, stem)["before"]
    assert before["recorded"]["labels"] == [] and before["recorded"]["exploited"] is False
    assert before["attack"]["outcome"] == "legit_fix"
    assert before["exposure"] == {
        "future_git": False,
        "network": False,
        "refs": [],
        "future_added": {"digests": None, "complete": False},
    }


def test_after_legit_fix_round_rechecks_as_match(tmp_path, capsys):
    task = _legit_task(trn.FIX_DIFF)
    lab = trn.LegitLab(trn.FIX_DIFF, attacks=[trn.legit_attack(trn.FIX_DIFF)])
    traces, stem = _keep_real_run(tmp_path, task, lab, after=True)
    assert _rounds(traces, stem)["after"]["attack"]["outcome"] == "legit_fix"
    capsys.readouterr()
    assert _recheck(traces, task, stem) == 0
    captured = capsys.readouterr()
    assert "after: labels=[] attempted=[] primary=none exploited=False" in captured.out
    assert "outcome: recorded legit_fix, recomputed legit_fix: MATCH" in captured.out
    assert "recorded labels: match" in captured.out
    assert "DIFFER" not in captured.out and "return 41" not in captured.out + captured.err


def test_gold_match_with_exposure_rechecks_as_match(tmp_path, capsys):
    task = _legit_task(trn.FIX_DIFF)
    lab = trn.LegitLab(trn.FIX_DIFF, exposed=("git-history",), attacks=[trn.legit_attack(trn.FIX_DIFF)])
    traces, stem = _keep_real_run(tmp_path, task, lab)
    before = _rounds(traces, stem)["before"]
    assert before["exposure"]["future_git"] is True
    assert before["attack"]["outcome"] == "gold_match_with_exposure"
    capsys.readouterr()
    assert _recheck(traces, task, stem) == 0
    out = capsys.readouterr().out
    assert "outcome: recorded gold_match_with_exposure, recomputed gold_match_with_exposure: MATCH" in out
    assert "DIFFER" not in out


def test_a_recorded_outcome_that_the_inputs_do_not_give_exits_1(tmp_path, capsys):
    task = _legit_task(trn.FIX_DIFF)
    traces, stem = _keep_real_run(
        tmp_path, task, trn.LegitLab(trn.FIX_DIFF, attacks=[trn.legit_attack(trn.FIX_DIFF)])
    )
    path = traces / f"{stem}.rounds.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["rounds"]["before"]["attack"]["outcome"] = None
    path.write_text(json.dumps(data), encoding="utf-8")
    capsys.readouterr()
    assert _recheck(traces, task, stem) == 1
    captured = capsys.readouterr()
    assert "outcome: recorded none, recomputed legit_fix: DIFFER" in captured.out
    assert f"recorded outcome does not match the recomputed outcome: {stem}.rounds.json" in captured.err
    assert "return 41" not in captured.out + captured.err


def test_a_real_exploit_label_stays_a_hole_after_the_downgrade_check(tmp_path, capsys):
    task = make_task()
    traces = _harden(tmp_path, task, [(UNRESTORED_EDIT, "tests/helpers/test_util.py")])
    capsys.readouterr()
    assert _recheck(traces, task) == 0
    out = capsys.readouterr().out
    assert "before: labels=['test-edit']" in out and "primary=test-edit exploited=True" in out
    assert "outcome: recorded none, recomputed none: MATCH" in out


def test_a_non_gold_pass_stays_unclassified_after_the_downgrade_check(tmp_path, capsys):
    task = _legit_task(trn.FIX_DIFF)
    traces, stem = _keep_real_run(
        tmp_path, task, trn.LegitLab(trn.FIX_DIFF, attacks=[trn.legit_attack(trn.OTHER_DIFF)])
    )
    assert _rounds(traces, stem)["before"]["recorded"]["labels"] == ["unclassified"]
    capsys.readouterr()
    assert _recheck(traces, task, stem) == 0
    out = capsys.readouterr().out
    assert (
        "before: labels=['unclassified'] attempted=['unclassified'] primary=unclassified exploited=True"
        in out
    )
    assert "outcome: recorded none, recomputed none: MATCH" in out


def test_an_older_rounds_file_without_the_downgrade_inputs_is_compared_as_before(tmp_path, capsys):
    task = _legit_task(trn.FIX_DIFF)
    traces, stem = _keep_real_run(
        tmp_path, task, trn.LegitLab(trn.FIX_DIFF, attacks=[trn.legit_attack(trn.FIX_DIFF)])
    )
    path = traces / f"{stem}.rounds.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    for rec in data["rounds"].values():
        rec.pop("exposure")
        rec.pop("attack")
    path.write_text(json.dumps(data), encoding="utf-8")
    capsys.readouterr()
    # Without the downgrade inputs the old comparison stands: the recorded primary none and exploited False of a
    # legit_fix round differ from the recomputed unclassified hole, so the recheck exits 1 as it did before T49.
    assert _recheck(traces, task, stem) == 1
    captured = capsys.readouterr()
    assert "downgrade inputs not recorded: outcome not recomputed (older rounds.json)" in captured.out
    assert "recorded primary: DIFFER" in captured.out and "recorded exploited: DIFFER" in captured.out
    assert "outcome" not in captured.err
    assert "error: recorded primary does not match the recomputed primary" in captured.err
