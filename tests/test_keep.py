"""T42: raw traces, diffs and restore sets are kept locally, and `holes recheck` re-runs the classifier offline.

Fakes only: no model, sandbox, network or budget. Every file goes under tmp_path.
"""

import dataclasses
import hashlib
import json
from pathlib import Path

import pytest

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
        return "attack-result"

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


def test_traces_folder_and_its_raw_files_are_ignored_by_version_control():
    root = Path(__file__).resolve().parent.parent
    lines = (root / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "results/traces/" in lines
    assert keep.ROUND_NAMES == ("before", "after")


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
    keep.write_restore(tmp_path, "stem", task)
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
    assert _recheck(traces, task) == 0
    out = capsys.readouterr().out
    assert "before: labels=['test-edit']" in out
    assert "tests/test_core.py: unrestored by the grade" in out
    assert "recorded labels: DIFFER" in out


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
