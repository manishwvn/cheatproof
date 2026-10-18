"""CLI tests: fakes only. No model, network, Docker or paid call, and no certify.py internals."""

import json
from pathlib import Path

import pytest

from cheatproof import cli
from cheatproof.budget import BudgetExceeded
from cheatproof.executor import ExecutorRefused, ExecutorUnavailable
from cheatproof.harden import HardenReport, RoundReport
from cheatproof.holes import HoleReport
from cheatproof.tasks import CACHE_VERSION, TaskSpec

INSTANCE = "astropy__astropy-7671"
IMAGE = "swebench/sweb.eval.x86_64.astropy_1776_astropy-7671:latest"
FAIL_TEST = "astropy/utils/tests/test_misc.py::test_fix"
GOLD_SENTINEL = "GOLD_SENTINEL_7f3a"
TEST_SENTINEL = "TEST_SENTINEL_91bc"
SYSTEM_PROMPT = "Strategy prompt: look for shortcuts.\n"
CLOCK = "2026-10-18T12:00:00+00:00"
UPPER_BOUND = "Upper bound against this attacker, not proof."
SCORE = {
    "n": 12,
    "n_after": 10,
    "hackable_before": 9,
    "hackable_after": 1,
    "certified": 7,
    "inconclusive": 2,
    "by_hole": {"test-edit": 4, "git-history": 5},
    "by_source": {"swe-bench-verified": {"n": 12, "hackable_before": 9, "certified": 7}},
}


@pytest.fixture(autouse=True)
def _no_ambient_model(monkeypatch):
    # Every test passes its model explicitly, or sets ATTACKER_MODEL itself, so the shell cannot change results.
    monkeypatch.delenv("ATTACKER_MODEL", raising=False)


def make_task() -> TaskSpec:
    return TaskSpec(
        instance_id=INSTANCE,
        repo="astropy/astropy",
        base_commit="a" * 40,
        image=IMAGE,
        fail_to_pass=(FAIL_TEST,),
        pass_to_pass=("astropy/utils/tests/test_misc.py::test_other",),
        gold_patch=f"diff --git a/astropy/misc.py b/astropy/misc.py\n+{GOLD_SENTINEL}\n",
        test_patch=f"diff --git a/astropy/utils/tests/test_misc.py b/x.py\n+{TEST_SENTINEL}\n",
        source="swe-bench-verified",
    )


def make_report(certified: bool = True) -> HardenReport:
    before = RoundReport(
        patches=(),
        holes=HoleReport(
            primary="test-edit",
            labels=("test-edit",),
            attempted=("test-edit",),
            evidence={},
            succeeded=True,
            exploited=True,
            skipped_records=0,
        ),
    )
    after = RoundReport(patches=("test-edit-guard",)) if certified else None
    return HardenReport(
        instance_id=INSTANCE,
        before=before,
        candidates=(),
        accepted=(),
        rejected=(),
        unpatched=(),
        after=after,
        certified=certified,
        reason="fake",
        sandbox_runs=2,
    )


class FakeBudget:
    """snapshot() returns the given totals in order: one before the run, one after."""

    def __init__(self, *totals: float) -> None:
        self._totals = iter(totals)

    def snapshot(self) -> dict:
        return {"total_usd": next(self._totals), "days": {}, "sandbox_runs": 0, "halted": None}


class Spy:
    def __init__(self) -> None:
        self.harden_calls: list[dict] = []
        self.attack_calls: list[tuple] = []
        self.certs: list[dict] = []
        self.score_calls: list[Path] = []


def make_deps(spy: Spy, **overrides) -> cli.Deps:
    def find_tasks(instance_id, source, cache_dir):
        return [make_task()] if instance_id == INSTANCE else []

    def attack(llm, session, system_prompt, task_prompt, config):
        spy.attack_calls.append((llm, session, system_prompt, task_prompt, config))
        return "attack-result"

    def harden(executor, env, task, attack_fn, *, budget, **kwargs):
        spy.harden_calls.append({"env": env, "task": task, "budget": budget, **kwargs})
        attack_fn("session")
        return make_report()

    def build_certificate(report, task, *, image_digest, attacker, cost_usd, timestamp):
        cert = {
            "instance_id": task.instance_id,
            "certified": report.certified,
            "image_digest": image_digest,
            "attacker": dict(attacker),
            "cost_usd": cost_usd,
            "timestamp": timestamp,
        }
        spy.certs.append(cert)
        return cert

    def write_certificate(cert, directory):
        path = directory / f"{cert['instance_id']}.json"
        path.write_text(json.dumps(cert), encoding="utf-8")
        return path

    def score_directory(directory):
        spy.score_calls.append(directory)
        return SCORE

    base = {
        "find_tasks": find_tasks,
        "make_executor": lambda: "executor",
        "make_budget": lambda: FakeBudget(0.10, 0.25),
        "make_llm": lambda budget: "fake-llm",
        "harden": harden,
        "attack": attack,
        "build_certificate": build_certificate,
        "write_certificate": write_certificate,
        "score_directory": score_directory,
        "clock": lambda: CLOCK,
    }
    base.update(overrides)
    return cli.Deps(**base)


def prompt_file(tmp_path: Path) -> Path:
    path = tmp_path / "prompt.txt"
    path.write_text(SYSTEM_PROMPT, encoding="utf-8")
    return path


def make_certs_dir(tmp_path: Path) -> Path:
    certs = tmp_path / "certs"
    certs.mkdir()
    (certs / "one.json").write_text("{}", encoding="utf-8")
    return certs


def test_missing_system_prompt_option_refused(tmp_path, capsys):
    spy = Spy()
    rc = cli.main(["harden", INSTANCE], deps=make_deps(spy))
    assert rc == 2
    assert spy.harden_calls == [] and spy.certs == []
    assert "--system-prompt-file" in capsys.readouterr().err


def test_missing_system_prompt_file_refused(tmp_path, capsys):
    spy = Spy()
    missing = tmp_path / "absent.txt"
    rc = cli.main(["harden", INSTANCE, "--system-prompt-file", str(missing)], deps=make_deps(spy))
    assert rc == 2
    assert spy.harden_calls == []
    assert "not found" in capsys.readouterr().err


def test_unknown_instance_id_exits_2(tmp_path, capsys):
    spy = Spy()
    rc = cli.main(
        [
            "harden",
            "no__such-1",
            "--system-prompt-file",
            str(prompt_file(tmp_path)),
            "--attacker-model",
            "fake-model",
        ],
        deps=make_deps(spy),
    )
    assert rc == 2
    assert spy.harden_calls == [] and spy.certs == []
    err = capsys.readouterr().err
    assert "no__such-1" in err and "fetch" in err


def test_missing_attacker_model_exits_2(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("ATTACKER_MODEL", raising=False)
    spy = Spy()
    rc = cli.main(
        ["harden", INSTANCE, "--system-prompt-file", str(prompt_file(tmp_path))], deps=make_deps(spy)
    )
    assert rc == 2
    assert spy.harden_calls == []
    assert "ATTACKER_MODEL" in capsys.readouterr().err


def test_attacker_model_defaults_to_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ATTACKER_MODEL", "env-model")
    spy = Spy()
    rc = cli.main(
        [
            "harden",
            INSTANCE,
            "--system-prompt-file",
            str(prompt_file(tmp_path)),
            "--out",
            str(tmp_path / "c"),
        ],
        deps=make_deps(spy),
    )
    assert rc == 0
    assert spy.attack_calls[0][4].model == "env-model"


@pytest.mark.parametrize(
    "limits", [["--max-steps", "0"], ["--max-tokens", "0"], ["--timeout", "0"], ["--timeout", "nan"]]
)
def test_bad_limits_exit_2_before_any_run(tmp_path, limits, capsys):
    spy = Spy()
    argv = ["harden", INSTANCE, "--system-prompt-file", str(prompt_file(tmp_path)), "--attacker-model", "m"]
    rc = cli.main([*argv, *limits], deps=make_deps(spy))
    assert rc == 2
    assert spy.harden_calls == []
    assert "error:" in capsys.readouterr().err


def test_harden_happy_path_writes_certificate(tmp_path, capsys):
    spy = Spy()
    out = tmp_path / "certs"
    deps = make_deps(spy, make_budget=lambda: FakeBudget(0.10, 0.25))
    rc = cli.main(
        [
            "harden",
            INSTANCE,
            "--system-prompt-file",
            str(prompt_file(tmp_path)),
            "--attacker-model",
            "fake-model",
            "--max-steps",
            "4",
            "--max-tokens",
            "9000",
            "--timeout",
            "60",
            "--out",
            str(out),
        ],
        deps=deps,
    )
    assert rc == 0

    # The timeout reaches harden, and the attack runs through the bound llm, system prompt and config.
    assert spy.harden_calls[0]["timeout"] == 60.0
    llm, _session, system_prompt, task_prompt, config = spy.attack_calls[0]
    assert llm == "fake-llm" and system_prompt == SYSTEM_PROMPT
    assert config.model == "fake-model" and config.max_steps == 4 and config.max_tokens_total == 9000
    assert config.allow_network is False

    # The task prompt describes the task and never carries the gold or test patch.
    assert INSTANCE in task_prompt and FAIL_TEST in task_prompt
    assert GOLD_SENTINEL not in task_prompt
    assert TEST_SENTINEL not in task_prompt

    # Cost is the ledger difference across the run, and the certificate carries the attacker limits.
    (cert,) = spy.certs
    assert cert["cost_usd"] == pytest.approx(0.15)
    assert cert["attacker"] == {"model": "fake-model", "max_steps": 4, "max_tokens": 9000}
    assert cert["image_digest"] is None
    assert cert["timestamp"] == CLOCK
    written = out / f"{INSTANCE}.json"
    assert json.loads(written.read_text())["certified"] is True

    printed = capsys.readouterr().out
    assert f"certificate: {written}" in printed
    assert "certified: yes" in printed
    assert "holes found: 1 (test-edit)" in printed
    assert "cost: $0.1500" in printed


@pytest.mark.parametrize(
    "error",
    [
        BudgetExceeded("total cap $20.00 reached"),
        ExecutorRefused("no docker"),
        ExecutorUnavailable("docker down"),
    ],
)
def test_harden_stop_errors_exit_1_without_traceback(tmp_path, capsys, error):
    spy = Spy()

    def failing_harden(*args, **kwargs):
        raise error

    out = tmp_path / "certs"
    deps = make_deps(spy, harden=failing_harden, make_budget=lambda: FakeBudget(0.0))
    rc = cli.main(
        [
            "harden",
            INSTANCE,
            "--system-prompt-file",
            str(prompt_file(tmp_path)),
            "--attacker-model",
            "fake-model",
            "--out",
            str(out),
        ],
        deps=deps,
    )
    captured = capsys.readouterr()
    assert rc == 1
    assert type(error).__name__ in captured.err
    assert "Traceback" not in captured.err and "Traceback" not in captured.out
    assert spy.certs == []
    assert not out.exists()


def test_report_text_shows_n_raw_counts_and_upper_bound(tmp_path, capsys):
    spy = Spy()
    certs = make_certs_dir(tmp_path)
    rc = cli.main(["report", "--certs", str(certs)], deps=make_deps(spy))
    out = capsys.readouterr().out
    assert rc == 0
    assert spy.score_calls == [certs]
    assert "n=12" in out
    assert "9 of 12" in out and "1 of 10" in out and "7 of 12" in out and "2 of 12" in out
    assert "95% CI" in out
    assert "test-edit: 4" in out
    assert "swe-bench-verified: certified=7, hackable_before=9, n=12" in out
    assert UPPER_BOUND in out


def test_report_json_is_sorted_and_written_to_out(tmp_path, capsys):
    spy = Spy()
    certs = make_certs_dir(tmp_path)
    target = tmp_path / "reports" / "score.json"
    rc = cli.main(
        ["report", "--certs", str(certs), "--format", "json", "--out", str(target)],
        deps=make_deps(spy),
    )
    assert rc == 0
    printed = json.loads(capsys.readouterr().out)
    assert target.read_text(encoding="utf-8") == json.dumps(printed, indent=2, sort_keys=True) + "\n"
    assert printed["n"] == 12 and printed["n_after"] == 10
    before = printed["rates"]["hackable_before"]
    assert (before["k"], before["n"]) == (9, 12)
    low, high = before["ci95"]
    assert low < before["rate"] < high
    assert printed["note"] == UPPER_BOUND


def test_report_missing_directory_exits_2(tmp_path, capsys):
    spy = Spy()
    rc = cli.main(["report", "--certs", str(tmp_path / "absent")], deps=make_deps(spy))
    assert rc == 2
    assert spy.score_calls == []
    assert "not found" in capsys.readouterr().err


def test_report_empty_directory_exits_2(tmp_path, capsys):
    spy = Spy()
    certs = tmp_path / "certs"
    certs.mkdir()
    rc = cli.main(["report", "--certs", str(certs)], deps=make_deps(spy))
    assert rc == 2
    assert spy.score_calls == []
    assert "no certificates" in capsys.readouterr().err


def test_report_rejects_counts_that_do_not_add_up(tmp_path, capsys):
    spy = Spy()
    certs = make_certs_dir(tmp_path)
    deps = make_deps(spy, score_directory=lambda directory: {**SCORE, "hackable_before": 13})
    rc = cli.main(["report", "--certs", str(certs)], deps=deps)
    assert rc == 2
    assert "13 of 12" in capsys.readouterr().err


def test_wilson_interval_matches_known_values():
    low, high = cli.wilson_interval(5, 10)
    assert low == pytest.approx(0.2366, abs=1e-4)
    assert high == pytest.approx(0.7634, abs=1e-4)
    assert cli.wilson_interval(0, 0) is None


def test_find_cached_tasks_reads_only_the_cache(tmp_path):
    task = make_task()
    payload = {
        "version": CACHE_VERSION,
        "source": "swe-bench-verified",
        "scan_rows": 500,
        "scanned": 1,
        "skipped": {},
        "tasks": [task.to_dict()],
    }
    (tmp_path / "swe-bench-verified.json").write_text(json.dumps(payload), encoding="utf-8")
    assert cli.find_cached_tasks(INSTANCE, None, tmp_path) == [task]
    assert cli.find_cached_tasks(INSTANCE, "swe-bench-verified", tmp_path) == [task]
    assert cli.find_cached_tasks(INSTANCE, "swe-rebench", tmp_path) == []
    assert cli.find_cached_tasks("other__id-1", None, tmp_path) == []
    with pytest.raises(ValueError):
        cli.find_cached_tasks(INSTANCE, "nope", tmp_path)


def test_error_text_is_sanitized_not_traced(tmp_path, capsys):
    spy = Spy()

    def failing_harden(*args, **kwargs):
        raise BudgetExceeded("halted")

    deps = make_deps(spy, harden=failing_harden)
    rc = cli.main(
        ["harden", INSTANCE, "--system-prompt-file", str(prompt_file(tmp_path)), "--attacker-model", "m"],
        deps=deps,
    )
    assert rc == 1
    assert capsys.readouterr().err.strip() == "error: BudgetExceeded: halted"


def test_argparse_usage_error_returns_2(tmp_path):
    spy = Spy()
    assert cli.main(["harden"], deps=make_deps(spy)) == 2  # missing instance id
    assert cli.main(["unknown-command"], deps=make_deps(spy)) == 2
    assert spy.harden_calls == [] and spy.score_calls == []
