"""audit-exposure checks the run cap of the executor it uses: LOCAL_RUN_CAP for docker, SANDBOX_RUN_CAP for sandbox.
Fakes and a throwaway ledger only: no Docker, sandbox, model, network or paid call."""

import pytest
import test_audit as ta

from rewardseal import cli
from rewardseal.budget import Budget, create_ledger


@pytest.fixture(autouse=True)
def _in_tmp_path(tmp_path, monkeypatch):
    # The CLI defaults are relative (results/exposure): no test writes under the repo's results/.
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("EXECUTOR", raising=False)
    monkeypatch.delenv("MIN_FREE_DISK_GB", raising=False)
    monkeypatch.setattr(cli, "_env_file_values", dict)  # never read the owner's .env


class DockerSession(ta.CountedSession):
    def reset(self):
        self.budget.reserve_local_run()  # a Docker reset re-launches the container: one local run


class DockerExecutor(ta.CountedExecutor):
    def start(self, env, budget=None):
        self.starts += 1
        budget.reserve_local_run()  # every Docker start books a local run, never a sandbox run
        return DockerSession(budget)


def real_budget(tmp_path, *, sandbox_cap, local_cap):
    ledger = tmp_path / "ledger.json"
    create_ledger(ledger)
    return Budget(ledger, 1.0, 1.0, sandbox_run_cap=sandbox_cap, local_run_cap=local_cap)


def audit(budget, executor, capsys, *extra):
    deps = ta.make_deps(ta.tasks_for("a__a-1"), budget=budget, executor=executor)
    rc = cli.main(ta.audit_argv(*extra), deps=deps)
    return rc, capsys.readouterr().out


def test_docker_is_not_refused_by_a_small_sandbox_run_cap(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("EXECUTOR", "docker")
    budget = real_budget(tmp_path, sandbox_cap=3, local_cap=2000)
    rc, printed = audit(budget, DockerExecutor(), capsys)
    assert rc == 0 and "stopped before" not in printed and "SANDBOX_RUN_CAP" not in printed
    assert ta.records() == ["a__a-1.json"]
    assert (budget.snapshot()["local_runs"], budget.snapshot()["sandbox_runs"]) == (5, 0)


def test_docker_stops_cleanly_on_the_local_run_cap_and_names_it(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("EXECUTOR", " Docker ")  # read as the executor reads it: stripped, any case
    budget = real_budget(tmp_path, sandbox_cap=250, local_cap=4)
    rc, printed = audit(budget, DockerExecutor(), capsys)
    assert rc == 1 and "stopped before a__a-1" in printed
    assert "only 4 local run(s) remain under LOCAL_RUN_CAP=4 (0 used) and one task needs about 5" in printed
    assert "raise LOCAL_RUN_CAP yourself" in printed and "SANDBOX_RUN_CAP" not in printed
    assert ta.records() == [] and budget.snapshot()["local_runs"] == 0  # nothing was half-run


def test_docker_counts_the_local_runs_already_used(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("EXECUTOR", "docker")
    budget = real_budget(tmp_path, sandbox_cap=250, local_cap=6)
    budget.reserve_local_run()
    budget.reserve_local_run()
    rc, printed = audit(budget, DockerExecutor(), capsys)
    assert rc == 1 and "only 4 local run(s) remain under LOCAL_RUN_CAP=6 (2 used)" in printed
    assert budget.snapshot()["local_runs"] == 2


@pytest.mark.parametrize("executor", [None, "sandbox", " Sandbox "])
def test_sandbox_still_stops_on_the_sandbox_run_cap_only(tmp_path, monkeypatch, capsys, executor):
    if executor is not None:
        monkeypatch.setenv("EXECUTOR", executor)
    budget = real_budget(tmp_path, sandbox_cap=3, local_cap=2000)
    rc, printed = audit(budget, ta.CountedExecutor(), capsys)
    assert rc == 1
    assert (
        "stopped before a__a-1: only 3 sandbox run(s) remain under SANDBOX_RUN_CAP=3 (0 used) and one task needs "
        "about 5. This command never changes the cap: raise SANDBOX_RUN_CAP yourself, then run the same command "
        "again; tasks that already have a record are skipped"
    ) in printed
    assert ta.records() == []


def test_sandbox_ignores_an_exhausted_local_run_cap(tmp_path, capsys):
    budget = real_budget(tmp_path, sandbox_cap=250, local_cap=0)
    rc, _ = audit(budget, ta.CountedExecutor(), capsys)
    assert rc == 0 and ta.records() == ["a__a-1.json"]
    assert budget.snapshot()["sandbox_runs"] == 5


def dry_run_plan(capsys):
    deps = ta.make_deps(ta.tasks_for("a__a-1", "b__b-2"))
    assert cli.main(ta.audit_argv("--dry-run"), deps=deps) == 0
    return capsys.readouterr().out


@pytest.mark.parametrize("executor", [None, "sandbox", " Sandbox "])
def test_sandbox_dry_run_plan_is_unchanged(monkeypatch, capsys, executor):
    if executor is not None:
        monkeypatch.setenv("EXECUTOR", executor)
    assert dry_run_plan(capsys).splitlines()[3:] == [
        (
            "estimated sandbox runs: 10 (about 5 per task: the collect-only preflight start, the audit start and 3 "
            "resets); Sandboxes about $0.30 (an estimate: Sandboxes are not billed, the counter is a guard). No "
            "model, attacker or Tavily call: $0 of trial credit"
        ),
        "caps (ledger not read): SANDBOX_COST_CAP_USD $0.5, REAL_SPEND_CAP_USD $10",
    ]


@pytest.mark.parametrize(
    ("executor", "cap", "shown"),
    [(" Docker ", "1234", "1234"), ("docker", None, "2000")],
)
def test_docker_dry_run_plan_counts_local_container_runs_not_sandboxes(
    monkeypatch, capsys, executor, cap, shown
):
    monkeypatch.setenv("EXECUTOR", executor)
    if cap is not None:
        monkeypatch.setenv("LOCAL_RUN_CAP", cap)
    else:
        monkeypatch.delenv("LOCAL_RUN_CAP", raising=False)
    printed = dry_run_plan(capsys)
    assert printed.splitlines()[3:] == [
        (
            "estimated local container runs: 10 (about 5 per task: the collect-only preflight start, the audit "
            "start and 3 resets); local Docker runs are not billed and count against LOCAL_RUN_CAP. No model, "
            "attacker or Tavily call: $0 of trial credit"
        ),
        f"caps (ledger not read): LOCAL_RUN_CAP {shown}, REAL_SPEND_CAP_USD $10",
    ]
    assert "andbox" not in printed.split("audit  b__b-2")[1]


def test_docker_dry_run_plan_reads_the_executor_and_cap_from_dot_env(monkeypatch, capsys):
    # A dry run does not load .env into the process environment, so the plan looks there as the caps do.
    monkeypatch.setattr(cli, "_env_file_values", lambda: {"EXECUTOR": "docker", "LOCAL_RUN_CAP": "77"})
    printed = dry_run_plan(capsys)
    assert "estimated local container runs: 10" in printed
    assert "caps (ledger not read): LOCAL_RUN_CAP 77," in printed
