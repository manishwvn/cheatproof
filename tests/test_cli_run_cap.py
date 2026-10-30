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
