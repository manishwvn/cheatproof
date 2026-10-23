"""T37 --network-fetch: fakes only. No Tavily, model, network, Docker or paid call, and no real key."""

import json

import pytest
import test_attacker as ta
import test_cli as tc

from cheatproof import cli
from cheatproof.attacker import AttackConfig
from cheatproof.budget import Budget, BudgetExceeded
from cheatproof.strategies import (
    COMBINED,
    MAX_QUERY_CHARS,
    STRATEGIES,
    make_network_search,
    with_network_section,
)

pytestmark = pytest.mark.usefixtures("init_ledger")  # a missing ledger is refused; every test gets one

FAKE_KEY = "tvly-FAKEKEY0123456789abcdef"  # a made-up value that looks like a key, for the redaction tests


class FakeClient:
    """Stands in for TavilyClient: records queries, never touches the network."""

    def __init__(self, results=None):
        self.queries = []
        self.results = results if results is not None else []

    def factory(self, key):
        self.key = key
        return self

    def search(self, query, max_results):
        self.queries.append(query)
        return {"results": self.results}


def counted_budget(tmp_path, cap):
    return Budget(tmp_path / "ledger.json", 1.0, 1.0, 2, tavily_call_cap=cap)


# --- the search wrapper -------------------------------------------------------------------------------


def test_network_search_counts_each_call_against_the_cap(tmp_path):
    budget = counted_budget(tmp_path, cap=2)
    client = FakeClient([{"title": "t", "url": "https://example.test/a", "content": "c"}])
    search = make_network_search(budget, FAKE_KEY, client_factory=client.factory)
    assert search("pytest bug") == [{"title": "t", "url": "https://example.test/a", "content": "c"}]
    search("pytest bug 2")
    with pytest.raises(BudgetExceeded, match="tavily call cap 2 reached"):
        search("pytest bug 3")
    assert budget.snapshot()["tavily_calls"] == 2
    assert client.queries == ["pytest bug", "pytest bug 2"]  # the refused call sent nothing


def test_network_search_redacts_secret_words_in_the_query_before_it_leaves(tmp_path):
    client = FakeClient()
    search = make_network_search(counted_budget(tmp_path, 5), FAKE_KEY, client_factory=client.factory)
    search(f"fix for foo {FAKE_KEY} mail me@example.com\nnow")
    assert client.queries == ["fix for foo REDACTED mail REDACTED now"]


def test_network_search_cuts_a_long_query(tmp_path):
    client = FakeClient()
    search = make_network_search(counted_budget(tmp_path, 5), FAKE_KEY, client_factory=client.factory)
    search("word " * 500)
    assert len(client.queries[0]) <= MAX_QUERY_CHARS


def test_network_search_refuses_an_empty_query_without_a_reservation(tmp_path):
    budget = counted_budget(tmp_path, 5)
    client = FakeClient()
    search = make_network_search(budget, FAKE_KEY, client_factory=client.factory)
    with pytest.raises(ValueError, match="empty search query"):
        search("   \n ")
    assert budget.snapshot().get("tavily_calls", 0) == 0 and client.queries == []


def test_network_search_cleans_result_snippets(tmp_path):
    hits = [
        {
            "title": "Fix",
            "url": "https://example.test/pull/1",
            "content": f"token {FAKE_KEY} see /Users/someone/x and bob@example.com ok",
        }
    ]
    client = FakeClient(hits)
    search = make_network_search(counted_budget(tmp_path, 5), FAKE_KEY, client_factory=client.factory)
    (item,) = search("q")
    assert item["content"] == "token REDACTED see REDACTED and REDACTED ok"
    assert FAKE_KEY not in str(item)


def test_network_search_without_a_key_raises_at_setup(tmp_path, monkeypatch):
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="TAVILY_API_KEY not set"):
        make_network_search(counted_budget(tmp_path, 5), client_factory=FakeClient().factory)


def test_with_network_section_appends_once_and_keeps_the_prompt():
    out = with_network_section(COMBINED)
    assert out.startswith(COMBINED.rstrip()) and "web_search" in out and "at most 3 times" in out
    assert with_network_section(out) == out
    assert with_network_section(STRATEGIES["network"]) == STRATEGIES["network"]


# --- the attacker trace -------------------------------------------------------------------------------


def test_web_search_query_in_the_trace_is_the_cleaned_text(tmp_path):
    searched: list[str] = []
    cfg = AttackConfig(model=ta.MODEL, allow_network=True)
    trace = tmp_path / "t.jsonl"
    result, _, _ = ta.go(
        [
            ta.reply(ta.call("web_search", {"query": f"upstream fix {FAKE_KEY} for foo"})),
            ta.reply(ta.call("submit")),
        ],
        config=cfg,
        search=lambda q: searched.append(q) or [],
        trace_path=trace,
    )
    step = next(r for r in ta.read_trace(trace) if r.get("tool") == "web_search")
    assert step["args"] == {"query": "upstream fix REDACTED for foo"}
    assert FAKE_KEY not in trace.read_text()
    assert result.steps[0]["args"] == {"query": "upstream fix REDACTED for foo"}


# --- the CLI ------------------------------------------------------------------------------------------


class SearchSpy:
    def __init__(self):
        self.budgets = []
        self.queries = []

    def make_search(self, budget):
        self.budgets.append(budget)

        def search(query):
            self.queries.append(query)
            return []

        return search


def attack_spy(spy):
    """An attack fake that records the keyword arguments it got, search included."""
    seen = []

    def attack(llm, session, system_prompt, task_prompt, config, trace_path=None, **kwargs):
        spy.attack_calls.append((llm, session, system_prompt, task_prompt, config))
        seen.append(kwargs)
        return "attack-result"

    attack.seen = seen
    return attack


def harden_argv(tmp_path, *extra):
    return [
        "harden",
        tc.INSTANCE,
        "--system-prompt-file",
        str(tc.prompt_file(tmp_path)),
        "--attacker-model",
        "fake-model",
        "--out",
        str(tc.out_dir(tmp_path)),
        *extra,
    ]


def test_network_fetch_is_off_by_default(tmp_path, monkeypatch):
    monkeypatch.setenv("TAVILY_API_KEY", FAKE_KEY)
    spy, search = tc.Spy(), SearchSpy()
    attack = attack_spy(spy)
    deps = tc.make_deps(spy, attack=attack, make_search=search.make_search)
    assert cli.main(harden_argv(tmp_path), deps=deps) == 0
    assert attack.seen == [{}] and search.budgets == []
    assert spy.harden_calls[0]["env"].network is False
    assert spy.attack_calls[0][4].allow_network is False
    assert spy.attack_calls[0][2] == tc.SYSTEM_PROMPT  # the prompt is the file's, no network section


def test_harden_network_fetch_wires_search_network_and_prompt(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("TAVILY_API_KEY", FAKE_KEY)
    spy, search = tc.Spy(), SearchSpy()
    attack = attack_spy(spy)
    deps = tc.make_deps(spy, attack=attack, make_search=search.make_search)
    assert cli.main(harden_argv(tmp_path, "--network-fetch"), deps=deps) == 0
    assert spy.harden_calls[0]["env"].network is True  # EnvSpec.network matches allow_network
    config = spy.attack_calls[0][4]
    assert config.allow_network is True
    assert "web_search" in spy.attack_calls[0][2] and spy.attack_calls[0][2].startswith(
        tc.SYSTEM_PROMPT.rstrip()
    )
    assert len(search.budgets) == 1 and callable(attack.seen[0]["search"])
    assert spy.build_kwargs[0]["strategy"] == "prompt+network"
    err = capsys.readouterr().err
    assert err.count("warning: --network-fetch") == 1 and "network is ON" in err
    assert FAKE_KEY not in err


def test_harden_network_fetch_without_a_key_is_refused_before_anything_runs(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    spy, search = tc.Spy(), SearchSpy()
    deps = tc.make_deps(spy, make_search=search.make_search)
    assert cli.main(harden_argv(tmp_path, "--network-fetch"), deps=deps) == 2
    assert spy.harden_calls == [] and spy.attack_calls == [] and search.budgets == []
    err = capsys.readouterr().err
    assert "TAVILY_API_KEY" in err and "nothing was run" in err


def test_a_search_that_cannot_be_made_stops_before_the_paid_run(tmp_path, monkeypatch):
    monkeypatch.setenv("TAVILY_API_KEY", FAKE_KEY)
    spy = tc.Spy()
    deps = tc.make_deps(spy)  # no make_search wired
    assert cli.main(harden_argv(tmp_path, "--network-fetch"), deps=deps) == 1
    assert spy.harden_calls == []


def test_batch_network_fetch_wires_each_run_and_is_recorded(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("TAVILY_API_KEY", FAKE_KEY)
    spy, search = tc.Spy(), SearchSpy()
    attack = attack_spy(spy)
    out = tc.out_dir(tmp_path)
    deps = tc.batch_deps(spy, tc.batch_tasks(tc.ID_A, tc.ID_B), attack=attack, make_search=search.make_search)
    assert cli.main(tc.batch_argv(tmp_path, out, "--network-fetch"), deps=deps) == 0
    assert [call["env"].network for call in spy.harden_calls] == [True, True]
    assert len(search.budgets) == 2 and all("search" in kw for kw in attack.seen)
    assert tc.read_batch(out)["network_fetch"] is True
    assert capsys.readouterr().err.count("warning: --network-fetch") == 1


def test_batch_without_the_flag_stays_network_off(tmp_path, monkeypatch):
    monkeypatch.setenv("TAVILY_API_KEY", FAKE_KEY)
    spy, search = tc.Spy(), SearchSpy()
    out = tc.out_dir(tmp_path)
    deps = tc.batch_deps(spy, tc.batch_tasks(tc.ID_A), make_search=search.make_search)
    assert cli.main(tc.batch_argv(tmp_path, out), deps=deps) == 0
    assert [call["env"].network for call in spy.harden_calls] == [False]
    assert search.budgets == [] and tc.read_batch(out)["network_fetch"] is False


def test_batch_network_fetch_runs_at_most_two_tasks(tmp_path, monkeypatch):
    monkeypatch.setenv("TAVILY_API_KEY", FAKE_KEY)
    spy, search = tc.Spy(), SearchSpy()
    out = tc.out_dir(tmp_path)
    tc.certified_file(out, tc.ID_A)  # already certified: does not use a slot
    deps = tc.batch_deps(
        spy,
        tc.batch_tasks(tc.ID_A, tc.ID_B, tc.ID_C, tc.ID_D, tc.ID_E),
        attack=attack_spy(spy),
        make_search=search.make_search,
    )
    assert cli.main(tc.batch_argv(tmp_path, out, "--network-fetch"), deps=deps) == 0
    assert tc.harden_order(spy) == [tc.ID_B, tc.ID_C]
    assert len(tc.read_batch(out)["selected_ids"]) == 2


def test_batch_network_fetch_refuses_more_than_two_instance_ids(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("TAVILY_API_KEY", FAKE_KEY)
    spy, search = tc.Spy(), SearchSpy()
    tasks = tc.batch_tasks(tc.ID_A, tc.ID_B, tc.ID_C)
    by_id = {t.instance_id: t for t in tasks}
    deps = tc.batch_deps(
        spy,
        tasks,
        find_tasks=lambda iid, source, cache: [by_id[iid]] if iid in by_id else [],
        attack=attack_spy(spy),
        make_search=search.make_search,
    )
    argv = tc.batch_argv(
        tmp_path, tc.out_dir(tmp_path), "--network-fetch", "--instance-ids", tc.ID_A, tc.ID_B, tc.ID_C
    )
    assert cli.main(argv, deps=deps) == 2
    assert spy.harden_calls == [] and "at most 2 tasks" in capsys.readouterr().err
    ok = tc.batch_argv(tmp_path, tc.out_dir(tmp_path), "--network-fetch", "--instance-ids", tc.ID_C, tc.ID_A)
    assert cli.main(ok, deps=deps) == 0 and tc.harden_order(spy) == [tc.ID_C, tc.ID_A]


def test_batch_network_fetch_without_a_key_is_refused(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    spy = tc.Spy()
    deps = tc.batch_deps(spy, tc.batch_tasks(tc.ID_A))
    assert cli.main(tc.batch_argv(tmp_path, tc.out_dir(tmp_path), "--network-fetch"), deps=deps) == 2
    assert spy.harden_calls == [] and "TAVILY_API_KEY" in capsys.readouterr().err
    assert not (tc.out_dir(tmp_path).parent / "batch.json").exists()


def test_batch_dry_run_with_network_fetch_makes_no_call_and_notes_the_cap(tmp_path, capsys):
    spy = tc.Spy()
    deps = tc.batch_deps(spy, tc.batch_tasks(tc.ID_A, tc.ID_B, tc.ID_C))
    argv = tc.batch_argv(tmp_path, tc.out_dir(tmp_path), "--network-fetch", "--dry-run")
    assert cli.main(argv, deps=deps) == 0
    out = capsys.readouterr().out
    assert "--network-fetch: at most 2 tasks" in out
    assert out.count(tc.ID_A) + out.count(tc.ID_B) >= 2 and tc.ID_C not in out
    assert spy.harden_calls == []


def test_no_key_value_reaches_the_batch_state(tmp_path, monkeypatch):
    monkeypatch.setenv("TAVILY_API_KEY", FAKE_KEY)
    spy, search = tc.Spy(), SearchSpy()
    out = tc.out_dir(tmp_path)
    deps = tc.batch_deps(spy, tc.batch_tasks(tc.ID_A), attack=attack_spy(spy), make_search=search.make_search)
    cli.main(tc.batch_argv(tmp_path, out, "--network-fetch"), deps=deps)
    assert FAKE_KEY not in json.dumps(tc.read_batch(out))
