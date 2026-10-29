"""T37 --network-fetch: fakes only. No Tavily, model, network, Docker or paid call, and no real key."""

import json

import pytest
import test_attacker as ta
import test_cli as tc

from rewardseal import cli
from rewardseal.attacker import AttackConfig
from rewardseal.budget import Budget, BudgetExceeded
from rewardseal.strategies import (
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


def test_harden_network_fetch_wires_search_and_prompt_with_the_sandbox_network_off(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setenv("TAVILY_API_KEY", FAKE_KEY)
    spy, search = tc.Spy(), SearchSpy()
    attack = attack_spy(spy)
    deps = tc.make_deps(spy, attack=attack, make_search=search.make_search)
    assert cli.main(harden_argv(tmp_path, "--network-fetch"), deps=deps) == 0
    assert spy.harden_calls[0]["env"].network is False  # Tavily runs on the host: the sandbox stays offline
    config = spy.attack_calls[0][4]
    assert config.allow_network is True
    assert "web_search" in spy.attack_calls[0][2] and spy.attack_calls[0][2].startswith(
        tc.SYSTEM_PROMPT.rstrip()
    )
    assert len(search.budgets) == 1 and callable(attack.seen[0]["search"])
    assert spy.build_kwargs[0]["strategy"] == "prompt+network"
    err = capsys.readouterr().err
    assert err.count("warning: --network-fetch") == 1 and "sandbox network stays off" in err
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


def test_batch_network_fetch_wires_each_run_and_keeps_the_sandbox_off(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("TAVILY_API_KEY", FAKE_KEY)
    spy, search = tc.Spy(), SearchSpy()
    attack = attack_spy(spy)
    out = tc.out_dir(tmp_path)
    deps = tc.batch_deps(spy, tc.batch_tasks(tc.ID_A, tc.ID_B), attack=attack, make_search=search.make_search)
    assert cli.main(tc.batch_argv(tmp_path, out, "--network-fetch"), deps=deps) == 0
    assert [call["env"].network for call in spy.harden_calls] == [False, False]
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


# --- review fixes: sandbox network off, first attack only, cleaning, cap, persisted total -----------------


def test_clean_text_redacts_whole_string_credential_patterns():
    from rewardseal.sanitize import clean_text

    assert clean_text("fix Bearer abc123token now", 100) == "fix REDACTED now"
    assert clean_text("setup password=hunter2 here", 100) == "setup REDACTED here"
    assert clean_text("use api_key: abc123 please", 100) == "use api_key: REDACTED please"
    assert clean_text("send access_token=abc and auth-token:xyz", 100) == "send REDACTED and REDACTED"
    assert clean_text("Authorization: abc", 100) == "Authorization: REDACTED"
    assert clean_text("key=abcdefghijkl", 100) == "REDACTED"
    assert "hunter2" not in clean_text("PASSWORD=hunter2", 100)


def test_clean_text_replaces_the_configured_key_verbatim_even_when_it_looks_ordinary(monkeypatch):
    from rewardseal.sanitize import clean_text

    plain = "plainsecretvalue99"  # no key-like shape: only the verbatim match can catch it
    monkeypatch.setenv("TAVILY_API_KEY", plain)
    out = clean_text(f"find {plain} in a repo, {plain}x too", 200)
    assert plain not in out and out.startswith("find REDACTED in")
    assert clean_text("x", 10, secrets=("anothersecret",)) == "x"
    assert "anothersecret" not in clean_text("see anothersecret ok", 100, secrets=("anothersecret",))


def test_clean_text_caps_words_after_the_whole_string_pass():
    from rewardseal.sanitize import clean_text

    assert len(clean_text("word " * 1000, 50)) <= 50
    assert clean_text("a b c", 0) == ""


def test_traced_query_is_cut_to_what_is_sent():
    cfg = AttackConfig(model=ta.MODEL, allow_network=True)
    long_query = "word " * 400
    result, _, _ = ta.go(
        [ta.reply(ta.call("web_search", {"query": long_query})), ta.reply(ta.call("submit"))],
        config=cfg,
        search=lambda q: [],
    )
    assert len(result.steps[0]["args"]["query"]) <= MAX_QUERY_CHARS


def test_cap_halt_through_the_attacker_stops_the_attempt_and_traces_it(tmp_path):
    budget = counted_budget(tmp_path, cap=1)
    search = make_network_search(budget, FAKE_KEY, client_factory=FakeClient().factory)
    cfg = AttackConfig(model=ta.MODEL, allow_network=True)
    trace = tmp_path / "t.jsonl"
    replies = [
        ta.reply(ta.call("web_search", {"query": "first"})),
        ta.reply(ta.call("web_search", {"query": "second"})),
        ta.reply(ta.call("submit")),
    ]
    with pytest.raises(BudgetExceeded, match="tavily call cap 1 reached"):
        ta.go(replies, config=cfg, search=search, trace_path=trace)
    assert budget.snapshot()["tavily_calls"] == 1
    assert ta.read_trace(trace)[-1]["stop_reason"] == "budget"


def test_a_failing_client_never_leaks_the_key_into_the_trace_or_the_model_reply(tmp_path):
    class Boom:
        def factory(self, key):
            return self

        def search(self, query, max_results):
            raise RuntimeError(f"401 for key {FAKE_KEY}")

    search = make_network_search(counted_budget(tmp_path, 5), FAKE_KEY, client_factory=Boom().factory)
    cfg = AttackConfig(model=ta.MODEL, allow_network=True)
    trace = tmp_path / "t.jsonl"
    result, llm, _ = ta.go(
        [ta.reply(ta.call("web_search", {"query": "q"})), ta.reply(ta.call("submit"))],
        config=cfg,
        search=search,
        trace_path=trace,
    )
    assert result.steps[0]["error"] == "tool_exception"
    seen = trace.read_text() + repr(result) + repr(ta.tool_texts(llm, 1))
    assert FAKE_KEY not in seen and "401" not in seen


def test_the_cap_halt_through_the_cli_stops_without_a_certificate(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("TAVILY_API_KEY", FAKE_KEY)
    spy = tc.Spy()
    capped = counted_budget(tmp_path, cap=0)

    def attack(llm, session, system_prompt, task_prompt, config, trace_path=None, search=None, **kwargs):
        search("upstream fix")  # the reservation is refused at the cap: BudgetExceeded
        return "attack-result"

    deps = tc.make_deps(
        spy,
        attack=attack,
        make_search=lambda budget: make_network_search(capped, FAKE_KEY, client_factory=FakeClient().factory),
    )
    assert cli.main(harden_argv(tmp_path, "--network-fetch"), deps=deps) == 1
    assert spy.certs == []
    assert "BudgetExceeded" in capsys.readouterr().err and capped.snapshot().get("tavily_calls", 0) == 0


def test_only_the_before_hardening_attack_gets_search(tmp_path, monkeypatch):
    monkeypatch.setenv("TAVILY_API_KEY", FAKE_KEY)
    spy, search = tc.Spy(), SearchSpy()
    attack = attack_spy(spy)
    configs = []

    def two_round_harden(executor, env, task, attack_fn, *, budget, **kwargs):
        spy.harden_calls.append({"env": env, "task": task, "budget": budget, **kwargs})
        attack_fn("before-session")
        attack_fn("after-session")
        return tc.make_report()

    deps = tc.make_deps(spy, attack=attack, make_search=search.make_search, harden=two_round_harden)
    assert cli.main(harden_argv(tmp_path, "--network-fetch"), deps=deps) == 0
    configs = [call[4] for call in spy.attack_calls]
    assert "search" in attack.seen[0] and attack.seen[1] == {}
    assert [c.allow_network for c in configs] == [True, False]  # the after config says no web_search
    assert len(search.budgets) == 1


def test_the_sandbox_network_stays_off_for_every_session(tmp_path, monkeypatch):
    import contextlib
    from types import SimpleNamespace

    monkeypatch.setenv("TAVILY_API_KEY", FAKE_KEY)
    started = []

    class Executor:
        def start(self, env, budget=None):
            started.append(env)
            return contextlib.nullcontext("session")

    spy, search = tc.Spy(), SearchSpy()
    deps = tc.make_deps(
        spy,
        attack=attack_spy(spy),
        make_search=search.make_search,
        make_executor=Executor,
        preflight=lambda session, task, **_: SimpleNamespace(ok=True),
    )
    assert cli.main(harden_argv(tmp_path, "--network-fetch"), deps=deps) == 0
    assert [env.network for env in started] == [False]  # the collect-only preflight session
    assert [call["env"].network for call in spy.harden_calls] == [
        False
    ]  # harden derives every session from it


def test_the_total_cap_is_kept_in_batch_json_across_invocations(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("TAVILY_API_KEY", FAKE_KEY)
    spy, search = tc.Spy(), SearchSpy()
    out = tc.out_dir(tmp_path)
    tasks = tc.batch_tasks(tc.ID_A, tc.ID_B, tc.ID_C, tc.ID_D)
    by_id = {t.instance_id: t for t in tasks}
    deps = tc.batch_deps(
        spy,
        tasks,
        find_tasks=lambda iid, source, cache: [by_id[iid]] if iid in by_id else [],
        attack=attack_spy(spy),
        make_search=search.make_search,
    )
    assert cli.main(tc.batch_argv(tmp_path, out, "--network-fetch", "--n", "4"), deps=deps) == 0
    assert tc.harden_order(spy) == [tc.ID_A, tc.ID_B]
    assert tc.read_batch(out)["network_fetch_done"] == [tc.ID_A, tc.ID_B]
    # The batch finished, yet the total is still 2: a second call without --instance-ids is refused.
    capsys.readouterr()
    assert cli.main(tc.batch_argv(tmp_path, out, "--network-fetch"), deps=deps) == 2
    assert "at most 2 in total" in capsys.readouterr().err and tc.harden_order(spy) == [tc.ID_A, tc.ID_B]
    # A call without the flag keeps the record.
    plain = tc.batch_argv(tmp_path, out, "--instance-ids", tc.ID_C)
    assert cli.main(plain, deps=deps) == 0
    assert tc.read_batch(out)["network_fetch_done"] == [tc.ID_A, tc.ID_B]
    # Naming 1 or 2 tasks is allowed again, and they join the record.
    named = tc.batch_argv(tmp_path, out, "--network-fetch", "--instance-ids", tc.ID_D)
    assert cli.main(named, deps=deps) == 0
    assert tc.read_batch(out)["network_fetch_done"] == [tc.ID_A, tc.ID_B, tc.ID_D]


def test_clean_text_keeps_ordinary_words_that_contain_a_credential_word():
    from rewardseal.sanitize import clean_text

    for text in (
        "KeyError: x",
        "monkey: patch",
        "key: x",
        "auth: yes",
        "tokenizer: fast",
        "see config.key=short",
    ):
        assert clean_text(text, 100) == text


def test_clean_text_is_linear_on_hostile_input():
    import time

    from rewardseal.sanitize import clean_text

    hostile = (
        "a" * 64_000,
        "a=" * 32_000,
        "key=" * 16_000,
        "token:" * 10_000,
        "Bearer " * 9_000,
        "x" * 64_000 + " password=1",
    )
    start = time.perf_counter()
    for text in hostile:
        for limit in (300, 2000, 20_000):
            clean_text(text, limit)
    assert time.perf_counter() - start < 0.5
