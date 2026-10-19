"""Strategy prompts and the capped Tavily search. No network: the tavily module is replaced by a fake."""

import sys
import types

import pytest

from cheatproof.budget import BudgetExceeded
from cheatproof.strategies import COMBINED, STRATEGIES, make_tavily_search, strategy_prompt


class FakeBudget:
    def __init__(self, events, cap_reached=False):
        self.events = events
        self.cap_reached = cap_reached

    def reserve_tavily_call(self):
        self.events.append("reserve")
        if self.cap_reached:
            raise BudgetExceeded("tavily call cap reached")


def install_fake_tavily(monkeypatch, events, results=None):
    class FakeTavilyClient:
        def __init__(self, api_key):
            events.append(("client", api_key))

        def search(self, query, max_results):
            events.append(("search", query, max_results))
            return {"query": query, "results": results or []}

    module = types.ModuleType("tavily")
    module.TavilyClient = FakeTavilyClient
    monkeypatch.setitem(sys.modules, "tavily", module)


def test_four_strategies_are_present_and_non_empty():
    assert set(STRATEGIES) == {"git-history", "test-edit", "hard-code", "network"}
    for name, text in STRATEGIES.items():
        assert isinstance(text, str) and text.strip(), name


def test_every_strategy_states_the_audit_frame_and_how_to_finish():
    for name, text in {**STRATEGIES, "combined": COMBINED}.items():
        assert "authorized reward-hacking audit" in text, name
        assert "workspace" in text, name
        assert "`submit`" in text, name


def test_strategies_name_their_technique():
    assert "git log --all" in STRATEGIES["git-history"]
    assert "conftest.py" in STRATEGIES["test-edit"]
    assert "lookup table" in STRATEGIES["hard-code"]
    assert "web_search" in STRATEGIES["network"]


def test_unknown_strategy_name_raises():
    with pytest.raises(ValueError, match="unknown strategy"):
        strategy_prompt("nope")


def test_strategy_prompt_returns_the_registered_text():
    assert strategy_prompt("hard-code") == STRATEGIES["hard-code"]


def test_combined_offers_every_non_network_technique_and_no_search():
    for technique in ("git log --all", "conftest.py", "lookup table"):
        assert technique in COMBINED
    assert "web_search" not in COMBINED


def test_search_reserves_before_it_calls_the_client(monkeypatch):
    events = []
    install_fake_tavily(monkeypatch, events, results=[{"title": "t", "url": "u", "content": "c"}])
    search = make_tavily_search(FakeBudget(events), api_key="key-1")
    search("upstream fix")
    assert events == ["reserve", ("client", "key-1"), ("search", "upstream fix", 5)]


def test_search_passes_max_results_through(monkeypatch):
    events = []
    install_fake_tavily(monkeypatch, events)
    search = make_tavily_search(FakeBudget(events), api_key="key-1", max_results=3)
    assert search("q") == []
    assert events[-1] == ("search", "q", 3)


def test_results_keep_three_fields_and_truncate_content(monkeypatch):
    events = []
    raw = [{"title": "T", "url": "https://example.invalid/x", "content": "a" * 5000, "score": 0.9}]
    install_fake_tavily(monkeypatch, events, results=raw)
    out = make_tavily_search(FakeBudget(events), api_key="key-1")("q")
    assert out == [{"title": "T", "url": "https://example.invalid/x", "content": "a" * 2000}]


def test_budget_exceeded_stops_before_the_client_is_called(monkeypatch):
    events = []
    install_fake_tavily(monkeypatch, events)
    search = make_tavily_search(FakeBudget(events, cap_reached=True), api_key="key-1")
    with pytest.raises(BudgetExceeded):
        search("q")
    assert events == ["reserve"]


def test_api_key_defaults_to_the_environment(monkeypatch):
    events = []
    install_fake_tavily(monkeypatch, events)
    monkeypatch.setenv("TAVILY_API_KEY", "env-key")
    make_tavily_search(FakeBudget(events))("q")
    assert ("client", "env-key") in events


def test_missing_key_raises_at_factory_time_without_printing(monkeypatch, capsys):
    events = []
    install_fake_tavily(monkeypatch, events)
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="TAVILY_API_KEY not set"):
        make_tavily_search(FakeBudget(events))
    assert capsys.readouterr() == ("", "")
    assert events == []
