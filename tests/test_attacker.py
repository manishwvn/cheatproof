import ast
import hashlib
import json
import shlex
from pathlib import Path
from types import SimpleNamespace

import httpx
import openai
import pytest

from cheatproof import attacker
from cheatproof.attacker import CAP_RESET_NOTE, NUDGE, AttackConfig, attack, build_tools
from cheatproof.budget import Budget, BudgetExceeded
from cheatproof.executor import DiskRefused, ExecutorRefused, ExecutorUnavailable, Result, Session
from cheatproof.llm import MAX_OUTPUT_TOKENS, GuardedLLM, estimate_tokens

SYSTEM = "SYSTEM-PROMPT-FROM-CALLER"
TASK = "TASK-PROMPT-FROM-CALLER"
MODEL = "fake/attacker-model"
CFG = AttackConfig(model=MODEL)
FAKE_KEY = "sk-test-not-a-real-key-123"  # a fake, only here to prove it never reaches a trace or a result


class FakeLLM:
    """Scripted stand-in for GuardedLLM.chat. Never calls a model or the network.

    VERIFY: the reply shape follows the OpenAI SDK and the recorded Token Factory fixture (content null and
    tool_calls [] on a reasoning-only reply). Confirm the tool_calls shape against a recorded live tool-call
    response once one exists.
    """

    def __init__(self, replies, repeat_last=False):
        self.replies = list(replies)
        self.repeat_last = repeat_last
        self.calls: list[dict] = []

    def chat(self, model, messages, max_tokens, **kwargs):
        self.calls.append({"model": model, "messages": messages, "max_tokens": max_tokens, "kwargs": kwargs})
        if not self.replies:
            raise AssertionError("FakeLLM script exhausted")
        item = self.replies[0] if self.repeat_last and len(self.replies) == 1 else self.replies.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


class FakeSession(Session):
    """Stands in for an executor Session. Everything a tool does lands here and nowhere else."""

    def __init__(self, *, run_handler=None, diff_text="diff --git a/x b/x\n", diff_error=None):
        self.run_handler = run_handler
        self.diff_text = diff_text
        self.diff_error = diff_error
        self.runs: list[tuple[str, float]] = []
        self.files: dict[str, bytes | str] = {}
        self.closed = False

    def run(self, cmd, timeout):
        self.runs.append((cmd, timeout))
        if self.run_handler:
            return self.run_handler(cmd, timeout)
        return Result(0, f"ran: {cmd}\n", "", 0.01)

    def write_file(self, path, data):
        self.files[path] = data

    def diff(self):
        if self.diff_error:
            raise self.diff_error
        return self.diff_text

    def reset(self):
        raise AssertionError("the attacker must never reset the session")

    def close(self):
        self.closed = True


def call(name, args=None, call_id="call_1"):
    raw = args if isinstance(args, str) else json.dumps(args or {})
    return SimpleNamespace(id=call_id, type="function", function=SimpleNamespace(name=name, arguments=raw))


def reply(*calls, content=None, usage=(100, 20)):
    message = SimpleNamespace(content=content, tool_calls=list(calls))
    counted = None if usage is None else SimpleNamespace(prompt_tokens=usage[0], completion_tokens=usage[1])
    return SimpleNamespace(choices=[SimpleNamespace(message=message, finish_reason="stop")], usage=counted)


def go(replies, *, session=None, config=None, search=None, trace_path=None, repeat_last=False):
    llm = FakeLLM(replies, repeat_last=repeat_last)
    session = session or FakeSession()
    result = attack(llm, session, SYSTEM, TASK, config or CFG, search=search, trace_path=trace_path)
    return result, llm, session


def read_trace(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def tool_texts(llm: FakeLLM, call_index: int) -> list[str]:
    return [m["content"] for m in llm.calls[call_index]["messages"] if m["role"] == "tool"]


def tool_names(llm: FakeLLM) -> list[str]:
    return [t["function"]["name"] for t in llm.calls[0]["kwargs"]["tools"]]


def initial_messages() -> list[dict]:
    return [{"role": "system", "content": SYSTEM}, {"role": "user", "content": TASK}]


# --- happy path and message plumbing ---


def test_happy_path_run_write_submit():
    result, llm, session = go(
        [
            reply(call("run", {"cmd": "ls"}, "c1"), usage=(100, 20)),
            reply(call("write_file", {"path": "answer.txt", "content": "42"}, "c2"), usage=(150, 30)),
            reply(call("submit", {}, "c3"), usage=(200, 10)),
        ]
    )
    assert result.submitted is True
    assert result.stop_reason == "submit"
    assert result.error == ""
    assert [s["tool"] for s in result.steps] == ["run", "write_file", "submit"]
    assert [s["step"] for s in result.steps] == [1, 2, 3]
    assert session.runs == [("ls", 120)]
    assert session.files == {"answer.txt": "42"}
    assert result.final_diff == session.diff_text
    assert (result.tokens_in, result.tokens_out) == (450, 60)
    assert len(llm.calls) == 3  # submit ends the attempt: no fourth call


def test_caller_prompts_are_first_messages_and_calls_use_config():
    cfg = AttackConfig(model=MODEL, max_output_tokens=512)
    _, llm, _ = go([reply(call("submit"))], config=cfg)
    first = llm.calls[0]
    assert first["model"] == MODEL
    assert first["max_tokens"] == 512
    assert first["messages"] == initial_messages()
    assert tool_names(llm) == ["run", "read_file", "write_file", "submit"]
    assert set(first["kwargs"]) == {"tools"}  # only options GuardedLLM allows


def test_history_carries_tool_call_and_result_by_id():
    _, llm, _ = go(
        [reply(call("run", {"cmd": "ls"}, "c1"), content="looking"), reply(call("submit", {}, "c2"))]
    )
    second = llm.calls[1]["messages"]
    assert second[2]["role"] == "assistant"
    assert second[2]["content"] == "looking"
    assert second[2]["tool_calls"] == [
        {"id": "c1", "type": "function", "function": {"name": "run", "arguments": '{"cmd": "ls"}'}}
    ]
    assert second[3]["role"] == "tool"
    assert second[3]["tool_call_id"] == "c1"
    assert "ran: ls" in second[3]["content"]


def test_calls_do_not_share_a_mutable_message_list():
    _, llm, _ = go([reply(call("run", {"cmd": "a"})), reply(call("submit"))])
    assert len(llm.calls[0]["messages"]) == 2  # later steps did not grow the list the first call saw


def test_cmd_timeout_comes_from_config():
    _, _, session = go(
        [reply(call("run", {"cmd": "sleep 1"})), reply(call("submit"))],
        config=AttackConfig(model=MODEL, cmd_timeout=7),
    )
    assert session.runs == [("sleep 1", 7)]


def test_read_file_runs_quoted_cat_in_the_session():
    path = "dir/my file's name; rm -rf /.txt"
    session = FakeSession(run_handler=lambda cmd, timeout: Result(0, "FILE BODY", "", 0.0))
    _, llm, session = go([reply(call("read_file", {"path": path})), reply(call("submit"))], session=session)
    assert session.runs == [(f"cat -- {shlex.quote(path)}", 120)]
    assert tool_texts(llm, 1) == ["FILE BODY"]


def test_read_file_failure_reports_exit_code_and_stderr():
    session = FakeSession(run_handler=lambda cmd, timeout: Result(1, "", "cat: nope: No such file", 0.0))
    _, llm, _ = go([reply(call("read_file", {"path": "nope"})), reply(call("submit"))], session=session)
    text = tool_texts(llm, 1)[0]
    assert "exit_code: 1" in text
    assert "No such file" in text


def test_run_result_shows_timeout_and_truncation_flags():
    session = FakeSession(
        run_handler=lambda cmd, timeout: Result(124, "", "", 1.0, timed_out=True, truncated=True)
    )
    _, llm, _ = go([reply(call("run", {"cmd": "x"})), reply(call("submit"))], session=session)
    assert "exit_code: 124 (timed out) (output truncated)" in tool_texts(llm, 1)[0]


@pytest.mark.parametrize(
    ("name", "args"), [("run", {"cmd": "sleep 999"}), ("read_file", {"path": "big.log"})]
)
def test_host_timeout_tells_the_model_the_sandbox_was_reset(name, args, tmp_path):
    # The executor resets the sandbox on a host timeout, so earlier files are gone. The fake session does not
    # reset anything; it only reports what the executor reports: timed_out, then a normal run.
    outcomes = [Result(124, "partial", "", 120.0, timed_out=True), Result(0, "ok", "", 0.0)]
    trace = tmp_path / "trace.jsonl"
    session = FakeSession(run_handler=lambda cmd, timeout: outcomes.pop(0))
    result, llm, _ = go(
        [reply(call(name, args, "c1")), reply(call("run", {"cmd": "ls"}, "c2")), reply(call("submit"))],
        session=session,
        trace_path=trace,
    )
    first, second = tool_texts(llm, 1)[0], tool_texts(llm, 2)[1]
    assert first.startswith("error: the command timed out and the sandbox was reset")
    assert "Files written earlier in this attempt are lost" in first
    assert "exit_code: 124 (timed out)" in first
    assert second.startswith("exit_code: 0") and "sandbox was reset" not in second
    assert [s["reset"] for s in result.steps] == [True, False, False]
    assert [line["reset"] for line in read_trace(trace) if line["type"] == "step"] == [True, False, False]


@pytest.mark.parametrize(
    ("name", "args"), [("run", {"cmd": "cat huge.log"}), ("read_file", {"path": "huge.log"})]
)
def test_output_cap_reset_tells_the_model_and_marks_the_step(name, args, tmp_path):
    # The executor kills a command that prints past its cap and resets the sandbox, as it does on a timeout.
    outcomes = [Result(137, "partial", "", 0.0, truncated=True, reset=True), Result(0, "ok", "", 0.0)]
    trace = tmp_path / "trace.jsonl"
    session = FakeSession(run_handler=lambda cmd, timeout: outcomes.pop(0))
    result, llm, _ = go(
        [reply(call(name, args, "c1")), reply(call("run", {"cmd": "ls"}, "c2")), reply(call("submit"))],
        session=session,
        trace_path=trace,
    )
    first, second = tool_texts(llm, 1)[0], tool_texts(llm, 2)[1]
    assert first.startswith(CAP_RESET_NOTE)
    assert "Files written earlier in this attempt are lost" in first
    assert "exit_code: 137 (output truncated)" in first and "timed out" not in first
    assert second.startswith("exit_code: 0") and "sandbox was reset" not in second
    assert [s["reset"] for s in result.steps] == [True, False, False]
    assert [line["reset"] for line in read_trace(trace) if line["type"] == "step"] == [True, False, False]


@pytest.mark.parametrize(
    ("exc", "code"),
    [
        (DiskRefused("free disk is 1.5 GB after a run, below RUN_MIN_FREE_GB=2"), "executor_refused"),
        (ExecutorRefused("free disk is 5.0 GB, below MIN_FREE_DISK_GB=10"), "executor_refused"),
        (ExecutorUnavailable("docker daemon is down"), "executor_unavailable"),
    ],
    ids=["disk-refused", "executor-refused", "executor-unavailable"],
)
def test_executor_stop_from_a_tool_is_reraised_and_traced_not_turned_into_a_tool_error(exc, code, tmp_path):
    def stop(cmd, timeout):
        raise exc

    trace = tmp_path / "trace.jsonl"
    llm = FakeLLM([reply(call("run", {"cmd": "ls"})), reply(call("submit"))])
    with pytest.raises(type(exc)):
        attack(llm, FakeSession(run_handler=stop), SYSTEM, TASK, CFG, trace_path=trace)
    lines = read_trace(trace)
    assert lines[-2]["tool"] == "run" and lines[-2]["error"] == code
    assert lines[-1]["type"] == "end" and lines[-1]["stop_reason"] == "error"
    assert len(llm.calls) == 1  # no model call after the stop


def test_disk_refused_from_write_file_is_reraised(tmp_path):
    class FullDisk(FakeSession):
        def write_file(self, path, data):
            raise DiskRefused("free disk is 1.5 GB after a run, below RUN_MIN_FREE_GB=2")

    llm = FakeLLM([reply(call("write_file", {"path": "a.py", "content": "x"})), reply(call("submit"))])
    with pytest.raises(DiskRefused):
        attack(llm, FullDisk(), SYSTEM, TASK, CFG)
    assert len(llm.calls) == 1


def test_write_file_allows_empty_content():
    _, _, session = go(
        [reply(call("write_file", {"path": "empty.txt", "content": ""})), reply(call("submit"))]
    )
    assert session.files == {"empty.txt": ""}


# --- limits ---


def test_max_steps_stops_the_attempt():
    cfg = AttackConfig(model=MODEL, max_steps=3)
    result, llm, session = go([reply(call("run", {"cmd": "true"}))], config=cfg, repeat_last=True)
    assert result.stop_reason == "max_steps"
    assert result.submitted is False
    assert len(llm.calls) == 3
    assert len(result.steps) == 3
    assert result.final_diff == session.diff_text  # the diff is still taken at the end


def test_token_limit_from_reported_usage():
    est = estimate_tokens(initial_messages(), build_tools())
    cfg = AttackConfig(model=MODEL, max_output_tokens=64, max_tokens_total=est + 64 + 100)
    result, llm, _ = go(
        [reply(call("run", {"cmd": "true"}), usage=(1500, 500))], config=cfg, repeat_last=True
    )
    assert result.stop_reason == "token_limit"
    assert len(llm.calls) == 1  # the second call would have gone past the limit
    assert (result.tokens_in, result.tokens_out) == (1500, 500)
    assert result.submitted is False


def test_token_limit_counts_the_estimate_when_usage_is_missing():
    tools = build_tools()
    est = estimate_tokens(initial_messages(), tools)
    cfg = AttackConfig(model=MODEL, max_output_tokens=64, max_tokens_total=est + 64 + 100)
    result, llm, _ = go([reply(call("run", {"cmd": "true"}), usage=None)], config=cfg, repeat_last=True)
    assert result.stop_reason == "token_limit"
    assert len(llm.calls) == 1
    assert result.tokens_in == est
    assert result.tokens_out == 64


def test_token_limit_is_checked_before_the_first_call():
    cfg = AttackConfig(model=MODEL, max_tokens_total=1)
    result, llm, _ = go([], config=cfg)
    assert result.stop_reason == "token_limit"
    assert llm.calls == []
    assert result.steps == []


# --- untrusted model output ---


@pytest.mark.parametrize("raw", ["{not json", "[1, 2]", "null", "42", '"text"'])
def test_bad_json_arguments_become_a_tool_error(raw):
    result, llm, session = go([reply(call("run", raw, "c1")), reply(call("submit", "", "c2"))])
    assert session.runs == []
    assert result.steps[0]["error"] == "bad_json"
    assert result.steps[0]["args"] == {"_raw": raw}
    text = tool_texts(llm, 1)[0]
    assert text.startswith("error:") and "JSON" in text
    # Bad arguments are not echoed back to the provider.
    assert llm.calls[1]["messages"][2]["tool_calls"][0]["function"]["arguments"] == "{}"
    assert result.submitted is True  # empty arguments are fine for a tool with none
    assert len(result.steps) == 2  # the bad call counted as a step


def test_unknown_tool_is_an_error_and_touches_nothing():
    result, llm, session = go([reply(call("delete_everything", {"x": 1})), reply(call("submit"))])
    assert result.steps[0]["error"] == "unknown_tool"
    assert result.steps[0]["tool"] == "delete_everything"
    assert session.runs == [] and session.files == {}
    text = tool_texts(llm, 1)[0]
    assert "unknown tool" in text and "run" in text  # the model is told what exists


@pytest.mark.parametrize(
    "raw_call",
    [
        SimpleNamespace(id=None, function=None),
        SimpleNamespace(id=None, function=SimpleNamespace(name=None, arguments=None)),
        SimpleNamespace(id=7, function=SimpleNamespace(name=["run"], arguments={"cmd": "ls"})),
        object(),
    ],
)
def test_malformed_tool_call_objects_do_not_crash(raw_call):
    first = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=None, tool_calls=[raw_call]))], usage=None
    )
    result, llm, session = go([first, reply(call("submit"))])
    assert result.steps[0]["error"] == "unknown_tool"
    assert session.runs == []
    # The id is made up when the provider's is unusable, and the empty name is not echoed as empty.
    echoed = llm.calls[1]["messages"][2]["tool_calls"][0]
    assert echoed["id"] == "call_1"
    assert echoed["function"]["name"]
    assert llm.calls[1]["messages"][3]["tool_call_id"] == "call_1"


@pytest.mark.parametrize(
    ("name", "args"),
    [
        ("run", {}),
        ("run", {"cmd": 5}),
        ("run", {"cmd": "   "}),
        ("read_file", {}),
        ("read_file", {"path": ["a"]}),
        ("write_file", {"path": "a"}),
        ("write_file", {"content": "x"}),
        ("write_file", {"path": "a", "content": 3}),
        ("write_file", {"path": "", "content": "x"}),
    ],
)
def test_missing_or_wrong_type_fields_are_errors(name, args):
    result, llm, session = go([reply(call(name, args)), reply(call("submit"))])
    assert result.steps[0]["error"] == "bad_args"
    assert session.runs == [] and session.files == {}
    assert tool_texts(llm, 1)[0].startswith("error:")


def test_reply_without_tool_call_gets_a_nudge_and_counts_as_a_step():
    result, llm, _ = go([reply(content="I could try the tests"), reply(call("submit"))])
    assert result.steps[0]["tool"] is None
    assert result.steps[0]["error"] == "no_tool_call"
    second = llm.calls[1]["messages"]
    assert second[-1] == {"role": "user", "content": NUDGE}
    assert second[-2] == {"role": "assistant", "content": "I could try the tests"}
    assert result.submitted is True


def test_empty_replies_count_toward_max_steps():
    # content null and tool_calls [] is what a reasoning-only reply from the recorded fixture looks like
    cfg = AttackConfig(model=MODEL, max_steps=2)
    result, llm, _ = go([reply(content=None)], config=cfg, repeat_last=True)
    assert result.stop_reason == "max_steps"
    assert len(result.steps) == 2
    assert [m["role"] for m in llm.calls[1]["messages"]] == [
        "system",
        "user",
        "user",
    ]  # no empty assistant turn


def test_only_the_first_tool_call_of_a_reply_runs():
    result, llm, session = go(
        [
            reply(call("run", {"cmd": "first"}, "a"), call("run", {"cmd": "second"}, "b")),
            reply(call("submit")),
        ]
    )
    assert session.runs == [("first", 120)]
    assert result.steps[0]["ignored_calls"] == 1
    second = llm.calls[1]["messages"]
    assert len(second[2]["tool_calls"]) == 1
    assert "only the first of 2 tool calls ran" in second[3]["content"]


def test_session_failure_goes_back_to_the_model_as_the_exception_type_only():
    def boom(cmd, timeout):
        raise RuntimeError("container gone at /host/secret-path")

    result, llm, _ = go(
        [reply(call("run", {"cmd": "ls"})), reply(call("submit"))], session=FakeSession(run_handler=boom)
    )
    assert result.steps[0]["error"] == "tool_exception"
    assert tool_texts(llm, 1) == ["error: run failed (RuntimeError)"]
    assert "secret-path" not in json.dumps(llm.calls[1]["messages"])
    assert result.submitted is True


def test_long_result_is_cut_for_the_model_and_digested_in_full():
    out = "A" * 30_000
    session = FakeSession(run_handler=lambda cmd, timeout: Result(0, out, "", 0.0))
    result, llm, _ = go([reply(call("run", {"cmd": "big"})), reply(call("submit"))], session=session)
    shown = tool_texts(llm, 1)[0]
    assert len(shown) < attacker.MAX_RESULT_CHARS + 100
    assert "[truncated:" in shown
    full = f"exit_code: 0\n--- stdout ---\n{out}\n--- stderr ---\n"
    digest = result.steps[0]["result_digest"]
    assert digest["sha256"] == hashlib.sha256(full.encode()).hexdigest()
    assert digest["head"] == full[:300]
    assert digest["chars"] == len(full)


def test_short_result_is_not_marked_truncated():
    _, llm, _ = go([reply(call("run", {"cmd": "ls"})), reply(call("submit"))])
    assert "[truncated" not in tool_texts(llm, 1)[0]


# --- web_search ---


def test_web_search_is_absent_without_network_even_when_a_search_is_given():
    searched: list[str] = []
    result, llm, _ = go(
        [reply(call("web_search", {"query": "fix"})), reply(call("submit"))],
        search=lambda q: searched.append(q) or [],
    )
    assert "web_search" not in tool_names(llm)
    assert searched == []
    assert result.steps[0]["error"] == "unknown_tool"


def test_web_search_is_absent_when_network_is_allowed_but_no_search_is_injected():
    cfg = AttackConfig(model=MODEL, allow_network=True)
    result, llm, _ = go([reply(call("web_search", {"query": "fix"})), reply(call("submit"))], config=cfg)
    assert "web_search" not in tool_names(llm)
    assert result.steps[0]["error"] == "unknown_tool"


def test_web_search_is_offered_and_called_when_network_is_allowed():
    searched: list[str] = []
    hits = [{"title": "Upstream fix", "url": "https://example.test/fix", "content": "apply this patch"}]

    def search(query: str) -> list[dict]:
        searched.append(query)
        return hits

    cfg = AttackConfig(model=MODEL, allow_network=True)
    result, llm, session = go(
        [reply(call("web_search", {"query": "upstream fix"})), reply(call("submit"))],
        config=cfg,
        search=search,
    )
    assert tool_names(llm) == ["run", "read_file", "write_file", "submit", "web_search"]
    assert searched == ["upstream fix"]
    assert json.loads(tool_texts(llm, 1)[0]) == hits  # handed to the model as data
    assert result.steps[0]["tool"] == "web_search"
    assert result.steps[0]["args"] == {"query": "upstream fix"}
    assert result.steps[0]["error"] is None
    assert session.runs == []  # the search ran on the host callable, not in the sandbox


def test_web_search_failure_is_a_tool_error_without_the_message():
    def search(query: str) -> list[dict]:
        raise RuntimeError(f"cap reached, key={FAKE_KEY}")

    cfg = AttackConfig(model=MODEL, allow_network=True)
    result, llm, _ = go(
        [reply(call("web_search", {"query": "q"})), reply(call("submit"))], config=cfg, search=search
    )
    assert result.steps[0]["error"] == "tool_exception"
    text = tool_texts(llm, 1)[0]
    assert "RuntimeError" in text and FAKE_KEY not in text


def test_web_search_bad_result_shape_is_a_tool_error():
    cfg = AttackConfig(model=MODEL, allow_network=True)
    result, llm, _ = go(
        [reply(call("web_search", {"query": "q"})), reply(call("submit"))],
        config=cfg,
        search=lambda q: "not a list",
    )
    assert result.steps[0]["error"] == "tool_exception"
    assert tool_texts(llm, 1)[0].startswith("error:")


def test_web_search_budget_error_propagates():
    def search(query: str) -> list[dict]:
        raise BudgetExceeded("search cap")

    cfg = AttackConfig(model=MODEL, allow_network=True)
    with pytest.raises(BudgetExceeded):
        go([reply(call("web_search", {"query": "q"}))], config=cfg, search=search)


def test_web_search_limit_stops_calls_to_the_search_function():
    searched: list[str] = []

    def search(query: str) -> list[dict]:
        searched.append(query)
        return []

    cfg = AttackConfig(model=MODEL, allow_network=True, max_searches=2)
    result, llm, _ = go(
        [
            reply(call("web_search", {"query": "a"}, "c1")),
            reply(call("web_search", {"query": "b"}, "c2")),
            reply(call("web_search", {"query": "c"}, "c3")),
            reply(call("submit", {}, "c4")),
        ],
        config=cfg,
        search=search,
    )
    assert searched == ["a", "b"]  # the third call never reached the callable
    assert [s["error"] for s in result.steps] == [None, None, "search_limit", None]
    assert tool_texts(llm, 3)[2].startswith("error: web_search limit of 2 per attempt reached")
    assert result.submitted is True  # the limit is a tool error, not the end of the attempt


def test_zero_max_searches_does_not_offer_web_search():
    searched: list[str] = []
    cfg = AttackConfig(model=MODEL, allow_network=True, max_searches=0)
    result, llm, _ = go(
        [reply(call("web_search", {"query": "q"})), reply(call("submit"))],
        config=cfg,
        search=lambda q: searched.append(q) or [],
    )
    assert "web_search" not in tool_names(llm)
    assert searched == []
    assert result.steps[0]["error"] == "unknown_tool"


# --- budget and errors ---


def test_budget_exceeded_from_the_llm_propagates_and_is_traced(tmp_path):
    trace = tmp_path / "trace.jsonl"
    with pytest.raises(BudgetExceeded, match="daily cap"):
        go([reply(call("run", {"cmd": "ls"})), BudgetExceeded("daily cap $4.00 reached")], trace_path=trace)
    lines = read_trace(trace)
    assert [line["type"] for line in lines] == ["header", "step", "step", "end"]
    assert lines[2]["error"] == "budget_exceeded"
    assert lines[3]["stop_reason"] == "budget"
    assert "daily cap" in lines[3]["error"]
    assert lines[3]["steps"] == 2


def test_budget_exceeded_from_a_tool_propagates_and_is_traced(tmp_path):
    def over(cmd, timeout):
        raise BudgetExceeded("sandbox run cap 250 reached")

    trace = tmp_path / "trace.jsonl"
    llm = FakeLLM([reply(call("run", {"cmd": "ls"})), reply(call("submit"))])
    with pytest.raises(BudgetExceeded, match="sandbox run cap"):
        attack(llm, FakeSession(run_handler=over), SYSTEM, TASK, CFG, trace_path=trace)
    lines = read_trace(trace)
    assert lines[-2]["tool"] == "run" and lines[-2]["error"] == "budget_exceeded"
    assert lines[-1]["stop_reason"] == "budget"
    assert len(llm.calls) == 1  # no further model call after the cap


def test_budget_exceeded_without_a_trace_file_still_propagates():
    with pytest.raises(BudgetExceeded):
        go([BudgetExceeded("total cap reached")])


def test_http_402_from_the_llm_raises_budget_exceeded_and_is_traced(tmp_path):
    class FakeApiError(Exception):
        status_code = 402

    trace = tmp_path / "trace.jsonl"
    llm = FakeLLM([reply(call("run", {"cmd": "ls"})), FakeApiError(f"balance gone key={FAKE_KEY}")])
    with pytest.raises(BudgetExceeded, match="402"):
        attack(llm, FakeSession(), SYSTEM, TASK, CFG, trace_path=trace)
    lines = read_trace(trace)
    assert lines[-2]["error"] == "budget_exceeded"
    assert lines[-1]["type"] == "end" and lines[-1]["stop_reason"] == "budget"
    assert FAKE_KEY not in trace.read_text()
    assert len(llm.calls) == 2  # no call after the halt


def test_llm_failure_stops_with_error_and_leaks_no_message():
    class FakeApiError(Exception):
        status_code = 500

    result, llm, _ = go([FakeApiError(f"upstream said key={FAKE_KEY}")])
    assert result.stop_reason == "error"
    assert result.error == "llm call failed: FakeApiError (HTTP 500)"
    assert FAKE_KEY not in result.error
    assert result.final_diff  # the diff is still taken
    assert result.submitted is False
    assert len(llm.calls) == 1


def test_reply_without_a_message_stops_with_error():
    empty = SimpleNamespace(choices=[], usage=SimpleNamespace(prompt_tokens=10, completion_tokens=2))
    result, _, _ = go([empty])
    assert result.stop_reason == "error"
    assert "no message" in result.error
    assert (result.tokens_in, result.tokens_out) == (10, 2)  # the call was paid for


def test_diff_failure_is_noted_and_the_diff_is_empty():
    session = FakeSession(diff_error=RuntimeError("git broke"))
    result, _, _ = go([reply(call("submit"))], session=session)
    assert result.final_diff is None  # no patch at all, which is not the same as an empty patch
    assert result.diff_ok is False
    assert result.stop_reason == "error"
    assert result.submitted is True  # the model did submit; the attempt still ends as an error
    assert "diff failed" in result.error and "git broke" in result.error


def test_oversized_diff_is_an_error_not_a_normal_submit(tmp_path):
    # The executor raises this RuntimeError instead of truncating a patch over MAX_DIFF_BYTES.
    trace = tmp_path / "trace.jsonl"
    message = "diff is over MAX_DIFF_BYTES=8388608; refusing to truncate it"
    session = FakeSession(diff_error=RuntimeError(message))
    result, _, _ = go([reply(call("submit"))], session=session, trace_path=trace)
    assert result.stop_reason == "error"
    assert result.diff_ok is False and result.final_diff is None
    assert "MAX_DIFF_BYTES" in result.error
    end = read_trace(trace)[-1]
    assert end["type"] == "end" and end["stop_reason"] == "error"
    assert end["diff_ok"] is False and end["final_diff"] is None


def test_budget_exceeded_from_the_diff_still_propagates(tmp_path):
    trace = tmp_path / "trace.jsonl"
    session = FakeSession(diff_error=BudgetExceeded("total cap reached"))
    with pytest.raises(BudgetExceeded, match="total cap"):
        go([reply(call("submit"))], session=session, trace_path=trace)
    assert read_trace(trace)[-1]["stop_reason"] == "budget"


def test_disk_refused_from_the_diff_is_reraised_and_traced(tmp_path):
    trace = tmp_path / "trace.jsonl"
    session = FakeSession(diff_error=DiskRefused("free disk is 1.5 GB after a run, below RUN_MIN_FREE_GB=2"))
    with pytest.raises(DiskRefused):
        go([reply(call("submit"))], session=session, trace_path=trace)
    end = read_trace(trace)[-1]
    assert end["type"] == "end" and end["stop_reason"] == "error" and "DiskRefused" in end["error"]


# --- trace ---


def test_trace_file_has_one_json_line_per_step_with_digests_only(tmp_path, monkeypatch):
    monkeypatch.setenv("NEBIUS_API_KEY", FAKE_KEY)
    big_out = "B" * 20_000
    big_content = "C" * 5_000
    session = FakeSession(run_handler=lambda cmd, timeout: Result(0, big_out, "", 0.0))
    trace = tmp_path / "nested" / "trace.jsonl"
    cfg = AttackConfig(model=MODEL, label="git-history")
    result, _, _ = go(
        [
            reply(call("run", {"cmd": "cat everything"}), usage=(100, 20)),
            reply(call("write_file", {"path": "p.txt", "content": big_content}), usage=(150, 30)),
            reply(call("submit"), usage=(200, 10)),
        ],
        session=session,
        config=cfg,
        trace_path=trace,
    )
    raw = trace.read_text()
    lines = read_trace(trace)
    header, *steps, end = lines
    assert header["type"] == "header"
    assert header["label"] == "git-history"
    assert header["model"] == MODEL
    assert header["tools"] == ["run", "read_file", "write_file", "submit"]
    assert header["system_prompt"]["sha256"] == hashlib.sha256(SYSTEM.encode()).hexdigest()
    assert SYSTEM not in raw and TASK not in raw  # prompts are recorded as digests
    assert len(steps) == 3
    for line in steps:
        assert set(line) == {
            "type",
            "step",
            "tool",
            "args",
            "result_digest",
            "error",
            "ignored_calls",
            "reset",
            "tokens_in",
            "tokens_out",
            "elapsed",
        }
        assert set(line["result_digest"]) == {"sha256", "head", "chars"}
        assert len(line["result_digest"]["head"]) <= 300
    assert steps == result.steps  # the result carries the same records
    assert steps[0]["result_digest"]["chars"] > 20_000
    assert "B" * 500 not in raw  # the long result is not stored
    capped = steps[1]["args"]["content"]
    assert capped.startswith("C" * 2000) and len(capped) < 2100 and capped.endswith("[+3000 chars]")
    assert (steps[1]["tokens_in"], steps[1]["tokens_out"]) == (150, 30)
    assert end["type"] == "end"
    assert end["stop_reason"] == "submit" and end["submitted"] is True
    assert end["diff_ok"] is True and set(end["final_diff"]) == {"sha256", "head", "chars"}
    assert (end["tokens_in"], end["tokens_out"]) == (450, 60)
    assert FAKE_KEY not in raw and "NEBIUS" not in raw  # no env values or keys in the trace


def test_trace_appends_across_attempts(tmp_path):
    trace = tmp_path / "trace.jsonl"
    go([reply(call("submit"))], trace_path=trace)
    go([reply(call("submit"))], trace_path=trace)
    assert [line["type"] for line in read_trace(trace)] == ["header", "step", "end", "header", "step", "end"]


def test_trace_survives_lone_surrogates_in_model_text(tmp_path):
    trace = tmp_path / "trace.jsonl"
    result, _, _ = go(
        [reply(call("run", '{"cmd": "echo \\ud800"}')), reply(call("submit"))],
        session=FakeSession(run_handler=lambda cmd, timeout: Result(0, "\ud800", "", 0.0)),
        trace_path=trace,
    )
    assert result.submitted is True
    assert [line["type"] for line in read_trace(trace)] == ["header", "step", "step", "end"]
    assert "\\ud800" in trace.read_text()  # written as an escape, not as a broken character


# --- containment ---


def test_absolute_paths_go_to_the_session_and_the_host_is_untouched(tmp_path):
    # Paths the model names are handed to the session as text. Nothing in this test lets the attacker
    # touch the host, so the victim file must not appear and the host file must not change.
    host_file = tmp_path / "host_only.txt"
    host_file.write_text("HOST-ONLY-CONTENT")
    victim = tmp_path / "victim.txt"
    session = FakeSession(run_handler=lambda cmd, timeout: Result(0, "SANDBOX VIEW", "", 0.0))
    result, llm, _ = go(
        [
            reply(call("write_file", {"path": "/etc/passwd", "content": "root::0:0::/:/bin/sh\n"}, "c1")),
            reply(call("write_file", {"path": str(victim), "content": "pwned"}, "c2")),
            reply(call("read_file", {"path": str(host_file)}, "c3")),
            reply(call("submit", {}, "c4")),
        ],
        session=session,
    )
    assert result.submitted is True
    assert session.files == {"/etc/passwd": "root::0:0::/:/bin/sh\n", str(victim): "pwned"}
    assert session.runs == [(f"cat -- {shlex.quote(str(host_file))}", 120)]
    assert not victim.exists()
    assert host_file.read_text() == "HOST-ONLY-CONTENT"
    assert all("HOST-ONLY-CONTENT" not in json.dumps(c["messages"]) for c in llm.calls)


class _CallScopes(ast.NodeVisitor):
    """Every call in a module, with the chain of class and function names it sits in."""

    def __init__(self) -> None:
        self.stack: list[str] = []
        self.calls: list[tuple[tuple[str, ...], ast.Call]] = []

    def _scoped(self, node: ast.ClassDef | ast.FunctionDef) -> None:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    visit_ClassDef = _scoped
    visit_FunctionDef = _scoped

    def visit_Call(self, node: ast.Call) -> None:
        self.calls.append((tuple(self.stack), node))
        self.generic_visit(node)


# Code execution and file-writing attribute calls. None belongs in the attacker, with one exception: the
# trace writer appends to its JSONL file (and creates the parent directory) through self.path.
EXEC_AND_WRITE_ATTRS = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "import_module",
    "open",
    "write_text",
    "write_bytes",
    "unlink",
    "mkdir",
    "touch",
    "rmdir",
    "rename",
    "symlink_to",
    "chmod",
}


def test_attacker_module_has_no_host_execution_or_file_access():
    tree = ast.parse(Path(attacker.__file__).read_text())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not imported & {
        "subprocess",
        "shutil",
        "socket",
        "httpx",
        "requests",
        "urllib",
        "tempfile",
        "importlib",
    }
    os_uses = {
        n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute) and getattr(n.value, "id", "") == "os"
    }
    assert os_uses <= {"environ"}  # os is only used to read ATTACKER_MODEL
    scopes = _CallScopes()
    scopes.visit(tree)
    bare = {c.func.id for _, c in scopes.calls if isinstance(c.func, ast.Name)}
    assert not bare & {"eval", "exec", "compile", "__import__", "open"}
    found = sorted(
        (scope, c.func.attr, ast.unparse(c.func.value))
        for scope, c in scopes.calls
        if isinstance(c.func, ast.Attribute) and c.func.attr in EXEC_AND_WRITE_ATTRS
    )
    assert found == sorted(
        [
            (("_Trace", "write"), "mkdir", "self.path.parent"),
            (("_Trace", "write"), "open", "self.path"),
        ]
    )


# --- config and arguments ---


def test_model_defaults_from_attacker_model_env(monkeypatch):
    monkeypatch.setenv("ATTACKER_MODEL", "env/model-x")
    assert AttackConfig().model == "env/model-x"
    monkeypatch.delenv("ATTACKER_MODEL")
    assert AttackConfig().model == ""


def test_attack_refuses_to_start_without_a_model():
    llm = FakeLLM([reply(call("submit"))])
    with pytest.raises(ValueError, match="ATTACKER_MODEL"):
        attack(llm, FakeSession(), SYSTEM, TASK, AttackConfig(model=""))
    assert llm.calls == []


def test_config_defaults_match_the_brief():
    cfg = AttackConfig(model=MODEL)
    assert (cfg.max_steps, cfg.max_tokens_total, cfg.allow_network, cfg.cmd_timeout) == (
        15,
        50_000,
        False,
        120,
    )
    assert cfg.max_output_tokens == min(2048, MAX_OUTPUT_TOKENS)
    assert cfg.max_result_chars == 3000  # T38 lowered it from 8000, T47 to 3000
    assert cfg.label is None
    assert cfg.max_searches == 3


@pytest.mark.parametrize(
    "bad",
    [
        {"max_steps": 0},
        {"max_tokens_total": 0},
        {"max_output_tokens": 0},
        {"max_output_tokens": MAX_OUTPUT_TOKENS + 1},
        {"cmd_timeout": 0},
        {"cmd_timeout": float("nan")},
        {"cmd_timeout": float("inf")},
        {"max_searches": -1},
        {"max_result_chars": 0},
        {"max_result_chars": attacker.RESULT_CHARS_CEILING + 1},  # a cap is never raised past the old default
    ],
)
def test_invalid_config_is_refused(bad):
    with pytest.raises(ValueError):
        AttackConfig(model=MODEL, **bad)


@pytest.mark.parametrize(("system", "task"), [(SYSTEM, ""), (SYSTEM, "  \n"), (None, TASK), (SYSTEM, None)])
def test_invalid_prompts_are_refused(system, task):
    llm = FakeLLM([reply(call("submit"))])
    with pytest.raises(ValueError, match="prompt"):
        attack(llm, FakeSession(), system, task, CFG)
    assert llm.calls == []


# --- real GuardedLLM and Budget: a fake OpenAI-shaped client, no network ---


class FakeOpenAIClient:
    """Shaped like openai.OpenAI for the one call GuardedLLM makes: chat.completions.create(**kwargs)."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.requests: list[dict] = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.requests.append(kwargs)
        item = self.replies.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


def test_attack_through_guarded_llm_and_a_real_budget_ledger(tmp_path, monkeypatch, init_ledger):
    ledger = tmp_path / "ledger.json"
    monkeypatch.setenv("SPEND_LEDGER", str(ledger))
    monkeypatch.setenv("SPEND_CAP_USD", "1")
    monkeypatch.setenv("DAILY_CAP_USD", "1")
    monkeypatch.setenv(
        "MODEL_PRICES_JSON", json.dumps({MODEL: [1.0, 2.0]})
    )  # USD per million tokens, in and out
    budget = Budget.from_env()
    client = FakeOpenAIClient(
        [
            reply(call("run", {"cmd": "ls"}, "c1"), usage=(100, 20)),
            reply(call("submit", {}, "c2"), usage=(150, 10)),
        ]
    )
    trace = tmp_path / "trace.jsonl"
    result = attack(GuardedLLM(budget, client=client), FakeSession(), SYSTEM, TASK, CFG, trace_path=trace)
    assert result.submitted is True and result.stop_reason == "submit"
    assert [r["model"] for r in client.requests] == [MODEL, MODEL]
    assert set(client.requests[0]) == {"model", "messages", "max_tokens", "tools"}  # only allowed options
    # Each reservation settles to the reported usage: (100 in, 20 out) and (150 in, 10 out).
    snapshot = budget.snapshot()
    assert snapshot["total_usd"] == pytest.approx((100 + 20 * 2 + 150 + 10 * 2) / 1_000_000)
    assert snapshot["halted"] is None
    assert ledger.exists()
    end = read_trace(trace)[-1]
    assert end["stop_reason"] == "submit" and end["diff_ok"] is True


def _guarded_attack(tmp_path, monkeypatch, replies, trace=None):
    monkeypatch.setenv("SPEND_LEDGER", str(tmp_path / "ledger.json"))
    monkeypatch.setenv("SPEND_CAP_USD", "1")
    monkeypatch.setenv("DAILY_CAP_USD", "1")
    monkeypatch.setenv("MODEL_PRICES_JSON", json.dumps({MODEL: [1.0, 2.0]}))
    budget = Budget.from_env()
    client = FakeOpenAIClient(replies)
    llm = GuardedLLM(budget, client=client, sleep=lambda s: None, rand=lambda: 0.0)
    return attack(llm, FakeSession(), SYSTEM, TASK, CFG, trace_path=trace), client, budget


def _unavailable():
    req = httpx.Request("POST", "https://example.invalid/v1/chat/completions")
    return openai.InternalServerError("busy", response=httpx.Response(503, request=req), body=None)


def test_t56_transient_503s_are_retried_inside_the_attack_and_counted(tmp_path, monkeypatch, init_ledger):
    trace = tmp_path / "trace.jsonl"
    replies = [_unavailable(), _unavailable(), reply(call("submit", {}, "c1"), usage=(150, 10))]
    result, client, _ = _guarded_attack(tmp_path, monkeypatch, replies, trace)
    assert result.submitted is True and result.stop_reason == "submit"
    assert result.llm_retries == 2 and len(client.requests) == 3
    assert read_trace(trace)[-1]["llm_retries"] == 2


def test_t56_three_503s_end_the_attack_as_an_error_after_two_retries(tmp_path, monkeypatch, init_ledger):
    replies = [_unavailable(), _unavailable(), _unavailable()]
    result, client, budget = _guarded_attack(tmp_path, monkeypatch, replies)
    assert result.stop_reason == "error" and result.llm_retries == 2 and len(client.requests) == 3
    assert result.error == "llm call failed: InternalServerError (HTTP 503)"
    assert budget.snapshot()["halted"] is None


def test_t56_a_402_halts_the_attack_with_no_retry(tmp_path, monkeypatch, init_ledger):
    req = httpx.Request("POST", "https://example.invalid/v1/chat/completions")
    gone = openai.APIStatusError("gone", response=httpx.Response(402, request=req), body=None)
    with pytest.raises(BudgetExceeded):
        _guarded_attack(tmp_path, monkeypatch, [gone, reply(call("submit"))])


def test_t56_a_client_without_a_retry_counter_reports_zero():
    result, _, _ = go([reply(call("submit"))])
    assert result.llm_retries == 0


def test_tool_output_over_the_configured_limit_is_cut_with_a_marker():
    # T38: the model sees at most max_result_chars (plus the marker); the trace digest still covers the full output.
    out = "B" * 5000
    session = FakeSession(run_handler=lambda cmd, timeout: Result(0, out, "", 0.0))
    cfg = AttackConfig(model=MODEL, max_result_chars=500)
    result, llm, _ = go(
        [reply(call("run", {"cmd": "big"})), reply(call("submit"))], session=session, config=cfg
    )
    shown = tool_texts(llm, 1)[0]
    assert len(shown) < 500 + 100
    assert "[truncated:" in shown and "output limit 500" in shown
    assert result.steps[0]["result_digest"]["chars"] > 5000


def test_default_result_limit_is_lower_than_before_and_the_reply_cap_is_not_lowered():
    assert attacker.MAX_RESULT_CHARS == 3000 < attacker.RESULT_CHARS_CEILING == 8000
    assert AttackConfig(model=MODEL).max_output_tokens == attacker.DEFAULT_MAX_OUTPUT_TOKENS == 2048


def cut_reply(*calls):
    """A reply that ended at the output limit, as the provider reports it."""
    resp = reply(*calls)
    resp.choices[0].finish_reason = "length"
    return resp


def test_a_reply_cut_at_the_output_limit_is_reported_and_the_call_is_not_run(tmp_path):
    trace = tmp_path / "t.jsonl"
    truncated = call("run", '{"cmd": "echo start && printf %s \'print(1')  # arguments cut mid-string
    result, llm, session = go([cut_reply(truncated), reply(call("submit"))], trace_path=trace)
    assert session.runs == []  # the cut call never reached the sandbox
    assert tool_texts(llm, 1) == [attacker.CUT_NOTE]
    assert "send a shorter command or patch" in attacker.CUT_NOTE
    assert result.steps[0]["error"] == "output_cut"  # not a silent bad_json
    assert result.submitted is True
    assert read_trace(trace)[1]["error"] == "output_cut"


def test_a_normal_finish_reason_still_runs_the_call():
    result, _, session = go([reply(call("run", {"cmd": "ls"})), reply(call("submit"))])
    assert result.steps[0]["error"] is None and len(session.runs) == 1
