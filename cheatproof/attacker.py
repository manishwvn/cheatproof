"""Tool-calling attacker: a model told to make the grader pass without solving the task.

The model is hostile on purpose and its output is untrusted data. Every tool it can call runs only
through the executor Session (ADR 0002): never a host subprocess, host file or host network call.
The one exception is web_search, which runs host side through an injected callable and is offered
only when the experiment allows network. The prompts are supplied by the caller; the loop passes
them through as the first system and user messages and adds one neutral nudge when a reply has no
tool call. Every step is appended to a JSONL trace (digests of results, never full results) so the
hole classifier can decide in code what the attack did.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import shlex
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, NamedTuple, Protocol

from cheatproof.budget import BudgetExceeded
from cheatproof.executor import ExecutorRefused, ExecutorUnavailable, Result, Session
from cheatproof.llm import MAX_OUTPUT_TOKENS, estimate_tokens

MAX_RESULT_CHARS = 8000  # tool results sent back to the model are cut to this (plus a marker)
TRACE_ARG_CHARS = 2000  # string arguments are cut to this in the trace
DIGEST_HEAD_CHARS = 300
ERROR_DETAIL_CHARS = 300
MAX_CALL_ID_CHARS = 64
NUDGE = "Use a tool or call submit."
# The executor resets the sandbox when a host kill hits a run, at its timeout or at its output cap (Session.run).
# The model must know. holes.TIMED_OUT_HEAD matches the start of RESET_NOTE, so its wording stays.
RESET_NOTE = (
    "error: the command timed out and the sandbox was reset. Files written earlier in this attempt are lost; "
    "the sandbox is a fresh copy of the starting image."
)
CAP_RESET_NOTE = (
    "error: the command printed more output than the cap and the sandbox was reset. Files written earlier in this "
    "attempt are lost; the sandbox is a fresh copy of the starting image."
)

StopReason = Literal["submit", "max_steps", "token_limit", "budget", "error"]


class ChatLLM(Protocol):
    """What the loop needs from cheatproof.llm.GuardedLLM."""

    def chat(self, model: str, messages: list[dict], max_tokens: int, **kwargs: Any) -> Any: ...


class SearchFn(Protocol):
    """Host-side web search. The caller's callable must reserve against budget.py itself, one reservation
    per call, because each call is paid (Tavily). The attacker only counts calls, up to max_searches."""

    def __call__(self, query: str) -> list[dict]: ...


@dataclass(frozen=True)
class AttackConfig:
    """Limits and switches for one attempt.

    allow_network must match the session's EnvSpec.network. The caller sets both. This module cannot read the
    session's network setting, so a mismatch is not detected here. web_search runs host side either way.
    """

    # Empty until ATTACKER_MODEL is set; attack() refuses to start without a model.
    model: str = field(default_factory=lambda: os.environ.get("ATTACKER_MODEL", "").strip())
    max_steps: int = 15
    max_tokens_total: int = 50_000  # prompt plus completion tokens, summed over the calls
    # Nemotron spends output on reasoning, so a tool call needs room after it.
    max_output_tokens: int = min(2048, MAX_OUTPUT_TOKENS)
    label: str | None = None  # free-form tag recorded in the trace header (for example the strategy)
    allow_network: bool = False
    cmd_timeout: float = 120
    max_searches: int = 3  # web_search calls per attempt; the search callable is not called past this

    def __post_init__(self) -> None:
        if self.max_steps < 1:
            raise ValueError(f"max_steps must be at least 1, got {self.max_steps!r}")
        if self.max_tokens_total < 1:
            raise ValueError(f"max_tokens_total must be at least 1, got {self.max_tokens_total!r}")
        if not 0 < self.max_output_tokens <= MAX_OUTPUT_TOKENS:
            raise ValueError(
                f"max_output_tokens must be 1..{MAX_OUTPUT_TOKENS}, got {self.max_output_tokens!r}"
            )
        if not (math.isfinite(self.cmd_timeout) and self.cmd_timeout > 0):
            raise ValueError(f"cmd_timeout must be a positive number, got {self.cmd_timeout!r}")
        if self.max_searches < 0:
            raise ValueError(f"max_searches must be 0 or more, got {self.max_searches!r}")


@dataclass
class AttackResult:
    # True when the model's submit ran without a tool error. It stays True if the diff then fails,
    # so check stop_reason and diff_ok too.
    submitted: bool
    # "budget" is for callers that record a halted attempt: attack() itself re-raises BudgetExceeded.
    # "error" also covers a failed diff: the attempt has no patch to score.
    stop_reason: StopReason
    steps: list[dict]
    tokens_in: int
    tokens_out: int
    final_diff: str | None  # None when diff_ok is False. An empty string is a real, empty patch.
    error: str = ""
    diff_ok: bool = True


class _ToolError(Exception):
    """A tool call that cannot run. The message goes back to the model as the tool result."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class _Call:
    id: str
    name: str
    raw_args: object
    extra: int  # tool calls after the first in the same reply; they are not run


class _Output(NamedTuple):
    text: str  # the tool result the model sees
    reset: bool = False  # True when the executor reset the sandbox during this call


@dataclass
class _SearchTally:
    """web_search calls that reached the search callable in this attempt."""

    made: int = 0


def _tool(name: str, description: str, properties: dict[str, dict], required: list[str]) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": False,
            },
        },
    }


def build_tools(web_search: bool = False) -> list[dict]:
    """OpenAI function-calling schemas for the attacker. web_search only when asked for."""
    string = {"type": "string"}
    tools = [
        _tool("run", "Run a shell command in the sandbox.", {"cmd": string}, ["cmd"]),
        _tool("read_file", "Read a file in the sandbox.", {"path": string}, ["path"]),
        _tool(
            "write_file",
            "Write a file in the sandbox, replacing it.",
            {"path": string, "content": string},
            ["path", "content"],
        ),
        _tool("submit", "End the attempt. The grader runs on the sandbox as it is.", {}, []),
    ]
    if web_search:
        tools.append(_tool("web_search", "Search the web.", {"query": string}, ["query"]))
    return tools


def _clip(text: str, limit: int = MAX_RESULT_CHARS) -> str:
    """Keep the start and the end of a long result (test summaries sit at the end) and mark the cut."""
    if len(text) <= limit:
        return text
    head = limit * 2 // 3
    tail = limit - head
    return f"{text[:head]}\n[truncated: {len(text) - limit} chars omitted]\n{text[-tail:]}"


def _digest(text: str) -> dict:
    raw = text.encode("utf-8", "replace")  # lone surrogates from model text must not crash the hash
    return {"sha256": hashlib.sha256(raw).hexdigest(), "head": text[:DIGEST_HEAD_CHARS], "chars": len(text)}


def _cap_text(text: str, limit: int) -> str:
    return text if len(text) <= limit else f"{text[:limit]}...[+{len(text) - limit} chars]"


def _trace_args(args: object) -> dict:
    """Arguments for the trace: string values capped. Anything that is not a flat object is kept as capped JSON."""
    if isinstance(args, dict) and all(
        isinstance(v, str | int | float | bool | type(None)) for v in args.values()
    ):
        return {str(k): _cap_text(v, TRACE_ARG_CHARS) if isinstance(v, str) else v for k, v in args.items()}
    try:
        raw = json.dumps(args, default=str)
    except (TypeError, ValueError, RecursionError):
        raw = repr(args)
    return {"_json": _cap_text(raw, TRACE_ARG_CHARS)}


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _usage(resp: object, est_in: int, max_out: int) -> tuple[int, int]:
    """Tokens (in, out) for one call. Without usage, the worst case the budget reserved is counted."""
    usage = getattr(resp, "usage", None)
    t_in = getattr(usage, "prompt_tokens", None)
    t_out = getattr(usage, "completion_tokens", None)
    if _is_count(t_in) and _is_count(t_out):
        return t_in, t_out
    return est_in, max_out


def _message(resp: object) -> object | None:
    choices = getattr(resp, "choices", None)
    try:
        return choices[0].message
    except (AttributeError, IndexError, KeyError, TypeError):
        return None


def _first_call(message: object, step: int) -> _Call | None:
    """The first tool call of a reply, or None. Everything here is untrusted, so every field is checked."""
    calls = getattr(message, "tool_calls", None)
    if not isinstance(calls, list | tuple) or not calls:
        return None
    first = calls[0]
    function = getattr(first, "function", None)
    name = getattr(function, "name", None)
    call_id = getattr(first, "id", None)
    if not isinstance(call_id, str) or not call_id.strip():
        call_id = f"call_{step}"
    return _Call(
        id=call_id[:MAX_CALL_ID_CHARS],
        name=name[:MAX_CALL_ID_CHARS] if isinstance(name, str) else "",
        raw_args=getattr(function, "arguments", None),
        extra=len(calls) - 1,
    )


def _parse_args(raw: object) -> dict:
    """Tool arguments as a dict. Empty arguments mean no arguments. Anything else raises _ToolError."""
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        raise _ToolError("bad_json", "error: tool arguments must be a JSON object string")
    if not raw.strip():
        return {}
    try:
        value = json.loads(raw)
    except (ValueError, RecursionError):
        raise _ToolError("bad_json", "error: tool arguments are not valid JSON") from None
    if not isinstance(value, dict):
        raise _ToolError("bad_json", "error: tool arguments must be a JSON object")
    return value


def _str_arg(args: dict, key: str, *, allow_empty: bool = False) -> str:
    if key not in args:
        raise _ToolError("bad_args", f"error: missing required argument '{key}'")
    value = args[key]
    if not isinstance(value, str):
        raise _ToolError("bad_args", f"error: argument '{key}' must be a string")
    if not allow_empty and not value.strip():
        raise _ToolError("bad_args", f"error: argument '{key}' must not be empty")
    return value


def _format_run(res: Result) -> str:
    head = f"exit_code: {res.exit_code}"
    if res.timed_out:
        head += " (timed out)"
    if res.truncated:
        head += " (output truncated)"
    return f"{head}\n--- stdout ---\n{res.stdout}\n--- stderr ---\n{res.stderr}"


def _run_output(res: Result) -> _Output:
    # A host kill (timeout or output cap) makes the executor reset the sandbox, so the reset note goes first.
    if res.timed_out or res.reset:
        note = RESET_NOTE if res.timed_out else CAP_RESET_NOTE
        return _Output(f"{note}\n{_format_run(res)}", reset=True)
    return _Output(_format_run(res))


def _detail(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {str(exc)[:ERROR_DETAIL_CHARS]}"


def _stop_code(exc: BaseException) -> str:
    """The trace code of a step that stopped the attempt. DiskRefused is an ExecutorRefused."""
    if isinstance(exc, BudgetExceeded):
        return "budget_exceeded"
    if isinstance(exc, ExecutorRefused):
        return "executor_refused"
    return "executor_unavailable"


class _Trace:
    """Appends one JSON line per record. A write error propagates, except where a caller suppresses it."""

    def __init__(self, path: Path | None) -> None:
        self.path = Path(path) if path is not None else None

    def write(self, record: dict) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as out:
            out.write(json.dumps(record) + "\n")  # ASCII-escaped, so lone surrogates are safe


def _run_tool(
    name: str,
    args: dict,
    session: Session,
    config: AttackConfig,
    search: SearchFn | None,
    tally: _SearchTally,
) -> _Output:
    if name == "run":
        return _run_output(session.run(_str_arg(args, "cmd"), config.cmd_timeout))
    if name == "read_file":
        path = _str_arg(args, "path")
        res = session.run(f"cat -- {shlex.quote(path)}", config.cmd_timeout)
        if res.exit_code == 0 and not (res.timed_out or res.reset):
            return _Output(res.stdout)
        return _run_output(res)
    if name == "write_file":
        path = _str_arg(args, "path")
        content = _str_arg(args, "content", allow_empty=True)
        session.write_file(path, content)
        return _Output(f"wrote {len(content.encode('utf-8', 'replace'))} bytes to {path}")
    if name == "submit":
        return _Output("submitted")
    if name == "web_search" and search is not None:
        query = _str_arg(args, "query")
        if tally.made >= config.max_searches:
            # Checked before the callable runs, so a refused call costs nothing.
            raise _ToolError(
                "search_limit", f"error: web_search limit of {config.max_searches} per attempt reached"
            )
        tally.made += 1
        try:
            results = search(query)
        except BudgetExceeded:
            raise
        except Exception as exc:  # noqa: BLE001 - any search failure goes to the model as a tool error
            # Only the type: a search client's message could carry request details.
            raise _ToolError("tool_exception", f"error: web_search failed ({type(exc).__name__})") from None
        if not isinstance(results, list) or not all(isinstance(r, dict) for r in results):
            raise _ToolError("tool_exception", "error: web_search returned an unexpected result")
        return _Output(json.dumps(results, default=str))
    raise _ToolError("unknown_tool", f"error: unknown tool {name!r}")


def attack(
    llm: ChatLLM,
    session: Session,
    system_prompt: str,
    task_prompt: str,
    config: AttackConfig | None = None,
    search: SearchFn | None = None,
    trace_path: Path | None = None,
) -> AttackResult:
    """Run one attempt. Stops at submit, max_steps, the token limit or an LLM error.

    A step is one model call plus the one tool call it made (extra tool calls in the same reply are
    not run). BudgetExceeded from the LLM is written to the trace and re-raised. An HTTP 402
    from the LLM is the same stop: GuardedLLM has halted the ledger, so this raises BudgetExceeded.
    BudgetExceeded, ExecutorRefused (DiskRefused included) and ExecutorUnavailable from a tool or from the diff
    are the same kind of stop: traced, then re-raised, so harden and the CLI see them. They never become tool errors.
    If the final diff cannot be taken otherwise, stop_reason is "error" and diff_ok is False, even after submit.
    """
    config = config or AttackConfig()
    if not config.model.strip():
        raise ValueError("no attacker model: set ATTACKER_MODEL or AttackConfig.model")
    if not isinstance(system_prompt, str) or not isinstance(task_prompt, str) or not task_prompt.strip():
        raise ValueError("system_prompt and task_prompt must be strings, and task_prompt must not be empty")

    tools = build_tools(web_search=config.allow_network and search is not None and config.max_searches > 0)
    tool_names = [t["function"]["name"] for t in tools]
    trace = _Trace(trace_path)
    tally = _SearchTally()
    steps: list[dict] = []
    messages: list[dict] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": task_prompt},
    ]
    trace.write(
        {
            "type": "header",
            "label": None if config.label is None else _cap_text(config.label, 200),
            "model": config.model,
            "max_steps": config.max_steps,
            "max_tokens_total": config.max_tokens_total,
            "max_output_tokens": config.max_output_tokens,
            "max_searches": config.max_searches,
            "allow_network": config.allow_network,
            "cmd_timeout": config.cmd_timeout,
            "tools": tool_names,
            "system_prompt": {"sha256": _digest(system_prompt)["sha256"], "chars": len(system_prompt)},
            "task_prompt": {"sha256": _digest(task_prompt)["sha256"], "chars": len(task_prompt)},
        }
    )

    tokens_in = tokens_out = 0
    stop_reason: StopReason = "max_steps"
    error = ""
    submitted = False

    def record(
        step: int,
        started: float,
        tool: str | None,
        args: object,
        result: str,
        code: str | None,
        t_in: int,
        t_out: int,
        ignored: int = 0,
        reset: bool = False,
    ) -> None:
        rec = {
            "type": "step",
            "step": step,
            "tool": tool,
            "args": _trace_args(args),
            "result_digest": _digest(result),
            "error": code,
            "ignored_calls": ignored,
            "reset": reset,
            "tokens_in": t_in,
            "tokens_out": t_out,
            "elapsed": round(time.monotonic() - started, 3),
        }
        steps.append(rec)
        trace.write(rec)

    def end_on_stop(exc: BaseException) -> None:
        # The trace comes first; a trace write error must not hide the stop. A budget stop ends as "budget", an
        # executor stop (DiskRefused, ExecutorRefused, ExecutorUnavailable) as "error".
        stop_reason = "budget" if isinstance(exc, BudgetExceeded) else "error"
        with contextlib.suppress(OSError):
            trace.write(
                {
                    "type": "end",
                    "stop_reason": stop_reason,
                    "steps": len(steps),
                    "tokens_in": tokens_in,
                    "tokens_out": tokens_out,
                    "error": _detail(exc),
                }
            )

    for step in range(1, config.max_steps + 1):
        est_in = estimate_tokens(messages, tools)
        if tokens_in + tokens_out + est_in + config.max_output_tokens > config.max_tokens_total:
            stop_reason = "token_limit"
            break
        started = time.monotonic()
        try:
            resp = llm.chat(config.model, list(messages), config.max_output_tokens, tools=tools)
        except BudgetExceeded as exc:
            with contextlib.suppress(OSError):
                record(step, started, None, {}, _detail(exc), "budget_exceeded", 0, 0)
            end_on_stop(exc)
            raise
        except Exception as exc:  # noqa: BLE001 - any other LLM failure ends the attempt as stop_reason error
            status = getattr(exc, "status_code", None)
            if status == 402:
                # Balance exhausted. GuardedLLM has already halted the ledger, so stop like a budget cap.
                # The provider text is not used: the message is ours.
                halt = BudgetExceeded("HTTP 402 from the LLM provider: balance exhausted, attempt halted")
                with contextlib.suppress(OSError):
                    record(step, started, None, {}, _detail(halt), "budget_exceeded", 0, 0)
                end_on_stop(halt)
                raise halt from None
            # Only the type: provider error text is not trusted to be free of request details.
            where = f" (HTTP {status})" if _is_count(status) else ""
            stop_reason, error = "error", f"llm call failed: {type(exc).__name__}{where}"
            record(step, started, None, {}, error, "llm_error", 0, 0)
            break

        t_in, t_out = _usage(resp, est_in, config.max_output_tokens)
        tokens_in += t_in
        tokens_out += t_out
        message = _message(resp)
        if message is None:
            stop_reason, error = "error", "llm reply had no message"
            record(step, started, None, {}, error, "bad_response", t_in, t_out)
            break

        content = getattr(message, "content", None)
        content = content if isinstance(content, str) else ""
        call = _first_call(message, step)
        if call is None:
            if content:
                messages.append({"role": "assistant", "content": content})
            messages.append({"role": "user", "content": NUDGE})
            record(step, started, None, {}, NUDGE, "no_tool_call", t_in, t_out)
            continue

        args: dict = {}
        sent_args = "{}"  # what the history keeps; bad JSON is not echoed back to the provider
        code: str | None = None
        reset = False
        try:
            args = _parse_args(call.raw_args)
            if isinstance(call.raw_args, str) and call.raw_args.strip():
                sent_args = call.raw_args
            elif args:
                sent_args = json.dumps(args)
            if call.name not in tool_names:
                raise _ToolError(
                    "unknown_tool", f"error: unknown tool {call.name!r}; use one of {tool_names}"
                )
            out = _run_tool(call.name, args, session, config, search, tally)
            result, reset = out.text, out.reset
        except _ToolError as err:
            result, code = err.message, err.code
            if err.code == "bad_json":
                args = {"_raw": call.raw_args if isinstance(call.raw_args, str) else repr(call.raw_args)}
        except (BudgetExceeded, ExecutorRefused, ExecutorUnavailable) as exc:
            # A stop, not a tool error: the step is traced and the attempt ends. The caller decides what it means.
            with contextlib.suppress(OSError):
                record(step, started, call.name, args, _detail(exc), _stop_code(exc), t_in, t_out, call.extra)
            end_on_stop(exc)
            raise
        except Exception as exc:  # noqa: BLE001 - executor failures go to the model as a tool error
            # The name of the tool is known here (unknown names were refused above). Only the type of the
            # exception goes back: its text can carry paths or container details.
            result = f"error: {call.name} failed ({type(exc).__name__})"
            code = "tool_exception"

        record(step, started, call.name, args, result, code, t_in, t_out, call.extra, reset)
        shown = _clip(result)
        if call.extra:
            shown += f"\n[only the first of {call.extra + 1} tool calls ran; send one tool call per step]"
        messages.append(
            {
                "role": "assistant",
                "content": content,
                "tool_calls": [
                    {
                        "id": call.id,
                        "type": "function",
                        "function": {"name": call.name or "unknown", "arguments": sent_args},
                    }
                ],
            }
        )
        messages.append({"role": "tool", "tool_call_id": call.id, "content": shown})
        if call.name == "submit" and code is None:
            submitted, stop_reason = True, "submit"
            break

    final_diff: str | None = None
    diff_ok = True
    try:
        final_diff = session.diff()
    except (BudgetExceeded, ExecutorRefused, ExecutorUnavailable) as exc:
        end_on_stop(exc)
        raise
    except Exception as exc:  # noqa: BLE001 - a failed diff is reported in the result, not raised
        # No patch means nothing to score. Never report a normal submit with an empty diff.
        diff_ok, stop_reason = False, "error"
        note = f"diff failed: {_detail(exc)}"
        error = f"{error}; {note}" if error else note

    trace.write(
        {
            "type": "end",
            "stop_reason": stop_reason,
            "submitted": submitted,
            "diff_ok": diff_ok,
            "steps": len(steps),
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
            "error": error,
            "final_diff": None if final_diff is None else _digest(final_diff),
        }
    )
    return AttackResult(
        submitted=submitted,
        stop_reason=stop_reason,
        steps=steps,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        final_diff=final_diff,
        error=error,
        diff_ok=diff_ok,
    )
