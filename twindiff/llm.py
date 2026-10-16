"""Token Factory client: every chat completion passes the spend cap first."""

from __future__ import annotations

import json
import os

import openai

from .budget import Budget

BASE_URL = "https://api.tokenfactory.nebius.com/v1/"
MAX_OUTPUT_TOKENS = int(os.environ.get("MAX_OUTPUT_TOKENS", "4096"))
# Options that would change what one reservation pays for (several outputs, or usage hidden in a stream).
FORBIDDEN_KWARGS = {"stream", "n", "best_of"}


def estimate_tokens(messages: list[dict], tools: list[dict] | None = None) -> int:
    # About 3 chars per token, which over-counts on purpose so reservations stay conservative.
    return len(json.dumps(messages)) // 3 + len(json.dumps(tools or [])) // 3 + 16


class GuardedLLM:
    def __init__(self, budget: Budget, client=None) -> None:
        self.budget = budget
        self.client = client or openai.OpenAI(base_url=BASE_URL, api_key=os.environ["NEBIUS_API_KEY"])

    def chat(self, model: str, messages: list[dict], max_tokens: int, **kwargs):
        if not 0 < max_tokens <= MAX_OUTPUT_TOKENS:
            raise ValueError(f"max_tokens must be 1..{MAX_OUTPUT_TOKENS}")
        if FORBIDDEN_KWARGS & kwargs.keys():
            raise ValueError(f"unsupported options: {sorted(FORBIDDEN_KWARGS & kwargs.keys())}")
        est_input = estimate_tokens(messages, kwargs.get("tools"))
        hold = self.budget.reserve(model, est_input, max_tokens)
        try:
            resp = self.client.chat.completions.create(
                model=model, messages=messages, max_tokens=max_tokens, **kwargs
            )
        except openai.APIStatusError as err:
            if err.status_code == 402:
                self.budget.halt("HTTP 402 from Token Factory: balance exhausted")
            if 400 <= err.status_code < 500:
                # Rejected request: count the prompt only, never assume it was free.
                self.budget.settle(hold, est_input, 0)
            # 5xx: the server may have generated output, so keep the worst-case reservation.
            raise
        except Exception:
            # Timeouts or dropped connections may still be billed: keep the worst-case reservation.
            raise
        usage = resp.usage
        if usage is None:
            # No usage reported: keep the worst-case reservation.
            return resp
        self.budget.settle(hold, usage.prompt_tokens, usage.completion_tokens)
        return resp
