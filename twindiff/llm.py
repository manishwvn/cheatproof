"""Token Factory chat client that cannot call a model without passing the spend cap."""

from __future__ import annotations

import json
import os

import openai

from .budget import Budget

BASE_URL = "https://api.tokenfactory.nebius.com/v1/"
MAX_OUTPUT_TOKENS = int(os.environ.get("MAX_OUTPUT_TOKENS", "4096"))


def estimate_tokens(messages: list[dict]) -> int:
    # About 3 chars per token, which over-counts on purpose so reservations stay conservative.
    return len(json.dumps(messages)) // 3 + 16


class GuardedLLM:
    def __init__(self, budget: Budget, client=None) -> None:
        self.budget = budget
        self.client = client or openai.OpenAI(base_url=BASE_URL, api_key=os.environ["NEBIUS_API_KEY"])

    def chat(self, model: str, messages: list[dict], max_tokens: int, **kwargs):
        if not 0 < max_tokens <= MAX_OUTPUT_TOKENS:
            raise ValueError(f"max_tokens must be 1..{MAX_OUTPUT_TOKENS}")
        est_input = estimate_tokens(messages)
        hold = self.budget.reserve(model, est_input, max_tokens)
        try:
            resp = self.client.chat.completions.create(
                model=model, messages=messages, max_tokens=max_tokens, **kwargs
            )
        except openai.APIStatusError as err:
            if err.status_code == 402:
                self.budget.halt("HTTP 402 from Token Factory: balance exhausted")
            # Assume the prompt may have been billed; never assume a failed call was free.
            self.budget.settle(hold, est_input, 0)
            raise
        except Exception:
            self.budget.settle(hold, est_input, 0)
            raise
        usage = resp.usage
        if usage is None:
            # No usage reported: keep the worst-case reservation.
            return resp
        self.budget.settle(hold, usage.prompt_tokens, usage.completion_tokens)
        return resp
