"""Token Factory client: every chat completion passes the spend cap first."""

from __future__ import annotations

import json
import os

import openai

from .budget import Budget, BudgetExceeded

BASE_URL = "https://api.tokenfactory.nebius.com/v1/"
MAX_OUTPUT_TOKENS = int(os.environ.get("MAX_OUTPUT_TOKENS", "4096"))
# Only options that cannot change what one reservation pays for.
ALLOWED_KWARGS = {"temperature", "top_p", "tools", "tool_choice", "response_format", "stop", "seed"}


def estimate_tokens(messages: list[dict], tools: list[dict] | None = None) -> int:
    # About 3 chars per token, which over-counts on purpose so reservations stay conservative.
    return len(json.dumps(messages)) // 3 + len(json.dumps(tools or [])) // 3 + 16


class GuardedLLM:
    def __init__(self, budget: Budget, client=None) -> None:
        self.budget = budget
        self._client = client or openai.OpenAI(
            # No SDK retries: each retry could be billed while only one reservation is held.
            base_url=BASE_URL,
            api_key=os.environ["NEBIUS_API_KEY"],
            max_retries=0,
            timeout=120.0,
        )

    def list_models(self) -> list[str]:
        # VERIFY: listing assumed free, so it skips the budget.
        page = self._client.models.list()
        return [m.id for m in page.data]

    def chat(self, model: str, messages: list[dict], max_tokens: int, **kwargs):
        if not 0 < max_tokens <= MAX_OUTPUT_TOKENS:
            raise ValueError(f"max_tokens must be 1..{MAX_OUTPUT_TOKENS}")
        if kwargs.keys() - ALLOWED_KWARGS:
            raise ValueError(f"unsupported options: {sorted(kwargs.keys() - ALLOWED_KWARGS)}")
        est_input = estimate_tokens(messages, kwargs.get("tools"))
        hold = self.budget.reserve(model, est_input, max_tokens)
        paid = None
        try:
            resp = self._client.chat.completions.create(
                model=model, messages=messages, max_tokens=max_tokens, **kwargs
            )
        except openai.APIStatusError as err:
            if err.status_code != 402:
                if 400 <= err.status_code < 500:
                    # Rejected request: count the prompt only, never assume it was free.
                    self.budget.settle(hold, est_input, 0)
                # 5xx: the server may have generated output, so keep the worst-case reservation.
                raise
            paid = self._halt_for_402(hold, est_input)
        except Exception:
            # Timeouts or dropped connections may still be billed: keep the worst-case reservation.
            raise
        if paid is not None:
            # Outside the except block: the SDK error never becomes __context__, and its text never leaves.
            raise paid from None
        usage = resp.usage
        if usage is None:
            # No usage reported: keep the worst-case reservation.
            return resp
        self.budget.settle(hold, usage.prompt_tokens, usage.completion_tokens)
        return resp

    def _halt_for_402(self, hold, est_input: int) -> BudgetExceeded:
        """HTTP 402 halts every paid call. Returns the error to raise: fixed text, so the SDK error's URL, headers and
        body never reach it. Same pattern as executor._halt_for_payment. The prompt is counted as in any 4xx."""
        halted = True
        try:
            self.budget.halt("HTTP 402 from Token Factory: balance exhausted")
        except BudgetExceeded:
            halted = False  # the ledger's own error is dropped unread
        try:
            self.budget.settle(hold, est_input, 0)
        except BudgetExceeded:
            pass  # the hold stays at its worst case: conservative, never a refund past the reservation
        if not halted:
            return BudgetExceeded("HTTP 402 from Token Factory; ledger could not be halted")
        return BudgetExceeded("HTTP 402 from Token Factory; the budget is halted")
