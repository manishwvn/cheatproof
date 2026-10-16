# ADR 0001: in-app hard spend cap

**Status:** accepted, 2026-10-16

**Context.** Token Factory needs a card. It has no documented hard spend limit, the balance can go negative, and the
card is auto-charged at month start or at a billing threshold. The project must stay inside free credits, including
during public judging (Dec 1–15) when anyone can trigger runs.

**Decision.** Every paid call goes through `twindiff/budget.py`:
- It reserves the worst-case cost (estimated input × price, plus `max_tokens` × price) before calling, and settles
  the real cost from `usage` after.
- Total, daily and sandbox-run caps are checked against a file-locked JSON ledger shared by all processes.
- HTTP 402 halts all paid calls until a person clears the flag.
- Unknown models are priced high ($3/$10 per 1M), and failed calls still count their prompt cost.
- Output size is bounded (`MAX_OUTPUT_TOKENS`).

**Consequences.** Spend estimates err high, so the app may stop early; that is intended. Prices must be recorded from
the console (`MODEL_PRICES_JSON`) to avoid stopping far too early. Sandbox cost is capped by run count until a
per-run price is known.
