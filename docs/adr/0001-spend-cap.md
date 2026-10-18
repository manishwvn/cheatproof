# ADR 0001: in-app hard spend cap

**Status:** accepted, 2026-10-16; amended 2026-10-18 (fail-closed settings, read-only snapshot)

**Context.** Token Factory needs a card. It has no documented hard spend limit, the balance can go negative, and the
card is auto-charged at month start or at a billing threshold. The project must stay inside free credits, including
during public judging (Dec 1–15) when anyone can trigger runs.

**Decision.** Every paid call goes through `cheatproof/budget.py`:
- It reserves the worst-case cost (estimated input × price, plus `max_tokens` × price) before calling, and settles
  the real cost from `usage` after.
- Total, daily and sandbox-run caps are checked against a file-locked JSON ledger shared by all processes. The
  one total cap is **$20** (`SPEND_CAP_USD`) against about $25 of credits; the daily cap is $4 (`DAILY_CAP_USD`).
  A sandbox run checks the halt flag, the run cap and the money caps and books itself under one lock.
- **Fail closed.** `SPEND_CAP_USD` and `DAILY_CAP_USD` are required, with no default. Each must parse as a finite
  number above 0. Every price (`MODEL_PRICES_JSON`, `SANDBOX_RUN_USD`) must be finite and above 0, and
  `SANDBOX_RUN_CAP` a whole number of 0 or more. A missing, empty, nan, inf, zero or negative money value, or a bad
  run cap or price, raises `BudgetExceeded` before any spend. A ledger amount that is nan, inf or negative is
  refused the same way. Zero is never read as "unlimited".
- **Read-only snapshot.** `snapshot()` reads the ledger under the lock and never writes it. A `halted` flag that a
  person has cleared stays cleared.
- HTTP 402 halts all paid calls until a person clears the flag.
- Unknown models are priced high ($3/$10 per 1M), and failed calls still count their prompt cost.
- Output size is bounded (`MAX_OUTPUT_TOKENS`).

**Consequences.** Spend estimates err high, so the app may stop early; that is intended. Prices must be recorded from
the console (`MODEL_PRICES_JSON`) to avoid stopping far too early. Sandbox cost is capped by run count until a
per-run price is known.
