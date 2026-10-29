# ADR 0001: in-app hard spend cap

**Status:** accepted, 2026-10-16. Amendments:
- 2026-10-18: fail-closed settings, read-only snapshot, $20 ceiling, validated token counts, settle and ledger checks.
- 2026-10-21: Sandboxes became the default executor; a reported Sandboxes cost is logged, not booked (U21).
- 2026-10-22: Sandboxes cost passed the then-current $0.50 cap and the budget halted (U25).
- 2026-10-23: logged-cost rule written into this ADR; the real-spend cap `REAL_SPEND_CAP_USD` ($10, T43) replaced the
  trial-only cap. Current `SANDBOX_COST_CAP_USD`: 5.00 in the live `.env` since 2026-10-23 (an estimate counter, not a
  bill). The code default is still 0.50; the earlier 0.50 and 1.50 settings are history.

**Context.** Token Factory needs a card. It has no documented hard spend limit, the balance can go negative, and the
card is auto-charged at month start or at a billing threshold. The project must stay inside free credits (the $1 trial
and the hackathon promo credit, not card money), including during public judging (Dec 1–15) when anyone can trigger runs.

**Decision.** Every paid call goes through `rewardseal/budget.py`:
- It reserves the worst-case cost (estimated input × price, plus `max_tokens` × price) before calling, and settles
  the real cost from `usage` after.
- Total, daily and sandbox-run caps are checked against a file-locked JSON ledger shared by all processes. The
  total cap is **$20** (`SPEND_CAP_USD`) against the $26.65 hackathon promo credit (not card money) plus the $0.71 trial left on 2026-10-23; the daily cap is $4 (`DAILY_CAP_USD`).
  A sandbox run checks the halt flag, the run cap and the money caps and books itself under one lock.
- **Ceiling.** The code enforces $20 as a hard maximum on the total cap (`MAX_TOTAL_CAP_USD`). A larger total cap
  raises `BudgetExceeded`, and so does a daily cap above the total cap. Only the owner may lower caps in `.env`.
  Raising the ceiling needs a code change through planner merge.
- **Real-spend cap (T43, 2026-10-23).** `REAL_SPEND_CAP_USD` caps TOTAL real Token Factory spend (trial + promo credit).
  Default and hard ceiling $10 (`MAX_REAL_SPEND_CAP_USD`); a set value above 10, zero, negative or invalid raises
  `BudgetExceeded`, never a higher cap. It counts in the ledger field `trial_spend_usd` (name kept so the live ledger
  keeps counting). The old `TRIAL_CREDIT_CAP_USD`, if set, is an extra, stricter cap. The balance must never go negative.
- **Fail closed.** `SPEND_CAP_USD` and `DAILY_CAP_USD` are required, with no default. Each must parse as a finite
  number above 0. Every price (`MODEL_PRICES_JSON`, `SANDBOX_RUN_USD`) must be finite and above 0, and
  `SANDBOX_RUN_CAP` a whole number of 0 or more. A missing, empty, nan, inf, zero, negative or oversized money value,
  or a bad run cap or price, raises `BudgetExceeded` before any spend. Zero is never read as "unlimited".
- **Token counts.** Input and output token counts must be whole numbers of 0 or more. Bools, floats, nan, inf,
  negatives and counts too large to price are refused, and `reserve` books nothing for them.
- **Settle.** `settle` checks its token counts before it takes the lock. Invalid counts raise `BudgetExceeded` and the
  full hold stays booked. A valid settle never refunds more than its hold, and a booked amount never drops below zero.
- **Ledger.** A ledger is refused, not repaired, when it is not a JSON object, when `total_usd`, `days` or
  `sandbox_runs` is missing, when `total_usd` or any day amount is not finite and 0 or more, when `days` is not an
  object, when `sandbox_runs` is not a whole number of 0 or more, or when `halted` is not null, a bool or a non-empty
  string. A ledger amount that is nan, inf or negative is refused the same way.
- **Read-only snapshot.** `snapshot()` reads the ledger under the lock and never writes it. A `halted` flag that a
  person has cleared stays cleared.
- HTTP 402 halts all paid calls until a person clears the flag. `halt()` stores a non-empty reason, so an empty or
  missing reason still halts.
- Unknown models are priced high ($3/$10 per 1M), and failed calls still count their prompt cost.
- Output size is bounded (`MAX_OUTPUT_TOKENS`).

**Consequences.** Spend estimates err high, so the app may stop early; that is intended. Prices must be recorded from
the console (`MODEL_PRICES_JSON`) to avoid stopping far too early. Sandbox runs are bounded by run count and by the
logged-cost rule in the 2026-10-23 amendment below. A ledger that fails these checks stops all paid calls until a person fixes it by hand.

## 2026-10-21 update (amended 2026-10-23)
Token Factory Sandboxes work, and they are the default executor (`EXECUTOR` unset means `sandbox`). A sandbox run books
no Token Factory money: the money caps and the trial counter do not move. Each run counts against `SANDBOX_RUN_CAP`.
`SANDBOX_RUN_USD` is still parsed and validated, but not charged.

**Logged-cost rule (replaces the earlier "books $0, count-only" wording).** The Sandboxes API reports a non-zero
`resources.cost` on `done.result.cost`. The budget logs each reported cost in a separate Sandboxes section of the ledger
(`sandbox_cost_usd`, never added to the Token Factory totals) and halts once the logged sum passes
`SANDBOX_COST_CAP_USD` (default $0.50; an invalid value falls back to $0.50, never to no cap). A malformed cost halts.
HTTP 402 still halts. The reported cost is an estimate: on 2026-10-23 the Nebius console showed no Sandboxes billing
line, so the cap is a guard, not a bill. The live cap was first set to $1.50 that day; the live `.env` now has $5.00.
