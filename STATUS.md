# Status

**2026-10-16**: repo set up per the playbook (sections 4–7). No product code yet; the spend cap is in place and tested.

- Idea locked: R1 behavioural twin-diff (`docs/pitches.md`). Working name `twin-diff`; final name is owner task U5.
- Blocked on the owner: U1 (Nebius account, card, promo credits, API key), U2 (Tavily key), U3 (Sandboxes access).
- Weekly Claude usage was 82% (cap 80%), so heavy work is paused until the reset on **2026-10-20**.
- The scheduled routine is **not created yet**, on purpose. Create it on 2026-10-20 (playbook 6.10) after an
  independent review of `CYCLE.md` and the guards.
- Repo: github.com/manishwvn/twin-diff (private). CI and security green on main (448dddc).
- Next task when unblocked: T01 smoke test against live Token Factory.

## Audit 2026-10-16 (independent reviewer, in place of owner approval): APPROVE WITH CHANGES
Do these first, before any live spend:
1. `llm.py`: set `max_retries=0`, and switch kwargs to an allowlist (blocks `max_completion_tokens`, `extra_body`). Add tests for both.
2. `SPEND_LEDGER` must be an absolute path under `~/.twin-diff-autopilot/`, required, fail closed, so worktrees share one cap.
3. Sandbox run reservation in a single lock.
4. One cap number everywhere: $30, with ~$50 credits.
5. Scope cuts: T11 becomes a static replay page merged into T12; T14 becomes an owner screen capture; corpus 10+10. Add a T07 acceptance test: the verdict flips with vs without Tavily.
6. Hero go/no-go on Oct 22: if the canary isn't hijacked in 2 runs, change the prompt or tool surface before the eval.
