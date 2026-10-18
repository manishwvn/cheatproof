# Status

**2026-10-18: Cheatproof set up.** Coding & Agentic track; the owner submits 2026-10-28 (deadline 2026-10-30
10:00 PDT). Progress: `python3 docs/autopilot/progress.py`.

- **Built:** the spend cap (`cheatproof/budget.py`, `cheatproof/llm.py`; one $20 total cap; sandbox runs reserved
  under one lock), CI and security workflows, autopilot scripts (`next_run.py`, `progress.py`, `lock.py`) with tests,
  guards, docs, queue T01–T14, ADR 0001 (spend cap) and ADR 0002 (executor: Sandboxes, Docker fallback). No product
  code yet.
- **Next for the routine:** T02 executor with the Docker backend (no key needed), then T03 task loader and T04
  attacker on fakes.
- **Owner blockers:** U1 (account and $1 trial exist; promo code pending by email; key not in `.env` yet; T01 and
  every live run wait on it; until "promo applied", live spend stays inside the $1 trial), U3 (Sandboxes access), U7 (disk
  space for the Docker fallback: 16 GB free).
- **Risk:** the Oct 21 go/no-go needs live attacker runs, so it slips if U1 is not done by Oct 20.
- **Routine:** `cheatproof-autopilot`, hourly at about :23, state in `~/.cheatproof-autopilot/` (see
  `docs/autopilot/CYCLE.md`). Owner item U8: set its folder to the repo and mode to Bypass. Review fixes queued as T15.
