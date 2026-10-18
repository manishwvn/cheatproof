# Status

**2026-10-18: Cheatproof set up.** Coding & Agentic track; the owner submits 2026-10-28 (deadline 2026-10-30
10:00 PDT). Progress: `python3 docs/autopilot/progress.py`.

- **Built:** the spend cap (`cheatproof/budget.py`, `cheatproof/llm.py`; one $20 total cap; sandbox runs reserved
  under one lock), CI and security workflows, autopilot scripts (`next_run.py`, `progress.py`, `lock.py`) with tests,
  guards, docs, queue T01–T14, ADR 0001 (spend cap) and ADR 0002 (executor: Sandboxes, Docker fallback).
  2026-10-18 routine: executor with Docker backend (`cheatproof/executor.py`, #4), worktree `.env` loader and
  sanitized Token Factory fixtures (#5). Cycle 07:24: attacker loop (`cheatproof/attacker.py`, #6); task loader,
  grader gates and exposure scan (`tasks.py`, `grader.py`, `exposure.py`, hero fixture, #7). Cycle 08:24: hole
  classifier (`cheatproof/holes.py`, #8). 576 tests.
- **Next for the routine:** T06 patches and re-attack loop (unblocked), T15 review fixes.
- **Planner:** T16 (U9) attack strategy prompts and the Tavily budget counter; needed before live attacks (T08).
- **Owner blockers:** U3 (Sandboxes access), U7 (no Docker daemon on the Mac, and only 16 GB free disk). U1 done
  2026-10-18: promo applied, key in `.env`, caps 20/4.
- **Risk:** the Oct 21 go/no-go needs live attacker runs: T16 (planner) and an executor (U3 or U7) by Oct 20.
- **Routine:** `cheatproof-autopilot`, hourly at about :23, state in `~/.cheatproof-autopilot/` (see
  `docs/autopilot/CYCLE.md`). Owner item U8: set its folder to the repo and mode to Bypass. Review fixes queued as T15.
