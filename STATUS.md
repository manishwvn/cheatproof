# Status

**2026-10-18: Cheatproof set up.** Coding & Agentic track; the owner submits 2026-10-28 (deadline 2026-10-30
10:00 PDT). Progress: 82% (21/30 tasks done, 6 days to submit, 2026-10-22 06:30); `python3 docs/autopilot/progress.py`.

- **Built:** the spend cap (`cheatproof/budget.py`, `cheatproof/llm.py`; one $20 total cap; sandbox runs reserved
  under one lock), CI and security workflows, autopilot scripts (`next_run.py`, `progress.py`, `lock.py`) with tests,
  guards, docs, queue T01–T14, ADR 0001 (spend cap) and ADR 0002 (executor: Sandboxes, Docker fallback).
  2026-10-18 routine: executor with Docker backend (`cheatproof/executor.py`, #4), worktree `.env` loader and
  sanitized Token Factory fixtures (#5). Cycle 07:24: attacker loop (`cheatproof/attacker.py`, #6); task loader,
  grader gates and exposure scan (`tasks.py`, `grader.py`, `exposure.py`, hero fixture, #7). Cycle 08:24: hole
  classifier (`cheatproof/holes.py`, #8). 576 tests. Cycle 11:24: patches and the re-attack loop (`patches.py`, `harden.py`, test-edit
  guard in `grader.py`, #9), 812 tests; T15 review fixes open as PR #10 for the planner (U10). Cycle 13:24:
  certificates, hackability score and CLI (`certify.py`, `cli.py`, #11), 1028 tests.
  Cycle 16:24: report site merged after review fixes (T09, #12); attacker prompt now carries the problem statement
  (T20, #13), 1095 tests. First daily audit: fresh clone green; 18 findings queued as T17–T22.
  Cycle 21:24: traces, sanitized attack diffs and kept paid-run reports (T17, #14); honest outcomes: `no_attempt`,
  certified split, grader-forgery cross-checks, hard-code only as a lead (T19, #15). 1210 tests.
  Cycle 22:24: container tmpfs, per-start disk check and owner-scoped leftover sweep (T21, #16); `cheatproof batch`
  with resume, not-run rows, budget and cost-check stops and `batch.json` run counts in report and site (T18, #17).
  1332 tests.
  Cycle 2026-10-19 18:18: first live run on Docker (#21: grader uses the SWE-bench `testbed` env). One task end to
  end (`psf__requests-1142`: gates pass, Super attack inconclusive, $0.0146); batch stopped at 5.9 GB free disk (U14).
- **Handoff 2026-10-23:** read `docs/autopilot/HANDOFF.md` first. T01 is done (#36); T08 batch 3 is queued, then the routine halts the budget (U26). T31 and T32 are new.
- **Next for the routine:** U21 closed: Sandboxes cost is logged, and the budget halts only past `SANDBOX_COST_CAP_USD`
  ($0.50). The planner clears the live ledger `halted` after merge. T23 (#30) and T25 (#31) are done; T01 and T08 are
  unblocked. Token Factory trial cap `TRIAL_CREDIT_CAP_USD` ($0.74 from now) is on. 2026-10-22: first Sandboxes batch
  (5 of 40, PR #34, $0.21) is in `docs/results.md`; T28 (gold-gate error text) is done (#35). T01 (smoke sandbox fix) is in review (PR #36, planner merge). T29 done (#37). T08 batch 2 merged (#38, 8 of 40 so far, first hole: CycloneDX test-edit). Budget halted on the Sandboxes cost cap: U25. T30 queued. T30 done (#39): the exit-4 collection rerun also covers "found no collectors". No runnable task until U25 (T08) or T12 (after 2026-10-27).
- **Certificates:** schema 2 since #15; schema 1 files are refused (none are committed).
- **Planner:** T22 (U11): Docker runs are booked at $0.05 each in `budget.py`, so the $4 daily cap would halt the
  40-task Docker run near task 16; plus `llm.py` timeout, workflow pins and git-ignoring `results/traces/`.
- **Planner:** T16 (U9) attack strategy prompts and the Tavily budget counter; needed before live attacks (T08).
- **Owner blockers:** U25: clear the Sandboxes cost halt and set caps (T08 waits). U24: merge PR #36 (T01). None for T08 (U12 and U3 done). Owner removed all local swebench images 2026-10-21: Sandboxes is
  the default, no task assumes a local image. U7: colima is installed
  and runs (22 GB free on Oct 19). U10: merge
  PR #10 (planner-merge). U1 done
  2026-10-18: promo applied, key in `.env`, caps 20/4.
- **Risk:** the Oct 21 go/no-go needs live attacker runs: T16 (planner) and an executor (U3 or U7) by Oct 20.
- **Routine:** `cheatproof-autopilot`, hourly at about :23, state in `~/.cheatproof-autopilot/` (see
  `docs/autopilot/CYCLE.md`). Owner item U8: set its folder to the repo and mode to Bypass. Review fixes queued as T15.
