# Status

**2026-10-18: Cheatproof set up.** Coding & Agentic track; the owner submits 2026-10-28 (deadline 2026-10-30
10:00 PDT). Progress: `python3 docs/autopilot/progress.py`.

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
- **Next for the routine:** 2026-10-20 19:24 cycle: T08 reran `sphinx-doc__sphinx-8595` (inconclusive at the token
  limit, $0.034, n = 1, kept uncommitted in `../cheatproof-wt/t08-eval/results/`), then a pull grew colima's data disk
  on the Mac and host free disk fell to 2 GB (later 0.8 GB); the run was killed (U17, alerted). T08 waits on U17,
  U18 (PR #25 leakcheck skips public `.env.example` values) and U20 (PR #27, T26 audit fixes). PR #26 (U19) bumps
  certifi for a new pip-audit advisory that turns the `security` check red on every branch. T11 opens 2026-10-21.
- **Certificates:** schema 2 since #15; schema 1 files are refused (none are committed).
- **Planner:** T22 (U11): Docker runs are booked at $0.05 each in `budget.py`, so the $4 daily cap would halt the
  40-task Docker run near task 16; plus `llm.py` timeout, workflow pins and git-ignoring `results/traces/`.
- **Planner:** T16 (U9) attack strategy prompts and the Tavily budget counter; needed before live attacks (T08).
- **Owner blockers:** U12 (Docker image cap blocks T08; by Oct 20), U3 (Sandboxes access). U7: colima is installed
  and runs (22 GB free on Oct 19). U10: merge
  PR #10 (planner-merge). U1 done
  2026-10-18: promo applied, key in `.env`, caps 20/4.
- **Risk:** the Oct 21 go/no-go needs live attacker runs: T16 (planner) and an executor (U3 or U7) by Oct 20.
- **Routine:** `cheatproof-autopilot`, hourly at about :23, state in `~/.cheatproof-autopilot/` (see
  `docs/autopilot/CYCLE.md`). Owner item U8: set its folder to the repo and mode to Bypass. Review fixes queued as T15.
