# Autopilot log

## 2026-10-16 (interactive)
- Setup: repo skeleton, docs, queue, guards, CI, spend cap moved from the earlier scaffold (11 tests pass).
- Routine not created (usage pause until 2026-10-20).
- Independent review (Haiku, high): fixed spend-cap gaps (sandbox runs priced into the cap, stream/n>1 rejected,
  tool schemas counted, worst case kept on 5xx/timeouts) and added owner-only merge paths in CYCLE.md. Deferred:
  atomic lock (mkdir/flock) and ledger drift logging, to revisit before the routine is created.
- Commits use the GitHub noreply email. Private repo created; CI green after replacing gitleaks-action (root-commit
  bug) with the pinned gitleaks 8.18.4 CLI.

## 2026-10-18 (interactive planner)
- Project decided: Cheatproof. Renamed the package `twindiff` → `cheatproof` and every leftover `twin-diff` name.
- Rewrote CLAUDE.md, STATUS.md, PLAN.md, docs/pitches.md and QUEUE.md (T01–T14, U1–U7); added ADR 0002 (Sandboxes
  primary, local Docker fallback behind one executor interface).
- Audit fixes: `reserve_sandbox_run` now checks the halt flag, run cap and money caps and books under one lock (a
  40-thread test fails on the old code); one total cap number, $20, in code and docs.
- Added `docs/autopilot/lock.py` (atomic acquire, heartbeat, owner-only release), the deferred lock item from
  2026-10-16.
- Machine facts: arm64 Mac, Docker daemon stopped, 16 GB free disk, so the Docker fallback covers a subset until U7.
- Lesson: routine sessions take the working folder and model of the session that created them; create from the repo.
- Routine `cheatproof-autopilot` created (cron `22 * * * *`, dispatch about :23, notifications off). Skip test
  passed at 06:24Z (gate exit 3, "skip: not due"). The run started in the parent folder in auto mode on Opus, because
  the task was created from a turn another session started: owner item U8.
- Independent routine review: verdict fix first, no critical. Prompt fixes applied the same hour (lock before pull,
  absolute release command, LOST handling, alert body from a file); connector guard now fails closed. Repo-side
  findings queued as T15; full list in `~/.cheatproof-autopilot/review-2026-10-18.md`.

## 2026-10-18 routine (cycle 2026-10-18T05:42:00-05:00)
progress 8% (1/15 tasks done, 10 days to submit)
- Executor interface and Docker backend merged (T02, #4); worktree `.env` loader and sanitized fixtures merged (#5).
- T01 now waits only on the sandbox run (U3). T03 and T04 are unblocked.
- Owner: the Mac has no Docker daemon (no Docker Desktop app); U7 updated and alerted.
- Spend: one Nano call, ledger total $0.0000168 to $0.0000336; no sandbox runs.

- Task T02 (#4): Haiku build, Sonnet review "fix first" (3 high: image name parsed as a docker flag, unbounded host
  output buffering, `diff()` evadable through the sandbox's index and replace refs), one Haiku fix round, Opus final
  review added cache-dir excludes to `diff()`. 102 tests. Live Docker test not run (no daemon).
- Task T01 remainder (#5): Haiku build plus live Nano recording, Sonnet review "fix first" (medium: sanitize gaps,
  `BudgetExceeded` swallowed in the sandbox step), one Haiku fix round, Opus final review: merge.
- Lessons: repo agents in `.claude/agents/` do not load when the run starts in the parent folder (U8); run them as
  general-purpose agents told to follow the agent file. CLAUDE.md rule 10 ("never effort max") conflicts with
  CYCLE.md (max allowed for Haiku on hard size L pieces); the routine prompt follows CYCLE.md, planner to reconcile.
- Learning notes caught up for #2 to #5.
- Refused tool: `mcp__ccd_turn__wrap_up` (connector not on the routine allowlist); not retried.

## 2026-10-18 routine (cycle 2026-10-18T07:24:18-05:00)
progress 30% (3/16 tasks done, 10 days to submit)
- T04 attacker loop merged (#6); T03 task loader, grader gates and exposure scan merged (#7). 409 tests.
- T16 added (planner): strategy prompt text and the Tavily budget counter; U9 asks the planner for it.
- Spend: $0 (no model, sandbox or Tavily calls). Datasets-server fetches are free and keyless.

- Task T04 (#6): Sonnet core build. Sonnet review "fix first" (2 high: a failed `diff()` looked like an empty
  submit; timeout resets were silent), one Haiku fix round (diff_ok, reset note, max_searches, 402 raises
  BudgetExceeded, type-only tool errors, AST denylist, real GuardedLLM test). Opus final review: merge.
- The strategies/websearch builder's run was cut off by a safety classifier mid-brief; its output was set aside
  (trashed, never committed) and the loop now takes caller-supplied prompts. Prompt text goes to the planner (T16).
- Task T03 (#7): two Haiku builders. Sonnet review "fix first" (2 high: hidden tests restored only on apply
  failure; `git checkout` runs filter drivers), two parallel Haiku fixers. Opus final review: merge; object-store
  tampering noted for T06.
- Lessons: sanitizer guard redacts 40-hex SHAs in fixtures, so tests synthesise SHAs at runtime. `git apply` runs
  repo filter drivers too; apply with GIT_DIR pointing nowhere.
