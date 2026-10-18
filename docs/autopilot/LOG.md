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
