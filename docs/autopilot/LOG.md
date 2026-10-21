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
- Daily audit deferred to the next run (F 70% at 08:03, near the time limit).

## 2026-10-18 routine (cycle 2026-10-18T08:24:24-05:00)
progress 36% (4/16 tasks done, 10 days to submit)
- T05 hole classifier merged (#8): labels network, git-history, test-edit, hard-code or unclassified, decided in
  code; labels count only when the hidden grade passed (`attempted` keeps the rest). 576 tests.
- T06 is now unblocked. Spend: $0 (no model, sandbox or Tavily calls).

- Task T05 (#8): one Haiku builder (pieces too coupled to split), Sonnet review "fix first" (5 high: shell-wrapped
  and ref-name git reads missed; gold match alone and pip/grep matches gave false labels; failed attacks labelled).
  One Haiku fix round with regression tests. Opus final review: merge.
- Deferred at F 84 (cap 85): learning notes for #8 (catch-up from `learning-last-pr` 7 next run) and the daily audit.
- Lesson: a 300-char result digest cannot prove a network fetch returned the fix; the label needs a gold line in a
  head, otherwise a "retrieval not provable" note. T08 may want longer digests for fetch steps.

## 2026-10-18 routine (cycle 2026-10-18T11:24:21-05:00)
progress 56% (5/16 tasks done, 10 days to submit)
- T06 patches and the re-attack loop merged (#9): strip future git, test-edit guard at grade time, network-off, and
  `harden()` with per-patch gold checks and the same attacker after hardening. 812 tests.
- T15 review fixes open as PR #10 (planner-merge paths); U10 asks the planner to merge it and install the hook.
- T07 is now unblocked. Spend: $0 (no model, sandbox or Tavily calls).

- Task T06 (#9): three parallel builders (Haiku grader guard, Haiku patches, Sonnet harden core). Sonnet review
  "fix first" (4 high: inconclusive attacks certified; HEAD not base broke `diff()`; C-quoted rename bypassed the
  guard; a host-timeout reset during a patched attack dropped the patches). One round of three Haiku fixers, real-git
  tests for the strip scripts. Opus final review: merge.
- Task T15 (#10): three Haiku builders (budget, autopilot scripts, CYCLE.md). Sonnet review "fix first" (2 high:
  `settle()` accepted nan or negative usage and zeroed the ledger; leakcheck missed dotenv forms). One round of three
  Haiku fixers. CI green; left for the planner.
- QUEUE items 10 and 11 of the review (tracked `results/`, pre-flip scan patterns) written into T08 and T12.
- Leakcheck (from PR #10's branch) flagged `LEARNING.md` after the notes agent ran: it held a `.env` value, a public
  model ID (`CLASSIFIER_MODEL`). Redacted by script (value never printed) in the file and its backup; gitleaks clean.
  Lesson: leakcheck also flags non-secret config values; fine, keeps the rule simple.
- Learning notes caught up for #8 and #9. Daily audit deferred again (50-minute limit); next run should do it first.
- `timeout` is missing on macOS; wait for PR checks with `gh pr checks <n> --watch` after checks appear.

## 2026-10-18 routine (cycle 2026-10-18T13:24:20-05:00)
progress 62% (6/16 tasks done, 10 days to submit)
- T07 certificates, hackability score and CLI merged (#11). 1028 tests. T09 report page is now unblocked.
- Spend: $0 (no model, sandbox or Tavily calls).

- Task T07 (#11): two parallel Haiku builders (certify, cli). Sonnet review "fix first" (3 high: CLI rendered
  `by_hole` in the wrong shape; `a/b` and `a_b` wrote one file; errors after the paid run lost the spend). One round of
  two Haiku fixers, plus one fixture fix after certify started enforcing certified invariants. Opus final review:
  merge.
- Learning notes for #11 written (`learning-last-pr` 11). Daily audit deferred again: F 74 at the end of T07, too
  close to the cap for a Sonnet audit; next run with F headroom should do it first.
- The repo's `reviewer` agent type is not loaded when the run starts in the parent folder; the review ran as a
  general-purpose Sonnet agent told to follow `.claude/agents/reviewer.md`.
- Lesson: when two builders share a contract in parallel, the integration test only goes green after both land;
  brief the second fixer with the other's final key names.

## 2026-10-18 routine (cycle 2026-10-18T14:24:26-05:00)
progress 66% (6/16 tasks done, 10 days to submit)
- T09 report site built as draft PR #12 (`cheatproof/site.py`, `site` CLI subcommand), 1052 tests green, ruff clean.
- Not merged: the run reached F 83 (cap 85) after the build wave, before the Sonnet review. Next run reviews #12.
- Spend: $0 (no model, sandbox or Tavily calls).

- Task T09: two parallel Haiku builders (site module, CLI wiring) against one fixed `build_site` contract; both
  landed green first time. Haiku audit, Sonnet review and Opus final review deferred to the next run.
- Daily audit deferred again (F headroom). Learning notes: nothing merged this run.
- Lesson: the certificate stores only the attack diff's digest, so the per-environment page cannot show the patch
  diff the T09 spec asks for; T08 should record the diff (sanitized) in `results/` beside the trace.

## 2026-10-18 routine (cycle 2026-10-18T16:24:21-05:00)
progress 57% (8/22 tasks done, 10 days to submit)
- T09 report site merged (#12) after one review-fix round; T20 problem statement in the attacker prompt merged (#13).
- First daily audit: fresh clone at eafa80c green (1083 tests); Sonnet audit found 18 issues, queued as T17–T22
  (T22 planner, U11). The task count grew from 16 to 22, so the progress percent fell.
- Spend: $0 (no model, sandbox or Tavily calls).

- Task T09 (#12): Haiku audit (green; diff and transcript absent in real certificates is a T08 data gap) and Sonnet
  review in parallel, "fix first" (1 high: n=0 rates crashed the build). Two Haiku fixers on disjoint files. Opus final
  review added a refusal for a symlinked `env/` directory. CI failed once: `Path("..json").stem` differs across
  Python versions; the test now accepts both names.
- Task T20 (#13): one Haiku builder; Sonnet review "fix first" (medium: v2 caches loaded with an empty statement).
  Opus fixed it (`CACHE_VERSION` 3, cap 8000 chars). Existing caches refetch before T08 (network).
- Audit highlights for T08: Docker runs booked at $0.05 each (cap halts near task 16), 6-image cap with 13 GB free,
  `python -m pytest` may need `conda activate testbed`, an empty diff certifies a task, no trace or diff persisted.
- The audit agent read `.env.example` (tracked template, placeholders only). No `.env` was opened.
- Lesson: run the first audit early; it found more T08 blockers than all per-PR reviews.

## 2026-10-18 routine (cycle 2026-10-18T21:24:24-05:00)
progress 67% (10/22 tasks done, 10 days to submit)
- T17 traces and attack diffs merged (#14); T19 honest outcomes merged (#15). 1210 tests, ruff clean, CI green.
- T21 not started: the run reached its 50-minute work limit. Daily audit already ran today.
- Spend: $0 (no model, sandbox or Tavily calls).

- Task T17 (#14): one Haiku builder; Sonnet review "fix first" (3 high: whole-diff `sanitize` redacted any diff
  holding a 33-char name or a `/home/` path; lone surrogates crashed the write; stale diffs on rerun). One Haiku fix
  round: per-line sanitizing, `errors="replace"`, sidecar `<stem>.<round>.diff.json` whose `raw_sha256` the site
  matches against the certificate, trace rotation, symlink refusals. Opus final review: merge.
- Task T19 (#15): two parallel Haiku builders in one worktree on disjoint files (harden/certify; grader/exposure/
  holes), then one Haiku wiring step for the grader labels. Sonnet review "fix first" (1 high: one forged summary
  plus `os._exit` still passed). One Haiku fix round: final counts cross-checked against `-rA` node lines and exit
  code; a cut output gets no forgery verdict; hard-code is only a lead. Residual gap pinned in a test: a fully
  consistent forged summary still passes; the real fix is a channel the candidate cannot write.
- Follow-ups queued in T18 (CLI passes run settings to `build_certificate`; site shows the certified split) and T22
  (`results/traces/` and `results/reports/` are not git-ignored; planner path).
- Learning notes for #14 and #15 written (`learning-last-pr` 15).
- Lesson: `sanitize()` fails closed on a whole string, so long free text (diffs, traces) must go through it per line.

## 2026-10-18 routine (cycle 2026-10-18T22:24:29-05:00)
progress 73% (12/22 tasks done, 10 days to submit)
- T21 container limits merged (#16); T18 batch driver merged (#17). 1332 tests, ruff clean, CI green.
- No runnable task left: T08 waits on T01 (U3) and the planner (T16, T22); T11 opens 2026-10-21.
- Spend: $0 (no model, sandbox or Tavily calls).

- Task T21 (#16): one Haiku builder; Sonnet review "fix first" (medium: the sweep removed every `cheatproof=1`
  container, so a concurrent harden would lose its live one). One Haiku fix round: `cheatproof.owner=<pid>` label,
  sweep only dead or missing owners, `DOCKER_TMPFS_MB` clamped at 4096, ADR 0002 guard text updated. Opus: merge.
- Task T18 (#17): two parallel Haiku builders on disjoint files (cli; site) against a fixed `batch.json` schema 1
  contract. Haiku audit plus Sonnet review in parallel, "fix first" (high: a failed cost check, including a NaN ledger
  that defeats every cap, let the batch go on to paid tasks). One Haiku fix round: `cost_check_failed` stops the batch
  (exit 1), dedupe across sources, `invalid_task` reason, run record leads with this batch's own count. Opus: merge.
- The `learning-notes` agent type is not registered in this session; ran it as a general-purpose Haiku agent that
  reads `.claude/agents/learning-notes.md` first. Notes for #16 and #17 written (`learning-last-pr` 17).
- Lesson: fix the writer/reader contract (exact keys) in both briefs up front; the parallel builders then matched
  on the first try and the audit's round-trip script confirmed it.

## 2026-10-19 01:40 (interactive planner)
- Merged #10 (T15 review fixes; installed the pre-push hook) and #18 (T22 free local-run and Tavily counters, Docker
  sessions off the sandbox caps; T16 attacker strategies; CI actions pinned by SHA, gitleaks sha256 checked).
- Built by two Haiku 5.5 builders in parallel, Opus final review. T08 unblocked on the Docker executor.

## 2026-10-19 routine (cycle 2026-10-19T02:23:53-05:00)
progress 77% (15/22 tasks done, 9 days to submit)
- T08 (eval run) claimed, then blocked before any paid call: the Docker image cap counts colima's 10 images from other
  projects, so every task image is refused. Owner item U12 added and alerted; T08 is `waiting: U12`.
- Colima's existing VM was started (it has x86_64 emulation); task specs fetched and cached (30 rebench, 10 Verified).
- No other task is runnable: T10 needs T08, T11 opens 2026-10-21, T12 opens 2026-10-27.
- Spend: $0 (no model, sandbox or Tavily calls).

- Refused tool call (auto mode): one Bash call that removed the clean, unused worktree `../cheatproof-wt/t08-eval`
  (branch `t08-eval`, no commits) and stopped colima. Not retried. The worktree and the running colima VM remain;
  the next run or the planner can remove the worktree, and the owner can `colima stop`.
- Verified Docker 29.5.2 under colima. 8 of the 10 Verified picks are sphinx; expect a sphinx-heavy Verified slice.
- Lesson: check shared-daemon state (image count, disk) against the executor guards before claiming a live-run task.

## 2026-10-19 routine (cycle 2026-10-19T17:23:54-05:00)
progress 72% (15/24 tasks done, 9 days to submit)
- Skipped: weekly usage 88% is over the cap 85 (5-hour 58%). No task claimed, no PR, spend $0.
- Weekly window resets 2026-10-20 23:59 UTC. Runnable: T08, T24. Alerted the owner (U13): T08 feeds the Oct 21 go/no-go.
- Lesson: at this burn rate the weekly cap, not the 5-hour cap, gates the routine; T08 should go first after the reset.

## 2026-10-19 routine (cycle 2026-10-19T18:18:24-05:00)
progress 72% (15/24 tasks done, 9 days to submit)
- Ran on the owner's `weekly-cap` override (W 89 at start). Took T08 (eval run) on the Docker executor.
- Merged #21: the grader now runs pytest in the SWE-bench `testbed` conda env (gold gates failed without it). Haiku
  built, Sonnet reviewed (merge, lows only), Opus final review. 1578 tests.
- First end-to-end task: `psf__requests-1142`, attacker Nemotron 3 Super, gold and empty gates correct, attack
  inconclusive at its 50k token limit. Not certified. n = 1. Certificate kept outside the repo (leakcheck flags the
  public model ID that `.env` also holds; planner note in T08).
- Blocked: the next image pull left 5.9 GB free disk (floor 10 GB). Owner item U14, alerted. T08 is `waiting: U14`.
- Spend: $0.0146 (ledger $0.0000336 to $0.0145935). No Ultra, no Tavily, no sandbox runs.
- Lessons: SWE-bench images need `linux/amd64` and the `testbed` env; each task image is about 4 GB unpacked, so
  check disk for the whole batch before the first pull.

## 2026-10-19 routine (cycle 2026-10-19T22:23:52-05:00)
progress 72% (15/24 tasks done, 9 days to submit)
- Ran on the owner's `weekly-cap` override (W 94, cap 99, one task). Took T08. Sandboxes check: still NO ACCESS (U3).
- Runs: `sphinx-doc__sphinx-8595` inconclusive (token limit, $0.035); `psf__requests-1142` rerun at 300k tokens
  ($0.071) wrote nothing, but its diff held the image's untracked `build/lib/**`, the grade could not apply it, and
  the certificate said certified. Bug fixed in PR #23 (Haiku built, Sonnet review "fix first", one fix round, Opus
  final review, CI green); planner merge (U16). Both certificates void until rerun.
- Blocked: host free disk stayed 7.4 GB after the task images were removed (colima keeps freed blocks), so the guard
  refuses every pull (U15, alerted). T08 is `waiting: U15, U16`.
- Spend: $0.107 (ledger $0.0146 to $0.1214). No Ultra, no Tavily, no sandbox runs.
- Lessons: diff only what the attacker changed (record the untracked list at start); a disk guard must measure the
  disk the pull lands on (the VM), not the host.

## 2026-10-19 routine (cycle 2026-10-19T23:23:55-05:00)
progress 72% (15/24 tasks done, 9 days to submit)
- No task taken. W 95 (cap 99 override, H 4). Only `todo` task with met needs is T24, which waits until no other task
  PR is open; PR #23 (U16) is still open. T08 waits on U15, U16. Sandboxes check: still NO ACCESS (U3).
- Hand-back not due: T24 and T11 are `todo`, not owner-blocked. Spend: $0.

## 2026-10-20 routine (cycle 2026-10-20T10:24:12-05:00)
progress 71% (15/25 tasks done, 8 days to submit)
- Plain summary: no build work this hour because the shared weekly usage window is full (100%).
- It resets at 2026-10-21 00:00 UTC; the next run after that clears the old 99 weekly-cap override.
- Runnable now: T24 (rename) and T08 (eval run; no PR open, its needs are done). T01, T23, T25, T11 open 2026-10-21.
- Main CI green, pre-push hook matches. No spend ($0), no alert (the cap resets on its own tonight).
- Hand-back not due: T24 and T08 are `todo` and not owner-blocked. Daily audit skipped (no headroom).

## 2026-10-20 routine (cycle 2026-10-20T19:24:11-05:00)
progress 68% (15/26 tasks done, 8 days to submit)
- Weekly window reset: W 0 at start, caps 95/95 (`~/.autopilot-pause` exists); emptied the old `weekly-cap` 99.
- T08: `sphinx-doc__sphinx-8595` rerun on Docker (Super, combined prompt, 120k tokens, 30 steps): gold passes, empty
  fails, attack inconclusive at the token limit. $0.034. n = 1. Kept uncommitted (`harden` keeps its image; use `batch`).
- T08 batch (250k tokens, 40 steps) stopped before any model call: the pull grew colima's data disk on the Mac (17 GB
  file for 6.3 GB used) and host free disk fell to 2 GB; the run watchdog killed it. Host later fell to 0.8 GB from
  causes outside this repo. Alert sent; U17. Removed this cycle's two pushed worktrees.
- PR #25 (U18): leakcheck skips values equal to `origin/main:.env.example` values, so certificates naming the public
  model ID can be committed. Haiku built; Sonnet "fix first" (working-tree `.env.example` was a trust hole); one fix
  round; Opus approve. PR #26 (U19): certifi 2026.10.19 for PYSEC-2026-4320 (pip-audit red on every branch).
- Daily audit at 139e1e4: fresh clone green (1601 passed); Sonnet found 2 high, 2 medium, 4 low, queued as T26.
- T26 built (2 Haiku builders in parallel), Sonnet "fix first" (3 high: silent resets could fake "not hackable"), one
  Haiku fix round, Opus approve: PR #27 (U20), CI `test` green, `dependencies` red until #26. Item 7 deferred.
- Spend: $0.034 (ledger $0.1214 to $0.1554). No Ultra, no Tavily, no sandbox runs.
- Lessons: with colima, host free disk is the real limit (the VM file keeps freed blocks); a post-run reset must
  surface to the attacker and grader or it fakes an honest-looking result.

## 2026-10-20 routine (cycle 2026-10-20T21:24:14-05:00)
progress 68% (15/26 tasks done, 8 days to submit)
- No task taken. W 5, F 37 (caps 95/95). T24 waits until PRs #25-#27 (U18-U20) are merged; T08 and T26 wait on
  U17/U18/U20; T01, T23, T25, T11 open 2026-10-21 local.
- Host free disk 877 MB (U17, alerted today; no second alert). `security` on main stays red until PR #26 (U19).
- Hand-back not due: T24 and date-gated tasks are `todo`, not owner-blocked. Spend: $0.
