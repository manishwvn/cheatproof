# Handoff to the new planner session (2026-10-18)

The previous session did research and setup. **The project is decided: RewardSeal (formerly Cheatproof).** Start here.

## The project
**RewardSeal** (product name; formerly Cheatproof, see U5), in the Coding & Agentic Engineering
track. It is an automatic attack → patch → re-attack loop that hardens AI coding (RL/eval) environments against
reward hacking, and certifies each environment.
- A dishonest Nemotron agent (Nemotron Super as the attacker) tries to pass SWE tasks **without solving them**.
- Each success names a hole. Rule-based patches are applied, then the same attacker re-attacks.
- **Three gates per environment:** the gold patch passes, an empty patch fails, the attacker fails.
- Output: a per-environment certificate, a per-benchmark "hackability" score, and a report page.
- **Sharpest claim (Opus review):** the first closed loop that finds reward hacks in SWE environments, patches them,
  and certifies each patched environment is still solvable by gold and no longer hackable by the same adversary.
- **Minimal scope:** 30 SWE-rebench + 10 SWE-bench Verified tasks. 4 attacks: git-history retrieval, test edits,
  hard-coding, network fetch of the upstream fix. 4 patches: strip `.git` objects, hidden read-only tests,
  network off, a grader check for touched test files. About 15 steps and 50k tokens per attempt; about 4M tokens in
  total (about $1–3); sandbox cost per run unknown (measure on day 1).
- **Top risk:** hardening breaks legitimate solutions, or the attacker is weak. Keep the gates, use Nemotron Super as the
  attacker, report raw counts.
- **Fallback if Sandboxes access is denied or slow:** local Docker for the environments plus Token Factory for every
  model call. This satisfies the rules ("runtime call to the Token Factory inference API").
- Prior art to cite honestly: arXiv "Auditing Reward Hackability in Code RL Training" (Jun 2026: 28.5% on a 49-task
  SWE-bench Verified sample), ImpossibleBench, RHB (ICML 2026), Cursor (Jun 2026), Poolside, Vals.ai MiMo (Oct 2026).

Full research is in `/Users/manish/Documents/Nebius_X_Nvidia/research/` (outside the repo; owner-private):
`ideas/pitch-cheatproof.md`, `ideas/judging/opus-cheatproof-review.md` (read this one),
`ideas/discord-signals.md`, `HACKATHON_BRIEF.md`.

## Constraints
- **Money:** free credits only (the $1 trial, then the $26.65 hackathon promo credit; never card money). In-app caps `SPEND_CAP_USD=20`, `DAILY_CAP_USD=4`, `REAL_SPEND_CAP_USD=10` (total real spend, T43); the balance must never go negative. Every paid
  call goes through `twindiff/budget.py`; rename the package to `cheatproof/`.
- Text Nemotron models only; no vision. Model IDs and prices: VERIFY with `scripts/smoke.py`.
- Claude usage: weekly windows reset Oct 20 6:59 PM CT and Oct 27 6:59 PM CT. Playbook caps: W 80, F 80. Unused
  budget in a window is wasted, so keep the routine busy.

## First tasks for the new session (in order)

**All six done 2026-10-18** (PR `chore/setup-cheatproof`; see STATUS.md and LOG.md). Kept below as history.
1. ~~Rename~~ done 2026-10-18: GitHub repo `manishwvn/cheatproof`, local folder `/Users/manish/Documents/Nebius_X_Nvidia/cheatproof`, state folder `~/.cheatproof-autopilot`, guard allow file updated. Still to do: replace `twin-diff`/`twindiff` names inside files.
2. Rewrite CLAUDE.md, STATUS.md, PLAN.md, docs/prize-fit.md (kept), docs/pitches.md (replace with the RewardSeal
   pitch) and QUEUE.md (new tasks below), plus ADR 0002 (sandbox or Docker execution model).
3. Rename the Python package `twindiff` → `cheatproof`; keep the budget tests green.
4. Apply audit fixes still open from STATUS.md: single-lock sandbox reservation; one cap number everywhere.
5. Create the routine per the playbook (6.10, Appendix C), have an independent agent review it (6.11), then do the
   first-run check.
6. LEARNING.md: rewrite section 0 for RewardSeal.

## Queue outline (sizes)
T01 smoke test, model IDs and prices (S, needs U1) · T02 Sandboxes recon or Docker fallback ADR (M) · T03 task loader:
40 tasks with gold/empty gates (M) · T04 attacker agent with 4 attacks (L) · T05 hole classifier from traces (M) ·
T06 4 patches plus re-attack loop (L) · T07 certificates and hackability score (M) · T08 eval run and
`docs/results.md` with raw counts (M) · T09 report web page and judge replay mode (M) · T10 README, ADRs,
feedback write-up (M) · T11 video script and rough cut (M) · T12 fresh-clone and pre-flip check (S) · T13 learning
pack (M) · T14 submit (S, owner only).
Gates: go/no-go Oct 21 (attacker beats at least 5 of 40 unhardened tasks); freeze Oct 24; submit Oct 28.

## Owner items (unchanged)
U1 Nebius account, card, promo, key, project ID into `.env`. U2 Tavily key (optional). U3 Sandboxes access request.
U4 GitHub $0 budgets and branch protection. U5 final name. U6 voice-over and submission.
