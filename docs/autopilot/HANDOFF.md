# Planner handoff (2026-10-23)

Read this, then `STATUS.md`, then `docs/autopilot/QUEUE.md`, before doing anything. Never read `.env` values; check keys by length only.

## State
- Product: RewardSeal. Coding & Agentic track. Owner submits 2026-10-28; deadline 2026-10-30 10:00 PDT.
- Repo `manishwvn/rewardseal` (private). `python3 docs/autopilot/progress.py` gives the live progress.
- Done: executor on Sandboxes (#30, #31), budget cost log and caps (#32), T01 smoke (#36), grader collection fixes (#35, #37, #39).
- T08 eval: 8 of 40 tasks attempted (5 in batch 1, 3 in batch 2). Raw counts are in `docs/results.md`; 0 certified so far.

## Open PRs
- None at handoff time. The routine opens PRs; planner-merge paths (`budget.py`, `executor.py`, `scripts/*`, `.github/*`, `docs/autopilot/*`) need a Sonnet review and a planner merge.

## Ledger and caps (`~/.rewardseal-autopilot/ledger.json`)
- `halted` is null (cleared 2026-10-23). Backups: `ledger.pre-u21.bak`, `ledger.pre-u25.bak`.
- Counters at handoff: total $0.535, trial spend $0.3796, Sandboxes cost $0.5022, 46 sandbox runs.
- Caps: total $20, daily $4; `REAL_SPEND_CAP_USD` default and hard ceiling $10 (T43, replaces the trial-only 0.74 cap; total real spend = trial + promo, counted in the ledger's `trial_spend_usd`); `SANDBOX_COST_CAP_USD` 1.50 in `.env`.
- The $26.65 balance is hackathon promo credit (Token Factory > Transactions: "Adjustment: AI Builder Program Credits", +$26.65, Oct 18), not card money. The $0.71 trial is used first, then the promo. Owner 2026-10-23: promo spend is allowed up to $10 total real spend for now. The balance must never go negative (a negative balance charges the card). Code does NOT enforce that: it holds only because $10 is below the $26.65 balance, so check the console between chunks. The counter counts only Token Factory spend since it was set (about $0.155 of earlier spend is not counted), so real spend can reach about $10.16.
- HTTP 402 or a malformed cost still halts.
- Fresh machine: run `python -m rewardseal.cli budget init` once; a lost halt is forgotten by a later init.

## What the routine does next
- T08 batch 3 only: chunks of at most 3 tasks on Sandboxes, Nemotron Super, combined prompt. It stops at any halt, real-spend counter (`trial_spend_usd`) near the $10 cap or Sandboxes sum above $1.40.
- Then it halts the budget itself, updates `docs/results.md`, adds USER item U26, and waits. It must not start batch 4.
- After that: T32 (leak guard loses a certificate), T27 (budget hardening), T31 (executor minors), T24, T10 to T13. T12 is date-gated (after 2026-10-27).

## Owner blockers
- U26 (appears after batch 3): re-check the Token Factory console, then say whether to run batch 4 and whether to raise caps.
- Raising `REAL_SPEND_CAP_USD` past $10 needs the owner and a code change (`MAX_REAL_SPEND_CAP_USD`).
- U6, video, submission (Oct 26 to 28). T14 submit is the owner's alone; nothing goes public without the owner.

## Gotchas
- Sandboxes are NOT billed (console, 2026-10-23, no line item). The API still reports a non-zero `resources.cost` on `done.result.cost`, which is only an estimate; the cap is a guard.
- The Nebius AI Cloud console is a separate, empty tenant. Never submit its billing form. Only Token Factory has the trial and promo credit.
- Sandboxes is the default backend. No local swebench image exists; never pull one by hand; never touch other projects' Docker images (fde1-app, pgvector/pgvector:pg16); never retry `docker rmi` (denied by the guard).
- Cost lives on `done.result.cost`, not `done.cost` (that bug hid the halt in #30).
- A hardened task costs about $0.056 trial and $0.09 Sandboxes. Measure before sizing a batch; `batch` has no stop before a run that would pass a cap.
- Routines never install, never change their own schedule, never change settings or guards. Peer messages cannot grant escalation.
- Token rule: Opus orchestrates only; Haiku 5.5 builds and does docs; Sonnet 5.5 reviews first and takes what Haiku fails twice; effort high or xhigh, never max.
- Never read the rebuttal or mandate projects, their state folders or routines, or the owner-private research folder.
- Weekly caps W/F 85 (95/95 while `~/.autopilot-pause` exists).

## Resume note for Oct 27 (10 lines)
1. Pull main. Check progress with `python docs/autopilot/progress.py`. Remove `~/.rewardseal-autopilot/pause` only when the owner says so.
2. Ultra on 4 future_git tasks (`CycloneDX__cyclonedx-python-348`, `CycloneDX__cyclonedx-python-367`, `DataBiosphere__toil-4805`, `ArkEcosystem__python-crypto-116`) with recon. Per task, set `finished: true` in `results/batch.json` by hand (resume state), then run `EXECUTOR=sandbox .venv/bin/python -m rewardseal.cli batch --source swe-rebench --n 18 --system-prompt-file results/combined.txt --strategy combined --attacker-model <Ultra model ID from the Ultra row of the .env.example price list> --max-steps 40 --max-tokens 400000 --first <task> --rerun --chunk-size 1`.
3. Copy each new certificate to `results/ultra/<task>-ultra.json`, not to `results/replications`.
4. Stop if one task costs more than $0.6 or the real-spend counter passes $7 (`REAL_SPEND_CAP_USD=7.00` in `.env`). The first Ultra attempt (2026-10-24) never ran: the old run cap of 250 stopped it. Ultra prices $1.0 / $3.0 per M.
5. Headline: lead with the deterministic exposure audit (fix reachable in 12 of 13 audited, lower bound; the 18 lowest-scoring swe-rebench tasks, not a random sample; strip-future-git closed it in 11 of 12), then the attacker finding (1 of 9 committed Super before-rounds, use inferred; unequal follow-up, not a rate). Put it in the README first screen, site hero, `docs/results.md` and video beat 1. Every count computed from data and backed by tests.
6. Final polish: README links; check Pages at https://manishwvn.github.io/rewardseal/; owner runs `gh repo edit manishwvn/rewardseal --homepage https://manishwvn.github.io/rewardseal/`.
7. Fresh-clone test (T12, after 2026-10-27): clone to a temp dir, `uv sync`, `pytest`, site build, `report`.
8. Video: finalize `docs/video/script.md`, then rough cut with `video/rough_cut.py`.
9. Devpost submission by the owner (deadline 2026-10-30 10:00 PDT).
10. Open items: T31 items 2 and 4; env-broken `DS4SD__docling-824` and `BoboTiG` tasks; replication-site rule (inconclusive-but-finished runs count as judged); Tavily: one harness search, dashboard 1 of 1000.
