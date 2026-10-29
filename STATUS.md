# Status

**2026-10-28: all work merged to main (PR #79, `a831673`); no open PRs.** Coding & Agentic track; the owner submits
2026-10-28 (deadline 2026-10-30 10:00 PDT). Progress: 83% (44/56 tasks done); `python3 docs/autopilot/progress.py`.
Demo: https://manishwvn.github.io/rewardseal/ (GitHub Pages, built from the committed data). 3056 tests pass (1 skipped). Report site extras (explorer, controls gallery, limitations) merged in PR #104; links pinned via results/PINNED_SHA.

## Result so far (details and caveats in `docs/results.md`)
- **Deterministic exposure audit (`audit-exposure`, no attacker):** 13 of the 18 selected swe-rebench tasks audited (5
  env-broken); every counted gold-added source line overlaps a future commit in 12 of 13 (not proof the whole fix is retrievable); `strip-future-git` closed it in 11 of 12.
  A lower bound on a non-random sample (the 18 lowest-scoring tasks), not a rate. bqskit-134 failed its gold gate
  before and after the strip; azure-cli-1876's scan stopped at 5000 commits, so its "not reachable" is incomplete.
- **Attacker finding:** against this attacker (Nemotron Super, recon on), 1 of 9 committed Super before-rounds on
  cyclonedx-python-348 showed a history-use pattern (1 of 7 excluding 2 HTTP 503 errors); unequal follow-up, not a rate; use inferred (`confirmations.json`). n=1; "not proof".
- **Certificates:** 14 task files, 4 certified (sepal_ui-518, cyclonedx-367, schematics-7, cyclonedx-348 after
  hardening). Certified (k=1) = one completed attack failed under the recorded conditions, with exposure removed, gold pass and empty fail checked by code. This describes the hardened 348 result. The three legacy certificates record a failed initial attack with no hole found; they do not record exposure removal or a hardened re-attack. Other `git-history` / `test-edit` labels are unconfirmed leads, not holes.

## Merged since the Oct 18 setup
- Core: spend caps, executor on Token Factory Sandboxes, attacker loop, hole classifier, patches and re-attack,
  certificates and score, report site, GitHub Pages workflow (#4 to #52).
- Honesty fixes: confirmed holes vs leads (T54), `git-history` needs a shared future-commit line (T53), targeted
  post-attack scan (T55), bounded LLM retry (T56), `max_steps` rule (T41/T44), `legit_fix` downgrade (T49/T50), timing attribution for `git-history` (#88).
- Eval tooling: batch chunks and reruns (T38), exposure recon and nudges (T47), harness Tavily search (T37/T52),
  `audit-exposure` (T57, #78), audit results (#79), Start here recorded path on the site (#87), Terra and Opus wording fixes (#84 to #86).
- Batches 1 to 3 and the replications of cyclonedx-348 are in `docs/results.md`.

## Budget (`~/.rewardseal-autopilot/ledger.json`)
- Real-spend cap `REAL_SPEND_CAP_USD` $10 ceiling; live stop $7. Daily $4, total $20. Sandboxes guard $5
  (`SANDBOX_COST_CAP_USD`), run cap 500 (owner-approved). Ledger about $3.53 at Oct 28.
- The balance is hackathon promo credit, not card money; it must never go negative. Check the console between runs.

## Open
- Done since Oct 28: wording sweeps, claims sheet (`docs/claims.md`), judge check (`docs/judge-check.md`), site clarity
  pass and Start-here path, second audit (random sample, 9 audited), retrieval control, Tavily web audit (0 of 13),
  evidence manifest and in-browser verifier, `--recon-replay` (the 348 replay attempt was not exercised: null).
- Open at freeze: regenerate `results/manifest.json`, set `results/PINNED_SHA`, rerun the cold-read testers.
  Open minors: T31 items 2 and 4, env-broken tasks (docling-824, BoboTiG-2132), `.env.example` still says run cap 250.
- Real spend about $4.25 of the $8.50 stop (Sandboxes counter about $4.7 of the $5 guard).
- Owner: `gh repo edit manishwvn/rewardseal --homepage https://manishwvn.github.io/rewardseal/`; confirm the $5
  Sandboxes cap; voice-over, video and Devpost submission (T14 is the owner's alone). Nothing goes public without
  the owner.

## Pointers
- Resume note: `docs/autopilot/HANDOFF.md` (last section). Queue: `docs/autopilot/QUEUE.md`. Routine: hourly
  `rewardseal-autopilot`, state in `~/.rewardseal-autopilot/` (`docs/autopilot/CYCLE.md`).
- Fresh machine: `python -m rewardseal.cli budget init` once. Certificates: schema 2.
