# Status

**2026-10-28: all work merged to main (PR #79, `a831673`); no open PRs.** Coding & Agentic track; the owner submits
2026-10-28 (deadline 2026-10-30 10:00 PDT). Progress: 83% (44/56 tasks done); `python3 docs/autopilot/progress.py`.
Demo: https://manishwvn.github.io/cheatproof/ (GitHub Pages, built from the committed data). 2898 tests pass (1 skipped).

## Result so far (details and caveats in `docs/results.md`)
- **Deterministic exposure audit (`audit-exposure`, no attacker):** 13 of the 18 selected swe-rebench tasks audited (5
  env-broken); the upstream fix is reachable from git history in 12 of 13; `strip-future-git` closed it in 11 of 12.
  A lower bound on a non-random sample (the 18 lowest-scoring tasks), not a rate. bqskit-134 failed its gold gate
  before and after the strip; azure-cli-1876's scan stopped at 5000 commits, so its "not reachable" is incomplete.
- **Attacker finding:** against this attacker (Nemotron Super, recon on), the leak was used in 1 of 10 attack rounds on
  cyclonedx-python-348, with confirmed causality (`confirmations.json`). n=1; "not proof".
- **Certificates:** 14 task files, 4 certified (sepal_ui-518, cyclonedx-367, schematics-7, cyclonedx-348 after
  hardening). Other `git-history` / `test-edit` labels are unconfirmed leads, not holes.

## Merged since the Oct 18 setup
- Core: spend caps, executor on Token Factory Sandboxes, attacker loop, hole classifier, patches and re-attack,
  certificates and score, report site, GitHub Pages workflow (#4 to #52).
- Honesty fixes: confirmed holes vs leads (T54), `git-history` needs a shared future-commit line (T53), targeted
  post-attack scan (T55), bounded LLM retry (T56), `max_steps` rule (T41/T44), `legit_fix` downgrade (T49/T50), timing attribution for `git-history` (#88).
- Eval tooling: batch chunks and reruns (T38), exposure recon and nudges (T47), harness Tavily search (T37/T52),
  `audit-exposure` (T57, #78), audit results (#79), Start here recorded path on the site (#87), Terra and Opus wording fixes (#84 to #86).
- Batches 1 to 3 and the replications of cyclonedx-348 are in `docs/results.md`.

## Budget (`~/.cheatproof-autopilot/ledger.json`)
- Real-spend cap `REAL_SPEND_CAP_USD` $10 ceiling; live stop $7. Daily $4, total $20. Sandboxes guard $5
  (`SANDBOX_COST_CAP_USD`), run cap 500 (owner-approved). Ledger about $3.53 at Oct 28.
- The balance is hackathon promo credit, not card money; it must never go negative. Check the console between runs.

## Open
- Ultra on 4 future-git tasks (348, 367, toil-4805, python-crypto-116), one at a time, inside the caps.
- Headline rewrite from the audit numbers (README, site hero, `docs/results.md`, video beat 1).
- Fresh-clone test (T12), mock judge, video script and rough cut. Open minors: T31 items 2 and 4, env-broken tasks
  (docling-824, BoboTiG-2132), `.env.example` still says run cap 250.
- Owner: `gh repo edit manishwvn/cheatproof --homepage https://manishwvn.github.io/cheatproof/`; confirm the $5
  Sandboxes cap; voice-over, video and Devpost submission (T14 is the owner's alone). Nothing goes public without
  the owner.

## Pointers
- Resume note: `docs/autopilot/HANDOFF.md` (last section). Queue: `docs/autopilot/QUEUE.md`. Routine: hourly
  `cheatproof-autopilot`, state in `~/.cheatproof-autopilot/` (`docs/autopilot/CYCLE.md`).
- Fresh machine: `python -m cheatproof.cli budget init` once. Certificates: schema 2.
