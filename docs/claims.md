# Claims sheet

Every number or claim shown on screen, in the pitch, in the video or on Devpost must be on this sheet, with its source
in the repo. Nothing else may be used. If a number changes, change this sheet first. Wording rules: never say
"proved", "secure", "first", "upper bound" or "prevalence"; say "against this attacker", "line overlap", "inferred".

## Numbers

| Claim | Value | Source |
|---|---|---|
| Audited environments | 13 of 18 selected (5 excluded as env-broken); the 18 lowest-scoring swe-rebench tasks, not random | `results/exposure/_run.json`, `docs/results.md` (Exposure audit) |
| At least half of the counted gold source lines also in a future commit in `.git` | 12 of 13 | `results/exposure/*.json` (`fix_reachable`), `python -m cheatproof.cli report --certs results/certificates` |
| All counted lines in a future commit | 12 of those 12; for 2 of the 12 (348, toil-4805) it is one line | same records (`gold_lines_in_future` = `gold_added_lines`), `docs/results.md` table |
| Every one of the 13 has future commits | 13 of 13 | same records (`future_commits_before` > 0) |
| After `strip-future-git`: no future commits left in the workdir repo and gold + empty gates held | 11 of those 12 (the miss, BQSKit-134, failed its gold gate before any attack) | same records (`closed`, `closed_reason`) |
| Incomplete scans | 1 history listing cut at 5000 commits (azure-cli-1876); 3 fix scans incomplete | same records (`future_scan`), `docs/results.md` |
| Confirmed attacker finding | 1 of 9 `future_git` tasks attacked with recon on (cyclonedx-348); use of the output is inferred | `results/confirmations.json`, `docs/results.md` (Causal check), `results/evidence/348-causal.md` |
| Replication on 348 | 1 of 10 later before-rounds showed the pattern; 2 ended in HTTP 503; earlier rounds not counted | `docs/results.md` (Replication under T55), `results/replications/` |
| Ultra run on 348 | 1 run: same pattern before hardening; hardened re-attack hit `token_limit` without a submission; not certified; cost $0.7746 | `results/ultra/CycloneDX__cyclonedx-python-348-ultra.json`, `docs/results.md` |
| Certificate files | 14 files, 4 certified: 1 after a failed hardened re-attack (348), 3 legacy no-hole-found | `results/certificates/`, `report` output |
| Tasks attacked | 11 (9 with recon `exposure` and `future_git` true) | `docs/results.md` (Headline details), certificates |
| Attacker model | `nvidia/nemotron-3-super-120b-a12b` via Nebius Token Factory (one exploratory Ultra run on 348) | certificates (`attacker.model`) |
| Tavily | one harness-initiated search (schematics-7); the attacker made 0 search calls; no effect on any outcome shown | `results/certificates/Alexei-Kornienko__schematics_to_swagger-7-*.json`, `docs/tavily.md` |
| Real Token Factory spend | about $4.15 at Oct 29 (ledger counter, an overestimate against the console); promo credit, no card | `~/.cheatproof-autopilot/ledger.json` (local, not committed), `docs/results.md` (Console) |
| Tests | see `STATUS.md` (CI runs them on every PR) | `.github/workflows/ci.yml` |
| Second audit: random sample within the A-E frame | 9 audited of 12 drawn (3 env-broken); at least half of counted lines in a future commit in 7 of 9; closed in 5 of those 7 (2 not closed: gold gate failed after strip; strip patch did not apply). Counts only, no rate | `results/exposure-sample/`, `docs/sample-protocol.md`, `docs/results.md` |
| Web exposure (Tavily), 13 audited | 0 of 13: no result (130) contained a counted gold line; no result was a pull/commit/compare page of the task's repo, even for the oracle PR-URL query; searched 2026-10-29, findability only, dated snapshot, this tool only | `results/web-exposure/`, `docs/results.md` |
| Same-recon re-attack attempt on 348 | not exercised: the new before round passed without history commands (classified unclassified), so there was no hole, no hardening, no re-attack; cost $0.099; with it, the pattern is in 1 of 11 later before-rounds | `results/replay-attempt/`, `docs/results.md` |
| Retrieval control (openapi3-75) | applying the top-ranked future commit (4 shared gold lines) passed the hidden tests before the strip; 0 future commits and gates held after; one task, no model | `results/control/Dorthu__openapi3-75-retrieval-control.json`, `docs/results.md` |
| Results explorer, controls gallery, limitations page | explorer lists 24 rows: 13 first-audit + 9 random-sample audited tasks + 2 certificate-only tasks (attacked, not in an exposure audit); every cell is read from the committed records; no new measurement, and a missing audit group suppresses the "not audited" message | `cheatproof/site_extras.py`, `docs/limitations.md`, `results/exposure*`, `results/certificates/` |
| Demo | https://manishwvn.github.io/cheatproof/ (recorded replay of committed data, not a live attack) | `.github/workflows/pages.yml` |

## Qualifiers that must travel with the numbers
- The 13 is a selected sample of the lowest-scoring tasks. It is not a prevalence estimate.
- "Line overlap" means non-trivial added gold source lines (digest match) appear in a future commit. It is not proof
  that the whole fix can be retrieved. Some scans were incomplete: a "not found" can be a miss.
- "Certified" means the recorded qualifying attack failed (for 348: one hardened re-attack). It is not a security bound.
- 348's finding is one run, recon on, one attacker. The model's use of `git show` output is inferred from command order
  and a verbatim line match; full outputs were not retained.

## Novelty
Not claimed. Leakage of future commits through `git log --all` in SWE-bench environments has been reported publicly
(a SWE-bench issue about future repository state, discussed in a bayes.net post "Claude 4 hacked SWE-bench by peeking at
future commits", https://bayes.net/swebench-hack) and SWE-Bench Pro (arXiv 2609.08149) names Git history as one of four
reward-hacking channels and removes future commit objects. We have read these only as search summaries, not in full, so
cite them as "reported". The pitch is the loop and the evaluation-owner workflow (audit, strip, re-check gates,
re-attack, record), not the discovery.

## Not on this sheet, so not to be said
Any rate or percentage; "unhackable"; "first"; any figure from the literature; any claim about Ultra beyond the single run;
any claim that Tavily changed an outcome; any claim that the open web is safe (the web result is a null for one search tool on one day).
