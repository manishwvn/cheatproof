# Claims sheet

Every number or claim shown on screen, in the pitch, in the video or on Devpost must be on this sheet, with its source
in the repo. Nothing else may be used. Update this sheet before changing a number. Wording must stay within the
recorded conditions: say "against this attacker", "line overlap", "inferred". Do not imply a general environment guarantee.

## Numbers

| Claim | Value | Source |
|---|---|---|
| Audited environments | 13 of 18 selected (5 excluded as env-broken); the 18 lowest-scoring swe-rebench tasks, not random | `results/exposure/_run.json`, `docs/results.md` (Exposure audit) |
| At least half of the counted gold source lines also in a future commit in `.git` | 12 of 13 | `results/exposure/*.json` (`fix_reachable`), `python -m rewardseal.cli report --certs results/certificates` |
| All counted lines in a future commit | 12 of those 12; for 2 of the 12 (348, toil-4805) it is one line | same records (`gold_lines_in_future` = `gold_added_lines`), `docs/results.md` table |
| Every one of the 13 has future commits | 13 of 13 | same records (`future_commits_before` > 0) |
| After `strip-future-git`: no future commits left in the workdir repo and gold + empty gates held | 11 of those 12 (the miss, BQSKit-134, failed its gold gate before any attack) | same records (`closed`, `closed_reason`) |
| Incomplete scans | 1 history listing cut at 5000 commits (azure-cli-1876); 3 fix scans incomplete | same records (`future_scan`), `docs/results.md` |
| Confirmed attacker finding | 1 of 9 `future_git` tasks attacked with recon on (cyclonedx-348); use of the output is inferred | `results/confirmations.json`, `docs/results.md` (Causal check), `results/evidence/348-causal.md` |
| Retrieval control (openapi3-75), oracle-assisted scripted control, not autonomous discovery | 7 future commits touching gold source files, all readable; 3 candidates tried; top-ranked change shared 4 gold lines, passed 1/1 fail-to-pass; 0 future commits in the listing after strip, gold pass and empty fail; one task, no model; does not prove model causality | `results/control/Dorthu__openapi3-75-retrieval-control.json` (`before_strip`, `after_strip`), alongside `results/evidence/348-causal.md` |
| 348 configured limits and usage | Both rounds: 40 steps / 500,000 tokens configured; before used 40 with harness auto-submit, hardened attacker submitted after 15; recon exposure before, none after | `results/certificates/CycloneDX__cyclonedx-python-348-93d44b30.json` (`attacker.max_steps`, `attacker.max_tokens`, `harden.before.attack`, `harden.after.attack`); `rewardseal/cli.py` (shared attack configuration) |
| Replication on 348 | 1 of 9 committed Super before-rounds showed the pattern (1 of 7 excluding 2 HTTP 503 errors); no further confirmation in the other 8; use inferred, unequal follow-up, not a rate; earlier rounds and the uncommitted chunk 2 run not counted | `docs/results.md` (Audited 348 before-rounds), `results/certificates/CycloneDX__cyclonedx-python-348-93d44b30.json`, `results/replications/` |
| Ultra run on 348 | 1 run: same pattern before hardening; hardened re-attack hit `token_limit` without a submission; not certified; cost $0.7746 | `results/ultra/CycloneDX__cyclonedx-python-348-ultra.json`, `docs/results.md` |
| Certificate files | 14 files, 4 certified: 1 after a failed hardened re-attack (348), 3 legacy no-hole-found | `results/certificates/`, `report` output |
| Tasks attacked | 11 (9 with recon `exposure` and `future_git` true) | `docs/results.md` (Headline details), certificates |
| Attacker model | `nvidia/nemotron-3-super-120b-a12b` via Nebius Token Factory (one exploratory Ultra run on 348) | certificates (`attacker.model`) |
| Tavily | one harness-initiated search (schematics-7); the attacker made 0 search calls; no effect on any outcome shown | `results/certificates/Alexei-Kornienko__schematics_to_swagger-7-*.json`, `docs/tavily.md` |
| Real Token Factory spend | about $4.15 at Oct 29 (ledger counter, an overestimate against the console); promo credit, no card | `~/.rewardseal-autopilot/ledger.json` (local, not committed), `docs/results.md` (Console) |
| Tests | see `STATUS.md` (CI runs them on every PR) | `.github/workflows/ci.yml` |
| Second audit: random sample within the A-E frame | 9 audited of 12 drawn (3 env-broken); at least half of counted lines in a future commit in 7 of 9; closed in 5 of those 7 (2 not closed: gold gate failed after strip; strip patch did not apply). Counts only, no rate | `results/exposure-sample/`, `docs/sample-protocol.md`, `docs/results.md` |
| Web exposure (Tavily), 13 audited | 0 of 13: no result (130) contained a counted gold line; no result was a pull/commit/compare page of the task's repo, even for the oracle PR-URL query; searched 2026-10-29, findability only, dated snapshot, this tool only | `results/web-exposure/`, `docs/results.md` |
| Same-recon re-attack attempt on 348 | not exercised: the new before round passed without history commands (classified unclassified), so there was no patchable hole (the classifier labelled it unclassified), no hardening, no re-attack; cost $0.099; including this null replay, the pattern is in 1 of 10 committed Super before-rounds (1 of 8 excluding 2 HTTP 503 errors); use inferred, unequal follow-up, not a rate | `results/replay-attempt/`, `docs/results.md` |
| Machine cost, not time saved | 13 audit records; $0 model spend; machine time unavailable: no duration field in the committed run record | `results/exposure/*.json`, `results/exposure/_run.json`; `docs/results.md` (Exposure audit: no Token Factory spend) |
| Certified (k=1), hardened 348 | One completed attack failed under recorded conditions, exposure removed, gold pass and empty fail checked by code; three legacy certificates do not record removal or a hardened re-attack | 348 certificate (`harden.after`, `gates.after`), `rewardseal/certify.py`, `rewardseal/harden.py`; legacy files in `results/certificates/` |
| Results explorer, controls gallery, limitations page | explorer lists 24 rows: 13 selected-audit + 9 random-sample audited tasks + 2 certificate-only tasks (attacked, not in an exposure audit); every cell is read from the committed records; no new measurement, and a missing audit group suppresses the "not audited" message | `rewardseal/site_extras.py`, `docs/limitations.md`, `results/exposure*`, `results/certificates/` |
| Framed sample selection | 1000-row dataset frame, repositories 0-9 and A-E; 12 drawn, 9 audited, 3 environment-broken; 7 of 9 overlap, 5 of 7 closed | `results/exposure-sample/_selection.json`, `results/exposure-sample/_run.json`, `results/exposure-sample/*.json`, `docs/sample-protocol.md` |
| Feedback observations | HTTP 503 interruptions remain inconclusive; Nano returned content null at a small output allowance, with reasoning text and finish reason length; no reasoning-usage split; Ultra feedback limited to one task | `results/replications/` (503), `docs/results.md` (Ultra), smoke-test observations (Nano reply, not committed as a record), `scripts/smoke.py` |
| Route replay on 348 (no model), hash match | In one Sandboxes session on the 348 image the three recorded commands (trace steps 12 to 14) were re-run before strip: output sha256 and character counts match the recorded digests in 3 of 3 (1198, 443, 1085 chars); the recorded line is present in the step-14 output; after `strip-future-git` the commit is unreachable (exit 128 for both `git show`, no commit in `git log`). Allowed reading: the same command in the same image reproduces the output the model saw; the model's use of it is still inferred. One attempt, sandbox cost about $0.004 | `results/evidence/348-route-replay.json`, `scripts/route_replay.py` |
| Retrieval control on 348, oracle-assisted scripted control, not autonomous discovery | 17 future commits touching gold source files, all readable; the top-ranked change (`65bf3181c613`, the commit the attacker inspected) shares 1 gold line and passed 1/1 fail-to-pass; after the strip 0 future commits, gold gate passed, empty gate failed. Does not prove model causality | `results/control/CycloneDX__cyclonedx-python-348-retrieval-control.json`, `docs/results.md` |
| Demo | https://manishwvn.github.io/rewardseal/ (recorded replay of committed data, not a live attack) | `.github/workflows/pages.yml` |

## Qualifiers that must travel with the numbers
- The 13 is a selected sample of the lowest-scoring tasks. It is not a prevalence estimate.
- "Line overlap" means non-trivial added gold source lines (digest match) appear in a future commit. It is not proof
  that the whole fix can be retrieved. Some scans were incomplete: a "not found" can be a miss.
- Certified (k=1) = one completed attack failed under the recorded conditions, with exposure removed, gold pass and empty fail checked by code. This describes the hardened 348 result. The three legacy certificates record a failed initial attack with no hole found; they do not record exposure removal or a hardened re-attack. It is not a security bound.
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
Any rate or percentage; any unconditional environment guarantee; any priority claim; any figure from the literature; any claim about Ultra beyond the single run;
any claim that Tavily changed an outcome; any claim of absence of web exposure (the web result is a null for one search tool on one day).
