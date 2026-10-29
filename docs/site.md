# Report site

Build locally, with no paid calls and no network: `uv run python -m rewardseal.cli site`.
Output dir: `results/site/` (open `results/site/index.html`). It reads the committed `results/certificates/` and `results/batch.json`.
The Numbers key follows the header and names each number's population, source and limits. The 60-second reading guide explains the release rule: gold passes, empty fails, no future commits after hardening, and a failed re-attack under the same conditions; otherwise withhold. Certified means a recorded attack failed, nothing more. The guide links to `docs/claims.md`, the list of allowed numbers.

The Run record reconciles the union of `results/batch.json` and `results/exposure/_run.json` selected ids, one row per task. It separates certificate files, attacks, audit status and task fate. The old batch counts describe only the last call. Certificate counts include files for broken tasks whose gates failed before any attack; they are not audit counts.

When `results/exposure-sample/` exists, a separate Numbers key block uses `audit.exposure_summary` on its records and `_run.json`, with the seed and rule from `_selection.json`. It reports drawn, audited, excluded, overlapping and closed counts, without a percentage or interval. Its random sample is within the first 1000 dataset rows, repos 0-9 and A-E; it is not SWE-rebench at large and is not blended with the first audit.

Start here's Commands link opens `results/evidence/348-causal.md`. The card copies its recorded commands and compares the single Python line from step 15 with the gold-added line identified in that evidence file. If the Python line is absent, the matching card says "not in the evidence file". Commands are verbatim. Command outputs are heads of at most 300 characters plus a sha256; full outputs were not retained. Line overlap and command order support an inference of history use, not direct observation.

Environment pages call the transcript "Transcript (harness record)". Without a trace they say: "No transcript is committed on this site. For the one confirmed case the recorded commands of steps 12 to 15 are in the evidence file." Traces can be supplied under `results/traces/` (git-ignored); `--traces DIR` picks another folder. Plain-words notes explain writable/restored tests, clean after-hardening scans, unclassified evidence counts, legacy certification, missing image digests and ledger estimates. Dataset links use the instance id as text on the dataset landing-page link, without guessing a per-instance URL.

Before/after panels prominently flag differing recon labels or step counts. These re-attacks do not isolate the patch's effect; an equal pair has no warning. The before-hardening exposure table precedes the panel; the certificate JSON holds the after-hardening scan.

Evidence and raw-certificate links use `results/PINNED_SHA` when present: one line of 40 hexadecimal characters. Labels and footers show the short commit id. Without it they say latest (main); an invalid pin is a build error and links fall back to main. The same base applies to the hero, Start here, claims link and controls gallery record links. Data text uses the site's existing `_cell` escaping.

The index navigation links to `explorer.html`, `controls.html`, `limitations.html`, `verify.html` and the Numbers key. The Pages workflow publishes `verify.html`; the site builder only links to it. The 60-second guide also links to the explorer. Nearby, a comparison card lists the manual and RewardSeal workflows, their outputs and the human decisions still required, without timing claims.

The explorer lists every record from `results/exposure/` and `results/exposure-sample/` separately, followed in task order by certificate-only tasks. Certificate-only rows distinguish an attack from a broken task with no attack. Future commits are the before-strip count; incomplete listings and overlap scans are flagged as lower bounds. Web overlap is the best k of n across both recorded queries, including the oracle query; it measures findability only. Environment links appear when a certificate page exists.

The full explorer table works without JavaScript. Its optional external `explorer.js` creates search and sample/closed/incomplete-scan filters using DOM methods and `textContent`, never `innerHTML`. Search matches task id or repo, case-insensitively. An unknown query containing `__` or `/` hides the table and says "not audited: this id is not in either sample"; filters alone never establish that an id was not audited. Only the explorer permits scripts in its meta CSP: `default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; img-src 'self'`. The index has no meta CSP; other pages retain the existing script-free CSP and contain no JavaScript.

The controls gallery explains clean closure, broken gold gates, unapplied strips, incomplete scans, the 116 attribution and PR #88 timing rule, the unexercised 348 same-recon re-attack, the retrieval control and the dated web null. Each card links to the underlying committed records and states its limit. Missing optional groups show no matching records rather than invented results.

Environment pages with an after-hardening round add an "Environment change vs attacker solution" block. Certificate fields supply the scans, future-history evidence, patch names and gates. The right side shows only the reviewed steps 12 to 15 and matching line from `results/evidence/348-causal.md`, when available. Otherwise it says "attacker diff not published: only its sha256 and size are recorded" and shows those fields. Raw diff fields in certificates are never rendered.

`limitations.html` renders `docs/limitations.md` using an escaped Markdown subset: headings, `-` bullets and paragraphs. HTML and Markdown links are plain escaped text. The page includes detection, sampling, attribution and cost limits, plus responsible disclosure guidance. Explorer tables remain inside `.table-wrap`; controls use a single card column on narrow screens.

Exit 1 means the site was written but a committed file did not load; the page lists it under errors. Exit 0 means every file loaded.
CI (`.github/workflows/pages.yml`) builds the same way on push to main. It deploys to GitHub Pages only after a successful build, on a public repo, with Pages enabled.

When web exposure records are present, the index reports the full search date range and separates pull/commit/compare overlaps from current-file page overlaps. The oracle query searches for the pull request URL; these results show findability, not use, and are a lower-bound snapshot.
