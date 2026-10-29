# Report site

Build locally, with no paid calls and no network: `uv run python -m cheatproof.cli site`.
Output dir: `results/site/` (open `results/site/index.html`). It reads the committed `results/certificates/` and `results/batch.json`.
The Numbers key follows the header and names each number's population, source and limits. The 60-second reading guide explains the release rule: gold passes, empty fails, no future commits after hardening, and a failed re-attack under the same conditions; otherwise withhold. Certified means a recorded attack failed, nothing more. The guide links to `docs/claims.md`, the list of allowed numbers.

The Run record reconciles the union of `results/batch.json` and `results/exposure/_run.json` selected ids, one row per task. It separates certificate files, attacks, audit status and task fate. The old batch counts describe only the last call. Certificate counts include files for broken tasks whose gates failed before any attack; they are not audit counts.

When `results/exposure-sample/` exists, a separate Numbers key block uses `audit.exposure_summary` on its records and `_run.json`, with the seed and rule from `_selection.json`. It reports drawn, audited, excluded, overlapping and closed counts, without a percentage or interval. Its random sample is within the first 1000 dataset rows, repos 0-9 and A-E; it is not SWE-rebench at large and is not blended with the first audit.

Start here's Commands link opens `results/evidence/348-causal.md`. The card copies its recorded commands and compares the single Python line from step 15 with the gold-added line identified in that evidence file. If the Python line is absent, the matching card says "not in the evidence file". Commands are verbatim. Command outputs are heads of at most 300 characters plus a sha256; full outputs were not retained. Line overlap and command order support an inference of history use, not direct observation.

Environment pages call the transcript "Transcript (harness record)". Without a trace they say: "No transcript is committed on this site. For the one confirmed case the recorded commands of steps 12 to 15 are in the evidence file." Traces can be supplied under `results/traces/` (git-ignored); `--traces DIR` picks another folder. Plain-words notes explain writable/restored tests, clean after-hardening scans, unclassified evidence counts, legacy certification, missing image digests and ledger estimates. Dataset links use the instance id as text on the dataset landing-page link, without guessing a per-instance URL.

Before/after panels prominently flag differing recon labels or step counts. These re-attacks do not isolate the patch's effect; an equal pair has no warning. The before-hardening exposure table precedes the panel; the certificate JSON holds the after-hardening scan.

Evidence and raw-certificate links use `results/PINNED_SHA` when present: one line of 40 hexadecimal characters. Labels and footers show the short commit id. Without it they say latest (main); an invalid pin is a build error and links fall back to main. The same base applies to the hero, Start here and claims link. No JavaScript is emitted, CSP is unchanged, and data text uses the site's existing `_cell` escaping.

Exit 1 means the site was written but a committed file did not load; the page lists it under errors. Exit 0 means every file loaded.
CI (`.github/workflows/pages.yml`) builds the same way on push to main. It deploys to GitHub Pages only after a successful build, on a public repo, with Pages enabled.
