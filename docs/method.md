# Method

## Detector and its limits

Before an attack the scan lists future commits reachable from refs, reflogs, `ORIG_HEAD` and `FETCH_HEAD`; after the attack it hashes added lines in those commits for non-test files in the final diff and gold patch. Full commit IDs, text diffs and disabled text conversion prevent revision ambiguity and hidden binary diffs. A passing diff with a non-trivial matching line is classified as `git-history` only when the scan is complete; otherwise it remains a lead. The round records paths, short IDs, counts and completeness.

Completeness fails on errors, unverified sources, inexact diffs or caps: 5000 commits, 2 MiB output, 60 runs, 200 paths, or more than 1500 pre-attack IDs to name again. Dangling commits are not scanned, though an attacker can find them; such matches need manual review. `strip-future-git` prunes unreachable objects. The audit uses non-test gold source files and counts distinct non-trivial added lines, excluding blank, comment-only, docstring-only, string-only, import-only and generic lines. `fix_reachable` requires a future commit touching those files and at least `max(1, ceil(0.5 * gold_added_lines))` counted lines in future commits. Reformatting, moves, merge-only changes and dangling objects can be missed. Closure covers the workdir repository only, not submodules or other clones. A negative finding is not evidence of absence.

## Sample protocol

The protocol was written and committed before the run. The separate sample uses cached SWE-rebench rows, excluding denied repositories and the 18 selected audit tasks. The frame is the 1000 dataset rows ordered by repository name, with 243 valid tasks in 88 repositories starting 0-9 and A-E. The pool is sorted by instance ID and `random.Random(20261029).sample(pool, 12)` selects the tasks; the date seed was not tuned. Size 12 was set before results because the Sandboxes counter was $3.65 of its $5 guard; the stop rule was $4.8. Exclusions are recorded and never replaced. This frame does not represent the dataset at large; report counts separately from the selected audit.

## Execution model and spend cap

Token Factory Sandboxes is the default: a checkpoint per task and separate branches for attacks, gates and patches. Network is disabled in-guest using `unshare`, with a start probe that fails closed; containment is best effort because there is no API egress switch. The network-fetch experiment is the exception. Local Docker is a fallback with network disabled, resource limits and no host mounts; no reported results used it.

The file-locked budget ledger reserves estimated worst-case cost before paid model calls and settles usage afterward. Required total and daily caps reject invalid settings; total has a $20 ceiling, daily is $4 in the recorded configuration, and real Token Factory spend has a $10 ceiling. HTTP 402 halts paid calls. Sandbox runs have a run cap; reported Sandboxes costs are logged separately and capped, with a $0.50 code default and $5 recorded guard. That counter is an estimate, not a bill. Check the console between runs.

## Report site and verifier

Build offline with `uv run python -m rewardseal.cli site --certs results/certificates --out results/site`. It reads committed certificates and batch records; exit 1 indicates a committed file failed to load. Evidence links use the 40-hex commit in `results/PINNED_SHA`; without a pin they use main, and an invalid pin produces a build error. The Pages workflow publishes the browser verifier and the site.

Run `uv run python -m rewardseal.manifest verify` to check inventory, hashes, byte counts and recomputed totals; exit 0 matches, 1 indicates mismatch or unreadable evidence, and 2 indicates usage error. After an intentional evidence change, the owner can run `uv run python -m rewardseal.manifest build` and commit the snapshot with the evidence. The browser verifier hashes listed files and recomputes totals, while the local verifier also detects added evidence. The manifest is not a signature or independent trust anchor, and neither verifier establishes historical execution. The manual `.github/workflows/gate-example.yml` uses the local composite action after checkout with read-only contents permission; it verifies recorded evidence and uploads `report.txt` without running an attacker.

## Judge check

On 2026-10-29 an automated reader used a fresh public clone at `e678776`, without credentials or paid service calls. `uv sync` succeeded; `uv run pytest -q` reported 2898 passed and 1 skipped; Ruff checks passed. The report returned 14 certificates and 4 certified (1 hardened and 3 legacy); the site build returned 14 pages and 0 errors. The relative-link check reported 0 broken targets; anchors were not machine-checked. The live harden, batch, smoke and audit paths were not exercised by that check.
