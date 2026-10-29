# First-time judge check (actual outcomes)

Run on 2026-10-29 by an automated reader acting as a first-time judge, in a fresh clone of the public repository at
`e678776` (merge of PR #89), in an empty directory, with no `.env`, no key and no network call to a paid service.
These are the recorded outcomes, not expectations.

| Step | Command | Exit | Time | Outcome |
|---|---|---|---|---|
| 1 | `git clone https://github.com/manishwvn/cheatproof.git` | 0 | 1 s | HEAD `e678776` |
| 2 | `uv sync` | 0 | 1 s | installed |
| 3 | `uv run pytest -q` | 0 | 90 s | 2898 passed, 1 skipped |
| 4 | `uv run ruff check .` and `uv run ruff format --check .` | 0 | about 1 s | all checks passed; 82 files already formatted |
| 5 | `uv run python -m cheatproof.cli report --certs results/certificates` | 0 | 1 s | n=14, certified 4 of 14, `hardened_reattack_failed=1`, `legacy=3`; audit line matches the README |
| 6 | `uv run python -m cheatproof.cli site --certs results/certificates --out <dir>` | 0 | 1 s | 14 pages, 0 errors; index contains "Start here" and "not a live attack" |
| 7 | relative-link check over README and docs (script) | 0 | 1 s | 11 files, 6 relative targets, 0 broken; anchor `#causal-check-348-and-116` checked by hand |
| 8 | external URLs in README | 0 | 1 s | the demo URL and the uv docs return 200; the Token Factory URL was skipped |

Not run, on purpose: `harden`, `batch`, `smoke`, `audit-exposure` (they need credentials and spend credits). The live
path is unverified by this check.

## Problems found, and what was done

1. The README quoted "hackable before hardening: 2 of 5" and "after: 1 of 2", but `report` prints "confirmed holes before
   hardening: 1 of 5" and "after: 0 of 2". Fixed: the README now quotes what is printed and explains the raw counts.
2. The setup block mixed offline steps with `cp .env.example .env`, which is only for live runs. Fixed: split in two blocks.
3. `--out site` writes an untracked `site/` folder. Fixed: the README uses `--out results/site` (git-ignored).
4. `pytest -q` takes about 90 seconds, unlabelled. Fixed: the README now says so.
5. The `report` output is long. Not changed; the README now says to read the audit line first.

Anchors were not machine-checked.
