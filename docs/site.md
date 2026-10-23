# Report site

Build locally, with no paid calls and no network: `uv run python -m cheatproof.cli site`.
Output dir: `results/site/` (open `results/site/index.html`). It reads the committed `results/certificates/` and `results/batch.json`.
Transcripts say "no transcript recorded" until traces exist under `results/traces/` (git-ignored); `--traces DIR` picks another folder.
Exit 1 means the site was written but a committed file did not load; the page lists it under errors.
CI (`.github/workflows/pages.yml`) builds the same way on push to main and deploys to GitHub Pages, only once the repo is public.
