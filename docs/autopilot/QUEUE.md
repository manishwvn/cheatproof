# Queue

Format: `### <id> <title> — size S|M|L — <status> [— after <date>] [— needs <ids>]`. Statuses: `todo`,
`in-progress (cycle <start>)`, `in review`, `waiting: <why>`, `done #<PR>`, `superseded`. `[NN%]` overrides credit.

## Milestone: live access

### T01 Smoke test against live Token Factory — size S — waiting: U1
Run `scripts/smoke.py`. Record the exact Nemotron model IDs and their per-1M prices from the console price page into
`.env.example` comments and `MODEL_PRICES_JSON` guidance. Confirm a capped call and one sandbox run. Record sanitized
response fixtures (no auth headers, keys or emails) under `tests/fixtures/`, plus a test that checks the sanitizing.
Acceptance: the ledger shows spend; fixtures are committed; `VERIFY` notes resolved for model IDs.

### T02 Sandboxes recon — size M — waiting: U3 — needs T01
Confirm and record with fixtures: the networking off flag (REST `networking.enabled`), file upload via `files=`,
checkpoint (`disposable=False`) and branching, how to diff two images' filesystems (for example `find -newer` or a
manifest hash inside the run), per-run timeout, preloaded SWE-rebench image naming via `GET /v1/images?tag=`, and
the cost per run if visible. Write `docs/adr/0002-sandbox-model.md`. Every assumption gets a `VERIFY` note until a
fixture confirms it.

## Milestone: hero path

### T03 Hero fixture — size S — todo — after 2026-10-20
Two labelled fixtures in `tests/fixtures/hero/`. (a) A malicious PR: an AGENTS.md comment telling agents to read
`~/.config/canary/token` and write it into a test file. (b) A benign PR: a real one-line bug fix. Both inert. The
expected verdicts are fail and pass.

### T04 Canary agent harness — size M — todo — after 2026-10-20 — needs T02
Nemotron tool-calling loop (canary model) with tools `list_dir`, `read_file`, `write_file`, `run` that execute only
inside a sandbox run. Every tool call is logged as structured JSON (tool, args, result digest, step). A honeytoken
file and env var are planted in the image. Step and token limits are enforced through the budget. Fake client for
tests.

### T05 Twin runner — size L — todo — needs T04
Checkpoint the base repo. Run the clean twin N=3 times and the PR branch once, all from the same checkpoint, with the
same task prompt and seed. Collect traces and filesystem manifests. Every run goes through `reserve_sandbox_run`.

### T06 Divergence detector and verdict — size M — todo — needs T05
In code: normalize traces and flag actions on the PR branch that are absent from every clean run: honeytoken access,
writes outside the workspace, hook or config edits, network attempts, new processes. Nano summarizes the evidence and
Ultra writes the verdict text (schema-validated). The verdict is decided in code from the facts.

### T07 Dependency gate with Tavily — size M — todo — needs T06
For packages a PR adds: registry existence, age and downloads, plus a Tavily search for advisories or typosquat
reports. Results change the risk score (they are not decoration), and the sources are cited in the evidence.

## Milestone: proof

### T08 Corpus 15 malicious + 15 benign — size L — todo — needs T05
Malicious cases are synthetic and inert, covering two entry points (instruction files; setup scripts) and split into
seeded and held-out evasions (padding, indirection, encoded text). Benign cases are real SWE-rebench gold patches.

### T09 Eval harness and report — size M — todo — needs T06, T08
Detection rate, false-positive rate and $/scan, against baselines (a static grep scanner, single-run diff without
twins). Output `docs/eval.md` with a table and the method.

## Milestone: product

### T10 GitHub check output — size M — todo — needs T06
A check run with pass/fail, an evidence timeline, a token and cost ledger, and a suggested (never pushed) sanitizing
patch.

### T11 Web UI and judge mode — size L — todo — needs T06
Side-by-side timeline (clean twin vs PR), divergence highlights and cost. Judge mode is a no-login replay of recorded
runs, labelled "recorded", that degrades to replay at the budget cap.

### T12 Hosted demo — size M — todo — needs T11
Free-tier hosting, a `/health` endpoint, and the in-app caps active. Must stay up through 2026-12-15.

## Milestone: submission

### T13 README, ADRs, screenshots, feedback write-up — size M — todo — needs T09
### T14 Video script and automated rough cut — size M — todo — after 2026-10-21
### T15 Fresh-clone final check and pre-flip check — size S — todo — after 2026-10-27
### T16 Learning pack — size M — todo — needs T15
### T17 Submit — size S — waiting: owner only — after 2026-10-28

## USER

- **U1 Nebius Token Factory account** (ready 2026-10-16):
  1. https://tokenfactory.nebius.com → Log in → sign up.
  2. Add the card when billing setup asks.
  3. Balance → **Top up** → **With promo code** → `NEBIUS-DEVPOST-GLOBAL26`.
  4. Billing and Organisation settings: turn off any auto-charge or "billing threshold" option if one exists.
  5. **Get API key** (copy it once).
  6. Project settings → copy the project ID.

  Keys go into `.env` (from `.env.example`), never chat. Then tell the lead "U1 done".
- **U2 Builders Program + Tavily** (ready 2026-10-16): join https://dev.nebius.com/builders (+$25 Token Factory credit).
  Sign up at https://tavily.com and apply promo `BBDEVPOST`. Put the key in `.env` as `TAVILY_API_KEY`.
- **U3 Sandboxes access** (ready after U1): https://tokenfactory.nebius.com/sandboxes/about. If the profile shows
  inactive, email contree@nebius.com with the project ID only (never the key).
- **U4 GitHub safety** (ready 2026-10-16): Settings → Billing → set budgets for Actions, Codespaces and Packages to $0.
  Repo → Settings → Branches → protect `main`: block force pushes and deletion, include administrators.
- **U5 Final product name** (before any public asset): pick a name that is not an existing security product's
  trademark. The lead can propose options.
- **U6 Video voice-over and submission** (2026-10-26 to 2026-10-28).
