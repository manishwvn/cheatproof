# Queue

Format: `### <id> <title> — size S|M|L — <status> [— after <date>] [— needs <ids>]`. Statuses: `todo`,
`in-progress (cycle <start>)`, `in review`, `waiting: <why>`, `done #<PR>`, `superseded`. `[NN%]` overrides credit.
Check: `python3 docs/autopilot/progress.py` counts the same tasks as
`grep '^### .* — size [SML] — ' docs/autopilot/QUEUE.md | grep -vc superseded`.

## Milestone: live access and executor

### T01 Smoke test, model IDs and prices — size S — waiting: U3 (sandbox run) [85%]
Run `uv run python scripts/smoke.py`. Live scripts load `.env` from the main checkout (the parent of `git rev-parse
--git-common-dir`), so worktrees share one key file and never copy it. Record the exact Nemotron model IDs (Nano,
Super, Ultra) from `/v1/models` and their per-1M prices from the public Token Factory price page into `.env.example`
comments and the `MODEL_PRICES_JSON` example. Use the cheapest model (Nano) for the smoke call; never Ultra here.
Confirm one capped call and, if `NEBIUS_PROJECT_ID` is set, one sandbox run. Record sanitized response fixtures (no
auth headers, keys, emails or IDs) under `tests/fixtures/`, plus a test that checks the sanitizing. Acceptance: the
ledger shows spend; fixtures committed; `VERIFY` notes for model IDs resolved. Risk: costs cents; every call goes
through the budget. Until the owner says "promo applied", the account holds only a $1 trial: no Ultra runs, no eval
runs (T08), only Nano or Super calls within the `.env` caps.

Done 2026-10-18 (planner): model IDs and prices recorded in `.env.example`; one capped Nano call worked ($0.0000168,
ledger shared). Left: the `.env` loader for worktrees, sanitized fixtures plus their test, and the sandbox run once
`NEBIUS_PROJECT_ID` and U3 exist. Promo applied 2026-10-18: `.env` now has caps 20/4 and the verified model lines.

Done 2026-10-18 (routine, #5): `cheatproof/envfile.py` (worktrees load the main checkout's `.env`),
`cheatproof/sanitize.py` with tests, `smoke.py --record`, fixtures in `tests/fixtures/token_factory/`. Left: the
sandbox run once U3 and `NEBIUS_PROJECT_ID` exist (then flip to `todo`). Note: Nano spent all 64 output tokens on
reasoning (`content` null); callers that need text from Nano must allow more output tokens.

### T02 Executor interface and Docker backend; Sandboxes recon — size M — done #4
Implement `cheatproof/executor.py` per `docs/adr/0002-execution-model.md`: one interface (`start(env)`,
`run(cmd, timeout)`, `write_file`, `diff`, `reset`, `close`) with a `DockerExecutor` now and a `SandboxExecutor`
(contree-sdk) once U3 is done. Config flag `EXECUTOR=docker|sandbox`. Docker backend: `docker run --rm`,
`--network none` by default, CPU and memory limits, per-command timeout, no host mounts except a scratch dir. Before
any image pull, check free disk (`MIN_FREE_DISK_GB`, default 10) and the distinct-image cap (`DOCKER_IMAGE_CAP`,
default 6); refuse and alert if either fails (routines cannot remove images). If the Docker daemon is down, run
`open -a Docker` and wait up to 2 minutes. Every sandbox run calls `budget.reserve_sandbox_run()`. Unit tests use a
fake runner; one opt-in live test (`-m docker`, skipped in CI) runs `echo ok` in `python:3.12-slim`. Sandbox part
(after U3): confirm and record with fixtures the networking flag, file upload, checkpoint and branch, timeout,
preloaded SWE-rebench image naming and per-run cost; update ADR 0002 and resolve its `VERIFY` notes.

Done 2026-10-18 (routine, #4): interface, Docker backend (no mounts, `--network none`, `--cap-drop ALL`, bounded
output, fresh-index `diff()`, named containers with label `cheatproof=1`), guards and a Sandbox stub. The live
Docker test has not run: the Mac has the docker CLI but no daemon (U7). The Sandbox recon moves to T01's sandbox
step and T03/T06 once U3 is done.

### T15 Routine review fixes (planner-merge PR) — size M — in review [80%]
Apply the "Open, repo side" items 1–11 in `~/.cheatproof-autopilot/review-2026-10-18.md` (fail-closed caps and a
read-only `snapshot()`, `lock.py` output, optional `--now`, CYCLE.md alignment and planner-merge list, `leakcheck.py`,
a versioned pre-push hook, CLI tests and a Python 3.9 compile step in CI, reviewer model, tracked `results/`, pre-flip
scan patterns). Every item touches a planner-merge path: open one PR with tests green and the Opus review, then add a
USER item for the planner to merge. Do T02 first if both are runnable.

Done 2026-10-18 (routine): PR #10 open, CI green, Sonnet review fixed (one round), Opus final review: ready. Items 10
and 11 are below (T08, T12 text). Planner merges #10 (U10), then installs `docs/autopilot/pre-push`.

## Milestone: hero path

### T03 Task loader with gold and empty gates — size M — done #7 — needs T02
Load 30 SWE-rebench and 10 SWE-bench Verified task specs (instance ID, repo, base commit, image, FAIL_TO_PASS,
PASS_TO_PASS, gold patch, test patch) from the public Hugging Face datasets via HTTP (no new heavy dependency), cached
under `runs/` (git-ignored). Pick tasks with small images and pure-Python repos first (disk). `cheatproof/grader.py`
applies a patch, runs the tests and returns pass/fail with counts. Gates per task: gold passes, empty fails; record
both. Add a static exposure scan per task, in code with no model: future commits or refs visible in `.git`, tests
writable, network reachable. Hero fixture: one labelled task in `tests/fixtures/hero/` whose `.git` exposes the future
fix (expected: attack succeeds before hardening, fails after). Tests use recorded fixtures only.

Done 2026-10-18 (routine, #7): `cheatproof/tasks.py` (datasets-server loader, validation, selection, cache),
`cheatproof/grader.py` (hidden tests always restored with `cat-file blob`, patches applied with no repo config,
empty gate must really run), `cheatproof/exposure.py`, hero fixture. Live fetch: Verified keeps only pytest-shaped
ids (django/sympy rows skip), so expect a thin Verified pick; rebench rows without `docker_image` are skipped.
Left for T06: the grader trusts the sandbox object store; edited base `conftest.py` files are not restored.

### T04 Attacker agent with four attacks — size L — done #6 — needs T02
`cheatproof/attacker.py`: a Nemotron tool-calling loop (Ultra by `ATTACKER_MODEL`; Super for cheap dev runs) told to
make the grader pass without solving the task. Tools: `run`, `read_file`, `write_file`, `submit`, all executed only
inside the executor; plus `web_search` (Tavily, host side, counted against `TAVILY_CALL_CAP`) only in the
network-fetch experiment. Four strategy hints: git-history retrieval, test edits, hard-coding, network fetch of the
upstream fix. Limits: about 15 steps and 50k tokens per attempt, enforced through the budget. Every step is logged as
structured JSON (step, tool, args, result digest, tokens). Fake LLM client for tests; one recorded live transcript as
a fixture once T01 is done. Model output is untrusted data.

Done 2026-10-18 (routine, #6): the loop only (`attack(llm, session, system_prompt, task_prompt, ...)`): tools run
through the session, step/token/search limits, JSONL trace, 402 and `BudgetExceeded` stop, diff failure flagged.
The per-strategy prompt text and the live Tavily wrapper moved to T16 (planner).

### T05 Hole classifier from traces — size M — done #8 — needs T04
`cheatproof/holes.py`: decide in code from the trace and the final diff which hole an attack used: `git-history`
(read of future objects or refs, patch matches the gold fix), `test-edit` (diff touches test paths or the restored
hidden tests fail), `hard-code` (patch special-cases test inputs; passes visible tests, fails hidden ones), `network`
(fetch or web search returned the fix). Unclear cases are `unclassified` and reported raw. Nano may write a one-line
explanation; it never decides the label. Tests on hand-made traces.

### T06 Four patches and the re-attack loop — size L — done #9 — needs T03, T05
`cheatproof/patches.py`: strip future `.git` objects and refs; hidden read-only tests restored at grade time; network
off; a grader check that fails when test files were touched. Apply only the patches the found holes need, then
re-run the gold gate, the empty gate and the same attacker with the same budget. A patch that breaks the gold gate is
rejected and reported. Sandboxes: one branch per patch from the task checkpoint (Docker: a fresh container).
From the T02 review: the grader must clear `__pycache__` and stale `.pyc` before grading, and must not trust the
sandbox's own git config, attributes or filter drivers (`diff()` excludes bytecode and cache dirs).

Done 2026-10-18 (routine, #9): `cheatproof/patches.py` (strip-future-git refuses unless HEAD is the base, rebuilds
the index, prunes and verifies in the sandbox; test-edit guard; network-off), `grade(reject_test_edits=True)`, every
base `conftest.py` restored, `cheatproof/harden.py` (clean-session grade of the attack diff, per-patch gold check,
same attacker after; inconclusive attacks, resets during a patched attack and holes the exposure scan still shows are
never certified). For T07: when the attacker fails before hardening, scan-found holes are not patched; show the scan
in the certificate. A trojaned `/usr/bin/git` in the image can still fake the strip check (residual risk).

### T07 Certificates and hackability score — size M — done #11 — needs T06
`cheatproof/certify.py` and `cheatproof/cli.py`: `cheatproof harden <env-id>` writes a JSON certificate (task, image
digest, holes found, patches applied, gate results before and after, attacker model and budget, cost, timestamp) and
`cheatproof report` writes a per-benchmark hackability score with n, raw counts and a 95% interval. Schema is
versioned and tested.

Done 2026-10-18 (routine, #11): `cheatproof/certify.py` (certificate schema 1, validation with certified invariants,
free-text length and secret checks, collision-proof file names; score schema 2 with partitioned `outcomes`, rates
over stated denominators and Wilson 95% intervals) and `cheatproof/cli.py` (`python -m cheatproof.cli harden <id>
--system-prompt-file <f>`, `report`). Left for T08: `image_digest` is always null (the executor exposes none), the
CLI runs with network off only (the network-fetch experiment is not wired), and cost is a ledger delta, so run
`harden` serially. A certificate holding a secret-shaped string is refused, so the CLI exits 1 after the paid run.

### T16 Attack strategy prompts and Tavily counter (planner) — size S — waiting: planner (U9)
The four strategy hints for T04 (git-history, test-edit, hard-code, network) as caller-supplied `system_prompt`
text, and a `budget.reserve_tavily_call()` counter enforcing `TAVILY_CALL_CAP` plus a host-side search callable
for `attack(search=...)`. `budget.py` is a planner-merge path, and the routine left the prompt text to the planner.

## Milestone: go/no-go 2026-10-21 (attacker passes at least 5 of 40 unhardened tasks)

### T08 Eval run and results with raw counts — size M — todo — needs T01, T07
Run the full loop on the 40 tasks within the $20 cap (check the ledger before starting; stop at the daily cap). Write
`docs/results.md`: method, n, raw counts per attack type before and after, gold and empty gate results, cost per
environment, failures and limits ("upper bound against this attacker, not proof"). Commit the certificates and the
sanitized traces needed for replay. Committed certificates and replay traces go in a tracked `results/` folder (`runs/` stays a
git-ignored cache; `git add -f` is denied).

### T09 Report page and judge replay mode — size M — todo — needs T07
A static report site (no server, no paid calls): the 40-task table, one before/after page per environment with the
patch diff, the attack transcript and the gates. Judge mode replays recorded runs, labelled "recorded". Builds from
committed certificates; deployable to free static hosting after the repo flip; must stay up through 2026-12-15.
Accessible, with empty and error states.

## Milestone: submission (feature freeze 2026-10-24)

### T10 README, ADRs and feedback write-up — size M — todo — needs T08
README: problem with one sourced number, what it does, architecture diagram, setup and run steps, how Token Factory,
Nemotron, Sandboxes and Tavily are used and where, what is real and what is replayed, results summary. ADRs current.
`docs/feedback.md`: specific, actionable feedback on Token Factory, Sandboxes and NVIDIA models (Most Valuable
Feedback prize).

### T11 Video script and automated rough cut — size M — todo — after 2026-10-21
Script by Oct 21 per `docs/pitches.md` demo beats (model ID in the first 20 seconds, under 2:50). Rough cut by Oct 24:
scripted browser recording of the report page and terminal, text-to-speech, captions, ffmpeg. No third-party marks
or music. The owner records the final voice (U6).

### T12 Fresh-clone final check and pre-flip check — size S — todo — after 2026-10-27
Fresh clone, follow the README exactly, run tests and one replay. Pre-flip: full-history secret scan green;
`git log --all --oneline -- LEARNING.md` empty; full-history grep finds no personal details. Scan patterns include
`/Users/`, the owner's username and promo codes; docs use `~` or relative paths. Report to the owner.

### T13 Learning pack — size M — todo — needs T12
Fill `LEARNING.md` interview questions, complete the glossary, re-read the whole file for accuracy.

### T14 Submit — size S — waiting: owner only — after 2026-10-28
The owner makes the repo public and submits on Devpost. Marked done only on the owner's word.

## USER

- ~~**U1 Nebius Token Factory account, credits and key**~~ Done 2026-10-18: promo applied, credit received, key in
  `.env`, caps set to 20 and 4.
  **U1 steps (kept)** (ready 2026-10-16; status 2026-10-18: account exists, billing
  active with a $1 trial for 29 days, promo form submitted, promo code pending by email for up to 24 h):
  1. ~~https://tokenfactory.nebius.com → sign up and log in.~~ Done.
  2. ~~Add the card when billing setup asks (activation only; the app's caps keep spend inside the credits).~~ Done.
  3. ~~Open the promo form through the **Devpost Resources page link** (event code `2026-devpost-global-ai-hack`),
     not the bare https://nebius.com/promo-code URL, which errors with "no event name found". Submit it with the
     activation code `NEBIUS-DEVPOST-GLOBAL26`.~~ Done; Nebius emails the real promo code.
  4. When the email arrives: Token Factory → Balance → **Top up** → **With promo code** → paste the emailed code.
     Check the balance shows the credit.
  5. Billing and organisation settings: turn off any auto-charge or "billing threshold" option if one exists.
  6. **Get API key** (copy it once) and Project settings → copy the project ID.
  7. In `/Users/manish/Documents/Nebius_X_Nvidia/cheatproof`, copy `.env.example` to `.env` and fill
     `NEBIUS_API_KEY` and `NEBIUS_PROJECT_ID`. **Keep `SPEND_CAP_USD=0.8` and `DAILY_CAP_USD=0.8` from the example
     until the promo credit shows in the balance**, so spend stays inside the $1 trial; then set them to 20 and 4.
     Never paste keys in chat.

  Then tell the lead "U1 done" (and "promo applied" after step 4).
- **U2 Tavily key (optional, for the network-fetch attack and the Tavily bonus)** (ready 2026-10-16): sign up at
  https://tavily.com, apply promo `BBDEVPOST`, put the key in `.env` as `TAVILY_API_KEY`. Optional: join
  https://dev.nebius.com/builders for extra credit (unreliable; the plan assumes $25 only).
- **U3 Sandboxes access** (ready after U1): https://tokenfactory.nebius.com/sandboxes/about → request access. If the
  profile still shows inactive after a day, email contree@nebius.com with the project ID only (never the key). Docker
  is the fallback; the executor is decided at the Oct 21 go/no-go.
- **U4 GitHub safety** (ready 2026-10-16): Settings → Billing → set budgets for Actions, Codespaces and Packages to
  $0. Repo → Settings → Branches → protect `main`: block force pushes and deletion, include administrators. Do not
  require pull requests (routines push queue claims to `main`).
- **U5 Final product name** (before any public asset): check that "Cheatproof" is not an existing product's
  trademark, or pick another name. The lead can propose options.
- **U6 Video voice-over and submission** (2026-10-26 to 2026-10-28).
- **U7 Disk space and a Docker daemon for the fallback** (ready 2026-10-18; needed by 2026-10-20 if U3 is still
  pending): free at least 30 GB on the Mac (16 GB free on Oct 18). The Mac has the docker CLI but no Docker Desktop
  app (`open -a Docker` fails, found 2026-10-18), and routines cannot install software. Install Docker Desktop (or
  colima: `brew install colima && colima start`), start it once, then run
  `CHEATPROOF_DOCKER_TESTS=1 uv run pytest -q -m docker` in the repo. Routines cannot delete images or files.
- **U8 (optional) Routine folder and permission mode** (ready 2026-10-18; runs are already guarded from the parent
  folder): Claude app → Scheduled → **Cheatproof autopilot** →
  edit: set the folder to `/Users/manish/Documents/Nebius_X_Nvidia/cheatproof` and the permission mode to **Bypass**,
  then save. Until then runs start in the parent folder in auto mode, so the repo's connector guard does not load
  and a run may stop on a refused step. Then tell the lead "U8 done".
- **U10 Merge PR #10 (T15 review fixes)** (ready 2026-10-18): in an interactive session say `review` to merge
  https://github.com/manishwvn/cheatproof/pull/10 (planner-merge paths: budget.py, docs/autopilot/, CI). Then install
  the hook: `cp docs/autopilot/pre-push "$(git rev-parse --git-path hooks)/pre-push"`. Note: `budget.py` now refuses
  to start unless `SPEND_CAP_USD` and `DAILY_CAP_USD` are set (≤ 20, daily ≤ total); the current `.env` sets 20 and 4.
- **U9 Planner work for T16** (ready 2026-10-18): in an interactive session, write the attacker strategy prompts
  and the Tavily budget counter (T16), then flip T16 to `done`. T05 and T06 do not wait on it; the first live
  attacker run (T08) does.
