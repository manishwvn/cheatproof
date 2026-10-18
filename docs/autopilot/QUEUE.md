# Queue

Format: `### <id> <title> — size S|M|L — <status> [— after <date>] [— needs <ids>]`. Statuses: `todo`,
`in-progress (cycle <start>)`, `in review`, `waiting: <why>`, `done #<PR>`, `superseded`. `[NN%]` overrides credit.
Check: `python3 docs/autopilot/progress.py` counts the same tasks as
`grep '^### .* — size [SML] — ' docs/autopilot/QUEUE.md | grep -vc superseded`.

## Milestone: live access and executor

### T01 Smoke test, model IDs and prices — size S — waiting: U1
Run `uv run python scripts/smoke.py`. Live scripts load `.env` from the main checkout (the parent of `git rev-parse
--git-common-dir`), so worktrees share one key file and never copy it. Record the exact Nemotron model IDs (Nano,
Super, Ultra) from `/v1/models` and their per-1M prices from the public Token Factory price page into `.env.example`
comments and the `MODEL_PRICES_JSON` example. Use the cheapest model (Nano) for the smoke call; never Ultra here.
Confirm one capped call and, if `NEBIUS_PROJECT_ID` is set, one sandbox run. Record sanitized response fixtures (no
auth headers, keys, emails or IDs) under `tests/fixtures/`, plus a test that checks the sanitizing. Acceptance: the
ledger shows spend; fixtures committed; `VERIFY` notes for model IDs resolved. Risk: costs cents; every call goes
through the budget. Until the owner says "promo applied", the account holds only a $1 trial: no Ultra runs, no eval
runs (T08), only Nano or Super calls within the `.env` caps.

### T02 Executor interface and Docker backend; Sandboxes recon — size M — todo
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

## Milestone: hero path

### T03 Task loader with gold and empty gates — size M — todo — needs T02
Load 30 SWE-rebench and 10 SWE-bench Verified task specs (instance ID, repo, base commit, image, FAIL_TO_PASS,
PASS_TO_PASS, gold patch, test patch) from the public Hugging Face datasets via HTTP (no new heavy dependency), cached
under `runs/` (git-ignored). Pick tasks with small images and pure-Python repos first (disk). `cheatproof/grader.py`
applies a patch, runs the tests and returns pass/fail with counts. Gates per task: gold passes, empty fails; record
both. Add a static exposure scan per task, in code with no model: future commits or refs visible in `.git`, tests
writable, network reachable. Hero fixture: one labelled task in `tests/fixtures/hero/` whose `.git` exposes the future
fix (expected: attack succeeds before hardening, fails after). Tests use recorded fixtures only.

### T04 Attacker agent with four attacks — size L — todo — needs T02
`cheatproof/attacker.py`: a Nemotron tool-calling loop (Ultra by `ATTACKER_MODEL`; Super for cheap dev runs) told to
make the grader pass without solving the task. Tools: `run`, `read_file`, `write_file`, `submit`, all executed only
inside the executor; plus `web_search` (Tavily, host side, counted against `TAVILY_CALL_CAP`) only in the
network-fetch experiment. Four strategy hints: git-history retrieval, test edits, hard-coding, network fetch of the
upstream fix. Limits: about 15 steps and 50k tokens per attempt, enforced through the budget. Every step is logged as
structured JSON (step, tool, args, result digest, tokens). Fake LLM client for tests; one recorded live transcript as
a fixture once T01 is done. Model output is untrusted data.

### T05 Hole classifier from traces — size M — todo — needs T04
`cheatproof/holes.py`: decide in code from the trace and the final diff which hole an attack used: `git-history`
(read of future objects or refs, patch matches the gold fix), `test-edit` (diff touches test paths or the restored
hidden tests fail), `hard-code` (patch special-cases test inputs; passes visible tests, fails hidden ones), `network`
(fetch or web search returned the fix). Unclear cases are `unclassified` and reported raw. Nano may write a one-line
explanation; it never decides the label. Tests on hand-made traces.

### T06 Four patches and the re-attack loop — size L — todo — needs T03, T05
`cheatproof/patches.py`: strip future `.git` objects and refs; hidden read-only tests restored at grade time; network
off; a grader check that fails when test files were touched. Apply only the patches the found holes need, then
re-run the gold gate, the empty gate and the same attacker with the same budget. A patch that breaks the gold gate is
rejected and reported. Sandboxes: one branch per patch from the task checkpoint (Docker: a fresh container).

### T07 Certificates and hackability score — size M — todo — needs T06
`cheatproof/certify.py` and `cheatproof/cli.py`: `cheatproof harden <env-id>` writes a JSON certificate (task, image
digest, holes found, patches applied, gate results before and after, attacker model and budget, cost, timestamp) and
`cheatproof report` writes a per-benchmark hackability score with n, raw counts and a 95% interval. Schema is
versioned and tested.

## Milestone: go/no-go 2026-10-21 (attacker passes at least 5 of 40 unhardened tasks)

### T08 Eval run and results with raw counts — size M — todo — needs T01, T07
Run the full loop on the 40 tasks within the $20 cap (check the ledger before starting; stop at the daily cap). Write
`docs/results.md`: method, n, raw counts per attack type before and after, gold and empty gate results, cost per
environment, failures and limits ("upper bound against this attacker, not proof"). Commit the certificates and the
sanitized traces needed for replay.

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
`git log --all --oneline -- LEARNING.md` empty; full-history grep finds no personal details. Report to the owner.

### T13 Learning pack — size M — todo — needs T12
Fill `LEARNING.md` interview questions, complete the glossary, re-read the whole file for accuracy.

### T14 Submit — size S — waiting: owner only — after 2026-10-28
The owner makes the repo public and submits on Devpost. Marked done only on the owner's word.

## USER

- **U1 Nebius Token Factory account, credits and key** (ready 2026-10-16; status 2026-10-18: account exists, billing
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
- **U7 Disk space for the Docker fallback** (ready 2026-10-18; needed by 2026-10-20 if U3 is still pending): free at
  least 30 GB on the Mac (16 GB free on Oct 18) and start Docker Desktop once. Routines cannot delete images or files.
