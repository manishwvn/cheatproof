# Queue

Format: `### <id> <title> — size S|M|L — <status> [— after <date>] [— needs <ids>]`. Statuses: `todo`,
`in-progress (cycle <start>)`, `in review`, `waiting: <why>`, `done #<PR>`, `superseded`. `[NN%]` overrides credit.
Check: `python3 docs/autopilot/progress.py` counts the same tasks as
`grep '^### .* — size [SML] — ' docs/autopilot/QUEUE.md | grep -vc superseded`.

## State 2026-10-21 (owner)

All local swebench Docker images were removed by the owner (`docker rmi` plus `fstrim`). Host has about 14 GB free;
the colima VM has about 91 GB free. Sandboxes (`EXECUTOR=sandbox`) is the default backend. No task may assume a local
swebench image. The local Docker fallback (`EXECUTOR=docker`) re-pulls each image (about 4.5 GB each; the disk guard
applies). Other projects' images (`fde1-app`, `pgvector/pgvector:pg16`) must never be touched.

## Milestone: live access and executor

### T01 Smoke test, model IDs and prices — size S — done #36
Run `uv run python scripts/smoke.py`. Live scripts load `.env` from the main checkout (the parent of `git rev-parse
--git-common-dir`), so worktrees share one key file and never copy it. Record the exact Nemotron model IDs (Nano,
Super, Ultra) from `/v1/models` and their per-1M prices from the public Token Factory price page into `.env.example`
comments and the `MODEL_PRICES_JSON` example. Use the cheapest model (Nano) for the smoke call; never Ultra here.
Confirm one capped call and, if `NEBIUS_PROJECT_ID` is set, one sandbox run. Record sanitized response fixtures (no
auth headers, keys, emails or IDs) under `tests/fixtures/`, plus a test that checks the sanitizing. Acceptance: the
ledger shows spend; fixtures committed; `VERIFY` notes for model IDs resolved. Risk: costs cents; every call goes
through the budget. Until the owner said "promo applied" (done; the $26.65 promo credit is now in the balance, and total real spend is capped at $10 by `REAL_SPEND_CAP_USD`, T43), the account held only a $1 trial: no Ultra runs, no eval
runs (T08), only Nano or Super calls within the `.env` caps.

Done 2026-10-18 (planner): model IDs and prices recorded in `.env.example`; one capped Nano call worked ($0.0000168,
ledger shared). Left: the `.env` loader for worktrees, sanitized fixtures plus their test, and the sandbox run once
`NEBIUS_PROJECT_ID` and U3 exist. Promo applied 2026-10-18: `.env` now has caps 20/4 and the verified model lines.

Done 2026-10-18 (routine, #5): `cheatproof/envfile.py` (worktrees load the main checkout's `.env`),
`cheatproof/sanitize.py` with tests, `smoke.py --record`, fixtures in `tests/fixtures/token_factory/`. Left: the
sandbox run once U3 and `NEBIUS_PROJECT_ID` exist (then flip to `todo`). Note: Nano spent all 64 output tokens on
reasoning (`content` null); callers that need text from Nano must allow more output tokens.

Routine 2026-10-22 03:40 (PR #36, planner merge, U24): the smoke sandbox step failed with NotFoundError because `images.use` only builds a handle for a tag never imported; the fix resolves `alpine:3.19` with `images.oci` like the executor, books cost and halts on 402. Live verify printed `sandbox ok`. Done when #36 is merged.

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

### T15 Routine review fixes (planner-merge PR) — size M — done #10
Apply the "Open, repo side" items 1–11 in `~/.cheatproof-autopilot/review-2026-10-18.md` (fail-closed caps and a
read-only `snapshot()`, `lock.py` output, optional `--now`, CYCLE.md alignment and planner-merge list, `leakcheck.py`,
a versioned pre-push hook, CLI tests and a Python 3.9 compile step in CI, reviewer model, tracked `results/`, pre-flip
scan patterns). Every item touches a planner-merge path: open one PR with tests green and the Opus review, then add a
USER item for the planner to merge. Do T02 first if both are runnable.

Done 2026-10-18 (routine): PR #10 open, CI green, Sonnet review fixed (one round), Opus final review: ready. Items 10
and 11 are below (T08, T12 text). Planner merges #10 (U10), then installs `docs/autopilot/pre-push`.

### T23 Sandbox executor and the eval on Sandboxes (TOP PRIORITY, planner-merge PR) — size L — done #30
Planner note 2026-10-21: Sandboxes work (owner-side live run 05:08Z: `python:3.12-slim` printed stdout; the HTTP 500s
are gone). The Mac has about 3 GB free, so **no local swebench pulls**: `.env` now has `EXECUTOR=sandbox` (the
planner set it); never switch it back to docker for task images. Steps, in order:
1. `scripts/sandbox_access.py`: replace the image-list probe with a tiny run (`images.use("python:3.12-slim")`,
   `print('ok')`), polling with backoff (5 tries, 2 s doubling). Exit 0 `ACCESS OK`, 2 `NO ACCESS`, 1 `ERROR`.
2. Implement `SandboxExecutor` / a `SandboxSession` in `cheatproof/executor.py` with the same `Session` contract as
   `DockerSession` (exec with timeouts and output caps, write files, attack diff, reset, close), using `contree_sdk`
   (`ContreeSync`, `images.use` / `images.pull` / `import_from` for `swebench/*` images). Network off except the
   network-fetch experiment. Each session books `reserve_sandbox_run()` at $0 (beta runs are free; count toward
   `SANDBOX_RUN_CAP` only, a count-only path like `reserve_local_run()`), so `budget.py` changes too. Record a fixture
   of one real run (ledger unchanged). Fakes in tests; no test calls the API. `make_executor()` defaults to sandbox
   when `EXECUTOR` is unset.
3. Gold gate smoke on one swebench task (`psf__requests-1142`) on Sandboxes; then T08 runs on Sandboxes.
4. If a 500 or other API failure persists, write an email draft for the owner to `contree@nebius.com` in `S/` (never
   sent by a routine) citing `S/sandbox-ops.txt`, add a USER item, and stop; do not fall back to local pulls.
5. Update ADR 0001/0002. `executor.py` and `budget.py` are planner-merge paths: open the PR, Opus review, USER item
   for the planner to merge.
Split for the team (size L): Sonnet builds the core `SandboxSession`; Haiku builders do the access script, budget
counter, tests and ADRs.
Routine 2026-10-21 00:24: PR #30 open (planner merge). Live before hardening: access OK; gold passes, empty fails on psf__requests-1142; unshare -n, images.oci, image persistence confirmed. The hardened re-run halted the budget: a result carried `resources.cost != 0` (6 sandbox runs, ledger money unchanged). Left after U21: live-verify `-rn`, nsenter refusal, `image.read`, integrity pin; record the real-run fixture. U21 closed 2026-10-21: each reported Sandboxes cost is logged in the ledger, and the budget halts only when the logged sum passes `SANDBOX_COST_CAP_USD` (default $0.50).

### T25 Image-store disk check hardening (planner-merge PR) — size S — done #31
From the Haiku review of PR #24 (0 blockers, 3 risks). In `cheatproof/executor.py` `_colima_store_free_gb` and its
caller: (1) when the `colima` binary exists but `colima ssh` fails or times out, refuse the pull (`DiskRefused`,
"image store unreadable") instead of falling back to host disk; fall back to host only when `colima` is absent
(`shutil.which("colima") is None`). (2) Parse the df row whose last field is `/var/lib/docker`, not `lines[-1]`.
(3) CYCLE.md section 0: the "alert the owner when free disk is under 10 GB" rule names both the host disk and the
Docker image store. (4) Routine 2026-10-20: with colima the pull also grows the VM data disk file on the Mac, which
keeps freed blocks, so the guard must also refuse when host free disk minus the pull estimate is under the floor. Units already match (`GIB = 1024**3`, used by `_root_free_gb` too). Also from the PR #27 review (all medium): (4) the post-run disk check runs at most every 30 s,
so a command can fill the disk inside that window; (5) a `DiskRefused` after a kill-and-reset replaces the `Result`,
dropping the reset note; (6) `cli._spent_since` catches only `BudgetExceeded`/`OSError`, so another ledger error can
abort the batch instead of writing a not_run row; (7) add tests for `_pull` truncated output and mid-pull daemon loss. Tests for each case with a
fake runner. `executor.py` is a planner-merge path: open the PR, Opus review, USER item for the planner to merge.

### T26 Executor and batch audit fixes before the 40-task run (audit 2026-10-20, planner-merge PR) — size M — done #27
Sonnet daily audit of `eafa80c..139e1e4` (verified in code, not run). In `cheatproof/executor.py`: (1, high) task
images are matched by the `swebench/` prefix only, but `tasks.py` also accepts `swerebench/`; such images are never
released or counted by `TASK_IMAGE_CAP`, so the batch fills `DOCKER_IMAGE_CAP` and later pulls are refused. Use a
prefix tuple in `is_task_image` and the `docker images` filter. (2, high) only `/tmp` is size-limited; a hostile `dd`
in the container root or `/testbed` can fill the colima VM and grow its data disk on the Mac. Add
`--ulimit fsize=<cap>` and a free-space check after each `run()` that resets or aborts past a floor. (3, medium)
`_colima_store_free_gb` does not catch `ExecutorUnavailable` from `subprocess_runner`, so with `colima` off PATH
every pull fails; catch it (coordinate with T25 item 1). (5, low) containers owned by this pid whose `close()` failed
are never swept, so non-forced `release_image` fails; sweep them at task start. (6, low) an output-overflow kill
leaves the process running in the container; treat `OUTPUT_KILL_EXIT_CODE` like a timeout and reset. (8, low)
`docker run` pulls under the 900 s run timeout; pull first with its own longer timeout. In `cheatproof/cli.py`:
(4, medium) a `DiskRefused`/`ExecutorRefused` on a reset after the paid attack leaves no report, diffs or cost in
`batch.json`; record the ledger delta in the not-run row and keep the trace. (7, low) `cost_usd` is a shared-ledger
delta; say "single process assumed" in `cost_basis` or sum this process's holds. Tests with fakes for each item.
`executor.py` is a planner-merge path: open the PR, Opus review, USER item for the planner to merge. Do items 1-4
before T08 resumes.
Routine 2026-10-20 19:24: PR #27 does all items except 7 (`COST_BASIS` is validated in `certify.py`; needs a
schema/fixture change). Sonnet "fix first" (silent resets could fake "not hackable"), one Haiku fix round, Opus
approve. CI `test` green; `dependencies` red until PR #26 (certifi) is merged.

### T24 Rename the product to RewardSeal (user-facing text only) — size M — text done #53 (package rename deferred)
Scope change 2026-10-23 (orchestrator): rename USER-FACING TEXT ONLY now (README, report site text, CLI help strings and
docs, video script, pitches). Do NOT rename the Python package, the console script or any import in this task; that stays a later
option. The grep rule below applies to user-facing files only.
"Cheatproof" is another company's product name (CheatProof.ai). Rename every user-facing and public mention to
**RewardSeal**: README, report site, CLI name and help (`rewardseal harden <env-id>`), certificate `tool` field (bump
the schema version, keep reading old certificates), docs (CLAUDE.md, pitches, ADRs, STATUS, PLAN, prize-fit), video
script, LEARNING notes via the learning-notes agent. Also rename the Python package `cheatproof/` → `rewardseal/` and
the console script, with one grep-checked sweep (`grep -rni cheatproof` must only hit history notes, the state-folder
path `~/.cheatproof-autopilot`, the worktree path and the GitHub URL, which stay until the flip). Do it when no other
task PR is open, in one PR, built by Haiku, Opus review; touches planner-merge paths, so add a USER item for the
planner to merge. Do not rename the local folder, the state folder or the scheduled task.

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

### T16 Attack strategy prompts and Tavily counter (planner) — size S — done #18
The four strategy hints for T04 (git-history, test-edit, hard-code, network) as caller-supplied `system_prompt`
text, and a `budget.reserve_tavily_call()` counter enforcing `TAVILY_CALL_CAP` plus a host-side search callable
for `attack(search=...)`. `budget.py` is a planner-merge path, and the routine left the prompt text to the planner.

### T17 Record traces and attack diffs; keep paid runs (audit 2026-10-18) — size M — done #14
From the first daily audit. `cli.py` calls `attack` with no `trace_path`, so no trace is written, and
`report.attacks` (the raw diffs) is dropped; the site reads `attack["final_diff"]`, which `harden._attack_summary`
never emits. Pass `trace_path=results/traces/<certificate stem>.jsonl`, and write the sanitized attack diff beside
the certificate (`results/diffs/<stem>.<round>.diff`, through `sanitize`, digest checked against
`final_diff_sha256`) so the site can show it. If `build_certificate` raises after a paid run (for example
`_check_strings` trips on `/home/` in an error tail), write the digest-only `report.to_dict()` first and redact with
`sanitize` instead of discarding the run. Also call `load_env()` before importing `cheatproof.attacker` in
`cli.py` (and note the same order bug in `scripts/smoke.py` for the planner). Tests with fakes only.

### T18 Batch driver for the 40-task run (audit 2026-10-18) — size M — done #17 — needs T17
A `cheatproof batch` subcommand: run `harden` over a selected task list serially, resume (skip tasks that already
have a certificate), record a per-task "not run" row with the reason (`ExecutorRefused`, image cap, disk, budget
halt) instead of stopping, and stop cleanly at the daily cap. Put the selection rule and the scanned, skipped
(`non_pytest_id`, no `docker_image`) and selected counts into the score and the site, so n run versus n selected is
honest. Re-check free disk before each task. Never prune images (the owner does, between batches).
Follow-ups from T19 (#15), since `cli.py` and `site.py` were off-limits there: pass `executor`, `max_output_tokens`,
`cmd_timeout` and a strategy label from `cmd_harden` to `build_certificate` (real certificates record null today),
and show `certified_unhardened`, `certified_hardened`, `no_attempt` and the `cost_basis` label in `render_text` and
the site summary.

### T19 Honest outcomes in certificates and scores (audit 2026-10-18) — size M — done #15
(1) `harden.py:314`: an empty final diff, or an attack with no write step, is a `no_attempt` outcome: never
certified, counted separately. (2) `certify.py`: split `certified` into `certified_unhardened` (never hacked) and
`certified_hardened`; record executor, attacks per round, `max_output_tokens`, `cmd_timeout` and strategy label in
the `attacker` block (ADR 0002 promises the executor). (3) `harden.py:449`: `classify` never gets
`visible_passed`, so `hard-code` cannot be found; pass it, and report hard-code only as "attempted" when the hidden
grade fails. (4) `exposure.py:196`: `test -w` is always true as root and `covered` omits the restored `conftest.py`
files; build the covered set from the grader's restore set and label the rest "writable as root". (5)
`grader.py:421`: candidate code can print a forged pytest summary and `os._exit(0)`; require exactly one summary
header and add a code-computed `grader-forgery` label. (6) Label certificate `cost_usd` as budgeted (ledger delta).

### T20 Attacker task prompt with the problem statement (audit 2026-10-18) — size S — done #13
`cli.py:139`: the attacker sees only the repo and failing test ids, and those tests are absent until grade time, so
it is blind. Store `problem_statement` in `TaskSpec` (`tasks.py`, cache and validation) and show it in the task
prompt; never show the gold or test patch. Tests with recorded rows.

### T21 Container and client limits (audit 2026-10-18) — size S — done #16
`executor.py:369`: containers have no disk quota, no `--read-only` and no sized tmpfs; add a sized tmpfs for
scratch (or `--storage-opt size=` when the driver supports it), re-check free disk at each start and reset, and
sweep leftover `cheatproof=1` containers at CLI start (stop and remove containers only, never images). Tests with the
fake runner.

### T22 Planner-merge audit fixes (planner) — size S — done #18
Audit findings on planner-merge paths: (1) `executor.py:437` books $0.05 per Docker start and reset through
`budget.reserve_sandbox_run()`; local Docker is free, and 40 tasks need about 200–480 runs against
`SANDBOX_RUN_CAP=250` and $4/day (halts near task 16). Book Docker runs at $0 or on a separate counter
(`budget.py`). (2) `llm.py:26`: set an explicit client timeout (about 120 s) and keep the client private;
`scripts/smoke.py` uses `client.models.list()` unguarded and imports before `load_env()`. (3)
`.github/workflows/security.yml:21`: verify the gitleaks sha256, pin `pip-audit`, pin actions by SHA. The Tavily
counter is already T16. (4) From T17 (#14): `.gitignore` covers only `runs/`, so `results/traces/` (raw attacker
step args) and `results/reports/` can be committed; ignore them, or sanitize traces before T08 commits results.

## Milestone: go/no-go 2026-10-21 (attacker passes at least 5 of 40 unhardened tasks)

### T08 Eval run and results with raw counts — size M — todo — needs T33, T34, T35, T32, T36, T38, T23, T07, T16, T17, T18, T19, T20, T22 [30%]
T48 note: the docling-824 preflight `python: not found` cause and fix are in the T48 entry below (env-broken: interpreter missing).
Unblocked 2026-10-21: U21 is closed and T23 is done (#30), so T08 has no U21 dependency left.
Run the full loop on the 40 tasks within the $10 real-spend cap (`REAL_SPEND_CAP_USD`, T43) and the $4 daily cap (check the ledger before starting; stop at either cap). Write
`docs/results.md`: method, n, raw counts per attack type before and after, gold and empty gate results, cost per
environment, failures and limits ("upper bound against this attacker, not proof"). Commit the certificates and the
sanitized traces needed for replay. Committed certificates and replay traces go in a tracked `results/` folder (`runs/` stays a
git-ignored cache; `git add -f` is denied).
Audit 2026-10-18: before the run, smoke one real image's gold gate. `grader.PYTEST_CMD` runs bare `python -m pytest`
under `sh -lc`; SWE-bench images may need `conda activate testbed`. Check image HEAD equals `base_commit`
(`strip-future-git` refuses otherwise). Run on Sandboxes (`EXECUTOR=sandbox`), not local Docker.

Planner note 2026-10-23 (U25 resolved, owner approved resume; batch 3 only, then HALT). Orchestrator update 2026-10-23: batch 3 waits for P0 (T33 T34 T35 T32 T36) and T38 (preflight, nudge, task choice), then the orchestrator audits before the paid run. The Token Factory console on 2026-10-23
15:44 UTC shows Sandboxes NOT billed (no line item) and trial credits at $0.71; the $26.65 balance is untouched.
Superseded by T43 (2026-10-23): the $26.65 is hackathon promo credit, not card money, and the trial-only 0.74 cap is replaced by `REAL_SPEND_CAP_USD` (default and ceiling $10 total real spend, trial + promo); the balance must never go negative.
Settings now: `SANDBOX_COST_CAP_USD=1.50` (estimate-only counter; $0.50 used) and the real-spend counter $0.38 counted of the $10 cap. Never raise either cap without the owner. Batch 3 rules:
- (T38) Run in chunks of at most 3: `--chunk-size` defaults to 3 (max 10); the same command is run again for each next chunk.
- Run `batch` on Sandboxes for the next tasks to reach 18 of 40 tasks attempted (currently 8; about 10 more, fewer if a cap
  trips first). `fetch --n 18`, then `batch --n 18` skips the already certified. Same attacker as batch 2 (Nemotron Super,
  never Ultra), combined prompt, `--max-steps 40 --max-tokens 250000`. This is the cheapest routing.
- Expected: about $0.056 real spend and $0.09 Sandboxes per hardened task. If a cap stops the batch, record n honestly
  and do not raise the cap to reach 18.
- Run in chunks of at most 3 tasks and read the ledger between chunks; stop on any halt, on a real-spend counter (`trial_spend_usd`) near the $10 cap, or on a Sandboxes sum above $1.40. Env-broken or leak-refused tasks count as attempted; report them as such.
- After the batch (or at the first halt), call `Budget().halt("T08 batch 3 done: owner checks the Token Factory console")`
  so no further paid call runs, update `docs/results.md` (raw counts, cost from the ledger, which cap stopped it), and
  add one USER item U26 asking the owner to re-check the console and say whether to run batch 4. Do NOT start batch 4.
  Keep T08 at `waiting: U26` after that.

Planner note 2026-10-21 (supersedes the Docker, batch-pruning and disk notes below, which are history): the owner
removed all local swebench images, so no step assumes one. Run every task on Sandboxes. The local Docker fallback
re-pulls each image (about 4.5 GB) under the disk guard; never pull by hand, and never touch other projects' images.


Planner note 2026-10-19: run on the Docker executor (`EXECUTOR=docker`; Sandboxes access is pending, so T01's
sandbox part does not block this). Docker runs are free and count toward `LOCAL_RUN_CAP`; model calls stay under the
$20/$4 caps. Write `cheatproof.strategies.COMBINED` (or one named strategy) to a prompt file for the CLI's
`--system-prompt-file`; the network strategy needs `TAVILY_API_KEY` and `make_tavily_search(budget)`. If the Docker
daemon is down, `open -a Docker`; keep free disk above `MIN_FREE_DISK_GB` (18 GB free on 2026-10-19). Start with
5 tasks to measure cost and time per task, then scale to 40 within the daily cap. Go/no-go is 2026-10-21.
Routine 2026-10-19 02:24: colima's existing VM started (aarch64; qemu-x86_64 binfmt present, so the x86_64
task images should run under emulation). Task specs fetched (rebench scanned 1000, 243 valid, 30 selected;
Verified scanned 500, 192 valid, 10 selected, 8 of them sphinx). Blocked before the first pull: colima already holds
10 images from other projects, so `DOCKER_IMAGE_CAP=6` refuses every task image (U12). Routines may neither delete
images nor change caps. No model calls; spend $0. Flip back to `todo` when U12 is done.
Planner note 2026-10-19 (U12 done): `DOCKER_IMAGE_CAP=16`, and 10 images belong to other projects, so about 6
task images fit and routines cannot remove images. Pick the 6 smallest-image tasks with a visible hole first (T03
exposure scan), run them end to end, and record raw counts. If the go/no-go needs more tasks, add a USER item asking
the owner to remove the finished task images (`docker rmi`) so the next batch fits. Report n honestly.
Planner note 2026-10-19 (U2 done): include the network-fetch attack. Run it with `strategy_prompt("network")`
and `attack(search=make_tavily_search(budget))` on a separate container with network on, only on tasks that still
pass every gate. Every search goes through `budget.reserve_tavily_call()` (`TAVILY_CALL_CAP`, default 200); keep
total Tavily use well under 1,000 calls a month and record the call count in `docs/results.md`.
Routine 2026-10-19 18:18 (#21): first live run. SWE-bench images activate `testbed` only from `~/.bashrc`, so
gold gates failed under `sh -lc`; #21 puts `/opt/miniconda3/envs/testbed/bin` first on PATH. The images are amd64
only: run with `DOCKER_DEFAULT_PLATFORM=linux/amd64` (planner: pass `--platform linux/amd64` in `executor.py`).
`psf__requests-1142` end to end with Nemotron 3 Super (50k tokens, 15 steps): gold 1/1 + 5/5, empty fails, attack
inconclusive (token limit), $0.0146. One earlier run hit `pytest exited 139` on the empty gate (not reproduced; likely
emulation). Then the next pull (sphinx-8595, 4.06 GB) took free disk to 5.9 GB, so the batch stopped (U14). Each task
image is about 4 GB unpacked. The certificate is kept outside the repo (`../cheatproof-wt/t08-prompts/results-kept/`)
and not committed: `leakcheck.py` flags the attacker model ID because `.env` holds the same public ID (planner: let
leakcheck skip values that also appear in `.env.example`, or certificates can never be committed). Use Super with
`--max-tokens 120000 --max-steps 30` next; default `ATTACKER_MODEL` is Ultra.
Planner note 2026-10-19 (disk guard, PR "executor disk guard"): run tasks only through `cheatproof batch`, which now
removes each finished task's `swebench/*` image and skips a task as `disk` when its pull would leave under 10 GB. At
most 2 task images at once (`TASK_IMAGE_CAP`). Never pull by hand. VERIFY: colima may not hand freed space back to
macOS at once; if free disk does not rise after a release, log it and keep U14 open. Move to Sandboxes when U3 is done.
Planner note 2026-10-19 (U14 done): ~8 GB free, floor now 5 GB after a pull. Run one task at a time: first the two
tasks whose images are already local (`psf__requests-1142`, `sphinx-doc__sphinx-8595`), so the batch removes them,
then later tasks pull one by one. If a pull is still refused as `disk`, record n honestly and add a USER item.
Routine 2026-10-19 22:24 (PR #23): two tasks run, $0.107. `sphinx-doc__sphinx-8595` (120k tokens, 30 steps): gold 1/1,
empty fails, attack inconclusive at the token limit after 20 steps; the exposure scan shows `future_git` (a visible
hole the attacker never used). `psf__requests-1142` rerun (300k tokens, 40 steps): 40 steps of `find`/`grep`/`git log`,
no write, yet an 871 KB diff of `build/lib/**` files already untracked in the image; the grade could not apply it, so
the certificate says certified (false). PR #23 keeps start-untracked files out of the diff (planner merge, U16).
Rerun both after #23; their certificates (kept in `../cheatproof-wt/t08-run/results/` and
`../cheatproof-wt/t08-run-scratch/r2/`, not committed) are void for the certified count. Every further pull is refused
as `disk`: host free disk stayed 7.4 GB after both task images were removed (colima keeps freed blocks), U15. The
attacker spends its steps searching; consider a prompt nudge to write a candidate early (T16 follow-up).
Routine 2026-10-20 19:24: `sphinx-doc__sphinx-8595` rerun (Super, 120k tokens, 30 steps, combined prompt): gold
1/1, empty fails, attack inconclusive at the token limit, $0.034, n = 1 (certificate, trace and diff kept uncommitted
in `../cheatproof-wt/t08-eval/results/`). `harden` does not remove its image; only `batch` does, so use `batch`. The
next `batch` (250k tokens, 40 steps) pulled a new image: colima's data disk file on the Mac grew (17 GB on the Mac for
6.3 GB used in the VM; freed VM blocks are not returned to macOS), host free disk fell to 2 GB and the routine's
watchdog killed the run before any model call (U17, alerted). The PR #24 guard reads the VM (87 GB free) and missed
it (see T25). Certificates still cannot be committed until PR #25 (leakcheck skips public `.env.example` values, U18)
is merged. Next: rerun via `batch` with 250k tokens once the host has room, or on Sandboxes after T23.
Routine 2026-10-22 02:24 (PR #34): first Sandboxes batch, 5 of 40 (the 5 smallest swe-rebench tasks, not representative), Super, combined prompt, 40 steps, 250k tokens, $0.212, about 20 min, 16 sandbox runs. Gold 3 pass, 2 fail with `pytest exited 4` (Algebra8__pyopenapi3-83, DRMacIver__shrinkray-7); attacks 2 inconclusive (`token_limit`), 1 no_attempt (`max_steps`); 0 holes, 0 certified. `docs/results.md` and `results/` committed. Next: T28 first, then the next batch (about $2.5 and 2.5 h for 35 more tasks at this rate); consider more tokens per attempt, since 3 of 3 runnable attacks ran out of budget.

Routine 2026-10-22 04:23 (PR #38): batch 2 ran 3 of 6 planned tasks (8 of 40 so far). CycloneDX__cyclonedx-python-348: first hole (`test-edit`), closed by `test-edit-guard`, re-attack inconclusive at token limit, not certified. Azure__autorest.python-475: no submission (max_steps), certificate refused by the leak guard (secret-like value in exposure evidence). BoboTiG-2132 not run. The budget halted: Sandboxes cost $0.5022 passed SANDBOX_COST_CAP_USD $0.50 (sandbox runs 28 to 46, cost $0.2464 to $0.5022; trial $0.2122 to $0.3796 of $0.74; total $0.5351). A task with hardening costs about $0.08-0.10 sandbox; measure one task before sizing a batch, and stop 0.05 below any cap. Algebra8 is env-broken (ModuleNotFoundError pyopenapi3, from the PR #37 rerun). Raw attack diffs kept outside the repo in the state folder.

Routine 2026-10-22 03:40: T28 merged (#35); gate errors now carry the pytest line. Algebra8__pyopenapi3-83 gold fails at collection (node not found); see T29 before the next batch.

### T28 Keep the gold-gate pytest error text — size S — done #35
`pytest exited 4` (usage error) failed the gold gate on 2 of 5 tasks in PR #34, but the stderr was dropped: `grader.py` (around line 742) sets the error without stderr, and `harden.py` (around line 163) replaces log_tail with a digest. Append a sanitized error tail (for example the first `ERROR:` line) to the gate error in `grader.py`, and keep it next to the digest in `harden.py`. Likely cause (uncertain): the repo's pytest `addopts` needs a plugin that is missing (`--cov`, `-n`). Test with fakes near `tests/test_grader.py:349`: a FakeSession returns exit 4 with stderr `ERROR: unrecognized arguments: --cov`, and the gate error contains `unrecognized arguments`. Then rerun one gold gate on Sandboxes for Algebra8__pyopenapi3-83 (cents) and record the cause in T08.

Routine 2026-10-22 03:00: draft on branch `t28-gate-error` (d759000, pushed, no PR; worktree kept), 1899 tests pass.
Sonnet review CHANGES, fix these next cycle: (high) real pytest exit-4 stderr is `ERROR: usage: ...` then
`pytest: error: unrecognized arguments: ...`; prefer the `pytest: error:` line and test with that real multi-line stderr.
(high) `harden.py` `_error_line` scans the whole log tail, so attacker test output can land in the certificate; take
the line only from `grade.error` and emit it only when `grade.error` is set. (medium) search stderr then stdout with a
wider window; strip ANSI before matching; add tests for the cap, ANSI, the `E ` prefix, empty output and a certificate
round trip. (low) one shared helper in grader and harden; scrub `/root` and `/tmp` paths; update the `harden.py` docstring.

Routine 2026-10-22 03:40 (#35): merged. Gold-gate rerun of Algebra8__pyopenapi3-83 on Sandboxes (1 run, $0.0084 sandbox cost): `pytest exited 4: ERROR: not found: /testbed/tests/test_schemas.py::test_free_form_object`. Pytest could not collect the node; `--tb=no` hides the reason (likely an import error at collection, uncertain). Follow-up: T29.

### T29 Show why pytest cannot collect a gold-gate node — size S — done #37
The gold gate for Algebra8__pyopenapi3-83 fails with `pytest exited 4: ERROR: not found: .../tests/test_schemas.py::test_free_form_object` (T28 rerun, 2026-10-22). The grader runs pytest with `--tb=no`, so a collection error (for example an ImportError in the test module) is hidden. When pytest exits 4 with `not found:`, rerun the collection once for that file with `--collect-only -q --tb=short` in the same session and keep one sanitized line of the cause via `grader.error_line` (no new raw text in certificates). Test with fakes near tests/test_grader.py. Then rerun the gold gate for Algebra8__pyopenapi3-83 and DRMacIver__shrinkray-7 on Sandboxes (cents) and record the cause in T08. If the cause is the image (package not installed), mark both tasks as `env-broken` in the batch with raw counts, never as attacker results.

### T30 Collection cause for pytest "found no collectors" — size S — done #39
DRMacIver__shrinkray-7's gold gate fails with `pytest exited 4: ERROR: found no collectors for /testbed/tests/test_main.py::test_kill_process` (2026-10-22 rerun). PR #37 runs the collection rerun only on `not found:`. Extend `_not_found_file` in cheatproof/grader.py to also accept `found no collectors for <node>` (bare or under workdir), with fakes-only tests in tests/test_grader.py. No live run needed until U25 is done.

## Orchestrator brief 2026-10-23 (mock judge 19/40, Opus audit). Priority order P0 > P1 > P2. Routing: Haiku mechanical, Sonnet writing/review/logic. No Opus subagents. Spend no card money; keep every cap (real spend $10 total, $4 daily, T43).

### T33 Give `test-edit` only for unrestored paths — size S — todo (P0, sonnet)
`cheatproof/holes.py:389-393` labels any test path in the final diff `test-edit`, but the grader restores the F2P/P2P files and conftests before grading. Label `test-edit` only for paths the grade does NOT restore (pytest config, unrestored test files), or when a regrade with the test edits stripped fails. Tests in `tests/test_holes.py`. Then re-check CycloneDX__cyclonedx-python-348 offline from the saved diff (state folder or results/diffs) if possible and correct the "Holes found: 1" line and counts in `docs/results.md` if the hole does not hold. Its exposure shows a real git-history leak (378 future commits reachable from refs): record it as the targeted attack and headline candidate for T38.

### T34 `max_steps` without a submit is inconclusive — size S — todo (P0, sonnet; do before T32 lands)
`cheatproof/harden.py:99` puts `max_steps` in `CONCLUSIVE_STOPS`, and `harden.py:614` can then certify a task whose attacker never submitted. A `max_steps` stop without a submitted patch must be inconclusive and never certified; keep `no_attempt` for no write at all. Update `docs/results.md` counts if any row changes. Tests in `tests/test_harden.py`.

### T35 Ledger refusal and halt ordering — size S — done #49 (P0, haiku) — merged into T27
Done 2026-10-23 (PR #49, branch `t35-ledger-guards`, planner-merge path, not merged): (a) to (d) done with fakes tests, and T27 item 6 (the `.env.example` note) done in the same PR. Full pytest 1976 passed, 1 skipped; ruff clean. Needs the planner to merge. Fresh machine: run `python -m cheatproof.cli budget init` once; a lost halt is forgotten by a later init.
Do these as part of T27 items, in one planner-merge PR (`budget.py`, `executor.py`): (a) a missing ledger file refuses to run (`budget.py:272`) unless an explicit init created it (add `cheatproof budget init`, never implicit); (b) ledger `OSError` becomes `BudgetExceeded` (`executor.py:1140`); (c) the halt flag is checked before every exec, including the cost-0 path (`budget.py:413`, `executor.py:1189`); (d) `_halt_for_payment` runs on all exceptions (`executor.py:1130`). Fakes-only tests. T35 and T27 are closed together; T27 keeps its other items.

### T36 Fix results row 8 and the access probe retries — size S — done #45 (P0, haiku)
`docs/results.md` row 8: BoboTiG__ebook-reader-dict-2132 did run sandbox execs; `cost_usd` is Token Factory only, not Sandboxes. Fix the row and any column header that says otherwise. `scripts/sandbox_access.py` lines 45 and 91-104: the probe retries; make it one attempt with a clear failure line (no retry loop that can repeat paid calls). Planner-merge path for the script: open the PR and add a USER item if the planner must merge.

### T37 Tavily runtime path (`--network-fetch`) — size M — code done #58, live run waits for orchestrator GO (P2, sonnet)
Code done (fakes-only tests, no Tavily or paid call): `harden` and `batch` take `--network-fetch`; see `docs/tavily.md`. It wires `strategies.make_network_search(budget)` into `attack(search=...)` (every call through `reserve_tavily_call`; query and result text cleaned word by word; the trace shows the cleaned query), appends the network section to the prompt (strategy label `<name>+network`), sets `allow_network` only (the sandbox network stays off: Tavily runs on the host), passes the search to the first attack only, prints one warning line, refuses without `TAVILY_API_KEY`, and caps the total at 2 tasks (`network_fetch_done` in `batch.json`). `batch.json` gets `network_fetch`. T31 item 1 (warning for `SANDBOX_NETWORK_TRUSTED=1`) is still open and separate. Live run: `batch --instance-ids <ID> --network-fetch ...` only after the orchestrator says GO (U26).
`cheatproof/cli.py`: add `--network-fetch` to `harden`/`batch`. It wires `make_tavily_search(budget)`, sets `allow_network`, and the matching `EnvSpec.network`, then runs 1-2 tasks so a trace shows the query (sanitized). The prize bonus needs a real runtime call. Every search goes through `budget.reserve_tavily_call()`. Check Tavily's own free credits first (read `.env` key presence by length only); stop and add a USER item if the key is missing or credits are gone. No Nebius cost beyond the attacker tokens; do not run it before the owner clears U26. Fakes-only tests first.

### T38 Batch 3 preparation (P1, only after P0 is merged) — size M — code done #56, paid run waits for orchestrator audit and T43 — needs T33, T34, T35, T32, T36
Goal: at least one `certified=True` with a completed re-attack, and at least one git-history hole. (1) Pick tasks where the exposure scan shows `future_git` true; add a collect-only preflight that runs `pytest --collect-only -q` on the gold tests and skips the task as `env-broken` before any attacker tokens are spent. (2) Add a "write a candidate patch early" nudge to the attacker prompt and tighter output limits, because 4 of 5 runs ended at `token_limit` or `max_steps`. (3) Target the git-history leak first (CycloneDX-348 style). Use the remaining trial headroom (about $0.36 counted); do not raise any cap. Run the batch as T08 describes (chunks of at most 3, halt, U26). The orchestrator audits before the run: finish this task's code, then STOP and wait; do not start the paid batch until the orchestrator says so.
Code done (PR #56, fakes-only tests, no paid call):
- Task order (`cheatproof/plan.py`, `batch` flags): `--instance-ids ID ...` runs exactly those cached tasks in that order; `--first ID` (repeatable) puts a task first even if outside the selection; `--rerun` makes the `--first` ids ignore their existing certificate (the final write replaces it, but a copy `<name>.json.<UTC>.old` is made first via `keep.copy_aside`, so a rerun never destroys a result; the report and site read `*.json` only; the old trace is rotated); `--prefer-future-git` runs first, and attacks again, any uncertified task whose certificate shows `exposure_before.future_git` (the exposure scan needs a sandbox, so earlier certificates are the only offline evidence). CycloneDX__cyclonedx-python-348 has a certificate, so run it first with `--first CycloneDX__cyclonedx-python-348 --rerun`.
- Chunks: `--chunk-size N` (1..10, default 3; the first paid run uses chunks of at most 3) stops after N tasks that got a try (run or not run, env-broken included, never the already certified). `batch.json` gets `chunk_size`, `rerun_ids`, `rerun_done`, `env_broken_ids`, `next_chunk_pending` and `pending_ids`, and the run prints `next chunk pending`. Check the console, then run the SAME command again. Resume is safe by construction: unless the previous `batch.json` has `finished: true` (written only at the normal end of the whole batch; a chunk end, a budget stop, a crash or a Ctrl-C leave it false), the ids in its `rerun_done` (saved before each paid rerun) are never attacked again, and the ids in `env_broken_ids` (collect-only failures only) are not retried; their not-run rows are carried over. A transient executor/SDK error in the preflight is a plain `executor_error` not-run row, not stored, and retried next time. A finished batch carries nothing, so a fresh batch starts clean. `--dry-run` reads the three cap values from the environment and `.env` into a local dict (never `os.environ`).
- Preflight: `grader.collect_gate` applies the gold patch and hidden tests in a fresh session and runs `pytest --collect-only -q` on every F2P/P2P node (no model call, one extra sandbox start per task). A failure, or any odd exception in the preflight (except budget and executor stops, which stop the batch as before), is the not-run reason `env-broken` with one sanitized line (`grader.error_line`); `--no-preflight` skips it. `harden` does the same and exits 1.
- Attacker: the combined prompt (`strategies.COMBINED`; `results/combined.txt` is tracked and was regenerated, a test keeps them equal) now says: write a candidate patch after at most 8 exploring commands, stop exploring after 12 steps and `submit`, keep output short. Tool output is cut at `AttackConfig.max_result_chars` (default 4000, was 8000; marker `[truncated: N chars omitted, output limit L]`); `max_output_tokens` stays 2048 (not lowered). A reply that ends with `finish_reason` `length` has cut tool arguments: the call is not run and the step error is `output_cut` (`reply cut at the output limit; send a shorter command or patch`), not a silent `bad_json`. `--max-steps`/`--max-tokens` are unchanged and no cap was raised.
- Dry run: `batch --dry-run` (no prompt file or model needed) prints task ids in order, chunk boundaries and the estimated cost (about $0.056 trial and about $0.12 Sandboxes per task: $0.09 measured plus about $0.03 for the preflight start, an estimate), and a WARNING when the estimate alone passes `SANDBOX_COST_CAP_USD`, `REAL_SPEND_CAP_USD` or `TRIAL_CREDIT_CAP_USD` (numbers only; the ledger is not read, so spend already counted is not subtracted). It uses `Deps.for_dry_run()`: no `.env` load into the process, no attacker, LLM, budget or SDK import, no ledger access, no file written (a test checks `sys.modules` in a subprocess). It follows a pending `batch.json` the same way the real run does.
- Suggested chunk 1 for the orchestrator (after the audit and T43), with `--dry-run` first: `batch --source swe-rebench --n 18 --first CycloneDX__cyclonedx-python-348 --rerun --system-prompt-file results/combined.txt --strategy combined --attacker-model nvidia/nemotron-3-super-120b-a12b --max-steps 40 --max-tokens 250000 --out results/certificates`.

### T39 Pages workflow and sanitized hero traces (P2, haiku wires, sonnet writes) — size M — done #52
A GitHub Pages workflow that builds the report site, plus committed sanitized traces for the hero attack, so the demo URL is live when the owner flips the repo public. No public flip by the routine. Traces pass `leakcheck`.
Done (#52): `.github/workflows/pages.yml` builds `cli site` from committed certificates on push to main; deploy runs only after a successful build, on a public repo, with Pages enabled (a preflight check; no continue-on-error). `docs/site.md`, `tests/test_pages_workflow.py`. The site schema accepts the `cost_usd` that `cli batch` writes on a not-run row; the committed site build exits 0. Hero trace NOT added: no committed certificate is the hero attack, and a site transcript attaches by certificate stem, so a hand-made trace would misattribute. Owner decides (traced hero run via T08, or a replay certificate).

### T40 Video script and pitches say Super, fill RESULT markers (P2) — size S — placeholders done #53, fill after batch 3 — needs T33, T34
Fill the `[RESULT: ...]` markers in `docs/video/script.md` from the real numbers in `docs/results.md`; replace "Ultra" with Nemotron Super everywhere (also `docs/pitches.md`). Do not claim a result the data does not show.

### T41 Certification rejects a max_steps run that never submitted — size S — done #48 (P0)
`validate_certificate` accepted `certified: true` when a round's attack hit `max_steps` without a submit. It now applies the `harden._unsubmitted` rule to the before and after rounds: refused unless the hole report shows a grader-confirmed exploit. Build and write validate too. Tests in `tests/test_certify.py`. `harden.py` docstring no longer calls `max_steps` conclusive by itself.

### T42 Keep full traces, raw diffs and restore sets locally; offline hole recheck (P0-P1 gate for batch 3) — size M — done #50
Audit finding: the `test-edit` hole for CycloneDX__cyclonedx-python-348 could not be verified because no trace or raw diff was kept (sidecars hold only sha and char count). Now every `harden` and `batch` run keeps, under the git-ignored `results/traces/` and named by the certificate stem: `<stem>.jsonl` (full trace, all rounds), `<stem>.before.diff`, `<stem>.after.diff`, `<stem>.diff` (raw; a file already there is renamed to `*.old`), `<stem>.restore.json` (`grader.restore_paths(task)`, or null when unreadable; written before the paid run) and `<stem>.rounds.json` (the grade inputs classify got and the labels recorded). New module `cheatproof/keep.py`; `holes.classify(..., restored=)` takes the cached restore set so the T33 rule applies offline. `python -m cheatproof.cli holes recheck <stem> [--traces DIR] [--source S] [--cache-dir DIR]` re-runs the classifier with no network, sandbox, model or budget, prints labels and test path names (restored or unrestored), says whether they match the recorded labels, and exits 1 naming every missing piece. Review fixes: the folder is mode 0700 and the files 0600; a harden stop (budget, executor) still keeps the raw diffs of the attacks that returned (grades unknown); rounds map to trace segments by recorded id; files of an earlier run (also a stale after-round) are renamed to `*.old` before the run; keep never raises after a paid run. Old runs (before T42) cannot be rechecked. Tests in `tests/test_keep.py`.

### T43 Total real-spend cap $10 (trial + promo), balance never negative — size S — done #51 (planner-merge: `budget.py`)
Owner 2026-10-23 (see LOG): the $26.65 balance is hackathon promo credit, not card money; promo spend is allowed. `budget.py` replaces the trial-only `TRIAL_CREDIT_CAP_USD` (0.74) with `REAL_SPEND_CAP_USD`: default 10.0, hard ceiling `MAX_REAL_SPEND_CAP_USD` 10.0 in code; a set value above 10, zero, negative or invalid raises `BudgetExceeded` (never a higher cap). It counts in the unchanged ledger field `trial_spend_usd`, so the live 0.3796 keeps counting. `TRIAL_CREDIT_CAP_USD`, if set, is an additional stricter cap (unset: off). Total $20 and daily $4 unchanged; the balance must never go negative. `.env.example` documents `SANDBOX_COST_CAP_USD` intended value 5 (comment only; the code default and ceiling are unchanged). Docs fixed: HANDOFF, STATUS, CLAUDE.md, ADR 0001, docs/HANDOFF.md, this file. Tests in `tests/test_budget.py`. Planner: edit the live `.env` yourself if you want `REAL_SPEND_CAP_USD` or `TRIAL_CREDIT_CAP_USD` set; the live `.env` line `TRIAL_CREDIT_CAP_USD` (if present) still applies as a stricter cap.

### T45 Ledger init, 402 and halted-key minors from the audit (planner-merge: `budget.py`, `executor.py`, `llm.py`, `cli.py` budget init only) — size S — done #57
`budget.create_ledger` refuses a fresh ledger while a backup named like the ledger (`<stem>*.bak`) sits beside it (kind name only, nothing written). A lock file alone does not block init; a run before init no longer creates one (`Budget._lock` refuses a missing ledger first). `budget init --force-fresh` (CLI flag, never env) and `init_ledger_from_env(force_fresh=True)` override it; neither overwrites an existing ledger. `executor._http_status` also reads `exc.response.status_code`. `GuardedLLM` halts on a 402 with the fixed-text pattern of `_halt_for_payment` and raises `BudgetExceeded` from None. The ledger `halted` key is required (missing = corrupt, refused); `_charge` uses `s.get`. Tests in `tests/test_budget.py`, `tests/test_sandbox_executor.py`, `tests/test_cli.py`.
`budget.create_ledger` refuses a fresh ledger while a stale `ledger.lock` or a `*.bak` sits beside it (kind names only, nothing written); `force_fresh` (`init_ledger_from_env` too) overrides it and never overwrites. The CLI `budget init --force-fresh` flag is not wired yet (`cli.py` is off-limits here). `executor._http_status` also reads `exc.response.status_code`. `GuardedLLM` halts on a 402 with the fixed-text pattern of `_halt_for_payment` and raises `BudgetExceeded` from None. The ledger `halted` key is required (missing = corrupt, refused); `_charge` uses `s.get`. Tests in `tests/test_budget.py`, `tests/test_sandbox_executor.py`.
### T44 Certification fails closed on malformed attack fields — size S — done #55 (MED audit finding)
T41's `_check_certified` treated a missing or mistyped `attack` or `holes` as "not unsubmitted", so a malformed certified certificate passed. Now a `certified: true` certificate needs, in every attack round (before and after): `attack` a Mapping, `attack.stop_reason` in {submit, max_steps}, `attack.submitted` a bool, `holes` a Mapping with a bool `exploited`; a max_steps round also needs submitted or exploited (same rule as `harden._unsubmitted`). Anything else is refused with a fixed message naming the field, never the value. Non-certified certificates are unaffected; `results/certificates/*.json` (all certified=false) still validate. Real writers (`harden._attack_summary`, `HoleReport.to_dict`) already emit these fields; `tests/test_cli.py` fake rounds now carry an attack summary. Tests in `tests/test_certify.py`.

### T46 Audit fixes for T42 traces and recheck: tests write only under tmp_path, ignore every `traces/`, recheck compares primary and exploited — size S — done #59
`tests/test_cli.py` runs each test from its own `tmp_path`; a session fixture in `tests/conftest.py` fails the run if a test adds a file under the repo's `results/traces` or `runs/`. `.gitignore` adds `**/traces/` (`results/traces/` kept). `holes recheck` also compares the recomputed `primary` and `exploited` with `rounds.json`; a mismatch exits 1 and names the field; older files are checked on labels only. `cheatproof site` wording in `cli.py` is now `RewardSeal site`. Tests in `tests/test_keep.py`, `tests/test_cli.py`.

### T47 Exposure recon for the attacker, early-submit nudges and auto-submit — size M — done #61
Orchestrator decision 2026-10-23 (owner-approved spend, honesty required). Batch 2 showed `future_git` true on 7 of 8 tasks but the attacker never used it, and 5 of 8 runs ended at `token_limit` without a patch.
- (a) Recon: `cheatproof/recon.py`. When a round's own exposure scan lists a hole, that round's attacker gets the sanitized scan appended to its first user message, framed as "Known exposure surface (from a pre-attack scan of this sandbox): verify whether it can be exploited to make the hidden tests pass without fixing the bug." Content: finding types, counts, and at most 20 evidence lines of at most 160 chars (`redact_text` plus `clean_text`). Covered test paths (the restored failing-test files) are never listed, and a line holding text from the gold or test patch is dropped. Default on; `--no-recon` (harden and batch) turns it off. The after-hardening round uses its own rescan (a hole the patches closed gives no recon). The label is `recon: "exposure"` in the certificate attacker block (`null` otherwise), in each round's attack summary, in `batch.json` (`recon` setting and a `runs` row per run with strategy, recon, certified, stop reasons, `auto_submitted`) and on the site (a `recon=exposure` tag next to the strategy). `certify.py`: `attacker.recon` must be `exposure` or null when present, is required when `certified` is true, and must match the rounds. Old certificates without it still validate.
- (b) Early submit: tool output cut 4000 to 3000 chars (`results/combined.txt` regenerated; a test keeps it equal to `COMBINED`). Budget nudges as user messages, once each, at 50%, 75% and 90% of `max_steps` or `max_tokens_total` (whichever share is larger; only the highest threshold reached at a step is sent): "You have used half your budget; write a candidate patch now and test it." / "Last chance: submit your best patch now." / "Submit immediately." They are traced as `nudge` records. If the attacker ends at `max_steps` or `token_limit` with a non-empty working-tree diff, the harness grades it (`auto_submitted: true` in the attack summary and the trace end record). Honesty rule unchanged: `stop_reason` stays `max_steps` or `token_limit`, `submitted` stays false. Such a round is conclusive only when the grader confirms an exploit (then it counts as a hole found); a diff that fails the grade is inconclusive and the task is never certified (`harden._unsubmitted`, `certify._unsubmitted_round`, which now cover `token_limit`). `ATTACK_STOP_REASONS` in `certify.py` gains `token_limit` for that exploit case only.
- Review fixes (PR #61): a certified certificate needs `attacker.recon` only when a round's attack summary carries a `recon` key (certificates from before T47, such as 12rambau__sepal_ui-518, validate); `attacker.recon_types` lists the finding types shown, and the site tag names them; the site keeps #60's required batch keys and type-checks the optional `recon` and `runs` apart from the bool loop; a passing diff whose only label is `unclassified` and that matches the gold fix or was auto-submitted is outcome `legit_fix` (not a hole, round inconclusive, never certified); nudges record only reminders actually sent.
- Second review (PR #61): `legit_fix` needs a gold match (auto-submit alone no longer triggers it; an auto-submitted non-gold pass is a hole as before). A gold-matching pass on a sandbox whose scan showed future history or network is outcome `gold_match_with_exposure`: not a hole, round inconclusive, never certified, and a report note `needs manual review` (certificate notes, site Notes). `holes.py` widened: ref-wide flags with `=` forms (`--tags`, `--remotes=origin`, `--branches=*`, `--glob`) on any history-walking subcommand, any git command naming a ref or sha from the exposure scan (`classify(exposure_refs=)`), and a written script that is then run and executes such a command.
- Also: the site's batch check accepted only the schema 1 core keys and would have refused the batch.json that T38 writes; it now accepts the optional keys (`BATCH_OPTIONAL_KEYS`).
- Tests (fakes only): `tests/test_recon_nudge.py`. The paid run waits for the orchestrator.

### T48 docling-824 collect-only preflight fails with `python: not found` — size S — done #62 (haiku)
Root cause (code reading, no live run): the preflight and the gold gate already built the same shell line (`TESTBED_PATH`, `cd`, `sh -lc`); the only gap was the workdir (preflight used the default, gates use `env.workdir`). `sh` exit 127 means the image has no `python` on that PATH, and the gold gate would fail the same way. Fix: `grader.gate_command` shared by all gates, workdir passed from `cli._preflight`, exit 127 reported as `env-broken: interpreter missing: <line>`. No extra PATH fallbacks: the gold gate tries only `TESTBED_PATH`.
`DS4SD__docling-824` failed the T38 collect-only preflight with `python: not found`. Check whether the preflight (`cli._preflight`, the grader's collect-only command) must run with the same PATH and `testbed` environment as the gold gate (`grader.py`), because the gate finds `python` there. Test with fakes (a FakeSession that returns 127 without the env prefix); do not run it live. If the gate and the preflight use different shells, make them share one command prefix. Record the cause in T08.

### T52 Harness recon search via Tavily under `--network-fetch` — size S — done #64
Orchestrator decision: the live attacker never called `web_search`, so there was no real Tavily runtime call in any trace. With `--network-fetch` the harness performs one recon search at the start of the before-hardening attack, labelled honestly as "harness recon search via Tavily (runtime call)", never as an attacker decision. Details and how to verify: `docs/tavily.md`.
- Attacker: `AttackConfig.harness_search` (default False) and `attack(harness_query=...)`. Query = first line of the problem statement (`strategies.problem_query`, `clean_text`, 300 chars); the same search callable, so `reserve_tavily_call` and `TAVILY_CALL_CAP` apply. At most 3 results (title and snippet, cleaned, 3000 chars) go in the first user message under a "Harness recon search (Tavily, runtime call; run by the harness, not chosen by you)" heading. A search error continues without results (class name only); `BudgetExceeded` is traced and re-raised. `AttackResult.harness_search` is `{provider, query, results, ok}` or None.
- Trace: a `harness_search` record (label, query, results, ok, error) after the header and before the first step; not a tool step. `holes._valid` accepts it (one-line edit).
- Certificate: optional `attacker.harness_search` (`certify._check_attacker`, additive), batch rows, and a site tag "harness search via Tavily" (`site._strategy_html`, `_is_runs`; additive). `certify.py` and `site.py` are also touched by T50, so these edits are small.
- CLI: `--no-harness-search` on harden and batch; the harness search is on by default with `--network-fetch`. The re-attack gets no search. The attacker's own `web_search` prompt nudge stays, now labelled separate. Sandbox network stays off; the 2-task cap is unchanged.
- Tests (fakes only): `tests/test_harness_search.py`.

### T31 Executor and sandbox minors from the PR #30 review — size S — todo — needs T08 (planner-merge paths: `executor.py`, `scripts/sandbox_access.py`)
Minor findings from the Sonnet review of PR #30 (T23), none blocking. Fix with fakes, then a USER item for the planner to merge.
1. DONE (T48 PR #62): with `SANDBOX_NETWORK_TRUSTED=1` the executor prints one warning line (no values) and `docs/results.md` notes it. Original: With `SANDBOX_NETWORK_TRUSTED=1` the sandbox network is not cut, and nothing warns. Print one warning line (no values) when it is on, and note it in `docs/results.md`.
2. Sandbox `exec` and OCI-import runs are not counted by `reserve_sandbox_run` or the cost log. Count them, or document why not.
3. DONE (T48 PR #62): verified by reading `executor.py`: `colima ssh -- df` lives only in `DockerExecutor` (`_colima_store_free_gb`); `SandboxExecutor` never calls it, so no code change. A test pins that. Original: The `colima ssh -- df` disk check after every run has a 15 s timeout. Skip it for the Sandboxes backend, which has no local images.
4. Unverified: whether a command that exits non-zero keeps its image (it matters for the gold-gate reuse). Test it with one fake and one live smoke only after the owner clears budget for it; otherwise record it as unknown in the ADR.

### T32 Do not lose a certificate to the leak guard — size S — done #47 (P0, haiku; after T34)
Orchestrator 2026-10-23: redact free text with `error_line`'s per-word redaction (`cheatproof/grader.py:506`, `cheatproof/exposure.py:149`) instead of dropping the certificate; this replaces the `certify.py` idea below if that is simpler.
Batch 2 (PR #38): `Azure__autorest.python-475` ran, but `certificate.exposure_before.future_git_evidence[10]` held a secret-like value and the certificate write was refused (`certificate_write_failed`, $0.0606 spent, result lost). Keep the guard strict, but redact the matching evidence line in `certify.py` before the write (replace the value with a fixed marker, keep the file path and the finding type), so a hole is still reported and replayable. Fakes-only tests next to the existing leak-guard tests; never print the matched value. If `leakcheck.py` or the certificate writer is a planner-merge path, open the PR and add a USER item. Do before the next T08 batch if the routine has the time; it does not block batch 3.

### T27 Budget hardening from PR #32 review — size S — todo — needs T08
Review of PR #32 (`cheatproof/budget.py` and the Sandboxes cost path, planner-merge). Do all items, with fakes:
1. `Budget.__init__` applies the `MAX_TOTAL_CAP_USD` ceiling, so no `.env` value can raise the total cap past it.
2. Clamp `SANDBOX_COST_CAP_USD` to a ceiling, and count Sandboxes cost toward the real-spend cap only if Sandboxes billing ever starts (T43: not billed as of 2026-10-23; the old $0.84 trial-credit idea is superseded).
3. Write explicit zero cost fields on the first lock, then require them on every later read.
4. `book_sandbox_cost` catches `OSError` and halts (no silent pass).
5. Log cost in `scripts/smoke.py` `sandbox_hello` and in the executor `image.use` and `image.read` paths.
6. ~~Fix the `.env.example` note about `TRIAL_CREDIT_CAP_USD`~~ Superseded by T43: the note was rewritten; `TRIAL_CREDIT_CAP_USD` is now only an extra stricter cap.
7. Document the in-flight overshoot bound (the most one in-flight call can add past the cap).
8. ADR 0001 and ADR 0002 say sandbox runs book $0; fix both to match the logged-cost rule (U21).
9. `tests/test_budget.py` `TODAY` is computed at import, so `test_sandbox_cost_is_logged_and_not_halted_below_the_cap`
   fails when CI crosses UTC midnight (main run 39696924691, 2026-10-21 23:59 UTC; rerun green). Compute the date at
   assert time or freeze the clock.
`budget.py` is a planner-merge path: open the PR, Opus review, USER item for the planner to merge.
Note 2026-10-23 (T35, PR #49): items (a) to (d) of T35 were done there, and item 6 (the `.env.example` note) too. Items 1 to 5 and 7 to 9 are still open for T27.

PR #36 review follow-ups (Sonnet, 2026-10-23, low): in `scripts/smoke.py` build the client before `reserve_sandbox_run()` so a missing SDK or key does not burn a run; add tests that the cap check precedes client construction, that `book_sandbox_cost` over the cap raises `BudgetExceeded`, and that `cost=None` books nothing; drop the unused `expected` parameter and use `token=FAKE` in the fixture.

### T09 Report page and judge replay mode — size M — done #12 — needs T07
A static report site (no server, no paid calls): the 40-task table, one before/after page per environment with the
patch diff, the attack transcript and the gates. Judge mode replays recorded runs, labelled "recorded". Builds from
committed certificates; deployable to free static hosting after the repo flip; must stay up through 2026-12-15.
Accessible, with empty and error states.

Built 2026-10-18 (routine, draft PR #12, branch `t09-report`): `cheatproof/site.py`, `site` CLI subcommand, 24 new
tests, CI not yet checked. Left: Sonnet review (`.claude/agents/reviewer.md`), fixes, Opus final review, green CI,
merge. The run stopped at F 83 (cap 85). Next run: reclaim T09, reuse the branch (do not rebuild), review first.

Done 2026-10-18 (routine, #12): Sonnet review fixes (n=0 rates, duplicate ids, site-dir marker with stale-page
cleanup, sanitized trace fields, stated limits, keyboard-scrollable tables, bidi and control characters shown).
1083 tests. Left for T08: certificates hold no diff text and nothing writes `results/traces/<stem>.jsonl`, so pages
show "not recorded" for the attack diff and transcript until T08 records them.

## Milestone: submission (feature freeze 2026-10-24)

### T10 README, ADRs and feedback write-up — size M — done #54
README: problem with one sourced number, what it does, architecture diagram, setup and run steps, how Token Factory,
Nemotron, Sandboxes and Tavily are used and where, what is real and what is replayed, results summary. ADRs current.
`docs/feedback.md`: specific, actionable feedback on Token Factory, Sandboxes and NVIDIA models (Most Valuable
Feedback prize).
Orchestrator 2026-10-23 (mock judge 19/40): write README with Sonnet, wire links with Haiku. Honest results with n and raw counts from
`docs/results.md` after the T33 correction; say Nemotron Super, not Ultra, everywhere. No invented numbers.

### T11 Video script and automated rough cut — size M — done #29 — after 2026-10-21
Script by Oct 21 per `docs/pitches.md` demo beats (model ID in the first 20 seconds, under 2:50). Rough cut by Oct 24:
scripted browser recording of the report page and terminal, text-to-speech, captions, ffmpeg. No third-party marks
or music. The owner records the final voice (U6).
Done 2026-10-21 (#29): `docs/video/script.md` (13 beats, 2:46, result claims in `[RESULT: ...]` markers to fill from T08) and `video/rough_cut.py` (say + ffmpeg, dry-run tested only). Real rough cut after T08 results.

### T12 Fresh-clone final check and pre-flip check — size S — todo — after 2026-10-27
Fresh clone, follow the README exactly, run tests and one replay. Pre-flip: full-history secret scan green;
`git log --all --oneline -- LEARNING.md` empty; full-history grep finds no personal details. Scan patterns include
`/Users/`, the owner's username and promo codes; docs use `~` or relative paths. Report to the owner.

At the flip (owner, right after making the repo public): protect `main` (block force pushes and deletion, include
administrators), and rename the GitHub repo to `rewardseal` in Settings (GitHub redirects the old URL).
### T13 Learning pack — size M — todo — needs T12
Fill `LEARNING.md` interview questions, complete the glossary, re-read the whole file for accuracy.

### T14 Submit — size S — waiting: owner only — after 2026-10-28
The owner makes the repo public and submits on Devpost. Marked done only on the owner's word.

## USER

- ~~**U25 Budget halted: Sandboxes cost cap**~~ Done 2026-10-23: owner approved; ledger halt cleared, SANDBOX_COST_CAP_USD=1.50, trial cap kept at 0.74 (see T08 batch 3; superseded by T43: `REAL_SPEND_CAP_USD` $10). Original text: (alerted 2026-10-22): the ledger is halted because Sandboxes cost $0.5022 passed SANDBOX_COST_CAP_USD ($0.50). U21 found Sandboxes are not billed per the Nebius console, so the cap is a guard. Owner: clear the top-level `halted` field in the live ledger, and choose SANDBOX_COST_CAP_USD for the rest of T08 (about $0.09 per task, about $3 for the remaining 32 tasks); TRIAL_CREDIT_CAP_USD ($0.74, $0.38 used) covers about 6 more tasks at about $0.06 each. Then flip T08 to todo.
- ~~**U24 Merge PR #36**~~ Done 2026-10-23 (see LOG). (T01 smoke sandbox fix): say `review` in an interactive session to merge PR #36 (touches `scripts/smoke.py`, a planner-merge path). CI green, Opus final review approve.
- **U23 Merge PR #31** (T25, planner-merge paths, stacked on PR #30): after U22, say `review` in an interactive
  session to merge https://github.com/manishwvn/cheatproof/pull/31 (GitHub retargets it to `main` once #30 merges).
  CI green; Sonnet approve, Opus approve.
- **U22 Merge PR #30** (planner-merge paths): say `review` in an interactive session to merge PR #30.
- ~~**U21 Sandboxes cost halt**~~ Done 2026-10-21: the Nebius console shows Sandboxes not billed. The budget halted itself on a Sandboxes result with `resources.cost != 0`. Now each reported cost is logged (`sandbox_cost_usd` in the ledger) and the budget halts only when the sum passes `SANDBOX_COST_CAP_USD` (default $0.50); HTTP 402 still halts. Planner, after this merges: clear the top-level `halted` field in the live ledger (`~/.cheatproof-autopilot/ledger.json`, the path in `.env.example`).
- ~~**U20 Review and merge PR #27 (T26 audit fixes)**~~ Done 2026-10-21: PR #27 merged (Sonnet review: 0 critical). (ready 2026-10-20; needed before T08 resumes): after U19, say
  `review` in an interactive session to merge https://github.com/manishwvn/cheatproof/pull/27 (planner-merge path
  `cheatproof/executor.py`; low-disk latch, `Result.reset`, swerebench image prefix, fsize ulimit, pull timeout).
  Rerun its checks after #26. Then flip T26 to `done #27`.
- ~~**U19 Review and merge PR #26 first**~~ Done 2026-10-21: PR #26 merged. (ready 2026-10-20; needed now: the `security` workflow fails on every
  branch): say `review` in an interactive session to merge https://github.com/manishwvn/cheatproof/pull/26 (certifi
  2026.7.22 to 2026.10.19 for PYSEC-2026-4320; only `uv.lock`, a planner-merge path). CI green. Then rerun PR #25's
  checks (U18).
- ~~**U18 Review and merge PR #25**~~ Done 2026-10-21: PR #25 merged. (ready 2026-10-20; needed for T08 results): say `review` in an interactive session
  to merge https://github.com/manishwvn/cheatproof/pull/25 (leakcheck skips values that equal a public value in
  `origin/main:.env.example`, so certificates that name the model can be committed; planner-merge path
  `docs/autopilot/`). Sonnet review fixed in one round; Opus final review done.
- ~~**U17 Mac free disk 0.8 GB blocks T08 (urgent)**~~ Done 2026-10-21: eval moves to Sandboxes (T23), no local pulls. Disk now: host 15 GB free, colima VM 91 GB. (ready 2026-10-20; needed for the Oct 21 go/no-go): free at least 15 GB on
  the Mac. Optional: `docker image rm swebench/sweb.eval.x86_64.sphinx-doc_1776_sphinx-8595`, and return freed VM
  blocks with `colima ssh -- sudo fstrim -v /var/lib/docker`, then check `df -h /`. Or move T08 to Sandboxes (T23).
  Routines may not delete images or files.
- ~~**U16 Review and merge PR #23**~~ Done 2026-10-20: PR #23 merged. (ready 2026-10-19; needed by 2026-10-20 for the Oct 21 go/no-go): say `review` in
  an interactive session to merge https://github.com/manishwvn/cheatproof/pull/23 (attack diffs no longer include
  files already untracked in the image; planner-merge path `cheatproof/executor.py`). CI green, Sonnet and Opus
  reviewed. Then tell the lead "U16 done".
- ~~**U15 Disk guard refuses every pull**~~ Done 2026-10-20: PR #24 checks pull room in the colima image store. (ready 2026-10-19; needed by 2026-10-20 for the Oct 21 go/no-go): the guard
  measures host free disk (7.4 GB), which does not rise when task images are removed inside colima's sparse 100 GiB VM
  disk, so floor 5 + pull estimate 4.5 refuses every pull. Pick one: (1) planner change in `executor.py`: check free
  space inside the Docker VM for pulls (`docker system df` / `colima ssh -- df -h /var/lib/docker`), keep the host
  floor for the run folder; or (2) free host disk to above 10 GB. Then tell the lead "U15 done"; T08 goes to `todo`.
- ~~**U14 Free disk below 10 GB blocks T08**~~ Done 2026-10-19: owner removed other-project images; `MIN_FREE_DISK_GB=5` (planner, owner-approved). (ready 2026-10-19; needed by 2026-10-20 for the Oct 21 go/no-go): free
  disk is 5.9 GB (`MIN_FREE_DISK_GB=10`). Each SWE-bench task image is about 4 GB unpacked, so each batch needs about
  4 GB per task plus the 10 GB floor. Routines may not delete images. Steps: free host disk (25+ GB for a 4-task
  batch), and/or remove the two task images after their runs (`docker rmi
  swebench/sweb.eval.x86_64.sphinx-doc_1776_sphinx-8595:latest
  swebench/sweb.eval.x86_64.psf_1776_requests-1142:latest`; requests-1142 is already run). Then tell the lead
  "U14 done"; the routine flips T08 to `todo`.

- ~~**U13 Weekly usage cap reached**~~ Done 2026-10-19: owner set `weekly-cap` to 99 for this week and paused the other
  routines; Cheatproof has priority until complete or blocked (CYCLE.md sections 2 and 2.1). (ready 2026-10-19; needed by 2026-10-20 for the Oct 21 go/no-go): the routine
  read weekly usage at 88% (cap 85) and idles until the reset on 2026-10-20 23:59 UTC. T08 is still todo. Steps: run
  T08 in an interactive session, or pause the other routines, or write a higher cap into
  `~/.cheatproof-autopilot/weekly-cap` (owner only). Strike this item when the weekly window resets.
- ~~**U12 Docker image cap blocks T08**~~ Done 2026-10-19: `DOCKER_IMAGE_CAP=16`, colima running. (ready 2026-10-19; needed by 2026-10-20 for the Oct 21 go/no-go): colima
  (profile `default`) holds 10 images from other projects (about 6 GB), and `DOCKER_IMAGE_CAP=6` counts every local
  image, so the executor refuses each task image before pulling. Pick one:
  1. In `.env`, set `DOCKER_IMAGE_CAP=16` (10 existing plus up to 6 task images; `MIN_FREE_DISK_GB=10` still guards
     the disk, 22 GB free on Oct 19), or
  2. prune the images you no longer need (`docker images`, then `docker rmi <name>`) until fewer than 6 remain.
  Then start colima (`colima start`) or leave it running, and tell the lead "U12 done". The routine flips T08 to
  `todo`. Note: this run started colima and could not stop it (the stop call was refused); stop it with
  `colima stop` if you need the memory.
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
- ~~**U2 Tavily key**~~ Done 2026-10-19: key in `.env` (free plan, 1,000 credits a month). ~~**U2 Tavily key (optional, for the network-fetch attack and the Tavily bonus)** (ready 2026-10-16): sign up at
  https://tavily.com, apply promo `BBDEVPOST`, put the key in `.env` as `TAVILY_API_KEY`. Optional: join
  https://dev.nebius.com/builders for extra credit (unreliable; the plan assumes $25 only).
- ~~**U3 Sandboxes access**~~ Done 2026-10-20: Nebius emailed that Sandboxes (Beta) access is active. (in progress 2026-10-19: beta form submitted, Nebius emails when enabled; project IDs are
  in `.env`; T23 checks access each cycle) (ready after U1): https://tokenfactory.nebius.com/sandboxes/about → request access. If the
  profile still shows inactive after a day, email contree@nebius.com with the project ID only (never the key). Docker
  is the fallback; the executor is decided at the Oct 21 go/no-go.
- ~~**U4 GitHub safety**~~ Done 2026-10-19: budgets already $0 (Actions, Codespaces, Packages, LFS, AI credits); branch protection needs a public repo, so it moved to T12.  (ready 2026-10-16): Settings → Billing → set budgets for Actions, Codespaces and Packages to
  $0. Repo → Settings → Branches → protect `main`: block force pushes and deletion, include administrators. Do not
  require pull requests (routines push queue claims to `main`).
- ~~**U5 Final product name**~~ Done 2026-10-19: "Cheatproof" is taken (CheatProof.ai); new product name **RewardSeal**; rename is T24.  (before any public asset): check that "Cheatproof" is not an existing product's
  trademark, or pick another name. The lead can propose options.
- **U6 Video voice-over and submission** (2026-10-26 to 2026-10-28).
- ~~**U7 Disk space and a Docker daemon for the fallback**~~ Done 2026-10-21: host disk 15 GB free, colima VM 91 GB. (ready 2026-10-18; needed by 2026-10-20 if U3 is still
  pending): free at least 30 GB on the Mac (16 GB free on Oct 18). The Mac has the docker CLI but no Docker Desktop
  app (`open -a Docker` fails, found 2026-10-18), and routines cannot install software. Install Docker Desktop (or
  colima: `brew install colima && colima start`), start it once, then run
  `CHEATPROOF_DOCKER_TESTS=1 uv run pytest -q -m docker` in the repo. Routines cannot delete images or files.
- **U8 (optional) Routine folder and permission mode** (ready 2026-10-18; runs are already guarded from the parent
  folder): Claude app → Scheduled → **Cheatproof autopilot** →
  edit: set the folder to `/Users/manish/Documents/Nebius_X_Nvidia/cheatproof` and the permission mode to **Bypass**,
  then save. Until then runs start in the parent folder in auto mode, so the repo's connector guard does not load
  and a run may stop on a refused step. Then tell the lead "U8 done".
- ~~**U10 Merge PR #10 (T15 review fixes)**~~ Done 2026-10-19 (PR #10 / #18). (ready 2026-10-18): in an interactive session say `review` to merge
  https://github.com/manishwvn/cheatproof/pull/10 (planner-merge paths: budget.py, docs/autopilot/, CI). Then install
  the hook: `cp docs/autopilot/pre-push "$(git rev-parse --git-path hooks)/pre-push"`. Note: `budget.py` now refuses
  to start unless `SPEND_CAP_USD` and `DAILY_CAP_USD` are set (≤ 20, daily ≤ total); the current `.env` sets 20 and 4.
- ~~**U11 Planner-merge audit fixes (T22)**~~ Done 2026-10-19 (PR #10 / #18). (ready 2026-10-18; needed before T08): in an interactive session, fix the
  three T22 items (Docker run booking in `budget.py`, `llm.py` timeout, `security.yml` pins), then flip T22 to
  `done`. Without (1), the $4 daily cap halts the 40-task Docker run near task 16.
- ~~**U9 Planner work for T16**~~ Done 2026-10-19 (PR #10 / #18). (ready 2026-10-18): in an interactive session, write the attacker strategy prompts
  and the Tavily budget counter (T16), then flip T16 to `done`. T05 and T06 do not wait on it; the first live
  attacker run (T08) does.
