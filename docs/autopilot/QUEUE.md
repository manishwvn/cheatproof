# Queue

Format: `### <id> <title> — size S|M|L — <status> [— after <date>] [— needs <ids>]`. Statuses: `todo`,
`in-progress (cycle <start>)`, `in review`, `waiting: <why>`, `done #<PR>`, `superseded`. `[NN%]` overrides credit.
Check: `python3 docs/autopilot/progress.py` counts the same tasks as
`grep '^### .* — size [SML] — ' docs/autopilot/QUEUE.md | grep -vc superseded`.

## Milestone: live access and executor

### T01 Smoke test, model IDs and prices — size S — todo — after 2026-10-21 [85%]
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

### T15 Routine review fixes (planner-merge PR) — size M — done #10
Apply the "Open, repo side" items 1–11 in `~/.cheatproof-autopilot/review-2026-10-18.md` (fail-closed caps and a
read-only `snapshot()`, `lock.py` output, optional `--now`, CYCLE.md alignment and planner-merge list, `leakcheck.py`,
a versioned pre-push hook, CLI tests and a Python 3.9 compile step in CI, reviewer model, tracked `results/`, pre-flip
scan patterns). Every item touches a planner-merge path: open one PR with tests green and the Opus review, then add a
USER item for the planner to merge. Do T02 first if both are runnable.

Done 2026-10-18 (routine): PR #10 open, CI green, Sonnet review fixed (one round), Opus final review: ready. Items 10
and 11 are below (T08, T12 text). Planner merges #10 (U10), then installs `docs/autopilot/pre-push`.

### T23 Sandbox executor and the eval on Sandboxes (TOP PRIORITY, planner-merge PR) — size L — todo
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

### T25 Image-store disk check hardening (planner-merge PR) — size S — todo — after 2026-10-21
From the Haiku review of PR #24 (0 blockers, 3 risks). In `cheatproof/executor.py` `_colima_store_free_gb` and its
caller: (1) when the `colima` binary exists but `colima ssh` fails or times out, refuse the pull (`DiskRefused`,
"image store unreadable") instead of falling back to host disk; fall back to host only when `colima` is absent
(`shutil.which("colima") is None`). (2) Parse the df row whose last field is `/var/lib/docker`, not `lines[-1]`.
(3) CYCLE.md section 0: the "alert the owner when free disk is under 10 GB" rule names both the host disk and the
Docker image store. (4) Routine 2026-10-20: with colima the pull also grows the VM data disk file on the Mac, which
keeps freed blocks, so the guard must also refuse when host free disk minus the pull estimate is under the floor. Units already match (`GIB = 1024**3`, used by `_root_free_gb` too). Tests for each case with a
fake runner. `executor.py` is a planner-merge path: open the PR, Opus review, USER item for the planner to merge.

### T26 Executor and batch audit fixes before the 40-task run (audit 2026-10-20, planner-merge PR) — size M — waiting: U20 (PR #27)
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

### T24 Rename the product to RewardSeal — size M — todo — needs T08
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

### T08 Eval run and results with raw counts — size M — waiting: U18, U20 — needs T23, T07, T16, T17, T18, T19, T20, T22
Run the full loop on the 40 tasks within the $20 cap (check the ledger before starting; stop at the daily cap). Write
`docs/results.md`: method, n, raw counts per attack type before and after, gold and empty gate results, cost per
environment, failures and limits ("upper bound against this attacker, not proof"). Commit the certificates and the
sanitized traces needed for replay. Committed certificates and replay traces go in a tracked `results/` folder (`runs/` stays a
git-ignored cache; `git add -f` is denied).
Audit 2026-10-18: before the run, smoke one real image's gold gate. `grader.PYTEST_CMD` runs bare `python -m pytest`
under `sh -lc`; SWE-bench images may need `conda activate testbed`. Check image HEAD equals `base_commit`
(`strip-future-git` refuses otherwise). With 13 GB free and a 6-image cap, Docker runs go in owner-pruned batches.


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

At the flip (owner, right after making the repo public): protect `main` (block force pushes and deletion, include
administrators), and rename the GitHub repo to `rewardseal` in Settings (GitHub redirects the old URL).
### T13 Learning pack — size M — todo — needs T12
Fill `LEARNING.md` interview questions, complete the glossary, re-read the whole file for accuracy.

### T14 Submit — size S — waiting: owner only — after 2026-10-28
The owner makes the repo public and submits on Devpost. Marked done only on the owner's word.

## USER

- **U20 Review and merge PR #27 (T26 audit fixes)** (ready 2026-10-20; needed before T08 resumes): after U19, say
  `review` in an interactive session to merge https://github.com/manishwvn/cheatproof/pull/27 (planner-merge path
  `cheatproof/executor.py`; low-disk latch, `Result.reset`, swerebench image prefix, fsize ulimit, pull timeout).
  Rerun its checks after #26. Then flip T26 to `done #27`.
- ~~**U19 Review and merge PR #26 first**~~ Done 2026-10-21: PR #26 merged. (ready 2026-10-20; needed now: the `security` workflow fails on every
  branch): say `review` in an interactive session to merge https://github.com/manishwvn/cheatproof/pull/26 (certifi
  2026.7.22 to 2026.10.19 for PYSEC-2026-4320; only `uv.lock`, a planner-merge path). CI green. Then rerun PR #25's
  checks (U18).
- **U18 Review and merge PR #25** (ready 2026-10-20; needed for T08 results): say `review` in an interactive session
  to merge https://github.com/manishwvn/cheatproof/pull/25 (leakcheck skips values that equal a public value in
  `origin/main:.env.example`, so certificates that name the model can be committed; planner-merge path
  `docs/autopilot/`). Sonnet review fixed in one round; Opus final review done.
- ~~**U17 Mac free disk 0.8 GB blocks T08 (urgent)**~~ Done 2026-10-21: eval moves to Sandboxes (T23), no local pulls. (ready 2026-10-20; needed for the Oct 21 go/no-go): free at least 15 GB on
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
