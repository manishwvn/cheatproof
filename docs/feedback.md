# Feedback on Token Factory, Sandboxes and NVIDIA models

From building RewardSeal (an attacker model tries to pass SWE tasks without fixing them; holes are classified, patched
and re-attacked) for the Nebius x NVIDIA hackathon, Coding & Agentic track. Everything below happened in this
project's own runs: 14 certificate files, 11 tasks attacked (13 attack rounds in the committed certificates), about 70
sandbox runs itemised in those certificates, all on the free credit.
Each item gives what happened, the impact, and a suggested fix. Where we did not hit a problem ourselves, the item
says so.

## Top five

1. Sandboxes reports a non-zero cost for runs that the console does not bill (Sandboxes 1).
2. We found no API to read remaining credit or usage, so cost control had to be rebuilt in our app
   (Token Factory 1, Sandboxes 3).
3. `images.use` returns a handle without checking the image, and the failure appears later (Sandboxes 2).
4. Sandboxes has no network-off switch, which a security tool needs (Sandboxes 4).
5. Reasoning models return `content: null` with no warning when `max_tokens` is small (NVIDIA models 1).

## Token Factory

### 1. No hard spend limit, and no way to read the balance by API
- **What happened.** Token Factory needs a card, the prepaid balance can go negative, and the card is charged at month
  start or at a billing threshold. We found no per-key or per-project hard limit. The remaining trial or promo credit
  was visible only in the console. We checked it by hand before each paid batch.
- **Impact.** We wrote a full spend layer (`rewardseal/budget.py`: reserve worst case before a call, settle from
  `usage`, a file-locked ledger, daily, total and trial caps, halt on 402). Our counter can only estimate, so it
  drifted from the console and errs high: it counted about $0.38 of Token Factory spend while the console showed $0.71
  of the $1 trial left (about $0.29 used). Any user who lets an agent loop on a card-backed account needs the same thing.
- **Suggested fix.** A hard limit setting per API key or project that returns a clear error at the limit. A
  `GET` endpoint for remaining credit and spend to date, so a client can reconcile. A `x-remaining-credit` style
  response header would be enough.

### 2. Prices are not in the default model listing
- **What happened.** `GET /v1/models` returns `id`, `created`, `owned_by` and `shutdown_date`. We got per-1M input and
  output prices only from `GET /v1/models?verbose=true`, then copied them into `.env` by hand
  (`MODEL_PRICES_JSON`). A model with no recorded price is treated as $3/$10 per 1M by our budget, so a missing price
  makes the run stop early.
- **Impact.** Easy to miss, and a typo in a hand-copied price silently changes the budget.
- **Suggested fix.** Document `verbose=true` on the models page, or include price and context length in the default
  listing.

### 3. `usage` does not split reasoning tokens
- **What happened.** In the recorded Nano response, `usage.completion_tokens_details` was `null`, so we cannot tell how
  many of the 64 completion tokens were reasoning.
- **Impact.** For an agent loop on a reasoning model, the budget is mostly reasoning tokens. We could not report to
  ourselves where the tokens went, and 7 of the 11 first attacks in the committed certificates ended at the token or step limit without a submit.
- **Suggested fix.** Fill `completion_tokens_details.reasoning_tokens` for reasoning models.

### 4. Billing rules for failed and retried calls are not stated where we looked
- **What happened.** We set `max_retries=0` on the OpenAI client and reserve the worst case per call, because we could
  not tell from the docs whether a timed-out or retried request is billed twice. A failed call still counts its prompt
  cost in our ledger.
- **Impact.** Our estimates err high on purpose, so some runs stopped earlier than needed.
- **Suggested fix.** State in the API docs whether failed, timed-out or retried requests are billed, and support an
  idempotency key so retries can be safe.

### 5. HTTP 402 is not described
- **What happened.** Our code halts all paid calls on any 402 from Token Factory or Sandboxes. We did not see a 402
  live. The docs we used do not say which conditions return it (balance exhausted, trial over, card declined), what
  the body contains, or whether the call was billed.
- **Impact.** We had to treat every 402 as "stop everything".
- **Suggested fix.** Document the error codes and bodies, including a machine-readable reason.

### 6. Rate limits
- **What happened.** We saw no 429 in our runs, which were small and sequential. We also found no stated per-model
  request or token limits in the material we used. This item is a docs request, not an incident.
- **Impact.** We could not size a parallel batch with confidence.
- **Suggested fix.** Publish per-model limits and return `retry-after` and remaining-limit headers.

### 7. Onboarding: the promo link fails without an event code
- **What happened.** The hackathon credit form only works through the link on the Devpost Resources page (event code
  `2026-devpost-global-ai-hack`). The bare promo URL returns "no event name found". A new account starts with a $1
  trial balance, and the promo credit arrives by email and is then redeemed under Balance, then Top up.
- **Impact.** Lost time at the start, and a window where only the $1 trial was available.
- **Suggested fix.** Make the bare URL explain what is missing and link to the event form.

### 8. `APITimeoutError` in the middle of a long agent run, with no retry guidance
- **What happened.** In batch 3 chunk 3 (2026-10-24), the attacker run on `BQSKit__bqskit-267` ended with
  `llm call failed: APITimeoutError` at step 36 of 40, after a long chain of tool-use calls. We use
  `max_retries=0` (Token Factory 4), so the run stopped and was recorded as inconclusive. We could not tell from the
  docs whether the timed-out request was still processed or billed, or what timeout and retry policy the API expects for
  chat completions with large prompts.
- **Impact.** An otherwise complete agent run was lost, and we cannot say whether the failure was in the model service
  or in the network path. The result counts as "no result", which weakens the sample. In the 348 replication, two further runs (run3 and run4, 2026-10-24) ended with HTTP 503 from the chat endpoint and were not judged, so server-side errors cost us 2 of 10 rounds on that task.
- **Suggested fix.** Document the server-side timeout per model, say whether a request that times out is billed or
  continues, and support an idempotency key or a resume token so a client can retry a step safely. A `Retry-After`
  or error body that says whether the request was accepted would help. We added a bounded retry (at most two, on 5xx and timeouts) after these runs; a documented retry and idempotency contract would let clients do this safely without risking double billing.

## Sandboxes (beta)

### 1. The reported cost is an estimate that the console does not bill
- **What happened.** Sandboxes results carry a non-zero `resources.cost` (read from `done.result.cost`; our first
  version read `done.cost`, which hid the value). We booked it as spend. On 2026-10-21 our budget halted on a result
  with a non-zero cost, and on 2026-10-22 it halted again when the summed cost reached $0.5022 over 46 runs (about
  $0.014 per run). On 2026-10-23 the Nebius console showed no Sandboxes line item and an untouched balance.
- **Impact.** Two halts, a manual console check each time, and a decision by the owner to treat the field as a guard
  and not as a bill. We cannot tell users the true cost of a task.
- **Suggested fix.** Either report 0 for runs that are free in beta, or name the field `estimated_cost` and add a
  `billable` flag. State the beta price policy on the Sandboxes page.

### 2. `images.use` builds a handle without checking the image
- **What happened.** `client.images.use("alpine:3.19")` makes no network request. For a tag never imported, the first
  run failed later with `NotFoundError`. Our smoke test failed this way, a first diagnosis blamed the wrong thing, and
  it took a second pass to find that registry images need `images.oci`. Two failed runs were counted against our
  run cap.
- **Impact.** An extra review cycle on the smoke test and wasted runs.
- **Suggested fix.** Have `images.use` raise a clear error naming `images.oci` or `images.pull` when the tag is not
  imported, or document the difference with an example for SWE-bench style images.

### 3. No usage or run listing
- **What happened.** We found no way to list our own sandbox runs or their cost by API. Our run count (46 over two
  batches) comes from our own counter, and the run count of one task is unrecorded because the budget halted around
  it.
- **Impact.** We could not reconcile our ledger with Nebius's records, or see which runs failed.
- **Suggested fix.** A usage endpoint per project: runs, status, duration, estimated cost.

### 4. No network-off switch
- **What happened.** The SDK has no network flag, and networking is on or off only at the platform level. A tool that
  runs an untrusted attacker model needs the network off. We built it in the guest: every command runs under
  `unshare -rn` after a start probe that checks only `lo` is present and that a connect fails, and we hash the loader,
  libc and `unshare` against values pinned from the base image before each call.
- **Impact.** A large block of guard code in `rewardseal/executor.py`, and residual risk we documented in ADR 0002: a
  platform path outside the guest's network namespace would not be caught.
- **Suggested fix.** A per-session or per-branch `network=False` that the platform enforces, plus a way to allow a
  list of hosts for experiments.

### 5. Preloaded environments: many rows without images, some images broken
- **What happened.** Of 1000 SWE-rebench rows we scanned, 756 had no image and were skipped, 1 had a non-pytest test
  id, and 243 were usable. Of the first 8 tasks we ran, 2 failed the gold gate before any attack:
  `Algebra8__pyopenapi3-83` (the image lacks the `pyopenapi3` package) and `DRMacIver__shrinkray-7` (pytest finds no
  collectors for the failing test).
- **Impact.** A quarter of our first batch was unusable, and the cause only showed up after we kept pytest's collection
  error (a pytest exit code 4 on its own looks like a usage error).
- **Suggested fix.** Run the gold patch once when an image is built and mark tasks whose gold patch fails. Publish
  which rows have images.

### 6. Timeouts arrive two ways
- **What happened.** An operation can end because the SDK cancelled it or because the server flagged a timeout. We
  handle both in `_SandboxTimeout`.
- **Impact.** Extra code, and uncertainty about whether the process was killed in the guest.
- **Suggested fix.** One documented timeout result with a field saying whether the process was killed.

### 7. Early availability
- **What happened.** Early in our access, calls returned HTTP 500. By 2026-10-21 a plain `python:3.12-slim` run
  worked and the errors were gone.
- **Impact.** The go/no-go on Sandboxes versus local Docker was delayed.
- **Suggested fix.** A status page or a "known issues" note on the beta page. Our fallback was local Docker, and that
  fallback is still in the code (`EXECUTOR=docker`).

### 8. Images cannot be deleted
- **What happened.** We found no server-side image delete in the SDK we used (`contree-sdk` 0.3.6).
- **Impact.** Our task images accumulate with no cleanup path.
- **Suggested fix.** Add an image delete call and a project listing of images.

### 9. The cost estimate keeps growing while the console shows no Sandboxes billing line
- **What happened.** After batch 3 chunk 3 our log of the cost the Sandboxes API reports (Sandboxes 1) stood at about
  $1.80, with that chunk's 29 runs adding about $0.34; the Token Factory real-spend counter then read about $1.91. After
  the reruns the Sandboxes estimate was about $2.17 and the real-spend counter about $2.35, of the $10 cap. The
  latest orchestrator console check, after chunk 3 and the reruns, showed total billed $1.17, all covered by trial
  credit (now exhausted), the $26.65 promo balance untouched, and no Sandboxes charge, while the ledger counted more
  (the ledger overstates).
- **Impact.** We had to trust the console over the API field, and our ledger overstates real spend. We cannot tell a
  user, or a reviewer reading our budget log, what a task costs on Sandboxes or whether it costs anything after the beta.
- **Suggested fix.** Same as Sandboxes 1, plus a usage view in the console that lists runs and the cost they were
  billed, so the API estimate can be reconciled with the bill.

## Tavily

### 1. The usage endpoint lagged behind a real call
- **What happened.** On 2026-10-24 our harness made one real Tavily search call (a recon search before the attacker's
  first step, query `Hide private model fields in swagger doc`, 3 results returned). Right after the run, the usage
  endpoint still read 0 of 1000. Our own counter showed the call. Later the same day (2026-10-24) the endpoint showed
  plan usage 1 of 1000 and 1 search, matching the one call.
- **Impact.** For a while we could not confirm on Tavily's side that the runtime call was counted, which matters for a
  bonus award that requires a functional runtime call. We do not know the expected delay.
- **Suggested fix.** State the reporting delay for usage in the API docs, or return a per-request id or usage field in
  the search response so a caller can match its own call to the dashboard.

## NVIDIA models (via Token Factory)

### 1. Reasoning models return `content: null` when `max_tokens` is small
- **What happened.** A smoke call to Nemotron 3 Nano with `max_tokens=64` returned `content: null`,
  `finish_reason: "length"`, and the text of the reasoning in a `reasoning` field. The reply we asked for never
  appeared.
- **Impact.** The caller sees an empty answer, billed for 64 tokens. Any short-answer use of a reasoning model needs
  a larger limit than the user expects.
- **Suggested fix.** Document a minimum useful `max_tokens` per model, a documented switch for reasoning effort or a
  reasoning budget separate from the answer budget, and a clear error or warning when the limit is hit during
  reasoning.

### 2. Model IDs use inconsistent casing and naming
- **What happened.** The IDs we use are `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`, `nvidia/Nemotron-3_5-Lightning`,
  `nvidia/nemotron-3-super-120b-a12b` and `nvidia/Nemotron-3-Ultra-550b-a55b`: mixed case, and an underscore in one.
- **Impact.** Easy to mistype. Our budget prices by exact ID string, so a wrong-case ID would fall back to the high default price ($3/$10 per 1M).
- **Suggested fix.** Use one convention, or accept case-insensitive aliases.

### 3. Nemotron 3 Super as a long-horizon tool-using attacker
- **What happened.** We ran Super as the attacker with a 40-step and 250,000-token limit per attempt. Of the 11
  first attacks in the committed certificates, 7 ended at a limit without a submit (6 on steps, 1 on tokens; the hero runs
  used 500,000 tokens), and 4 submitted. One task has a confirmed git-history exploit (`CycloneDX__cyclonedx-python-348`,
  from an auto-submitted diff at the step limit). Cost per attacked task was about $0.04 to $0.20 on Token Factory.
- **Impact.** The limits, not the model's decision to stop, decide most of our outcomes, so we can only say "not hacked
  by this attacker within these limits". We do not know how much of that is verbosity in the model's reasoning, since
  `usage` does not split it (Token Factory 3).
- **Suggested fix.** Guidance for agentic tool use: expected tokens per step, how to cap reasoning, and examples of
  loops with shell tools.
- **Barely tested.** We ran Nemotron 3 Ultra once (one task, 40 steps, cost $0.77, about 14 times a Super run), so we have little feedback on it.

### 4. No post-training for Nemotron on Token Factory
- **What happened.** The hackathon rules state post-training does not support Nemotron models. RewardSeal hardens
  environments that are meant for RL.
- **Impact.** We cannot close the loop by training a Nemotron policy on a hardened environment and measuring the
  change in hacking. That would be the natural next experiment.
- **Suggested fix.** Offer fine-tuning or RL on Nemotron, even in a small form, for environment research.
