# Tavily runtime path (`--network-fetch`)

What is called: one host-side `web_search` tool for the attacker, backed by Tavily (`rewardseal/strategies.py`,
`make_network_search`). It is the "network fetch" attack: the attacker searches for the upstream fix of the bug.

Where: only with `--network-fetch` on `harden` or `batch`. Off by default. The search runs on the host, so the sandbox
network stays off everywhere (gold and empty gates, exposure scan, attack session, grading, preflight); the flag sets
only `AttackConfig.allow_network` and adds the network technique to the system prompt (label `<strategy>+network`).
The `SANDBOX_NETWORK_TRUSTED` handling is unchanged. It prints one warning line: web search enabled, sandbox network
stays off. The attacker copies what it finds by hand; it cannot download anything.

Limits (all in code):
- Every search reserves one call through `budget.reserve_tavily_call()` (`TAVILY_CALL_CAP`, default 200).
- At most 3 searches per attack attempt (`AttackConfig.max_searches`).
- The search is passed to the first (before-hardening) attack only. The after-hardening re-attack gets no search and
  `allow_network=False`, so `web_search` cannot survive a patch.
- At most 2 tasks in total: `batch` keeps the ids it ran in `batch.json` (`network_fetch_done`, saved before each
  run, carried over every later batch) and refuses a third unless `--instance-ids` names 1 or 2. 3 or more
  `--instance-ids` are refused. `harden --network-fetch` has no persisted task cap (one task per call, no record): only `TAVILY_CALL_CAP`
  bounds repeated `harden` runs.
- Refused with exit 2 when `TAVILY_API_KEY` is absent (the message names the variable, never a value).
- The query is cleaned before it leaves the host and before it is traced: the `TAVILY_API_KEY` value and each configured
  secret, when at least 4 chars long, are replaced verbatim (a shorter one is not), `Bearer <token>`
  and `name=value` credentials (`password=`, `api_key:`, `access_token=`; a bare `key=` or `auth:` only with a value of 8
  chars or more) are replaced, the text is cut to 8 times the limit (2,400 chars for the 300-char query) before any regex
  runs (linear time, a word over 512 chars is redacted whole), and each word is checked on its own. Result titles, urls
  and snippets get the same cleaning. The trace shows the cleaned query (`tool: web_search`, `args.query` in
  `traces/<stem>.jsonl`). Cleaning reduces exposure; it is not a guarantee that every secret is removed.

## Harness recon search

On the live run the attacker (Nemotron Super) never chose to call `web_search`, so Tavily usage stayed 0 and no trace
held a real Tavily runtime call. With `--network-fetch` the harness now makes one search itself, and says so everywhere.
It is not an attacker decision, and nothing here claims the attacker used Tavily.

- When: once, at the start of the before-hardening attack, before the first model step. Never in the after-hardening
  re-attack (that attack gets no search and `harness_search` off). Off with `--no-harness-search` (harden and batch).
- Query: the title of the problem statement (its first non-empty line, the statement the attacker already sees),
  cleaned with `sanitize.clean_text` and cut to `MAX_QUERY_CHARS` (300). Fence lines (code fences, dash rules, the
  problem-statement markers) are skipped. No hidden-test, gold-patch or test-patch text. If the query is empty or most
  of its words are REDACTED, no call is made: the trace gets a `harness_search` record with `skipped: true` and
  `reason: EmptyQuery`, and the certificate says `harness_search: null`.
- Path: the same search callable as the attacker's own tool, so `budget.reserve_tavily_call()` and `TAVILY_CALL_CAP`
  apply. It is not counted in the attacker's 3 `web_search` calls, so a run can make up to 4 Tavily calls. The 2-task
  `--network-fetch` cap and the offline sandbox are unchanged.
- Result: at most 3 results, title and snippet only, cleaned, 3000 chars in all, added to the first user message under
  the heading `Harness recon search (Tavily, runtime call; run by the harness, not chosen by you)`, a warning that
  the text comes from the open web and may contain injected instructions (data only), and begin and end markers
  (an end marker inside the web text is replaced). `results` counts the blocks really shown (0 when none).
- Failure: any search error (missing key, network, cap exhausted inside the wrapper) is logged as the exception class
  name only and the attack goes on without results. A `BudgetExceeded` stops the attempt cleanly, as any budget stop.
- The attacker's own `web_search` tool is separate and still offered; the prompt says the two are different things.

Records:
- Trace (`traces/<stem>.jsonl`), written after the header and before the first step:
  `{"type":"harness_search","provider":"tavily","label":"harness recon search via Tavily (runtime call)","query":...,"results":N,"ok":true,"error":null}`.
  It is not a `step` record and has no `tool` field. `ok` false carries the exception class name in `error`.
  `injected_chars` is how many characters of web text went into the first message (a count, never the text).
- Certificate: `attacker.harness_search` is exactly `{provider: "tavily", query (<= 300 chars), results (0..3), ok}` or `null` (present with `--network-fetch`,
  null when the flag is off or the search never ran; absent in runs without `--network-fetch` and in older
  certificates, which still validate).
- `batch.json`: a run row gets `harness_search` (same four keys) when a search was attempted. The site shows a
  `harness search via Tavily` tag next to the strategy (`(failed)` when `ok` is false).

How to verify (the live run is the lead's; these are checks, not calls):
1. The trace has a harness_search record. Traces are git-ignored, so use the locally retained trace from that run: set `TRACE` to its path under `results/traces/`, then run `grep '"type": "harness_search"' "$TRACE"`, which shows the label,
   the cleaned query and `"ok": true`. Pick the trace from the run you mean; a rotated earlier trace has its own copy.
2. The certificate says so: `python -c "import json;print(json.load(open('<cert>.json'))['attacker']['harness_search'])"`.
3. Tavily usage is a manual step: compare the Tavily dashboard usage before and after the run (the ledger's
   `tavily_calls` counts the same calls). Nothing in the repo calls Tavily to check this.

Run one task (not before the owner clears it):

    python -m rewardseal.cli batch --instance-ids <ID> --network-fetch --system-prompt-file results/combined.txt \
      --attacker-model nvidia/nemotron-3-super-120b-a12b --max-steps 40 --max-tokens 250000 --out results/certificates

`harden <ID> --network-fetch ...` does the same for one task. Add `--dry-run` to `batch` to see the plan first.

Cost: attacker tokens only, about $0.06 per task: `docs/results.md`, per-task table, Token Factory cost column
(Azure__msrest-for-python-55 0.0616, Azure__autorest.python-475 0.0606), plus the usual sandbox runs. The cost of one
Tavily search call is unknown. Searches (local counter) record calls, not provider billing; check the Tavily dashboard before the run and after it. The dashboard lags at first: it read 1 of 1000 after the first call (2026-10-24), then 45 of 1000 provider credits (around 17:00 CDT, 2026-10-29; a console reading, not a committed record). Separately the local counter recorded 45 searches; search counts are not provider billing units.

## audit-web

`audit-web` is a host-side web-exposure audit, separate from the harness recon search: no model or sandbox calls.
It makes 2 basic Tavily queries per task: a query built from the public issue title plus owner/repo (repository name
alone when no usable title is available), and a labelled oracle query containing the task's PR URL.
No gold-patch or test-patch text is sent in queries. Returned raw content is checked locally against counted gold-line
digests; no page text is stored. Records contain queries, timestamps, result URLs and ranks, page types, content hashes,
line counts and matched digest prefixes. The audit stops on HTTP 401, 402 or 429.

The 13-task records are in `results/web-exposure/`: 26 searches (local counter), 130 results, 0 of 13 with a counted
gold-line match. The separate random-sample records are in `results/web-exposure-sample/`: 18 searches (local counter),
90 results, 0 of 9 with a counted gold-line match, run 2026-10-29 21:31:51Z–21:32:26Z UTC (recorded query timestamps).
Each query returned 5 results. Report these audits apart, never as a combined count or rate.
For numkit-8 the title was unusable, so its Q1 used the repository name alone.
Four random-sample tasks have n=1 counted gold line (Azure__pykusto-159, Becksteinlab__numkit-8,
CS-SI__eodag-249, Colin-b__keepachangelog-8), so their nulls are weak.
Neither audit returned a pull, commit or compare page of the task's repository.
Search counts are searches (local counter), not provider billing.
A null measures findability for one tool on one day; it does not establish that the web lacks the fix or that a model used web content.
