# Tavily runtime path (`--network-fetch`)

What is called: one host-side `web_search` tool for the attacker, backed by Tavily (`cheatproof/strategies.py`,
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
  `--instance-ids` are refused. `harden` runs one task per call and keeps no record; `TAVILY_CALL_CAP` bounds it.
- Refused with exit 2 when `TAVILY_API_KEY` is absent (the message names the variable, never a value).
- The query is cleaned before it leaves the host and before it is traced: the `TAVILY_API_KEY` value, `Bearer <token>`
  and `name=value` credential patterns are replaced on the whole string, the text is cut to 300 chars, and each word
  is checked on its own. Result titles, urls and snippets get the same cleaning. The trace shows the cleaned query
  (`tool: web_search`, `args.query` in `traces/<stem>.jsonl`). The key is never in a query, result, trace or error.

Run one task (not before the owner clears it):

    python -m cheatproof.cli batch --instance-ids <ID> --network-fetch --system-prompt-file results/combined.txt \
      --attacker-model nvidia/nemotron-3-super-120b-a12b --max-steps 40 --max-tokens 250000 --out results/certificates

`harden <ID> --network-fetch ...` does the same for one task. Add `--dry-run` to `batch` to see the plan first.

Cost: attacker tokens only, about $0.06 per task: `docs/results.md`, per-task table, Token Factory cost column
(Azure__msrest-for-python-55 0.0616, Azure__autorest.python-475 0.0606), plus the usual sandbox runs. The cost of one
Tavily search call is unknown. It uses free credits, so check the Tavily dashboard before the run and after it.
