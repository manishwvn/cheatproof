# Tavily runtime path (`--network-fetch`)

What is called: one host-side `web_search` tool for the attacker, backed by Tavily (`cheatproof/strategies.py`,
`make_network_search`). It is the "network fetch" attack: the attacker searches for the upstream fix of the bug.

Where: only with `--network-fetch` on `harden` or `batch`. Off by default, so normal runs stay network-off.
The flag sets `AttackConfig.allow_network` and `EnvSpec.network` together, adds the network technique to the
system prompt (label `<strategy>+network`), and prints one warning line. The sandbox network is not cut for that run,
for the grading sessions as well as the attack (the `SANDBOX_NETWORK_TRUSTED` probe is skipped when `network=True`).

Limits (all in code):
- Every search reserves one call through `budget.reserve_tavily_call()` (`TAVILY_CALL_CAP`, default 200).
- At most 3 searches per attack attempt (`AttackConfig.max_searches`).
- At most 2 tasks per invocation: `--instance-ids` with 3 or more ids is refused; `batch` otherwise keeps the first 2
  tasks that would run.
- Refused with exit 2 when `TAVILY_API_KEY` is absent (the message names the variable, never a value).
- The query is cleaned word by word (secret-like words become `REDACTED`) before it leaves the host, result titles,
  urls and snippets are cleaned the same way, and the trace shows the cleaned query (`tool: web_search`, `args.query`
  in `traces/<stem>.jsonl`). The key is never in a query, result, trace or error.

Run one task (not before the owner clears it):

    python -m cheatproof.cli batch --instance-ids <ID> --network-fetch --system-prompt-file results/combined.txt \
      --attacker-model nvidia/nemotron-3-super-120b-a12b --max-steps 40 --max-tokens 250000 --out results/certificates

`harden <ID> --network-fetch ...` does the same for one task. Add `--dry-run` to `batch` to see the plan first.

Cost: attacker tokens only, about $0.06 per task at the Super prices measured in `docs/results.md`, plus the usual
sandbox runs. Tavily cost per search call is unknown; it uses free credits, so check the Tavily dashboard for the
credit balance before the run and after it.
