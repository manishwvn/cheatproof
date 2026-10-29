# Second exposure audit: predeclared random sample

Written and committed BEFORE the run. The first audit (13 of 18, `results/exposure/`) used the 18 lowest-scoring
SWE-rebench tasks; it says nothing about typical tasks. This second audit draws a separate random sample, reports its
own counts, and is never blended into the 13.

- **Pool:** every cached swe-rebench task (`runs/tasks/swe-rebench.json`, 243 valid rows), minus repositories on the
  deny list (`DEFAULT_DENY_REPOS`), minus the 18 tasks of the first selection (`results/exposure/_run.json`).
- **Sampling frame (limit, stated before the run):** the cache holds the first 1000 rows of the dataset, which are
  ordered by repository name: 243 valid tasks in 88 repositories whose names start with 0-9, A, B, C, D or E (A: 67, B:
  29, C: 49, D: 66, E: 16). The sample is random within that frame only. It does not represent SWE-rebench at large, and
  the first 18 tasks came from the same frame.
- **Draw:** pool sorted by instance id, then `random.Random(20261029).sample(pool, 12)`; `scripts/draw_sample.py` writes
  `results/exposure-sample/_selection.json`. The seed is today's date (2026-10-29) and is not tuned.
- **Size 12, not 30:** the Sandboxes cost counter stood at $3.65 of its $5 guard, about $0.073 per audited task, so 30
  tasks would pass the guard. 12 tasks is about $0.9. The size was set by cost, before seeing any result.
- **Command:** `EXECUTOR=sandbox python -m rewardseal.cli audit-exposure --instance-ids <the 12> --out results/exposure-sample`.
  No model, no Token Factory spend, no Tavily.
- **Exclusions are kept:** env-broken and unlistable tasks are recorded in `results/exposure-sample/_run.json` and
  reported as exclusions with the reason, as in the first audit. Nothing is dropped or replaced after the draw.
- **Reported as:** "In this random sample of N audited (12 drawn; E excluded), at least half of the counted gold lines
  appeared in a future commit in K environments." Counts only: n is small, so no rate and no interval. The same
  qualifiers as the first audit apply (line overlap, workdir repository only, incomplete scans can miss).
- **Stop rule:** stop and report if the Sandboxes counter nears $4.8 (the guard is $5).
