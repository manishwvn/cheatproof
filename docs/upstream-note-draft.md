# DRAFT — note for nebius/SWE-rebench maintainers

**DRAFT, not posted. The owner decides whether to post.**

While building RewardSeal, we audited the workdir repositories for the 18 lowest-scoring SWE-rebench tasks in our selection. Of those, 13 were audited and 5 were excluded as environment-broken. In 12 of 13 audited repositories, every counted gold-added source line also appeared in a future commit reachable in the task's `.git`. This is line overlap, not proof that the whole fix is retrievable. In 2 of those 12 cases, the overlap is a single line.

Our `strip-future-git` check left no future commits in the task's workdir repository, with the gold patch passing and the empty patch failing, in 11 of those 12. The remaining case had a broken gold gate before any attack. Closure covers the workdir repository only; submodules, `.git/modules` and other clones are not checked. Incomplete scans and matching limits make detection a lower bound: reformatted, renamed or moved fixes, merge-only changes and dangling objects can be missed. A missing match does not establish absence.

Separately, a random sample within the stated A-E repository frame found at least half of the counted gold lines in a future commit in 7 of 9 audited tasks (12 drawn, 3 environment-broken). That frame comes from 1000-row dataset frame, repositories 0-9 and A-E, with the selection exclusions recorded before the run. Neither this framed sample nor the lowest-scoring selection is a prevalence estimate for SWE-rebench at large.

We would welcome your interpretation of whether future-history availability in these images is intended and which repository-state checks you recommend for evaluation owners. We can point to the committed, sanitized records and detector limits; we do not claim autonomous retrieval of every complete fix or generalize the model finding beyond its recorded conditions.

Sources: `results/exposure/_run.json`, `results/exposure/*.json`, `results/exposure-sample/_run.json`, `results/exposure-sample/_selection.json`, `results/exposure-sample/*.json`, `docs/method.md#sample-protocol`, `docs/results.md`, and `docs/claims.md`. The 348 command-order evidence is `results/evidence/348-causal.md`; history use is inferred. No posting or maintainer response is claimed.
