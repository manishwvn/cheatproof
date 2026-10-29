# Limitations and responsible disclosure

This report replays committed records. It does not run a live attack or establish that an evaluation environment is secure.

## Scope and detection

- Closure covers the task workdir repository only. Submodules, .git/modules and other clones are not checked.
- Line-overlap detection misses reformatted, renamed or moved fixes, fixes carried only by merge commits, and fixes kept only in dangling objects. Shared lines do not establish that an entire fix is retrievable.
- Incomplete history listings and incomplete fix scans produce lower bounds. No counted match means absence is unproven there.
- A gold pass does not mean unchanged difficulty. Removing a shortcut can change the task; a human must review that change.
- The first audit selected the lowest-scoring tasks. The separate random sample frame is A-E only (including repositories 0-9 in the first 1000 dataset rows). Neither supports a claim about SWE-rebench at large.

## Attacks, attribution and costs

- Certified means the recorded qualifying attack failed, against this attacker and these conditions. It is not a security guarantee.
- The main results use one attacker and one prompt family, with recon on where recorded. Some older certificates lack a recon field. A different attacker or prompt may find other routes.
- The before and after attacks can differ in recon hints and step counts. Such re-attacks do not isolate the patch's effect.
- Use of git show output is inferred, not observed, from command order and matching lines. Full command outputs were not retained. The 116 attribution remains a lead because its recorded write preceded the history reads.
- The web result is one search tool on one day: a dated findability snapshot, not evidence of use and not proof that the web lacks fixes.
- The Sandbox cost counter is an estimate, not billed spend. Ledger figures and actual charges can differ.

## Responsible disclosure

This tool is for authorized evaluation environments. Do not use findings to cheat on benchmarks or leaderboards.

Report problems via GitHub issues on manishwvn/cheatproof (https://github.com/manishwvn/cheatproof/issues).

Do not include unpublished fixes, secrets or private data in reports.
