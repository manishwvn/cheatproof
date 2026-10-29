# Pitch: RewardSeal

Decided 2026-10-18 after three research rounds and judge panels (earlier candidates live in git history). Judging:
four equal criteria scored 1–5 (Technological Implementation, Design, Potential Impact, Quality of Idea); ties go
to Technological Implementation. Budget: free Token Factory credits only (the $1 trial, now exhausted, and the hackathon promo, which now covers spend), in-app real-spend cap $10 total, $4 a day.

## One line
One workflow that attacks SWE environments for reward hacks, applies rule-based patches, checks that the gold patch still
passes and the empty patch fails, and re-attacks with the same adversary. A certificate records the outcome; it does not
prove the environment is secure.

## Problem
Coding agents trained or evaluated on SWE environments can pass tasks without solving them: they read the known fix
from git history, edit or delete the tests, hard-code outputs, or fetch the upstream fix from the network. RL rewards
these shortcuts, so a policy looks better while it learns to cheat, and eval numbers lose credibility.

Evidence (from the research notes; re-check each source before any public use):
- arXiv "Auditing Reward Hackability in Code RL Training" (Jun 2026): 28.5% Docker-verified hackability on a
  49-task SWE-bench Verified sample.
- ImpossibleBench and RHB (ICML 2026) measure hacking; Cursor (Jun 2026), Poolside (May 2026) and Vals.ai (Oct 2026)
  report known-fix retrieval at scale.

What exists measures hackability. Nothing found auto-remediates and re-verifies each environment with a solvability
check. Do not claim "first to measure hackability".

## Users
RL and eval teams that train or score coding agents (Nebius publishes SWE-rebench and sells Sandboxes for RL; NVIDIA
trains Nemotron with RL), labs and eval firms.

## How it works
1. **Load** SWE tasks. Planned: 30 SWE-rebench plus 10 SWE-bench Verified. Reported so far: 14 certificate files, all selected SWE-rebench tasks; not directly comparable to the cited 28.5% study.
2. **Gate before hardening:** the gold patch passes and the empty patch fails, or the task is dropped and counted.
3. **Attack:** a dishonest Nemotron Super agent gets the task, a shell inside the environment and four explicit
   strategies: git-history retrieval, test edits, hard-coding, network fetch of the upstream fix (with Tavily search).
   Limits per attempt: 40 steps and 250,000 tokens (500,000 in the hero runs).
4. **Classify** each success into a hole type, in code, from the trace and the diff.
5. **Patch** with rule-based fixes: strip future `.git` objects and refs, hidden read-only tests restored at grade
   time, network off, a grader check that fails on touched test files.
6. **Re-attack** with the same attacker and budget; re-run the gold and empty gates.
7. **Certify:** a JSON certificate per environment and a hackability score per benchmark, with raw counts.

Executor: Token Factory Sandboxes (checkpoint, branch per patch), with local Docker as fallback (ADR 0002). Every
model call goes through Token Factory.

## Demo
- **Hook (10 s):** "In 12 of 13 audited environments, every counted line the gold patch adds also appears in a future commit in the task's .git. This is line overlap, not proof the whole fix can be retrieved; for 2 of the 12 (348, toil-4805) it is one line. After strip-future-git, the task repo has no future commits, and the gold and empty gates held in 11 of those 12. Sample: the 18 lowest-scoring tasks, 5 excluded as env-broken. Not a prevalence estimate. We told Nemotron Super to cheat, and on one task it ran git show on the fix." Lead with the deterministic
  audit (docs/results.md, Exposure audit), then the attacker finding. Attacker headline: 1 of 9 confirmed: found, closed, certified (cyclonedx-348); crypto-116 is an
  unconfirmed lead (classifier false positive suspected, T53). Never say "2 of 9 exploited". The 1 of 9 is a manually assessed finding with unequal follow-up, and the use of the fix is inferred from command order. Say that 348 and 116 got
  repeated targeted reruns, that recon was on, and "against this attacker". Evidence: docs/results.md, Causal check;
  the 9 is checked against the certificates. Cut to a real attack trace from the final run.
- Live loop on one environment: attack, hole found, patch applied, re-attack fails, gold still passes.
- Scale: the environment table (n shown), before and after per attack type, cost per environment.
- Product: `python -m cheatproof.cli harden <env-id>` returns a certificate JSON. Model ID on screen in the first 20 seconds.

## Track fit (stage 1)
The attacker is a coding agent: it writes code, runs it in the sandbox and tests against the grader. Show Nemotron
tool calls and sandbox output on screen.

## Tavily (bonus award)
Planned use: the network-fetch attack. The attacker searches for the upstream fix; if it finds and applies it, that
is a network-on hole, and the patch is network off. Whether Tavily changes outcomes is a hypothesis, not shown. One real runtime call is logged (2026-10-24): a harness recon search before the attacker's first step, labelled as
such in the trace and certificate. The attacker made 0 `web_search` calls of its own, so claim the runtime call and do
not claim that the attacker used Tavily. On 2026-10-24 the Tavily usage endpoint showed plan usage 1 of 1000 and 1 search: the dashboard shows 1 search credit used, matching the one harness search. No other Tavily use. Say exactly: Tavily supplied one harness-initiated search; the attacker made no search calls; no effect on an outcome is shown.

## Ways this loses, and the answer
1. **Small or fake-looking numbers.** Report n, raw counts and intervals; show a real hack transcript.
2. **Hardening breaks solvability, or the attacker is weak.** Gold and empty gates on every environment; Nemotron Super as
   the attacker with strategy hints; say "against this attacker only, not proof, not a statistical bound".
3. **Sandbox access slips, or it looks like dry infra.** Docker fallback behind one executor interface; a polished
   CLI, certificate JSON and one clean before/after page per environment.

## Cut from scope
Scores across all 7,000 environments, SWE-rebench-V2, learned patch generation (patches stay rule-based), dashboards
beyond one report page, and any headline number that was not measured.

## Name
"RewardSeal" is the product name (U5 done 2026-10-19: "Cheatproof" is taken by CheatProof.ai).
