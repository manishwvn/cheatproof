# Pitch: RewardSeal

Decided 2026-10-18 after three research rounds and judge panels (earlier candidates live in git history). Judging:
four equal criteria scored 1–5 (Technological Implementation, Design, Potential Impact, Quality of Idea); ties go
to Technological Implementation. Budget: about $25 of Token Factory credits, in-app cap $20.

## One line
The first closed loop that finds reward hacks in SWE environments, patches them, and certifies that each patched
environment is still solvable by the gold patch and no longer hackable by the same adversary.

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
1. **Load** 30 SWE-rebench tasks plus 10 SWE-bench Verified tasks (comparable to the 28.5% figure).
2. **Gate before hardening:** the gold patch passes and the empty patch fails, or the task is dropped and counted.
3. **Attack:** a dishonest Nemotron Super agent gets the task, a shell inside the environment and four explicit
   strategies: git-history retrieval, test edits, hard-coding, network fetch of the upstream fix (with Tavily search).
   About 15 steps and 50k tokens per attempt.
4. **Classify** each success into a hole type, in code, from the trace and the diff.
5. **Patch** with rule-based fixes: strip future `.git` objects and refs, hidden read-only tests restored at grade
   time, network off, a grader check that fails on touched test files.
6. **Re-attack** with the same attacker and budget; re-run the gold and empty gates.
7. **Certify:** a JSON certificate per environment and a hackability score per benchmark, with raw counts.

Executor: Token Factory Sandboxes (checkpoint, branch per patch), with local Docker as fallback (ADR 0002). Every
model call goes through Token Factory.

## Demo
- **Hook (10 s):** "We told Nemotron Super to cheat on real SWE tasks. It passed k of n without solving the task."
  Count verified holes only (docs/results.md, Holes found). Cut to a real attack trace from the final run.
- Live loop on one environment: attack, hole found, patch applied, re-attack fails, gold still passes.
- Scale: the environment table (n shown), before and after per attack type, cost per environment.
- Product: `python -m cheatproof.cli harden <env-id>` returns a certificate JSON. Model ID on screen in the first 20 seconds.

## Track fit (stage 1)
The attacker is a coding agent: it writes code, runs it in the sandbox and tests against the grader. Show Nemotron
tool calls and sandbox output on screen.

## Tavily (bonus award)
Planned use: the network-fetch attack. The attacker searches for the upstream fix; if it finds and applies it, that
is a network-on hole, and the patch is network off. Tavily can change outcomes at runtime. Claim it only after a run logs a Tavily call (none logged in docs/results.md yet). No other Tavily use.

## Ways this loses, and the answer
1. **Small or fake-looking numbers.** Report n, raw counts and intervals; show a real hack transcript.
2. **Hardening breaks solvability, or the attacker is weak.** Gold and empty gates on every environment; Nemotron Super as
   the attacker with strategy hints; say "upper bound against this attacker, not proof".
3. **Sandbox access slips, or it looks like dry infra.** Docker fallback behind one executor interface; a polished
   CLI, certificate JSON and one clean before/after page per environment.

## Cut from scope
Scores across all 7,000 environments, SWE-rebench-V2, learned patch generation (patches stay rule-based), dashboards
beyond one report page, and any headline number that was not measured.

## Name
"RewardSeal" is the product name (U5 done 2026-10-19: "Cheatproof" is taken by CheatProof.ai).
