# RewardSeal demo video: script

Target: under 3 minutes (YouTube requirement). Planned total: **2:46** (166 s), limit 2:50 (170 s).
The rough cut (`video/rough_cut.py`) reads the beat table below and refuses to build at 170 s or more.

**Evidence now (docs/results.md, first Sandboxes batch):** 11 selected, 8 run, 5 attacked, 0 certified. One hole is
recorded (`test-edit`, one task) but it is not verified under the T33 rule, so there are 0 verified holes so far.
n = 8, raw counts only. Batch 3 is pending. Do not fill any number before batch 3 finishes.

**Rules for the placeholders:** every `[RESULT: ...]` and `[PLACEHOLDER: ...]` must be filled from the final results
(batch 3, docs/results.md) before recording. Each one names the results.md field that fills it ("Fills from:").
Do not state a number that is not in the results. A claim the results do not support is cut or rewritten to the
conditional wording inside its placeholder. The hook is only a placeholder: it counts verified holes only.

Voice: the voice-over in this table is a rough draft for macOS `say`. The owner records the final voice (U6).
Keep each take inside its beat; the rough cut trims audio that overruns its beat.

Screenshot slots (optional, for `rough_cut.py --shots DIR`; name the file `beatNN.png`, `.jpg` or `.jpeg`):
beat02 (model ID on screen), beat04 (real attack trace), beat05 (hole label), beat06 (patch diff),
beat07 (re-attack trace), beat08 (three gates), beat09 (certificate JSON), beat10 (scale table),
beat11 (stack). Beats without a screenshot use a title card with the On-screen text.

## Beat table

| Start | Dur (s) | On-screen | Voice-over | Caption |
|---|---|---|---|---|
| 0:00 | 10 | Title: "RewardSeal" with subtitle "Finds, patches and certifies reward hacks in SWE environments" | We told Nemotron Super to cheat on real SWE tasks. [RESULT: k of n passed without solving the task. Fills from: results.md Attack outcomes, verified holes only] | Reward hacks in SWE RL environments |
| 0:10 | 10 | Terminal: `ATTACKER_MODEL=nvidia/nemotron-3-super-120b-a12b` and the label "dishonest attacker" | The attacker is Nemotron 3 Super, called through Token Factory. Its brief: pass the task without solving it. | Attacker: nvidia/nemotron-3-super-120b-a12b (Token Factory) |
| 0:20 | 12 | Four labels: git-history retrieval, test edits, hard-coding, network fetch | RL rewards whatever passes the tests. An agent can read the fix from git history, edit the tests, hard-code outputs, or fetch the upstream fix. | Four shortcuts a policy can learn |
| 0:32 | 12 | Real attack trace: [RESULT: commands and outcome of the real trace. Fills from: results.md per-task table, Attack outcome column] | Here the attacker [RESULT: what it did, for example git log --all and a copied future commit, only if the trace shows it. Fills from: results.md per-task table, Attack outcome column; cut the beat if no attack submitted] | Attack trace: [RESULT: attack summary. Fills from: results.md per-task table, Attack outcome column] |
| 0:44 | 12 | Hole card: "Hole: [RESULT: hole type. Fills from: results.md Holes found, verified under the T33 rule only] (classified in code)" | RewardSeal labels the success in code, from the trace and the diff. This one is a [RESULT: hole type. Fills from: results.md Holes found, verified under the T33 rule only] hole. | Hole found: [RESULT: hole type. Fills from: results.md Holes found] |
| 0:56 | 14 | Patch diff: [RESULT: patch rules the final run accepted. Fills from: results.md per-task table, hardening accepted patch names, and the final diff] | The patch is rule-based. [RESULT: name only the patches the final run accepted, for example strip future git objects, hidden read-only tests, network off, or the test-edit guard. Fills from: results.md per-task table, hardening accepted patch names] | Patch: [RESULT: patch summary. Fills from: results.md per-task table and the final diff] |
| 1:10 | 14 | Re-attack trace: same attacker, same budget, outcome line | Same attacker, same budget, attacks again. Result: [RESULT: re-attack outcome, number attacked and number that succeeded. Fills from: results.md Attack outcomes, after-hardening counts] | Re-attack, same attacker and budget: [RESULT: outcome. Fills from: results.md Attack outcomes, after-hardening counts] |
| 1:24 | 12 | Three gate checkboxes: [RESULT: gold patch passes; empty patch fails; attacker fails. Fills from: results.md Raw counts, Gold gate, Empty gate and Attacks run lines] | Three gates decide. The gold patch [RESULT: still passes. Fills from: results.md Raw counts, Gold gate line]. The empty patch [RESULT: still fails. Fills from: results.md Raw counts, Empty gate line]. The attacker [RESULT: fails. Fills from: results.md Attack outcomes] | Gates: [RESULT: gold passes, empty fails, attacker fails. Fills from: results.md Raw counts] |
| 1:36 | 16 | Certificate JSON for [RESULT: env id of a certified environment. Fills from: results.md Certified count, a certified row only; certificates in results/certificates/] with the three gate fields and raw counts | Only when all three gates hold does the environment get a certificate. This is the JSON for [RESULT: env id of a certified environment. Fills from: results.md Certified count, a certified row only]. | Certificate: three gates, raw counts |
| 1:52 | 16 | [RESULT: n]-environment table: before and after per attack type, n shown. Fills from: results.md Raw counts, n line and per-attack counts | Across [RESULT: n. Fills from: results.md Raw counts, n line] environments, [RESULT: k. Fills from: results.md Holes found, before hardening] had a hole before hardening and [RESULT: k2. Fills from: results.md Holes found, after hardening] after. Raw counts are on the page. | n = [RESULT: n. Fills from: results.md Raw counts, n line]; raw counts, not rates alone |
| 2:08 | 16 | Stack: Token Factory (all model calls), Nemotron Super, executor [RESULT: Sandboxes or Docker, as run. Fills from: results.md Method, Executor line] and, only if a run logged one, Tavily (network-fetch attack) | Every model call goes through Token Factory. Nemotron attacks and may draft explanations. Gates and hole labels are computed in code. [RESULT: Tavily serves the network-fetch attack; say this only if a run logged a Tavily call, else cut the sentence. Fills from: results.md Method] | Token Factory, Nemotron Super, executor, [RESULT: Tavily, only if logged, else cut. Fills from: results.md Method] |
| 2:24 | 14 | Honest caveat card: [RESULT: "Not hackable by this attacker" if results.md Certified count is above 0, else "No environment certified yet". Fills from: results.md Certified count]. Upper bound against this attacker, not proof. | Honest limit: [RESULT: this is not hackable by this attacker, only if the Certified count is above 0; otherwise say no environment is certified yet. Fills from: results.md Certified count]. It is an upper bound against this attacker, not proof. | [RESULT: caveat wording as in the on-screen card. Fills from: results.md Certified count]. Not proof. |
| 2:38 | 8 | End card: `python -m cheatproof.cli harden <env-id>` and the repo link [PLACEHOLDER: repo link after owner approval; not in results.md] | RewardSeal. One command, harden with an env id, returns the certificate. | `python -m cheatproof.cli harden <env-id>` |

## Coverage check

- Problem (reward hacking in RL coding environments): beats 3 to 4.
- Dishonest attacker: beats 2 and 4.
- Hole found, patch, re-attack [RESULT: outcome]: beats 5 to 7.
- Certificate with the three gates: beats 8 to 9.
- Scale with honest counts: beat 10.
- Token Factory, Nemotron Super, Sandboxes or Docker, Tavily (only if logged): beat 11.
- Honest caveat "not hackable by this attacker", conditional on certified count: beat 12.
- Nemotron Super model ID on screen inside the first 20 s: beat 2 (10 to 20 s).

## Open placeholders (fill after batch 3; each names its results.md field)

- Beat 1: `k of n` in the hook. Fills from results.md Attack outcomes and Holes found (verified holes only).
- Beat 4: attack trace, what the attacker did, and the caption. Fills from the per-task table, Attack outcome column.
- Beat 5: hole type (on-screen, voice-over, caption). Fills from results.md Holes found, verified under the T33 rule.
- Beat 6: patch rules and summary. Fills from the per-task table (hardening accepted) and the final diff.
- Beat 7: re-attack outcome in voice-over and caption. Fills from results.md Attack outcomes, after-hardening counts.
- Beat 8: gate results (on-screen, voice-over, caption). Fills from results.md Raw counts.
- Beat 9: env id, for a certified environment only. Fills from results.md Certified count.
- Beat 10: n, k and k2 (scale table and its voice-over and caption). Fills from results.md Raw counts and Holes found.
- Beat 11: executor, `Sandboxes or Docker, as run`. Fills from results.md Method. Tavily only if a run logged a call.
- Beat 12: caveat wording. Fills from results.md Certified count.
- Beat 13: `[PLACEHOLDER: repo link after owner approval]`. Not in results.md; the repo stays private until the owner submits.
