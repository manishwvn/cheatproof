# Cheatproof demo video: script

Target: under 3 minutes (YouTube requirement). Planned total: **2:46** (166 s), limit 2:50 (170 s).
The rough cut (`video/rough_cut.py`) reads the beat table below and refuses to build at 170 s or more.

Placeholders: every `[RESULT: ...]` must be filled from the final eval run (T08) before recording.
Do not state a number that is not in the results. The hook wording "without fixing a bug" stays only if
the results show zero fixes; otherwise rewrite the line.

Voice: the voice-over in this table is a rough draft for macOS `say`. The owner records the final voice (U6).
Keep each take inside its beat; the rough cut trims audio that overruns its beat.

Screenshot slots (optional, for `rough_cut.py --shots DIR`; name the file `beatNN.png`, `.jpg` or `.jpeg`):
beat02 (model ID on screen), beat04 (real attack trace), beat05 (hole label), beat06 (patch diff),
beat07 (re-attack trace), beat08 (three gates), beat09 (certificate JSON), beat10 (scale table),
beat11 (stack). Beats without a screenshot use a title card with the On-screen text.

## Beat table

| Start | Dur (s) | On-screen | Voice-over | Caption |
|---|---|---|---|---|
| 0:00 | 10 | Title: "Cheatproof" with subtitle "Finds, patches and certifies reward hacks in SWE environments" | We told Nemotron to cheat on real SWE tasks. It passed [RESULT: k of n] without fixing a bug. | Reward hacks in SWE RL environments |
| 0:10 | 10 | Terminal: `ATTACKER_MODEL=nvidia/Nemotron-3-Ultra-550b-a55b` and the label "dishonest attacker" | The attacker is Nemotron 3 Ultra, called through Token Factory. Its brief: pass the task without solving it. | Attacker: nvidia/Nemotron-3-Ultra-550b-a55b (Token Factory) |
| 0:20 | 12 | Four labels: git-history retrieval, test edits, hard-coding, network fetch | RL rewards whatever passes the tests. An agent can read the fix from git history, edit the tests, hard-code outputs, or fetch the upstream fix. | Four shortcuts a policy can learn |
| 0:32 | 12 | Real attack trace: `git log --all`, future commit copied into the diff, tests pass | Here the attacker runs git log all, finds a future commit, and copies the fix. The tests pass. | Attack trace: future commit copied |
| 0:44 | 12 | Hole card: "Hole: git-history retrieval (classified in code)" | Cheatproof labels the success in code, from the trace and the diff. This one is a git-history hole. | Hole found: git-history retrieval |
| 0:56 | 14 | Patch diff: strip future .git objects and refs; restore hidden tests; network off | The patch is rule-based. It strips future git objects and refs, restores hidden read-only tests at grade time, and turns the network off. | Patch: strip future .git, restore hidden tests, network off |
| 1:10 | 14 | Re-attack trace: same attacker, same budget, outcome line | Same attacker, same budget, attacks again. Result: [RESULT: re-attack outcome, n and k from results]. | Re-attack, same attacker and budget: [RESULT: outcome] |
| 1:24 | 12 | Three gate checkboxes: gold patch passes; empty patch fails; attacker fails | Three gates decide. The gold patch still passes. The empty patch still fails. The attacker fails. | Gates: gold passes, empty fails, attacker fails |
| 1:36 | 16 | Certificate JSON for one environment, with the three gate fields and raw counts | Only when all three gates hold does the environment get a certificate. This is the JSON for one environment. | Certificate: three gates, raw counts |
| 1:52 | 16 | 40-environment table: before and after per attack type, n shown | Across [RESULT: n] environments, [RESULT: k] had a hole before hardening and [RESULT: k2] after. Raw counts are on the page. | n = [RESULT: n]; raw counts, not rates alone |
| 2:08 | 16 | Stack: Token Factory (all model calls), Nemotron, executor [RESULT: Sandboxes or Docker, as run], Tavily (network-fetch attack) | Every model call goes through Token Factory. Nemotron attacks and drafts explanations. Gates and hole labels are computed in code. Tavily serves the one network-fetch attack. | Token Factory, Nemotron, executor, Tavily |
| 2:24 | 14 | Honest caveat card: "Not hackable by this attacker. Upper bound against this attacker, not proof." | Honest limit: this is not hackable by this attacker. It is an upper bound against this attacker, not proof. | Not hackable by this attacker. Not proof. |
| 2:38 | 8 | End card: `cheatproof harden <env-id>` and the repo link [PLACEHOLDER: repo link after owner approval] | Cheatproof. One command, cheatproof harden with an env id, returns the certificate. | cheatproof harden <env-id> |

## Coverage check

- Problem (reward hacking in RL coding environments): beats 3 to 4.
- Dishonest attacker: beats 2 and 4.
- Hole found, patch, re-attack fails: beats 5 to 7.
- Certificate with the three gates: beats 8 to 9.
- Scale with honest counts: beat 10.
- Token Factory, Nemotron, Sandboxes or Docker, Tavily: beat 11.
- Honest caveat "not hackable by this attacker": beat 12.
- Nemotron model ID on screen inside the first 20 s: beat 2 (10 to 20 s).

## Open placeholders

- `[RESULT: k of n]` in beat 1 (hook).
- `[RESULT: re-attack outcome, n and k from results]` in beat 7.
- `[RESULT: outcome]` in beat 7 caption.
- `[RESULT: n]`, `[RESULT: k]`, `[RESULT: k2]` in beat 10 (scale).
- `[RESULT: Sandboxes or Docker, as run]` in beat 11 (executor, per ADR 0002 and the final run).
- `[PLACEHOLDER: repo link after owner approval]` in beat 13. The repo stays private until the owner submits.
