# Voice-over draft (about 2 minutes, for the owner)

Draft written by a read-only Codex run over the public repo, checked against `README.md` and `docs/results.md`. It is a
shorter alternative to the 13-beat table in `script.md`. The owner assembles the cut from that table and records the final
voice and may cut or reorder. Every number below is in `docs/results.md`.

| Timestamp | On-screen | Voice-over |
|---|---|---|
| 0:00-0:20 | Headline: "line overlap with future commits in 12 of 13 audited; closed in 11 of 12". Model ID on screen: `nvidia/nemotron-3-super-120b-a12b` | What if a coding agent could find the answer inside the environment? In 12 of 13 audited environments, every counted gold source line also appeared in future commits. This is line overlap, not proof the full fix was retrievable, on a non-random sample of the 18 lowest-scoring tasks. In 11 of those 12, the workdir repository's post-patch scan found no future commits and both gates held. |
| 0:20-0:45 | The loop: attack, classify, patch, re-attack, certify. Select `CycloneDX__cyclonedx-python-348`. | RewardSeal attacks, classifies, patches, re-attacks and certifies. On CycloneDX Python 348 we have one confirmed attacker finding: n equals one. Recon was on, so the attacker was shown what the exposure scan found. |
| 0:45-1:10 | The git commands, the matching fix line, the patch, the three gates, the certificate `hardened_reattack_failed`. | The attacker ran git show on the fix commit, then wrote a matching fix line; its auto-submitted diff passed the hidden tests. The command order and match are consistent with copying, but use of the output is inferred. After strip-future-git the gold patch still passed, the empty patch failed, and the re-attack failed. Both rounds configured 40 steps and 500,000 tokens; before used 40 with harness auto-submit, hardened attacker submitted after 15. Recon differed: exposure before, none after; the comparison does not isolate the patch. |
| 1:10-1:30 | "One attacker model", "lower bound", "Certified (k=1): recorded conditions only". Ultra run: "not certified". | These results have limits. The finding is one task and one attacker, and the audit is a lower bound. Certified, k equals one: one completed attack failed under the recorded conditions, with exposure removed, gold pass and empty fail checked by code. This describes hardened 348; legacy certificates lack exposure removal and hardened re-attacks. It is not a security bound. A separate Ultra run showed the same command-and-matching-line pattern; use of history is inferred. Its hardened re-attack hit the token limit, so it is not certified. |
| 1:30-2:00 | Token Factory, Nemotron, Sandboxes, Tavily, then https://manishwvn.github.io/rewardseal/ | Token Factory serves the model calls. Nemotron Super is the attacker, and Token Factory Sandboxes run the task code. Tavily ran one harness recon search; the attacker made zero own search calls. The web-exposure audit recorded twenty-six searches on thirteen tasks, zero of thirteen findability; separately eighteen on nine random-sample tasks, zero of nine. These are searches (local counter), one tool on one day, not evidence the web lacks the fix. The recorded report is at manishwvn dot github dot io slash rewardseal. |

Evidence companion to [`348-causal.md`](../../results/evidence/348-causal.md):
[`Dorthu retrieval control`](../../results/control/Dorthu__openapi3-75-retrieval-control.json), **oracle-assisted scripted control, not autonomous discovery**.
Gold-line ranking over 7 readable future commits; 3 candidates tried. The top change shares 4 gold lines and passes 1/1
fail-to-pass tests. After strip: 0 future commits in that listing, gold pass and empty fail. It **does not prove model causality**.
These numbers and the 348 budgets/usage are in `docs/claims.md`. The owner must fit this companion evidence and the expanded
comparison into the final recording; the timestamps above are draft slots, not measured narration durations.
