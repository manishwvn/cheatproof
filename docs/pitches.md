# Pitches: Nebius x NVIDIA Global AI Hackathon

Judging: 4 equally weighted criteria, each scored 1–5 (Technological Implementation, Design, Potential Impact, Quality of Idea). Tie-break is Tech Implementation. Solo dev plus AI, 14 days (deadline 2026-10-30 10:00 PDT). Budget: about $50 of Token Factory credits.

Research inputs (2026): "run N and pick one" is table stakes. Selecting a winner without ground truth is open (ICML 2026, arXiv 2603.04304). There were 7 sandbox-escape "trust handoff" disclosures across Cursor, Codex CLI, Gemini CLI and Antigravity (Jul 2026, CVE-2026-48124). Package hallucination runs 5–22%, which feeds slopsquatting (CSA, Apr 2026). AI-era PR review time is reportedly up 441% [weak source], and maintainers are banning AI PRs (Ghostty, QEMU, NetBSD). curl ended its bug bounty as valid reports fell below 5%. Past winners in this space: GitLab 2026 RedAgent (verifies AI security reports), Gitdefender (fixes security in review) and Time-Traveler (tests migrations on a prod copy).
Underused Nebius capabilities: Sandboxes branching from checkpoints (50 concurrent ops in beta), 7,000+ preloaded SWE environments, Batch at 50% price, Data Lab, LoRA/SFT post-training, custom speculators. Nemotron 3 Nano Omni takes audio up to 1 h and video up to 2 min, with `reasoning_budget`.

---

## P1. Forkcast: parallel-branch bug fixer (control)
- **Track:** Coding & Agentic Engineering
- **What:** issue → K hypotheses (Ultra) → one sandbox branch each (Super patches, Nano triages logs) → tests decide → PR.
- **Eval:** SWE-rebench solve rate vs a single-branch baseline.
- **Weakness:** "N attempts, pick one" is now a standard product feature, so the idea score is low.

## P2. Tripwire: detonation chamber for coding-agent inputs
- **Track:** Coding & Agentic Engineering
- **User:** teams that let background coding agents work on untrusted inputs (OSS issues and PRs, third-party repos, vendored code).
- **Problem:** in 2026, agents are hijacked through files they read: AGENTS.md, .cursorrules, MCP configs, postinstall scripts, test fixtures. There were 7 disclosures in 2026. Hallucinated dependencies enable slopsquatting.
- **What:** before a real agent touches a repo or PR, Tripwire "detonates" it. It forks a Contree sandbox per entry point (instruction files, setup scripts, tests, MCP config) from one checkpoint. A Nemotron canary agent holding honeytoken credentials does a normal task on each branch. Tripwire records hijack signals: honeytoken reads, egress attempts, writes outside the workspace, hook or config edits, tool calls that diverge from a clean twin branch. Nano triages traces, Ultra writes the verdict and a minimal sanitizing patch. Dependencies are checked against registries, and Tavily looks up advisories and typosquat reports.
- **Output:** a GitHub check "Agent-safe: pass/fail" with an evidence timeline.
- **Eval:** a corpus of about 40 seeded malicious repos (patterns from public disclosures) plus about 40 benign SWE-rebench repos. Report detection and false-positive rate, and compare with static scanners such as a grep for "ignore previous instructions".
- **Demo moment:** watch the canary agent get hijacked live in a branch, while the clean twin branch stays normal.
- **Risks:** building a credible malicious corpus in time. Defensive framing is required.

## P3. Oracle: a learned patch verifier trained on sandbox outcomes
- **Track:** Coding & Agentic Engineering
- **User:** anyone running several coding agents who must pick which patch to trust without hidden tests.
- **What:** a data flywheel entirely on Token Factory.
  1. Batch API (50% price): Super generates N patches per SWE-rebench task.
  2. Sandboxes runs each patch in a branch against the hidden tests, which yields labels.
  3. Data Lab builds a dataset; a LoRA fine-tune turns Nemotron Nano into a verifier.
  4. At inference the Nano verifier ranks patches without tests.
- **Product:** a GitHub Action that ranks competing agent PRs, plus an API.
- **Eval:** top-1 pick accuracy and $/task vs Ultra-as-judge, majority vote and random.
- **Why notable:** addresses an open ICML 2026 problem, uses the whole Token Factory stack, and few or no entrants will fine-tune.
- **Risks:** fine-tune cost and turnaround on $50, results may not beat Ultra-as-judge, and the product experience is thin (Design score).

## P4. Receipts: evidence-first review of AI pull requests for maintainers
- **Track:** Coding & Agentic Engineering, or Best Apps & Agents
- **User:** OSS maintainers flooded with AI-written PRs (projects banning them; review time exploding).
- **What:** for each PR, base and PR are forked from the same checkpoint. The agent writes **differential tests** that expose the behaviour change. It **mutation-tests the PR's own tests** to show whether they would catch regressions. It reproduces the linked issue before and after, and flags hallucinated or typosquatted dependencies (Tavily plus registry). It then posts a one-screen "receipt": what changed, proof, risk, and a verdict suggestion. The maintainer decides in 60 seconds.
- **Eval:** on SWE-rebench, known-good gold patches vs known-bad agent patches. Measure how often Receipts flags the bad ones and the reviewer time saved.
- **Graft option:** the Oracle verifier (P3) as v2.
- **Risks:** overlaps GitLab winners (Gitdefender, RedAgent) in theme, though the method differs.

## P5. Repro: paper-to-result reproduction agent
- **Track:** Best Apps & Agents
- **User:** ML reviewers and researchers. Nebius's core customers are ML teams.
- **Problem:** reproducibility of ML papers is low. One weak source claims a 28–30% median; the PaperBench top agent scores 24%.
- **What:** takes an arXiv URL. It finds the code and data (Tavily), then builds the environment in sandbox branches, one per dependency-version hypothesis. It runs a CPU-scale experiment and diffs the reproduced numbers against the paper's table. Output is a reproducibility report card.
- **Risks:** most papers need GPUs, while sandboxes are CPU only, so scope is limited to small papers. Reliability in 14 days is low.

## P6. Witness: a private meeting-to-action assistant
- **Track:** Personal AI
- **What:** Nemotron Nano Omni ingests meeting audio and video. Hermes Agent skills turn it into real actions (tickets, emails drafted, calendar). It runs under OpenShell egress policy with persistent memory.
- **Problem:** 42% of users have little trust in AI firms with private data [weak source].
- **Risks:** a crowded idea (meeting assistants); NemoClaw/OpenShell maturity is unverified.

---

# Round 2 (xhigh research, 2026-10-16)

## Corrections to round 1
- Token Factory post-training does **not** support Nemotron (only Qwen, Llama, gpt-oss, DeepSeek, Gemma). Any "fine-tune Nemotron" plan is invalid, so P3 Oracle is dropped. It is also novelty 1/5: SWE-Gym, R2E-Gym and OpenHands critic already did it.
- arXiv 2603.04304 is "V1: Unifying Generation and Self-Verification for Parallel Reasoners" (pairwise self-verification). It is not an "open problem" paper.
- "7 disclosures" is one Pillar Security series (Jul 20 2026): Cursor ×3, Antigravity ×2, Codex ×1, Docker socket ×1. CVE-2026-48124 affects Cursor versions **before** 3.0.0.
- Real CVEs: CVE-2025-53773 (Copilot autoApprove), CVE-2025-54135/54136 (Cursor MCP), CVE-2025-61260 (Codex CLI repo config, 9.8), CVE-2026-21852 (Claude Code repo settings leak key).
- Hallucinated packages: 21.7% open-source models, 5.2% commercial (Spracklen et al., USENIX Sec 2025, arXiv 2406.10279).
- curl bounty ended Feb 1 2026 (primary source has no percentages). +441% review time: unverified. CodeRabbit 10.83 vs 6.45 issues/PR: confirmed vendor study (Dec 2025). METR: experienced devs 19% slower with AI (Jul 2025).
- Sandboxes: networking can only be on or off (REST, `networking.enabled`); no egress allowlist. Only stdout/stderr are captured, with no strace or network logs. Root inside the VM. 50 concurrent ops. Per-run pricing not documented.
- Billing: card required, prepaid balance, auto-charge at a "configured threshold" (default unknown), no documented hard cap, HTTP 402 at zero.

## Refined candidates
### R1. Tripwire v2: behavioural twin-diff for agent inputs (from P2)
One checkpoint of the base branch. The same canary task runs on a **clean twin** branch and on a **PR-applied** branch. Every tool call and filesystem change is diffed (we own the agent harness, so all calls are logged; image diffs show file writes; network is off by default, and attempts show up as failed calls in the trace). A divergence the task does not explain is flagged as a GitHub check with a side-by-side timeline. Benchmark on Trail of Bits-style evasions (padding, indirection) that beat static scanners, plus benign SWE-rebench PRs. Novel part: action divergence from one checkpoint, not file text (closest: MELON masked re-run, SkillDetonate).
### R2. Ablate: which AGENTS.md rules are worth their tokens (new)
ETH Zurich (arXiv 2602.11988, Feb 2026): context files "do not generally improve task success" and raise cost by over 20%. Ablate forks a sandbox per rule (rule removed) and runs the same SWE tasks per branch. It reports pass-rate delta and token/step delta for each rule, then opens a PR with a trimmed file. Tavily flags rules that cite stale library versions. Risk: per-rule signal is noisy at a small task count. Lead with cost savings.
### R3. Clean Room: runtime environment bring-up (new)
EnvBench 2025: the best agent set up 6.69% of 329 Python repos (older models). Static "agent-readiness" scorers only read files. Clean Room runs the install inside a sandbox, forks one branch per fix hypothesis, and turns the first green branch into a PR with a devcontainer or setup script. Tavily searches the exact error string plus version.
### R4. Receipts v2: does this PR actually fix the linked issue? (from P4)
Derive a fail-to-pass test from the issue text, run it on base and on PR branches from one checkpoint, and show the flip. Measure false-accept on gold vs bad SWE-rebench patches. Closest: SWT-bench, Otter, PatchDiff.
### R5. Deposit Ledger: renter move-out evidence assistant (Personal AI, new)
Move-in and move-out phone video, sampled frames, Nemotron 3.5 Super VL. Room-by-room change log, persistent tenancy memory, a drafted dispute letter, deadline reminders, nothing sent without approval. Tavily cites current deposit-scheme rules. UK data: 22% faced unfair deductions (date unverified). Risks: legal-advice line, lighting and angle errors.

---

# Decision (judge panel, xhigh, 2026-10-16)

| Judge | Winner | Runner-up | R1 score (official 4, /20) |
|---|---|---|---|
| NVIDIA engineer | R1 | R5 | 14 |
| Nebius product head | R1 | R3 | 16 |
| Video-only skeptic + Tavily | R1 | R5 | 15 |
| (round 1, medium) Devpost skeptic | P2 → R1 | — | 17 |

**Pick: R1, behavioural twin-diff for coding-agent inputs.** Unanimous. Honest odds: about 4% top-3 (judge estimate; base rate 0.2%). Nothing guarantees a win.

## Must-fix before build (from judges)
1. **Noise control:** run the clean twin 2–3 times and flag only divergences absent from every clean run.
2. **Scope:** corpus of 15 malicious + 15 benign, not 40 + 40. Two entry points first (instruction files such as AGENTS.md/.cursorrules/MCP config, and setup scripts such as postinstall/conftest).
3. **Honest eval:** split seeded vs held-out evasions (Trail of Bits-style padding and indirection). Compare against static scanners and a MELON-style baseline. Report detection, false-positive rate and $/scan.
4. **Tavily must change the verdict, not decorate it:** packages a PR adds are checked against the registry plus Tavily (new, unpopular or advisory-flagged packages raise risk, since hallucination runs 21.7% for open models), and unexplained divergences are matched to disclosed techniques with cited sources.
5. **Name:** "Tripwire" is an existing security company's trademark, and the rules forbid third-party marks in the video. Rename before any public asset.

## Grafts
- Token and step ledger per branch (from R2), shown in the GitHub check.
- Gold-vs-bad SWE-rebench PRs as the benign-side eval (from R4).
- "Suggest, never push" rule for the sanitizing patch (from R5).

## Eval cost estimate (Nebius judge)
About 180 sandbox runs (30 repos × 2 branches × 3 reps), about 2–3k Nano canary calls, about 30 Ultra verdicts. Cap spend in-app at about $40.
