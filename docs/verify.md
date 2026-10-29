# Verify RewardSeal evidence

Run `uv run python -m rewardseal.manifest verify` to compare the frozen
`results/manifest.json` with local evidence: inventory, SHA-256, byte counts, and
report totals. Exit codes: 0 matches, 1 mismatch or unreadable evidence, 2 usage.

After reviewing an intentional evidence change, rebuild with
`uv run python -m rewardseal.manifest build` and commit the evidence and manifest
together. `--root`, `--out` (build), and `--manifest` (verify) support other local
checkouts; paths must stay inside the root. `build --fixed-time <UTC timestamp>`
supports reproducible fixtures. The snapshot includes all covered files in the
checkout, including new evidence awaiting commit; symlinks are refused.

Pages publishes `verify.html` with sibling `verify.js`, `verify.css`, and `manifest.json`. Click **Verify
evidence** to fetch the listed artifacts from this repository's `main` branch,
hash their bytes with Web Crypto, and independently recompute all stored exposure and certificate totals, including the exposure source.
Certificate fallback nulls mean unmeasured counts; unknown totals are labeled
"not recomputed in the browser". The page uses only self-hosted scripts and styles.
The **Tamper demo** flips one byte in a downloaded exposure record in memory;
it never writes a file or sends modified bytes. Its hash fails and the totals
check becomes untrusted. Reload or verify again to reset. Serve over HTTPS or
localhost for Web Crypto. A changed `main` can fail against an older manifest.

Verifies artifact integrity and calculations, not historical execution or security.
The manifest is a reviewable snapshot, not a signature or independent trust anchor.
The browser checks listed files; the local verifier also detects added evidence.
Only primary `results/exposure` records contribute to the headline exposure
totals; sample, replication, ultra, and web audit artifacts are integrity checked.

The manual `gate-example.yml` uses the local composite action with default
directories. Callers need checkout, `permissions: {contents: read}`, and this
Python project's `pyproject.toml`/`uv.lock`. Inputs `records-dir` and `certs-dir`
select records and certificates; frozen-manifest verification still covers the
standard evidence paths. The uploaded artifact contains `report.txt`. The gate
validates recorded evidence and calculations without running an attacker.
