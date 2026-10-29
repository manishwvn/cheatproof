# Recorded attack-check report

RewardSeal audits coding-agent task environments for exposed fixes and other shortcuts.
It applies rule-based hardening, rechecks gold and empty patches, and records attacker outcomes.
The report replays committed evidence; it is not a live attack.

## Recorded results

- In 12 of 13 audited environments, every counted gold-added source line appeared in a future commit; 2 of those 12 had only one counted line. After `strip-future-git`, no future commits remained in the task repo and gold and empty gates held in 11 of those 12. The 18 lowest-scoring tasks were selected; 5 were environment-broken. Line overlap does not establish that the whole fix is retrievable, and incomplete scans can miss it.
- On 348, 1 of 9 committed Super before-rounds showed a history-use pattern (1 of 7 excluding 2 HTTP 503 errors); use is inferred from command order and a matching line. Follow-up was unequal, recon was on, and these counts are not a rate. A fresh hardened re-attack failed. One separate Ultra run showed the pattern before hardening; its re-attack reached the token limit without submission and was not certified.
- The separate predeclared sample drew 12 tasks from a 1000-row frame: 9 audited, 3 environment-broken, 7 of 9 with at least half the counted lines in future commits, and 5 of those 7 closed. This is a count within the stated frame.
- There are 14 certificate files, 4 certified (1 after hardened re-attack, 3 legacy), and 11 tasks attacked. Of 9 future-history tasks attacked with recon, 1 finding was confirmed, 1 lead was unconfirmed, and 7 showed no leak use or were inconclusive.
- Tavily returned a counted gold line in 0 of 13 audited tasks; the query did not return the PR pages either. This is a dated result for one search tool, not evidence of absence.

Certified (k=1) means one completed attack failed under the recorded conditions, with exposure removed, gold pass and empty fail checked by code. The three legacy certificates record a failed initial attack with no hole found, without recorded exposure removal or hardened re-attack.

See [results](docs/results.md), [claims](docs/claims.md), [method](docs/method.md), and the [recorded report site](https://manishwvn.github.io/rewardseal/).

## How Nebius/NVIDIA are used

| Tool | Use |
|---|---|
| Nebius Token Factory + NVIDIA Nemotron | Token Factory serves model calls; Nemotron Super attacks, with one exploratory Ultra run. |
| Token Factory Sandboxes | Runs task code and gates in separate branches; Docker is a fallback. |
| Tavily | Host-side search for network-fetch experiments; one harness search was recorded, with 0 attacker search calls. |

## Quick start

Python 3.12 or newer and [uv](https://docs.astral.sh/uv/) are required. The offline commands use committed records and test fakes.

```sh
uv sync
uv run pytest -q
uv run python -m rewardseal.cli report --certs results/certificates
uv run python -m rewardseal.cli site --certs results/certificates --out results/site
uv run python -m rewardseal.manifest verify
```

The following live commands require configured credentials, cached tasks and budget settings; they can spend credits. See [method](docs/method.md) for execution and caps.

```sh
uv run python -m rewardseal.cli audit-exposure --instance-ids <task-id> --out results/exposure
uv run python -m rewardseal.cli harden <task-id> --system-prompt-file results/combined.txt --strategy combined --out results/certificates
uv run python scripts/smoke.py
```

## Limits

- Results describe small samples and the recorded attacker and conditions; recon differed in the 348 comparison.
- The detector misses some history, and model use of the observed output is inferred.
- The verifier checks artifact integrity and calculations, not historical execution. See [limitations](docs/limitations.md).

[Documentation index](docs/README.md) · [MIT license](LICENSE)
