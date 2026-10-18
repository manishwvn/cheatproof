"""Smoke test: Token Factory key, NVIDIA model IDs, one capped Nemotron call, one capped Sandbox run.

--record DIR also saves sanitized fixtures: the /v1/models listing (models.json) and the chat completion
(chat_completion.json).
"""

import argparse
import asyncio
import json
import os
from pathlib import Path

from cheatproof.budget import Budget
from cheatproof.envfile import load_env
from cheatproof.llm import GuardedLLM
from cheatproof.sanitize import assert_clean, sanitize


def list_nvidia_models(llm: GuardedLLM) -> dict:
    # VERIFY: model listing assumed free, so it skips the budget.
    page = llm.client.models.list()
    ids = [m.id for m in page.data]
    nvidia = sorted(i for i in ids if "nemotron" in i.lower() or i.lower().startswith("nvidia/"))
    print(f"{len(ids)} models total, NVIDIA/Nemotron:")
    for i in nvidia:
        print(f"  {i}")
    return page.model_dump(mode="json")


def call_cheap_model(llm: GuardedLLM):
    model = os.environ.get("CLASSIFIER_MODEL", "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B")
    resp = llm.chat(model, [{"role": "user", "content": "Reply with exactly: cheatproof ok"}], max_tokens=64)
    print(f"{model}: {resp.choices[0].message.content!r} usage={resp.usage}")
    return resp


async def sandbox_hello(budget: Budget) -> None:
    from contree_sdk import Contree

    budget.reserve_sandbox_run()
    base = await Contree().images.use("alpine:3.19", strict=True)
    result = await base.run(shell="echo sandbox ok && uname -a", disposable=True)
    print(f"sandbox exit={result.exit_code} stdout={result.stdout.strip()!r}")


def run_sandbox_step(budget: Budget) -> None:
    try:
        asyncio.run(sandbox_hello(budget))
    except Exception as exc:  # noqa: BLE001 - optional step: report the class and a short, redacted message
        print(f"sandbox step skipped ({type(exc).__name__}): {sanitize(str(exc))[:200]}")


def record_fixtures(out_dir: Path, models_listing: dict, completion: dict) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, payload in (("models.json", models_listing), ("chat_completion.json", completion)):
        clean = sanitize(payload)
        assert_clean(clean)
        (out_dir / name).write_text(json.dumps(clean, indent=2, sort_keys=True) + "\n")
        print(f"recorded {out_dir / name}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--record", metavar="DIR", type=Path, help="save sanitized fixtures into DIR")
    args = parser.parse_args(argv)

    print(f".env loaded from main checkout: {load_env()}")
    budget = Budget.from_env()
    llm = GuardedLLM(budget)
    print(f"ledger before: {budget.snapshot()}")
    try:
        models_listing = list_nvidia_models(llm)
        resp = call_cheap_model(llm)
        if os.environ.get("NEBIUS_PROJECT_ID"):
            run_sandbox_step(budget)
        else:
            print("NEBIUS_PROJECT_ID not set, skipping sandbox check")
        if args.record:
            record_fixtures(args.record, models_listing, resp.model_dump(mode="json"))
    finally:
        print(f"ledger after: {budget.snapshot()}")


if __name__ == "__main__":
    main()
