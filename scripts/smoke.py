"""Smoke test: Token Factory key, NVIDIA model IDs, one capped Nemotron call, one capped Sandbox run."""

import asyncio
import os

from dotenv import load_dotenv

load_dotenv()

from twindiff.budget import Budget
from twindiff.llm import GuardedLLM

budget = Budget.from_env()
llm = GuardedLLM(budget)


def list_nvidia_models() -> list[str]:
    # VERIFY: model listing assumed free, so it skips the budget.
    ids = [m.id for m in llm.client.models.list().data]
    nvidia = sorted(i for i in ids if "nemotron" in i.lower() or i.lower().startswith("nvidia/"))
    print(f"{len(ids)} models total, NVIDIA/Nemotron:")
    for i in nvidia:
        print(f"  {i}")
    return nvidia


def call_triage_model() -> None:
    model = os.environ.get("TRIAGE_MODEL", "nvidia/Nemotron-3-Nano-30B-A3B")
    resp = llm.chat(model, [{"role": "user", "content": "Reply with exactly: twin-diff ok"}], max_tokens=64)
    print(f"{model}: {resp.choices[0].message.content!r} usage={resp.usage}")


async def sandbox_hello() -> None:
    from contree_sdk import Contree

    budget.reserve_sandbox_run()
    base = await Contree().images.use("alpine:3.19", strict=True)
    result = await base.run(shell="echo sandbox ok && uname -a", disposable=True)
    print(f"sandbox exit={result.exit_code} stdout={result.stdout.strip()!r}")


if __name__ == "__main__":
    list_nvidia_models()
    call_triage_model()
    if os.environ.get("NEBIUS_PROJECT_ID"):
        asyncio.run(sandbox_hello())
    else:
        print("NEBIUS_PROJECT_ID not set, skipping sandbox check")
    print(f"ledger: {budget.snapshot()}")
