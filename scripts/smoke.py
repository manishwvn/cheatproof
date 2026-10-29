"""Smoke test: Token Factory key, NVIDIA model IDs, one capped Nemotron call, one capped Sandbox run.

--record DIR also saves sanitized fixtures: the /v1/models listing (models.json) and the chat completion
(chat_completion.json).
"""

import argparse
import json
import os
from pathlib import Path

ENV_LOADED = False
if __name__ == "__main__":
    # Load .env before the rewardseal imports below: llm.py reads MAX_OUTPUT_TOKENS when it is imported.
    # Only when run as a script, so importing this module (the tests do) never reads .env.
    from rewardseal.envfile import load_env

    ENV_LOADED = load_env()

from rewardseal.budget import Budget, BudgetExceeded
from rewardseal.executor import SandboxExecutor, _halt_for_payment
from rewardseal.llm import GuardedLLM
from rewardseal.sanitize import assert_clean, sanitize

SMOKE_IMAGE = "alpine:3.19"
SMOKE_CMD = "echo sandbox ok && uname -a"
SMOKE_TIMEOUT_S = 60


def list_nvidia_models(llm: GuardedLLM) -> dict:
    ids = llm.list_models()  # listing is free, see GuardedLLM.list_models
    nvidia = sorted(i for i in ids if "nemotron" in i.lower() or i.lower().startswith("nvidia/"))
    print(f"{len(ids)} models total, NVIDIA/Nemotron:")
    for i in nvidia:
        print(f"  {i}")
    return {"object": "list", "data": [{"id": i, "object": "model"} for i in ids]}


def call_cheap_model(llm: GuardedLLM):
    model = os.environ.get("CLASSIFIER_MODEL", "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B")
    resp = llm.chat(model, [{"role": "user", "content": "Reply with exactly: rewardseal ok"}], max_tokens=64)
    print(f"{model}: {resp.choices[0].message.content!r} usage={resp.usage}")
    return resp


def sandbox_hello(budget: Budget) -> None:
    # One reservation for the one disposable run below. A session start is not used: it runs `git ls-files` in its
    # workdir before any command, and alpine has no git repo, so it would fail after reserving a run.
    budget.reserve_sandbox_run()  # the cap check comes before any SDK import or network call
    client = SandboxExecutor()._get_client()
    failure: BaseException | None = None
    try:
        # images.oci finds the tag or imports it from the registry on a miss, as the executor does for task images.
        # images.use (the executor's path for other names) is lazy: it makes no call, and an untagged name only
        # fails later at run() with NotFoundError. alpine is about 3 MB, so the import is cheap.
        base = client.images.oci(SMOKE_IMAGE)
        done = base.run(shell=SMOKE_CMD, disposable=True, timeout=SMOKE_TIMEOUT_S).wait()
    except Exception as exc:
        failure = _halt_for_payment(exc, budget)  # HTTP 402 halts every paid call, as in the executor
        if failure is None:
            raise
    if failure is not None:
        raise failure from None  # outside the except block: the SDK error is never the __context__
    result = done.result
    print(f"sandbox exit={result.exit_code} stdout={result.stdout.strip()!r}")
    cost = getattr(result, "cost", None)  # the executor's _check_cost rule: no cost reported, nothing to book
    if cost is not None:
        budget.book_sandbox_cost(cost)


def run_sandbox_step(budget: Budget) -> None:
    try:
        sandbox_hello(budget)
    except BudgetExceeded:
        raise  # a tripped cap or a halt must stop the run, never turn into a skipped step
    except Exception as exc:  # noqa: BLE001 - optional step: print the class name only, never the message
        print(f"sandbox step skipped ({type(exc).__name__})")


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

    print(f".env loaded from main checkout: {ENV_LOADED}")
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
