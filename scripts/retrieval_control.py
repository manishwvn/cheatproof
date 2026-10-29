"""Deterministic retrieval control on one cached task (no model, no Tavily; Sandboxes only, booked on the budget).

    EXECUTOR=sandbox uv run python scripts/retrieval_control.py --instance-id Dorthu__openapi3-75 [--out results/control]

Writes results/control/<instance id>-retrieval-control.json. See rewardseal/control.py: the record says what a scripted
retrieval of the future commit did before and after strip-future-git; it does not prove model causality.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rewardseal import cli, control
from rewardseal.budget import BudgetExceeded
from rewardseal.executor import EnvSpec


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--cache-dir", type=Path, default=cli.DEFAULT_CACHE_DIR)
    parser.add_argument("--out", type=Path, default=Path("results/control"))
    args = parser.parse_args(argv)
    deps = cli.Deps.default()
    tasks = deps.find_tasks(args.instance_id, None, args.cache_dir)
    if not tasks:
        print(f"error: {args.instance_id} is not in the task cache", file=sys.stderr)
        return 2
    task = tasks[0]
    executor = deps.make_executor()
    budget = deps.make_budget()
    try:
        with executor.start(EnvSpec(image=task.image), budget) as session:
            record = control.run_control(session, task)
    except BudgetExceeded as exc:
        print(f"stopped (budget): {exc}", file=sys.stderr)
        return 1
    path = control.write_record(record, args.out)
    print(f"wrote {path}")
    print(record["before_strip"], record["after_strip"], sep="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
