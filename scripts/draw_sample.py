"""Draw the predeclared random sample for the second exposure audit (see docs/method.md#sample-protocol).

    uv run python scripts/draw_sample.py [--seed 20261029] [--n 12]

Pool: every cached swe-rebench task (runs/tasks/swe-rebench.json), minus the deny-listed repos, minus the 18 tasks of
the first (lowest-scoring) selection. Sorted by instance id, then random.Random(seed).sample. Prints the ids and writes
results/exposure-sample/_selection.json. Reads the task cache only: no network, no model, no sandbox.
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

from rewardseal import tasks
from rewardseal.tasks import DEFAULT_DENY_REPOS, TaskSpec

SEED = 20261029
N = 12


def draw(specs: list[TaskSpec], first_ids: set[str], seed: int, n: int) -> tuple[list[str], int]:
    pool = sorted(
        s.instance_id for s in specs if s.repo not in DEFAULT_DENY_REPOS and s.instance_id not in first_ids
    )
    return sorted(random.Random(seed).sample(pool, min(n, len(pool)))), len(pool)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--n", type=int, default=N)
    parser.add_argument("--cache-dir", type=Path, default=tasks.RUNS_TASKS)
    parser.add_argument("--first-run", type=Path, default=Path("results/exposure/_run.json"))
    parser.add_argument("--out", type=Path, default=Path("results/exposure-sample/_selection.json"))
    args = parser.parse_args(argv)
    cache = json.loads((args.cache_dir / "swe-rebench.json").read_text(encoding="utf-8"))
    specs = [TaskSpec.from_dict(item) for item in cache["tasks"]]
    first = set(json.loads(args.first_run.read_text(encoding="utf-8"))["selected_ids"])
    chosen, pool = draw(specs, first, args.seed, args.n)
    record = {
        "schema": "rewardseal.exposure-sample-selection",
        "seed": args.seed,
        "n": args.n,
        "pool_size": pool,
        "rule": "cached swe-rebench tasks, minus deny-listed repos, minus the first 18 selected, sorted by instance id, random.Random(seed).sample",
        "selected_ids": chosen,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"pool {pool}, drew {len(chosen)} with seed {args.seed}")
    print("\n".join(chosen))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
