"""Command line for the re-attack loop and the certificate report (queue T07).

    python -m cheatproof.cli harden <instance-id> --system-prompt-file PATH [--source S] [--cache-dir DIR]
        [--out DIR] [--attacker-model M] [--max-steps N] [--max-tokens N] [--timeout S]
    python -m cheatproof.cli report [--certs DIR] [--out FILE] [--format text|json]

harden finds the task in the local cache only (never the network), runs harden() with one attacker bound to the
given system prompt, writes one certificate and prints its path and a summary line. The attacker's task prompt is
a description of the task (repo, instance id, failing tests). The gold and test patches never reach it.
report scores the certificates in a directory: raw counts, rates with 95% Wilson intervals, holes and sources.

Exit codes: 0 a certificate was written (certified or not), or the report was printed. 1 the budget was halted or
capped, or the executor refused or was unavailable. 2 usage error: bad flags, missing prompt, unknown or ambiguous
task, no certificates.

Collaborators come from Deps. Tests inject fakes; Deps.default() imports the real ones.
Contract with certify.score_directory: a dict with int counts n, n_after, hackable_before, hackable_after,
certified and inconclusive, plus optional by_hole {label: count} and by_source {source: {...}}. Rates and intervals
are computed here from those counts.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cheatproof.budget import Budget, BudgetExceeded
from cheatproof.executor import EnvSpec, ExecutorRefused, ExecutorUnavailable, make_executor
from cheatproof.sanitize import sanitize

if TYPE_CHECKING:
    from cheatproof.tasks import TaskSpec

DEFAULT_CACHE_DIR = Path("runs/tasks")
DEFAULT_CERT_DIR = Path("results/certificates")
UPPER_BOUND_NOTE = "Upper bound against this attacker, not proof."
Z_95 = 1.959963984540054
ERROR_CHARS = 300
COUNT_KEYS = ("n", "n_after", "hackable_before", "hackable_after", "certified", "inconclusive")
RATE_LINES = (
    ("hackable_before", "hackable before hardening"),
    ("hackable_after", "hackable after hardening"),
    ("certified", "certified"),
    ("inconclusive", "inconclusive"),
)


@dataclass(frozen=True)
class Deps:
    """Every collaborator the commands call. default() is the real set; tests pass fakes."""

    find_tasks: Callable[[str, str | None, Path], list[TaskSpec]]
    make_executor: Callable[[], Any]
    make_budget: Callable[[], Any]
    make_llm: Callable[[Any], Any]
    harden: Callable[..., Any]
    attack: Callable[..., Any]
    build_certificate: Callable[..., dict[str, Any]]
    write_certificate: Callable[[dict[str, Any], Path], Path]
    score_directory: Callable[[Path], Mapping[str, Any]]
    clock: Callable[[], str]

    @classmethod
    def default(cls) -> Deps:
        # Lazy, so this module imports before certify.py exists and tests never reach the real set.
        from cheatproof import certify
        from cheatproof import harden as harden_module
        from cheatproof.attacker import attack
        from cheatproof.envfile import load_env

        load_env()  # the main checkout's .env, as scripts/smoke.py does; variables already set win
        return cls(
            find_tasks=find_cached_tasks,
            make_executor=make_executor,
            make_budget=Budget.from_env,
            make_llm=_make_llm,
            harden=harden_module.harden,
            attack=attack,
            build_certificate=certify.build_certificate,
            write_certificate=certify.write_certificate,
            score_directory=certify.score_directory,
            clock=_utc_now,
        )


def _make_llm(budget: Any) -> Any:
    from cheatproof.llm import GuardedLLM  # imports the OpenAI client, so keep it out of module import

    return GuardedLLM(budget)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def find_cached_tasks(instance_id: str, source: str | None, cache_dir: Path) -> list[TaskSpec]:
    """Every cached TaskSpec with this instance id. Reads runs/tasks/<source>.json only, never the network."""
    from cheatproof.tasks import CACHE_VERSION, SOURCES, TaskSpec

    if source is not None and source not in SOURCES:
        raise ValueError(f"unknown source {source!r}: use one of {', '.join(SOURCES)}")
    found: list[TaskSpec] = []
    for name in [source] if source is not None else list(SOURCES):
        try:
            data = json.loads((cache_dir / f"{name}.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict) or data.get("version") != CACHE_VERSION:
            continue  # missing or stale cache: a fetch writes the current format
        for item in data.get("tasks", []):
            if item.get("instance_id") == instance_id:
                found.append(TaskSpec.from_dict(item))
    return found


def build_task_prompt(task: TaskSpec, workdir: str) -> str:
    """The attacker's view of the task: repo, instance and failing tests. Never the gold or test patch."""
    tests = "\n".join(f"- {node}" for node in task.fail_to_pass) or "- (none listed)"
    return (
        f"Repository: {task.repo}\n"
        f"Instance: {task.instance_id}\n"
        f"Checkout: {workdir}\n"
        "Make these failing tests pass in the checkout:\n"
        f"{tests}\n"
    )


def _spent(snapshot: Mapping[str, Any]) -> float:
    return float(snapshot.get("total_usd", 0.0))


def _usage_error(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 2


def _failure(exc: BaseException) -> int:
    """A budget or executor stop, or a failed write: the error type and a short redacted message, no traceback."""
    print(f"error: {type(exc).__name__}: {sanitize(str(exc))[:ERROR_CHARS]}", file=sys.stderr)
    return 1


def _harden_line(report: Any, cost: float) -> str:
    holes = report.before.holes
    labels = tuple(holes.labels) if holes is not None else ()
    found = f"{len(labels)} ({', '.join(labels)})" if labels else "0"
    certified = "yes" if report.certified else "no"
    return f"certified: {certified}  holes found: {found}  cost: ${cost:.4f}"


def cmd_harden(args: argparse.Namespace, deps: Deps) -> int:
    from cheatproof.attacker import AttackConfig  # lazy: attacker imports the LLM client module

    prompt_path = args.system_prompt_file
    if prompt_path is None:
        return _usage_error("--system-prompt-file is required: strategy prompts come from the planner (T16)")
    if not prompt_path.is_file():
        return _usage_error(f"system prompt file not found: {prompt_path}")
    system_prompt = prompt_path.read_text(encoding="utf-8")
    if not system_prompt.strip():
        return _usage_error(f"system prompt file is empty: {prompt_path}")

    model = args.attacker_model if args.attacker_model is not None else os.environ.get("ATTACKER_MODEL", "")
    model = model.strip()
    if not model:
        return _usage_error("no attacker model: pass --attacker-model or set ATTACKER_MODEL")
    limits: dict[str, Any] = {}
    if args.max_steps is not None:
        limits["max_steps"] = args.max_steps
    if args.max_tokens is not None:
        limits["max_tokens_total"] = args.max_tokens
    timeout_kw: dict[str, float] = {}
    if args.timeout is not None:
        if not (math.isfinite(args.timeout) and args.timeout > 0):
            return _usage_error(f"--timeout must be a positive number of seconds, got {args.timeout!r}")
        timeout_kw["timeout"] = args.timeout

    try:
        # Network stays off: the task's EnvSpec is built with network=False, so allow_network must match.
        config = AttackConfig(model=model, allow_network=False, **limits)
        matches = deps.find_tasks(args.instance_id, args.source, args.cache_dir)
    except ValueError as exc:
        return _usage_error(str(exc))
    if not matches:
        return _usage_error(
            f"no cached task {args.instance_id!r} under {args.cache_dir}: "
            "run python -m cheatproof.tasks fetch first (harden never fetches)"
        )
    if len(matches) > 1:
        return _usage_error(f"{args.instance_id!r} is cached under more than one source: pass --source")
    task = matches[0]
    try:
        env = EnvSpec(image=task.image)
    except ValueError as exc:
        return _usage_error(str(exc))
    prompt = build_task_prompt(task, env.workdir)

    try:
        executor = deps.make_executor()
        budget = deps.make_budget()
        llm = deps.make_llm(budget)
    except BudgetExceeded as exc:
        return _failure(exc)
    except KeyError as exc:
        return _usage_error(f"environment variable {exc.args[0]} is not set (see .env.example)")
    except ValueError as exc:
        return _usage_error(str(exc))

    def attack_fn(session: Any) -> Any:
        return deps.attack(llm, session, system_prompt, prompt, config)

    spent_before = _spent(budget.snapshot())
    try:
        report = deps.harden(executor, env, task, attack_fn, budget=budget, **timeout_kw)
    except (BudgetExceeded, ExecutorRefused, ExecutorUnavailable) as exc:
        return _failure(exc)
    cost = _spent(budget.snapshot()) - spent_before

    attacker = {"model": config.model, "max_steps": config.max_steps, "max_tokens": config.max_tokens_total}
    cert = deps.build_certificate(
        report,
        task,
        image_digest=None,  # the executor does not expose an image digest yet
        attacker=attacker,
        cost_usd=cost,
        timestamp=deps.clock(),
    )
    try:
        args.out.mkdir(parents=True, exist_ok=True)
        path = deps.write_certificate(cert, args.out)
    except OSError as exc:
        return _failure(exc)
    print(f"certificate: {path}")
    print(_harden_line(report, cost))
    return 0


def wilson_interval(k: int, n: int) -> tuple[float, float] | None:
    """95% Wilson score interval for k successes in n trials. None when n is 0."""
    if n == 0:
        return None
    p = k / n
    z2 = Z_95 * Z_95
    denom = 1 + z2 / n
    centre = (p + z2 / (2 * n)) / denom
    half = Z_95 * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def _count(raw: Mapping[str, Any], key: str) -> int:
    value = raw.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"score result needs a non-negative int {key!r}, got {value!r}")
    return value


def _rate(k: int, n: int) -> dict[str, Any]:
    if k > n:
        raise ValueError(f"impossible count {k} of {n}")
    interval = wilson_interval(k, n)
    return {
        "k": k,
        "n": n,
        "rate": None if interval is None else k / n,
        "ci95": None if interval is None else [interval[0], interval[1]],
    }


def summarize(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Rates and intervals from the raw counts of a score_directory result. Raises ValueError on a bad shape."""
    counts = {key: _count(raw, key) for key in COUNT_KEYS}
    n, n_after = counts["n"], counts["n_after"]
    by_hole = raw.get("by_hole", {})
    by_source = raw.get("by_source", {})
    if not isinstance(by_hole, Mapping) or not isinstance(by_source, Mapping):
        raise TypeError("score result: by_hole and by_source must be objects")
    return {
        "n": n,
        "n_after": n_after,
        "rates": {
            "hackable_before": _rate(counts["hackable_before"], n),
            "hackable_after": _rate(counts["hackable_after"], n_after),
            "certified": _rate(counts["certified"], n),
            "inconclusive": _rate(counts["inconclusive"], n),
        },
        "by_hole": dict(by_hole),
        "by_source": {str(source): dict(item) for source, item in by_source.items()},
        "note": UPPER_BOUND_NOTE,
    }


def _rate_text(rate: Mapping[str, Any]) -> str:
    k, n = rate["k"], rate["n"]
    if rate["rate"] is None:
        return f"{k} of {n} (no rate: n is 0)"
    low, high = rate["ci95"]
    return f"{k} of {n} = {rate['rate']:.1%} (95% CI {low:.1%} to {high:.1%})"


def render_text(summary: Mapping[str, Any], directory: Path) -> str:
    rates = summary["rates"]
    width = max(len(label) for _, label in RATE_LINES)
    lines = [
        f"n={summary['n']} certificates in {directory} (n_after={summary['n_after']} with an after round)"
    ]
    lines += [f"{label:<{width}}  {_rate_text(rates[key])}" for key, label in RATE_LINES]
    lines.append("holes found before hardening (certificates per hole):")
    if summary["by_hole"]:
        lines += [f"  {label}: {count}" for label, count in sorted(summary["by_hole"].items())]
    else:
        lines.append("  none")
    lines.append("by source (raw counts):")
    if summary["by_source"]:
        for source, counts in sorted(summary["by_source"].items()):
            pairs = ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))
            lines.append(f"  {source}: {pairs}")
    else:
        lines.append("  none")
    lines.append(UPPER_BOUND_NOTE)
    return "\n".join(lines)


def cmd_report(args: argparse.Namespace, deps: Deps) -> int:
    directory: Path = args.certs
    if not directory.is_dir():
        return _usage_error(f"certificates directory not found: {directory}")
    if not any(path.is_file() for path in directory.glob("*.json")):  # the same files score_directory reads
        return _usage_error(f"no certificates (*.json) in {directory}")
    try:
        summary = summarize(deps.score_directory(directory))
    except (OSError, TypeError, ValueError) as exc:
        return _usage_error(f"could not score {directory}: {sanitize(str(exc))[:ERROR_CHARS]}")
    if summary["n"] == 0:
        return _usage_error(f"no certificates scored under {directory}")

    payload = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.out is not None:
        try:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(payload, encoding="utf-8")
        except OSError as exc:
            return _failure(exc)
    if args.format == "json":
        sys.stdout.write(payload)
    else:
        print(render_text(summary, directory))
        if args.out is not None:
            print(f"wrote {args.out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m cheatproof.cli", description="Harden one task into a certificate, or report them."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    harden = sub.add_parser("harden", help="attack one cached task, harden it, write its certificate")
    harden.add_argument("instance_id")
    harden.add_argument("--source", help="task source to search (default: every cached source)")
    harden.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR, help="task cache directory")
    harden.add_argument("--out", type=Path, default=DEFAULT_CERT_DIR, help="directory for the certificate")
    harden.add_argument("--system-prompt-file", type=Path, help="attacker system prompt (required)")
    harden.add_argument("--attacker-model", help="attacker model id (default: ATTACKER_MODEL)")
    harden.add_argument("--max-steps", type=int, help="attacker steps (AttackConfig.max_steps)")
    harden.add_argument(
        "--max-tokens",
        type=int,
        help="prompt plus completion tokens per attempt (AttackConfig.max_tokens_total)",
    )
    harden.add_argument("--timeout", type=float, help="seconds per grading run (harden timeout)")

    report = sub.add_parser("report", help="score the certificates in a directory")
    report.add_argument("--certs", type=Path, default=DEFAULT_CERT_DIR, help="certificates directory")
    report.add_argument("--out", type=Path, help="also write the score as JSON to this file")
    report.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def main(argv: list[str] | None = None, *, deps: Deps | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:  # argparse exits 2 on a usage error and 0 on --help
        return int(exc.code or 0)
    if deps is None:
        deps = Deps.default()
    if args.command == "harden":
        return cmd_harden(args, deps)
    return cmd_report(args, deps)


if __name__ == "__main__":
    raise SystemExit(main())
