"""Command line for the re-attack loop, the certificate report (T07) and the static site (T09).

    python -m cheatproof.cli harden <instance-id> --system-prompt-file PATH [--source S] [--cache-dir DIR]
        [--out DIR] [--attacker-model M] [--max-steps N] [--max-tokens N] [--timeout S]
    python -m cheatproof.cli report [--certs DIR] [--out FILE] [--format text|json]
    python -m cheatproof.cli site [--certs DIR] [--out DIR] [--traces DIR]

harden finds the task in the local cache only (never the network), runs harden() with one attacker bound to the
given system prompt, writes one certificate and prints its path and a summary line. The attacker's task prompt is
a description of the task (repo, instance id, failing tests). The gold and test patches never reach it.
report prints certify.score_directory() as it is: rates with their n, raw counts, outcomes, holes and sources.
The rates, intervals and totals are computed in certify.py only; this module does no statistics of its own.
site builds the static report site through site.build_site from the certificate files. It is not a paid call:
no Budget, LLM or executor is built for it.

Exit codes: 0 a certificate was written (certified or not), or the report was printed. 1 the budget was halted or
capped, the executor refused or was unavailable, or the certificate could not be written after a paid run. 2 usage
error: bad flags, missing prompt, unknown or ambiguous task, missing setting, no certificates.
site: 0 the site was written and every certificate loaded; 1 the site was written but some did not load (each
listed on stderr), or the write failed; 2 the certificates or traces directory is missing, or --out is a non-empty
directory that is not a cheatproof site.

Collaborators come from Deps. Tests inject fakes; Deps.default() imports the real ones.
Contract with certify.score_directory: a dict with int n, n_after, hackable_before, hackable_after, certified,
inconclusive, rate_before and rate_after ({count, n, interval_95, denominator}), outcomes {outcome: count},
by_hole {label: {"before": int, "after": int}}, by_source {source: {...counts}}, schema_version and cost_usd_total.
Only n is required here. Any other key is printed when present and skipped when absent.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
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
DEFAULT_SITE_DIR = Path("results/site")
UPPER_BOUND_NOTE = "Upper bound against this attacker, not proof."
ERROR_CHARS = 300
ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]*\Z")  # what an environment variable name looks like
RATE_LABELS = (
    ("rate_before", "hackable before hardening"),
    ("rate_after", "hackable after hardening"),
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
    build_site: Callable[..., Any]
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
            build_site=_build_site,
            clock=_utc_now,
        )


def _make_llm(budget: Any) -> Any:
    from cheatproof.llm import GuardedLLM  # imports the OpenAI client, so keep it out of module import

    return GuardedLLM(budget)


def _build_site(cert_dir: Path, out_dir: Path, *, traces_dir: Path | None = None) -> Any:
    from cheatproof.site import build_site  # lazy: keeps harden and report from loading the site module

    return build_site(cert_dir, out_dir, traces_dir=traces_dir)


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


def _missing_setting(exc: KeyError) -> int:
    """A missing setting. Names the variable only when the key looks like an environment variable name."""
    key = exc.args[0] if exc.args else None
    if isinstance(key, str) and ENV_NAME.match(key):
        return _usage_error(f"environment variable {key} is not set (see .env.example)")
    return _usage_error("a required setting is missing (see .env.example)")


def _not_written(exc: BaseException, cost: float) -> int:
    """The paid run finished but its certificate was not built or written: the error and the measured spend."""
    print(
        f"certificate not written: {type(exc).__name__}: {sanitize(str(exc))[:ERROR_CHARS]}", file=sys.stderr
    )
    print(f"cost: ${cost:.4f}", file=sys.stderr)
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
    except (BudgetExceeded, ExecutorRefused, ExecutorUnavailable) as exc:
        return _failure(exc)
    except KeyError as exc:
        return _missing_setting(exc)
    except ValueError as exc:
        return _usage_error(str(exc))

    def attack_fn(session: Any) -> Any:
        return deps.attack(llm, session, system_prompt, prompt, config)

    spent_before = _spent(budget.snapshot())
    try:
        report = deps.harden(executor, env, task, attack_fn, budget=budget, **timeout_kw)
    except (BudgetExceeded, ExecutorRefused, ExecutorUnavailable) as exc:
        return _failure(exc)
    spent_after = _spent(budget.snapshot())
    cost = spent_after - spent_before
    if not (math.isfinite(cost) and cost >= 0):
        # The ledger total went down or is not a number: the spend is unknown, so no certificate is built.
        print(
            "error: cost check failed: the ledger went from "
            f"${spent_before:.4f} to ${spent_after:.4f} during the run; no certificate written",
            file=sys.stderr,
        )
        return 1

    attacker = {"model": config.model, "max_steps": config.max_steps, "max_tokens": config.max_tokens_total}
    timestamp = deps.clock()
    try:
        cert = deps.build_certificate(
            report,
            task,
            image_digest=None,  # the executor does not expose an image digest yet
            attacker=attacker,
            cost_usd=cost,
            timestamp=timestamp,
        )
        args.out.mkdir(parents=True, exist_ok=True)
        path = deps.write_certificate(cert, args.out)
    except (ValueError, OSError) as exc:
        return _not_written(exc, cost)
    print(f"certificate: {path}")
    print(_harden_line(report, cost))
    return 0


def _cell(value: Any) -> str:
    return "-" if value is None else str(value)


def _money_text(value: Any) -> str:
    return f"${value:.4f}" if isinstance(value, int | float) else str(value)


def _rate_text(label: str, rate: Any) -> str:
    """One rate as the score dict gives it: count of n = x% (95% CI lo-hi%), then the denominator text."""
    if not isinstance(rate, Mapping) or "count" not in rate or "n" not in rate:
        return f"{label}: not in the score"
    count, n = rate["count"], rate["n"]
    if not n:
        text = f"{label}: {count} of {n} (no rate: n is 0)"
    else:
        value = rate.get("rate")
        if not isinstance(value, int | float):
            value = count / n
        text = f"{label}: {count} of {n} = {value:.1%}"
        interval = rate.get("interval_95")
        if isinstance(interval, list | tuple) and len(interval) == 2:
            text += f" (95% CI {interval[0]:.1%}–{interval[1]:.1%})"
    if rate.get("denominator") is not None:
        text += f"; denominator: {rate['denominator']}"
    return text


def render_text(score: Mapping[str, Any], directory: Path) -> str:
    """The score dict as text. Every key that is present is shown; a missing optional key is skipped."""
    n = score["n"]
    header = f"n={n} certificates in {directory}"
    if "n_after" in score:
        header += f" (n_after={score['n_after']} with an after round)"
    lines = [header]
    lines += [_rate_text(label, score[key]) for key, label in RATE_LABELS if key in score]
    lines.append(UPPER_BOUND_NOTE)
    for key in ("certified", "inconclusive"):
        if key in score:
            lines.append(f"{key}: {score[key]} of {n}")
    if "cost_usd_total" in score:
        lines.append(f"cost_usd_total: {_money_text(score['cost_usd_total'])}")
    if "schema_version" in score:
        lines.append(f"schema_version: {score['schema_version']}")
    outcomes = score.get("outcomes")
    if isinstance(outcomes, Mapping):
        lines.append("outcomes (raw counts):")
        if outcomes:
            lines += [
                f"  {name}: {count}" for name, count in sorted(outcomes.items(), key=lambda kv: str(kv[0]))
            ]
        else:
            lines.append("  none")
    by_hole = score.get("by_hole")
    if isinstance(by_hole, Mapping):
        lines.append("holes (certificates per hole):")
        if by_hole:
            width = max([len("hole")] + [len(str(label)) for label in by_hole])
            lines.append(f"  {'hole':<{width}}  {'before':>6}  {'after':>5}")
            for label in sorted(by_hole, key=str):
                item = by_hole[label] if isinstance(by_hole[label], Mapping) else {}
                before, after = _cell(item.get("before")), _cell(item.get("after"))
                lines.append(f"  {label!s:<{width}}  {before:>6}  {after:>5}")
        else:
            lines.append("  none")
    by_source = score.get("by_source")
    if isinstance(by_source, Mapping):
        lines.append("by source (raw counts):")
        if by_source:
            for source in sorted(by_source, key=str):
                counts = by_source[source]
                if isinstance(counts, Mapping):
                    pairs = ", ".join(
                        f"{key}={value}" for key, value in sorted(counts.items(), key=lambda kv: str(kv[0]))
                    )
                else:
                    pairs = str(counts)
                lines.append(f"  {source}: {pairs}")
        else:
            lines.append("  none")
    return "\n".join(lines)


def cmd_report(args: argparse.Namespace, deps: Deps) -> int:
    directory: Path = args.certs
    if not directory.is_dir():
        return _usage_error(f"certificates directory not found: {directory}")
    if not any(path.is_file() for path in directory.glob("*.json")):  # the same files score_directory reads
        return _usage_error(f"no certificates (*.json) in {directory}")
    try:
        score = deps.score_directory(directory)
    except (OSError, TypeError, ValueError) as exc:
        return _usage_error(f"could not score {directory}: {sanitize(str(exc))[:ERROR_CHARS]}")
    n = score.get("n") if isinstance(score, Mapping) else None
    if isinstance(n, bool) or not isinstance(n, int):
        return _usage_error(f"could not score {directory}: the score has no count n")
    if n == 0:
        return _usage_error(f"no certificates scored under {directory}")

    payload = json.dumps(score, indent=2, sort_keys=True) + "\n"
    if args.out is not None:
        try:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(payload, encoding="utf-8")
        except OSError as exc:
            return _failure(exc)
    if args.format == "json":
        sys.stdout.write(payload)
    else:
        print(render_text(score, directory))
        if args.out is not None:
            print(f"wrote {args.out}")
    return 0


def cmd_site(args: argparse.Namespace, deps: Deps) -> int:
    """Build the static site from the certificates. Not a paid call: no Budget, LLM or executor is built."""
    cert_dir: Path = args.certs
    if not cert_dir.is_dir():
        return _usage_error(f"certificates directory not found: {cert_dir}")
    if args.traces is not None and not args.traces.is_dir():
        return _usage_error(f"traces directory not found: {args.traces}")
    try:
        result = deps.build_site(cert_dir, args.out, traces_dir=args.traces)
    except FileNotFoundError as exc:
        return _usage_error(f"site input not found: {sanitize(str(exc))[:ERROR_CHARS]}")
    except ValueError as exc:  # --out is a non-empty directory that is not a cheatproof site
        return _usage_error(sanitize(str(exc))[:ERROR_CHARS])
    except OSError as exc:
        return _failure(exc)
    print(f"site: {len(result.pages)} pages, {len(result.errors)} errors -> {result.index}")
    for name, message in result.errors:
        text = sanitize(str(message))[:ERROR_CHARS]
        print(f"error: {sanitize(str(name))[:ERROR_CHARS]}: {text}", file=sys.stderr)
    return 1 if result.errors else 0


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

    site = sub.add_parser("site", help="build the static report site from certificates; no paid calls")
    site.add_argument("--certs", type=Path, default=DEFAULT_CERT_DIR, help="certificates directory")
    site.add_argument("--out", type=Path, default=DEFAULT_SITE_DIR, help="directory for the site")
    site.add_argument(
        "--traces", type=Path, help="directory of <certificate file stem>.jsonl attacker traces (optional)"
    )
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
    if args.command == "site":
        return cmd_site(args, deps)
    return cmd_report(args, deps)


if __name__ == "__main__":
    raise SystemExit(main())
