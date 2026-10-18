"""Task-spec loader for SWE-bench Verified and SWE-rebench (queue T03).

Rows come from the Hugging Face datasets-server rows API over plain HTTP (httpx, no datasets library, no key,
no budget: it is free and public). Each row becomes a TaskSpec or is skipped with a counted reason. select_tasks
picks small, pure-Python tasks in a fixed order, so the same input always gives the same list. Parsed candidates
are cached under runs/tasks/<source>.json (git-ignored). Tests inject a fake fetcher and never reach the network.

Run: python -m cheatproof.tasks fetch [--source swe-rebench|swe-bench-verified|all] [--n N]
"""

from __future__ import annotations

import argparse
import json
import os
import re
from collections import Counter
from collections.abc import Callable, Collection, Iterable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import httpx

from cheatproof.executor import IMAGE_RE

ROWS_URL = "https://datasets-server.huggingface.co/rows"
PAGE_MAX = 100  # the rows API refuses longer pages
HTTP_TIMEOUT_S = 60
CACHE_VERSION = 1
RUNS_TASKS = Path(__file__).resolve().parent.parent / "runs" / "tasks"
NON_PYTHON_PENALTY = 1000.0  # a gold patch touching a non-.py file ranks after every all-Python task
# Repos with compiled extensions: slow, disk-heavy images that do not fit the pure-Python goal.
DEFAULT_DENY_REPOS = frozenset(
    {
        "astropy/astropy",
        "numpy/numpy",
        "scipy/scipy",
        "pandas-dev/pandas",
        "matplotlib/matplotlib",
        "scikit-learn/scikit-learn",
    }
)
_DIFF_FILE = re.compile(r"^diff --git a/(\S+) b/", re.MULTILINE)


@dataclass(frozen=True)
class TaskSpec:
    instance_id: str
    repo: str
    base_commit: str
    image: str
    fail_to_pass: tuple[str, ...]
    pass_to_pass: tuple[str, ...]
    gold_patch: str
    test_patch: str
    source: str  # "swe-rebench" or "swe-bench-verified"

    def to_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "fail_to_pass": list(self.fail_to_pass),
            "pass_to_pass": list(self.pass_to_pass),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> TaskSpec:
        return cls(
            instance_id=data["instance_id"],
            repo=data["repo"],
            base_commit=data["base_commit"],
            image=data["image"],
            fail_to_pass=tuple(data["fail_to_pass"]),
            pass_to_pass=tuple(data["pass_to_pass"]),
            gold_patch=data["gold_patch"],
            test_patch=data["test_patch"],
            source=data["source"],
        )


@dataclass(frozen=True)
class Source:
    name: str
    dataset: str
    config: str
    split: str
    default_n: int
    scan_rows: int  # rows read from the top of the split when no scan size is given
    derive_image: bool  # SWE-bench Verified has no image field, so the name is built from instance_id


SOURCES: dict[str, Source] = {
    "swe-rebench": Source(
        "swe-rebench",
        "nebius/SWE-rebench",
        "default",
        "test",
        default_n=30,
        scan_rows=1000,
        derive_image=False,
    ),
    "swe-bench-verified": Source(
        "swe-bench-verified",
        "princeton-nlp/SWE-bench_Verified",
        "default",
        "test",
        default_n=10,
        scan_rows=500,
        derive_image=True,
    ),
}

# fetch(dataset, config, split, offset, length) -> one rows-API response, {"rows": [{"row": {...}}], ...}
Fetcher = Callable[[str, str, str, int, int], Mapping[str, Any]]


class RowSkip(Exception):
    """A row that cannot become a TaskSpec. `reason` is the label counted in the skip totals."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _http_fetch(dataset: str, config: str, split: str, offset: int, length: int) -> Mapping[str, Any]:
    # Errors raise, so a failed page never reaches the cache: a partial scan is never stored.
    res = httpx.get(
        ROWS_URL,
        params={"dataset": dataset, "config": config, "split": split, "offset": offset, "length": length},
        timeout=HTTP_TIMEOUT_S,
    )
    res.raise_for_status()
    return res.json()


def _text(row: Mapping[str, Any], key: str) -> str:
    value = row.get(key)
    if not isinstance(value, str) or not value:
        raise RowSkip("missing_field")
    return value


def _tests(row: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = row.get(key)
    if isinstance(value, str):  # the Verified split stores its test lists as JSON text
        try:
            value = json.loads(value)
        except ValueError:
            raise RowSkip("bad_tests") from None
    if not isinstance(value, list) or not all(isinstance(t, str) for t in value):
        raise RowSkip("bad_tests")
    return tuple(value)


def _derived_image(instance_id: str) -> str:
    # The name SWE-bench images use: "__" becomes "_1776_". Docker needs lower case.
    return f"swebench/sweb.eval.x86_64.{instance_id.replace('__', '_1776_')}:latest".lower()


def _image(source: Source, instance_id: str, row: Mapping[str, Any]) -> str:
    image = row.get("docker_image")
    if not image and source.derive_image:
        image = _derived_image(instance_id)
    if not image:
        raise RowSkip("no_image")
    # Same check the executor applies before docker sees the name, so a bad name is skipped here, not at run time.
    if not isinstance(image, str) or not IMAGE_RE.fullmatch(image):
        raise RowSkip("bad_image")
    return image


def parse_row(source: Source, row: Mapping[str, Any]) -> TaskSpec:
    """Turn one rows-API row into a TaskSpec. Raises RowSkip with the reason when the row cannot run."""
    fields = {key: _text(row, key) for key in ("instance_id", "repo", "base_commit", "patch", "test_patch")}
    image = _image(source, fields["instance_id"], row)
    fail_to_pass = _tests(row, "FAIL_TO_PASS")
    if not fail_to_pass:  # nothing to grade without a fail-to-pass test
        raise RowSkip("no_fail_to_pass")
    return TaskSpec(
        instance_id=fields["instance_id"],
        repo=fields["repo"],
        base_commit=fields["base_commit"],
        image=image,
        fail_to_pass=fail_to_pass,
        pass_to_pass=_tests(row, "PASS_TO_PASS"),
        gold_patch=fields["patch"],
        test_patch=fields["test_patch"],
        source=source.name,
    )


def parse_rows(source: Source, rows: Iterable[Mapping[str, Any]]) -> tuple[list[TaskSpec], Counter[str]]:
    specs: list[TaskSpec] = []
    skipped: Counter[str] = Counter()
    seen: set[str] = set()
    for row in rows:
        try:
            spec = parse_row(source, row)
        except RowSkip as skip:
            skipped[skip.reason] += 1
            continue
        if spec.instance_id in seen:
            skipped["duplicate"] += 1
            continue
        seen.add(spec.instance_id)
        specs.append(spec)
    return specs, skipped


def fetch_rows(
    source: Source, *, scan_rows: int, fetcher: Fetcher | None = None, page_size: int = PAGE_MAX
) -> list[Mapping[str, Any]]:
    """Read rows page by page until scan_rows rows, the end of the split, or an empty page."""
    fetch = fetcher or _http_fetch
    page = max(1, min(page_size, PAGE_MAX))
    rows: list[Mapping[str, Any]] = []
    while len(rows) < scan_rows:
        length = min(page, scan_rows - len(rows))
        data = fetch(source.dataset, source.config, source.split, len(rows), length)
        batch = data.get("rows") or []
        rows.extend(item["row"] for item in batch)
        total = data.get("num_rows_total")
        if not batch or (total is not None and len(rows) >= total):
            break
    return rows[:scan_rows]


def _patch_files(patch: str) -> list[str]:
    return _DIFF_FILE.findall(patch)


def score(spec: TaskSpec) -> float:
    """Lower is better: test count, then gold-patch size in KB, plus a penalty per non-.py file."""
    tests = len(spec.fail_to_pass) + len(spec.pass_to_pass)
    non_python = sum(1 for path in _patch_files(spec.gold_patch) if not path.endswith(".py"))
    return tests + len(spec.gold_patch) / 1000 + NON_PYTHON_PENALTY * non_python


def select_tasks(
    specs: Iterable[TaskSpec],
    n: int,
    *,
    allow_repos: Collection[str] | None = None,
    deny_repos: Collection[str] = DEFAULT_DENY_REPOS,
) -> list[TaskSpec]:
    """The n best tasks by score, then instance_id. The order of the input never changes the result."""
    if n < 0:
        raise ValueError("n must be >= 0")
    pool = [s for s in specs if s.repo not in deny_repos and (allow_repos is None or s.repo in allow_repos)]
    pool.sort(key=lambda s: (score(s), s.instance_id))
    return pool[:n]


@dataclass(frozen=True)
class Loaded:
    source: str
    scanned: int  # rows read from the API
    valid: int  # rows that parsed into a TaskSpec
    skipped: Mapping[str, int]  # rows that did not parse, counted by reason
    selected: tuple[TaskSpec, ...]


def _source(name: str) -> Source:
    try:
        return SOURCES[name]
    except KeyError:
        raise ValueError(f"unknown source {name!r}: use one of {', '.join(SOURCES)}") from None


def _read_cache(path: Path, source: str, scan_rows: int) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if (
        data.get("version") != CACHE_VERSION
        or data.get("source") != source
        or data.get("scan_rows") != scan_rows
    ):
        return None  # a different scan size or format is a different cache
    return data


def _write_cache(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=1), encoding="utf-8")
    os.replace(tmp, path)  # atomic: a crash never leaves half a cache


def load_tasks(
    source: str,
    refresh: bool = False,
    fetcher: Fetcher | None = None,
    *,
    n: int | None = None,
    scan_rows: int | None = None,
    cache_dir: Path | None = None,
    allow_repos: Collection[str] | None = None,
    deny_repos: Collection[str] = DEFAULT_DENY_REPOS,
) -> Loaded:
    """Selected tasks for one source, read from the cache when it matches, else from the rows API."""
    src = _source(source)
    scan = src.scan_rows if scan_rows is None else scan_rows
    path = (cache_dir or RUNS_TASKS) / f"{src.name}.json"
    cached = None if refresh else _read_cache(path, src.name, scan)
    if cached is None:
        rows = fetch_rows(src, scan_rows=scan, fetcher=fetcher)
        specs, skipped = parse_rows(src, rows)
        cached = {
            "version": CACHE_VERSION,
            "source": src.name,
            "scan_rows": scan,
            "scanned": len(rows),
            "skipped": dict(skipped),
            "tasks": [spec.to_dict() for spec in specs],
        }
        _write_cache(path, cached)
    specs = [TaskSpec.from_dict(item) for item in cached["tasks"]]
    picked = select_tasks(
        specs, src.default_n if n is None else n, allow_repos=allow_repos, deny_repos=deny_repos
    )
    return Loaded(
        source=src.name,
        scanned=cached["scanned"],
        valid=len(specs),
        skipped=cached["skipped"],
        selected=tuple(picked),
    )


def main(
    argv: list[str] | None = None, *, fetcher: Fetcher | None = None, cache_dir: Path | None = None
) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m cheatproof.tasks", description="Load and cache task specs."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    fetch = sub.add_parser("fetch", help="read rows, write runs/tasks/<source>.json, print counts")
    fetch.add_argument("--source", choices=[*SOURCES, "all"], default="all")
    fetch.add_argument("--n", type=int, help="tasks to select (needs a single --source)")
    fetch.add_argument("--scan-rows", type=int, help="rows to read per source (default: per source)")
    fetch.add_argument("--refresh", action="store_true", help="ignore the cache and read the rows API again")
    fetch.add_argument("--allow-repo", action="append", help="select only these repos (repeatable)")
    fetch.add_argument(
        "--deny-repo", action="append", help="leave these repos out (repeatable; replaces the default)"
    )
    args = parser.parse_args(argv)

    names = list(SOURCES) if args.source == "all" else [args.source]
    if args.n is not None and len(names) > 1:
        parser.error("--n needs a single --source")
    deny = DEFAULT_DENY_REPOS if args.deny_repo is None else args.deny_repo
    for name in names:
        loaded = load_tasks(
            name,
            refresh=args.refresh,
            fetcher=fetcher,
            n=args.n,
            scan_rows=args.scan_rows,
            cache_dir=cache_dir,
            allow_repos=args.allow_repo,
            deny_repos=deny,
        )
        reasons = ", ".join(f"{k}={v}" for k, v in sorted(loaded.skipped.items())) or "none"
        print(f"{name}: scanned={loaded.scanned} valid={loaded.valid} selected={len(loaded.selected)}")
        print(f"  skipped by reason: {reasons}")
        for spec in loaded.selected:
            print(f"  {spec.instance_id}  {spec.image}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
