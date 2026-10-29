"""Deterministic, text-free records of public web search overlap."""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import re
import tempfile
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from rewardseal import audit, holes
from rewardseal.strategies import clean_text

SCHEMA = "rewardseal.web-exposure"
DEFAULT_DIR = Path("results/web-exposure")
RESULT_KEYS = {
    "rank",
    "url",
    "page_type",
    "repo_match",
    "sha256",
    "chars",
    "k",
    "n",
    "trivial",
    "matched_line_digests",
    "current_file_page",
}
RECORD_KEYS = {
    "schema",
    "schema_version",
    "instance_id",
    "repo",
    "queries",
    "q1_best_k",
    "q2_best_k",
    "q1_best_k_history_pages",
    "q2_best_k_history_pages",
    "q1_best_k_blob_pages",
    "q2_best_k_blob_pages",
    "q1_first_pr_or_commit_rank",
    "q1_half_or_more",
    "n",
}


def make_tavily_raw_search(
    budget: Any,
    api_key: str | None = None,
    max_results: int = 5,
    client_factory: Callable[..., Any] | None = None,
) -> Callable[[str], list[dict]]:
    key = api_key if api_key is not None else os.environ.get("TAVILY_API_KEY")
    if not key:
        raise RuntimeError("TAVILY_API_KEY not set")
    if client_factory is None:
        from tavily import TavilyClient

        client_factory = TavilyClient

    def search(query: str) -> list[dict]:
        budget.reserve_tavily_call()
        response = client_factory(key).search(
            query, max_results=max_results, include_raw_content=True, search_depth="basic"
        )
        items = response.get("results") if isinstance(response, dict) else None
        items = [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []
        if any(isinstance(item, dict) and key in str(item.get("url", "")) for item in items):
            raise ValueError("search result URL contains a credential")
        return [
            {
                "title": item.get("title", ""),
                "url": item.get("url", ""),
                "raw_content": item.get("raw_content") or "",
            }
            for item in items
            if isinstance(item, dict)
        ]

    return search


def oracle_query(instance_id: str, repo: str) -> str:
    match = re.fullmatch(r"([^/]+)__([^/]+)-(\d+)", instance_id)
    if (
        not match
        or re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) is None
        or f"{match[1]}/{match[2]}".lower() != repo.lower()
    ):
        raise ValueError("task has no usable instance id or repo")
    return f"github.com/{repo}/pull/{match[3]}"


def queries(task: Any) -> list[tuple[str, str]]:
    title = next((line.strip() for line in task.problem_statement.splitlines() if line.strip()), "")

    def normalize(text: str) -> str:
        return " ".join(text.split()).lower()

    # Inspect the entire title and query before cleaning or truncating either.
    normalized_query = normalize(f"{title} {task.repo}")
    patch_lines = [
        normalize(line[1:])
        for patch in (task.gold_patch, task.test_patch)
        for line in patch.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]
    headers = [
        normalize(line)
        for patch in (task.gold_patch, task.test_patch)
        for line in patch.splitlines()
        if line.startswith(
            (
                "diff ",
                "index ",
                "---",
                "+++",
                "@@",
                "rename from ",
                "rename to ",
                "copy from ",
                "copy to ",
                "new file mode ",
                "deleted file mode ",
                "old mode ",
                "new mode ",
                "similarity index ",
                "dissimilarity index ",
            )
        )
    ]
    unsafe = (
        any(char in title for char in "(){};=")
        or any(line in normalized_query for line in patch_lines if len(line) >= 20)
        or any(line in normalized_query for line in headers)
    )
    title = "" if unsafe else clean_text(title, 150)
    query = f"{title} {task.repo}" if title else task.repo
    return [("q1", query), ("oracle", oracle_query(task.instance_id, task.repo))]


def best_k(results: list[dict], kinds: set[str]) -> int:
    return max((r["k"] for r in results if r["repo_match"] and r["page_type"] in kinds), default=0)


def page_type(url: str) -> str:
    parsed = urlsplit(url)
    if (parsed.hostname or "").lower() == "raw.githubusercontent.com":
        return "raw"
    parts = parsed.path.strip("/").split("/")
    if (
        (parsed.hostname or "").lower() == "github.com"
        and len(parts) >= 3
        and parts[2] in {"pull", "commit", "compare", "blob"}
    ):
        return parts[2]
    return "other"


def score_result(item: Mapping[str, Any], rank: int, repo: str, gold: frozenset[str]) -> dict[str, Any]:
    url = item.get("url", "")
    raw = item.get("raw_content", "")
    if not isinstance(url, str) or not isinstance(raw, str):
        raise TypeError("invalid search result")
    parsed = urlsplit(url)
    parts = parsed.path.strip("/").split("/")
    repo_match = (
        (parsed.hostname or "").lower() == "github.com"
        and len(parts) >= 2
        and "/".join(parts[:2]).lower() == repo.lower()
    )
    digests = set()
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("+"):
            line = line[1:].lstrip()
        if line:
            digest = holes.future_line_digest(line)
            if digest:
                digests.add(digest)
    matched = sorted(gold & digests)
    kind = page_type(url)
    return {
        "rank": rank,
        "url": url,
        "page_type": kind,
        "repo_match": repo_match,
        "sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        "chars": len(raw),
        "k": len(matched),
        "n": len(gold),
        "trivial": len(gold) <= 1,
        "matched_line_digests": [d[:16] for d in matched],
        "current_file_page": kind == "blob" and bool(matched),
    }


def build_record(task: Any, search: Callable[..., Any], clock: Callable[[], str]) -> dict[str, Any]:
    gold = audit.gold_line_digests(task)
    collected = []
    for label, query in queries(task):
        results = search(query)
        collected.append(
            {
                "label": label,
                "query": query,
                "searched_at": clock(),
                "results": [
                    score_result(item, rank, task.repo, gold) for rank, item in enumerate(results, 1)
                ],
            }
        )
    q1, q2 = (q["results"] for q in collected)
    relevant = [r for r in q1 if r["repo_match"] and r["page_type"] in {"pull", "commit", "compare"}]
    n = len(gold)
    record = {
        "schema": SCHEMA,
        "schema_version": 1,
        "instance_id": task.instance_id,
        "repo": task.repo,
        "queries": collected,
        "q1_best_k": max((r["k"] for r in q1), default=0),
        "q2_best_k": max((r["k"] for r in q2), default=0),
        "q1_best_k_history_pages": best_k(q1, {"pull", "commit", "compare"}),
        "q2_best_k_history_pages": best_k(q2, {"pull", "commit", "compare"}),
        "q1_best_k_blob_pages": best_k(q1, {"blob"}),
        "q2_best_k_blob_pages": best_k(q2, {"blob"}),
        "q1_first_pr_or_commit_rank": next(
            (r["rank"] for r in q1 if r["repo_match"] and r["page_type"] in {"pull", "commit"}), None
        ),
        "q1_half_or_more": n > 0 and any(r["k"] >= math.ceil(n / 2) for r in relevant),
        "n": n,
    }
    validate_record(record)
    return record


def validate_record(record: Any) -> None:
    def require(ok: bool) -> None:
        if not ok:
            raise ValueError("invalid web exposure record")

    def integer(v: Any) -> bool:
        return type(v) is int and v >= 0

    require(isinstance(record, dict) and set(record) == RECORD_KEYS)
    require(
        record["schema"] == SCHEMA and type(record["schema_version"]) is int and record["schema_version"] == 1
    )
    require(all(isinstance(record[x], str) and record[x] for x in ("instance_id", "repo")))
    audit.record_filename(record["instance_id"])
    oracle = oracle_query(record["instance_id"], record["repo"])
    require(integer(record["n"]) and isinstance(record["queries"], list) and len(record["queries"]) == 2)
    for q, label in zip(record["queries"], ("q1", "oracle"), strict=True):
        require(isinstance(q, dict) and set(q) == {"label", "query", "searched_at", "results"})
        require(
            q["label"] == label
            and isinstance(q["query"], str)
            and bool(q["query"])
            and isinstance(q["searched_at"], str)
            and isinstance(q["results"], list)
        )
        if label == "oracle":
            require(q["query"] == oracle)
        try:
            parsed = datetime.fromisoformat(q["searched_at"])
            require(parsed.utcoffset() is not None and parsed.utcoffset().total_seconds() == 0)
        except (ValueError, TypeError):
            raise ValueError("invalid web exposure timestamp") from None
        for rank, r in enumerate(q["results"], 1):
            require(isinstance(r, dict) and set(r) == RESULT_KEYS)
            require(
                r["rank"] == rank
                and integer(r["rank"])
                and isinstance(r["url"], str)
                and r["page_type"] == page_type(r["url"])
            )
            require(
                type(r["repo_match"]) is bool
                and type(r["trivial"]) is bool
                and type(r["current_file_page"]) is bool
            )
            require(
                all(integer(r[x]) for x in ("chars", "k", "n"))
                and r["n"] == record["n"]
                and r["k"] <= r["n"]
                and r["trivial"] == (r["n"] <= 1)
            )
            require(isinstance(r["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", r["sha256"]) is not None)
            require(
                isinstance(r["matched_line_digests"], list)
                and len(r["matched_line_digests"]) == r["k"]
                and all(
                    isinstance(d, str) and re.fullmatch(r"[0-9a-f]{16}", d) for d in r["matched_line_digests"]
                )
            )
            require(r["matched_line_digests"] == sorted(set(r["matched_line_digests"])))
            require(r["current_file_page"] == (r["page_type"] == "blob" and r["k"] > 0))
            parts = urlsplit(r["url"])
            require(
                r["repo_match"]
                == (
                    (parts.hostname or "").lower() == "github.com"
                    and "/".join(parts.path.strip("/").split("/")[:2]).lower() == record["repo"].lower()
                )
            )
    q1, q2 = (q["results"] for q in record["queries"])
    require(all(integer(record[k]) for k in ("q1_best_k", "q2_best_k")))
    require(
        record["q1_best_k"] == max((r["k"] for r in q1), default=0)
        and record["q2_best_k"] == max((r["k"] for r in q2), default=0)
    )
    for label, results in (("q1", q1), ("q2", q2)):
        for group, kinds in (("history", {"pull", "commit", "compare"}), ("blob", {"blob"})):
            key = f"{label}_best_k_{group}_pages"
            require(integer(record[key]) and record[key] == best_k(results, kinds))
    require(
        (record["q1_first_pr_or_commit_rank"] is None or type(record["q1_first_pr_or_commit_rank"]) is int)
        and record["q1_first_pr_or_commit_rank"]
        == next((r["rank"] for r in q1 if r["repo_match"] and r["page_type"] in {"pull", "commit"}), None)
    )
    require(
        type(record["q1_half_or_more"]) is bool
        and record["q1_half_or_more"]
        == (
            record["n"] > 0
            and any(
                r["repo_match"]
                and r["page_type"] in {"pull", "commit", "compare"}
                and r["k"] >= math.ceil(record["n"] / 2)
                for r in q1
            )
        )
    )


def check_path(path: Path, *, directory: bool = False) -> None:
    """Refuse links in any path component before reading, skipping or writing."""
    path = Path(path).absolute()
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise OSError("symbolic link refused")
        if parent != path and parent.exists() and not parent.is_dir():
            raise OSError("path parent is not a directory")
    if path.exists() and (not path.is_dir() if directory else not path.is_file()):
        raise OSError("invalid output path type")


def _write(data: Any, folder: Path, name: str) -> Path:
    folder = Path(folder)
    check_path(folder, directory=True)
    target = folder / name
    check_path(target)
    folder.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=folder, prefix=f".{name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise
    return target


def write_record(record: dict[str, Any], directory: Path) -> Path:
    validate_record(record)
    name = audit.record_filename(record["instance_id"])
    target = Path(directory) / name
    check_path(target)
    if target.exists():
        old = load_record(target)
        if old["instance_id"] != record["instance_id"]:
            raise ValueError("record belongs to another instance")
    return _write(record, directory, name)


def load_record(path: Path) -> dict[str, Any]:
    path = Path(path)
    check_path(path)
    data = json.loads(path.read_text(encoding="utf-8"), parse_constant=audit._refuse_constant)
    validate_record(data)
    if path.name != audit.record_filename(data["instance_id"]):
        raise ValueError("record filename does not match instance")
    return data
