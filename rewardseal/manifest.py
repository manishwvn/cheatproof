"""Freeze and verify local evidence bytes and the report's calculated totals. No network."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from rewardseal import audit, certify

SCHEMA = "rewardseal.evidence-manifest"
PATTERNS = (
    "results/certificates/*.json",
    "results/exposure/*.json",
    "results/exposure-sample/*.json",
    "results/confirmations.json",
    "results/batch.json",
    "results/evidence/*.md",
    "results/evidence/*.json",
    "results/replications/*.json",
    "results/ultra/*.json",
    "results/control/*.json",
    "results/web-exposure/*.json",
    "results/web-exposure-sample/*.json",
    "results/replay-attempt/*.json",
    "results/diffs/*.diff.json",
    "results/combined.txt",
    "docs/claims.md",
)
EXPOSURE_KEYS = ("M", "N_future", "N_fix", "N_full_overlap", "N_closed", "N_fix_closed")


def _covered(name: str) -> bool:
    path = PurePosixPath(name)
    return any(
        path.parent == PurePosixPath(pattern).parent and path.match(pattern) for pattern in PATTERNS
    ) and not name.endswith(".old")


def _local(root: Path, path: Path) -> Path:
    """Confine reads and writes to root; refuse links before following any component."""
    target = path if path.is_absolute() else root / path
    relative = target.relative_to(root)  # raises rather than reading outside root
    if ".." in relative.parts:
        raise ValueError(f"outside root: {path}")
    current = root
    if current.is_symlink():
        raise ValueError(f"symlink refused: {current}")
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"symlink refused: {relative.as_posix()}")
    return target


def evidence_files(root: Path, excluded: Path) -> list[Path]:
    """Every covered file in the checkout, including new evidence awaiting commit."""
    found: set[Path] = set()
    for pattern in PATTERNS:
        # Check parents even for an absent optional folder: glob must never traverse a link.
        _local(root, Path(pattern).parent)
        for path in root.glob(pattern):
            _local(root, path)
            if path == excluded or path.name.endswith(".old"):
                continue
            if not path.is_file():
                raise ValueError(f"not a regular evidence file: {path.relative_to(root)}")
            found.add(path)
    return sorted(found, key=lambda path: path.relative_to(root).as_posix())


def totals(root: Path) -> dict[str, Any]:
    summary = audit.exposure_summary(root / "results/exposure", root / "results/certificates")
    result = {key: summary[key] if summary is not None else 0 for key in EXPOSURE_KEYS}
    result["exposure_source"] = summary["source"] if summary is not None else "none"
    certs = [
        certify.load_certificate(path) for path in sorted((root / "results/certificates").glob("*.json"))
    ]
    score = certify.score(certs)
    result.update(n=score["n"], certified=score["certified"])
    return result


def _head_blobs(root: Path) -> dict[str, str]:
    """Covered paths in HEAD with their blob ids. ls-tree takes literal paths, not globs: list folders, then filter."""
    folders = sorted({str(PurePosixPath(p).parent) if "*" in p else p for p in PATTERNS})
    listed = subprocess.run(
        ["git", "-C", str(root), "ls-tree", "-r", "-z", "HEAD", "--", *folders],
        capture_output=True,
        check=True,
        timeout=30,
    ).stdout
    blobs = {}
    for record in listed.split(b"\0"):
        meta, _, name = record.partition(b"\t")  # "<mode> <type> <id>", a tab, then the raw path
        if name and _covered(os.fsdecode(name)):
            blobs[os.fsdecode(name)] = meta.split()[2].decode()
    return blobs


def _repo_sha(root: Path) -> str | None:
    try:
        top = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()
        if Path(top) != root:
            return None
        sha = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{40,64}", sha):
            return None
        # HEAD only names the bytes when the covered files on disk are exactly the covered files in HEAD, blob for
        # blob (modified, staged, deleted, untracked, ignored and nested files all differ). Compare against the HEAD
        # tree, not the index or status: --assume-unchanged and --skip-worktree hide edits from status, and a
        # submodule or nested repository hides its files from the parent. Ignore rules do not matter: only covered
        # paths are compared, so .venv, runs/ and results/traces never count, and a tracked file stays equal to HEAD.
        disk = [
            path.relative_to(root).as_posix() for path in evidence_files(root, root / "results/manifest.json")
        ]
        head = _head_blobs(root)
        if set(disk) != set(head):
            return None
        # Hash the raw bytes the manifest records, like hash-object --no-filters: a clean filter or eol attribute
        # could map other bytes onto the HEAD blob, and the blob is what a fetch at this sha returns.
        algorithm = "sha256" if len(sha) == 64 else "sha1"  # the repository's object format
        for name, blob in head.items():
            data = (root / name).read_bytes()
            if hashlib.new(algorithm, b"blob %d\0" % len(data) + data).hexdigest() != blob:
                return None
        return sha
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def build(root: Path, out: Path, fixed_time: str | None = None) -> dict[str, Any]:
    root = root.absolute()
    target = _local(root, out)
    files = []
    for path in evidence_files(root, target):
        data = path.read_bytes()
        files.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
            }
        )
    document = {
        "schema": SCHEMA,
        "schema_version": 1,
        "generated_utc": fixed_time or datetime.now(UTC).isoformat(),
        "repo_sha": _repo_sha(root),
        "files": files,
        "totals": totals(root),
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(document, sort_keys=True, indent=2, allow_nan=False) + "\n", encoding="utf-8"
    )
    return document


def _entries(document: Any) -> list[dict[str, Any]]:
    if (
        not isinstance(document, dict)
        or document.get("schema") != SCHEMA
        or document.get("schema_version") != 1
    ):
        raise ValueError("invalid manifest schema")
    files = document.get("files")
    if not isinstance(files, list) or not isinstance(document.get("totals"), dict):
        raise TypeError("manifest needs files and totals")
    seen = set()
    for entry in files:
        if not isinstance(entry, dict):
            raise TypeError("invalid manifest entry")
        name = entry.get("path")
        if (
            not isinstance(name, str)
            or "\\" in name
            or PurePosixPath(name).is_absolute()
            or any(part in ("", ".", "..") for part in name.split("/"))
            or not _covered(name)
            or name in seen
        ):
            raise ValueError(f"invalid or duplicate evidence path: {name}")
        if not isinstance(entry.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            raise ValueError(f"invalid sha256: {name}")
        if type(entry.get("bytes")) is not int or entry["bytes"] < 0:
            raise ValueError(f"invalid bytes: {name}")
        seen.add(name)
    return files


def verify(root: Path, manifest: Path) -> list[str]:
    """Return all detected mismatches; an untrusted manifest cannot widen the read scope."""
    root = root.absolute()
    source = _local(root, manifest)
    document = json.loads(source.read_text(encoding="utf-8"))
    entries = _entries(document)
    errors = []
    expected = {entry["path"] for entry in entries}
    # Inventory also checks symlinks before totals call any report readers.
    actual = {path.relative_to(root).as_posix() for path in evidence_files(root, source)}
    for name in sorted(expected - actual):
        errors.append(f"missing file: {name}")
    for name in sorted(actual - expected):
        errors.append(f"extra file: {name}")
    for entry in entries:
        name = entry["path"]
        if name not in actual:
            continue
        try:
            data = _local(root, Path(name)).read_bytes()
            if hashlib.sha256(data).hexdigest() != entry["sha256"]:
                errors.append(f"hash changed: {name}")
            if len(data) != entry["bytes"]:
                errors.append(f"bytes changed: {name}")
        except OSError as exc:
            errors.append(f"unreadable file: {name}: {exc}")
    try:
        calculated = totals(root)
        stored = document["totals"]
        for key in sorted(set(calculated) | set(stored)):
            if key not in calculated or key not in stored or calculated[key] != stored[key]:
                errors.append(
                    f"totals differ: {key} (expected {stored.get(key)!r}, actual {calculated.get(key)!r})"
                )
    except (OSError, ValueError, TypeError, KeyError) as exc:
        errors.append(f"totals differ: cannot recompute: {exc}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build_parser = sub.add_parser("build", help="freeze the covered local evidence")
    verify_parser = sub.add_parser("verify", help="check evidence bytes, inventory and totals")
    for command in (build_parser, verify_parser):
        command.add_argument("--root", type=Path, default=Path("."))
    build_parser.add_argument("--out", type=Path, default=Path("results/manifest.json"))
    build_parser.add_argument("--fixed-time", help="fixed generated_utc value for reproducible builds")
    verify_parser.add_argument("--manifest", type=Path, default=Path("results/manifest.json"))
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            result = build(args.root, args.out, args.fixed_time)
            print(f"Built {args.out}: {len(result['files'])} evidence files")
            return 0
        errors = verify(args.root, args.manifest)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"FAIL: {exc}")
        return 1
    for error in errors:
        print(f"FAIL: {error}")
    if not errors:
        print("OK: evidence inventory, hashes, bytes and totals match")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
