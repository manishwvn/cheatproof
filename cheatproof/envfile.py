"""Load the one `.env` from the main checkout, so git worktrees share it without copying it."""

from __future__ import annotations

import subprocess
from pathlib import Path

from dotenv import load_dotenv


def find_env_file(start: str | Path | None = None) -> Path | None:
    """Return `<main checkout>/.env` if it exists. None when not in a git repo or the file is absent."""
    cwd = Path(start) if start is not None else Path.cwd()
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--git-common-dir"],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    # The output is relative to cwd in the main checkout (".git") and absolute in a worktree.
    common_dir = (cwd / proc.stdout.strip()).resolve()
    candidate = common_dir.parent / ".env"
    return candidate if candidate.is_file() else None


def load_env(start: str | Path | None = None) -> bool:
    """Load the main checkout's `.env` without overriding variables already set. Never logs values."""
    path = find_env_file(start)
    if path is None:
        return False
    return load_dotenv(path, override=False)
