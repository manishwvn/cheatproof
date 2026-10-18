"""Load the one `.env` from the main checkout, so git worktrees share it without copying it."""

from __future__ import annotations

import subprocess
from pathlib import Path

from dotenv import load_dotenv


def find_env_file(start: str | Path | None = None) -> Path | None:
    """Return `<main checkout>/.env` if it exists. None when not in a git repo or the file is absent.

    `start` is the directory git runs in. Without it, the package's own directory decides, so the answer does
    not depend on where the process was started.
    """
    start_dir = Path(start).resolve() if start is not None else Path(__file__).resolve().parent
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--git-common-dir"],
            cwd=start_dir,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None  # missing start directory or no git binary
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    # git prints a path relative to start_dir (".git" at the checkout root, "../../.git" in a subdirectory)
    # and an absolute path in a worktree. Joining onto start_dir handles both.
    common_dir = (start_dir / proc.stdout.strip()).resolve()
    candidate = common_dir.parent / ".env"
    return candidate if candidate.is_file() else None


def load_env(start: str | Path | None = None) -> bool:
    """Load the main checkout's `.env` without overriding variables already set. Never logs values."""
    path = find_env_file(start)
    if path is None:
        return False
    return load_dotenv(path, override=False)
