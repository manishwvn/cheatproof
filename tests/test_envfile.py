import os
import subprocess
from pathlib import Path

import pytest

from cheatproof.envfile import find_env_file, load_env

GIT_ENV = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}


def git(cwd: Path, *args: str) -> None:
    identity = ["-c", "user.name=cheatproof-test", "-c", "user.email=test@example.invalid"]
    subprocess.run(
        ["git", *identity, "-c", "commit.gpgsign=false", *args],
        cwd=cwd,
        env=GIT_ENV,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def repo(tmp_path):
    """A main checkout with a .env (fake value) and one linked worktree."""
    main = tmp_path / "main"
    main.mkdir()
    git(main, "init", "-q")
    git(main, "commit", "-q", "--allow-empty", "-m", "init")
    (main / ".env").write_text("FAKE_VAR=fake-value\n")
    worktree = tmp_path / "wt"
    git(main, "worktree", "add", "-q", "-b", "feat-test", str(worktree))
    return main, worktree


@pytest.fixture
def fake_var():
    os.environ.pop("FAKE_VAR", None)
    yield
    os.environ.pop("FAKE_VAR", None)


def test_worktree_finds_main_checkout_env(repo):
    main, worktree = repo
    assert find_env_file(worktree) == (main / ".env").resolve()


def test_cwd_inside_worktree_finds_main_checkout_env(repo, monkeypatch):
    main, worktree = repo
    monkeypatch.chdir(worktree)
    assert find_env_file() == (main / ".env").resolve()


def test_main_checkout_without_env_returns_none(repo):
    main, worktree = repo
    (main / ".env").unlink()
    assert find_env_file(worktree) is None


def test_outside_a_git_repo_returns_none(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    assert find_env_file(plain) is None


def test_load_env_from_worktree_sets_variable(repo, fake_var, monkeypatch):
    _, worktree = repo
    monkeypatch.chdir(worktree)
    assert load_env() is True
    assert os.environ["FAKE_VAR"] == "fake-value"


def test_load_env_does_not_override_existing_variable(repo, fake_var, monkeypatch):
    _, worktree = repo
    monkeypatch.setenv("FAKE_VAR", "from-shell")
    monkeypatch.chdir(worktree)
    load_env()
    assert os.environ["FAKE_VAR"] == "from-shell"


def test_load_env_outside_repo_returns_false(tmp_path, fake_var, monkeypatch):
    plain = tmp_path / "plain"
    plain.mkdir()
    monkeypatch.chdir(plain)
    assert load_env() is False
    assert "FAKE_VAR" not in os.environ
