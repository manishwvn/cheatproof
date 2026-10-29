import os
import subprocess
from pathlib import Path

import pytest

from rewardseal import envfile
from rewardseal.envfile import find_env_file, load_env

GIT_ENV = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}


def git(cwd: Path, *args: str) -> None:
    identity = ["-c", "user.name=rewardseal-test", "-c", "user.email=test@example.invalid"]
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


@pytest.fixture
def package_in(monkeypatch):
    """Place the envfile module under `checkout`, which is what the default start directory resolves to.

    Without this, a default-start call in a test would read the real checkout's .env.
    """

    def place(checkout: Path) -> None:
        package = checkout / "rewardseal"
        package.mkdir(exist_ok=True)
        monkeypatch.setattr(envfile, "__file__", str(package / "envfile.py"))

    return place


def test_worktree_finds_main_checkout_env(repo):
    main, worktree = repo
    assert find_env_file(worktree) == (main / ".env").resolve()


def test_main_checkout_root_finds_its_own_env(repo):
    main, _ = repo
    assert find_env_file(main) == (main / ".env").resolve()


def test_subdirectory_of_main_checkout_finds_env(repo):
    main, _ = repo
    sub = main / "a" / "b"
    sub.mkdir(parents=True)
    assert find_env_file(sub) == (main / ".env").resolve()


def test_subdirectory_of_worktree_finds_main_checkout_env(repo):
    main, worktree = repo
    sub = worktree / "a" / "b"
    sub.mkdir(parents=True)
    assert find_env_file(sub) == (main / ".env").resolve()


def test_relative_start_is_resolved_against_process_cwd(repo, monkeypatch):
    main, _ = repo
    sub = main / "a"
    sub.mkdir()
    monkeypatch.chdir(sub)
    assert find_env_file(".") == (main / ".env").resolve()


def test_default_start_is_package_directory_not_cwd(repo, package_in, monkeypatch, tmp_path):
    main, _ = repo
    package_in(main)
    plain = tmp_path / "plain"
    plain.mkdir()
    monkeypatch.chdir(plain)
    assert find_env_file() == (main / ".env").resolve()


def test_default_start_outside_any_repo_returns_none(tmp_path, package_in):
    plain = tmp_path / "plain"
    plain.mkdir()
    package_in(plain)
    assert find_env_file() is None


def test_main_checkout_without_env_returns_none(repo):
    main, worktree = repo
    (main / ".env").unlink()
    assert find_env_file(worktree) is None


def test_outside_a_git_repo_returns_none(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    assert find_env_file(plain) is None


def test_missing_start_directory_returns_none(tmp_path):
    assert find_env_file(tmp_path / "does-not-exist") is None


def test_load_env_from_worktree_sets_variable(repo, fake_var):
    _, worktree = repo
    assert load_env(worktree) is True
    assert os.environ["FAKE_VAR"] == "fake-value"


def test_load_env_default_start_loads_main_checkout_env(repo, fake_var, package_in):
    main, _ = repo
    package_in(main)
    assert load_env() is True
    assert os.environ["FAKE_VAR"] == "fake-value"


def test_load_env_does_not_override_existing_variable(repo, fake_var, monkeypatch):
    _, worktree = repo
    monkeypatch.setenv("FAKE_VAR", "from-shell")
    load_env(worktree)
    assert os.environ["FAKE_VAR"] == "from-shell"


def test_load_env_outside_repo_returns_false(tmp_path, fake_var, package_in):
    plain = tmp_path / "plain"
    plain.mkdir()
    package_in(plain)
    assert load_env() is False
    assert "FAKE_VAR" not in os.environ
