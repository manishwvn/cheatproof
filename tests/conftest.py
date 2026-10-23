import os
from pathlib import Path

import pytest

from cheatproof.budget import create_ledger

# The repo's own run output. No test may add a file here: the CLI's defaults point at these folders.
REPO_ROOT = Path(__file__).resolve().parents[1]
GUARDED_FOLDERS = ("results/traces", "runs")


def _files_under(folder: Path) -> set[str]:
    if not folder.is_dir():
        return set()
    return {str(path.relative_to(folder)) for path in folder.rglob("*") if path.is_file()}


@pytest.fixture(scope="session", autouse=True)
def _repo_run_output_untouched():
    """Fails the session when a test adds a file under the repo's results/traces or runs/. Tests use tmp_path."""
    before = {name: _files_under(REPO_ROOT / name) for name in GUARDED_FOLDERS}
    yield
    added = [
        f"{name}/{rel}"
        for name in GUARDED_FOLDERS
        for rel in sorted(_files_under(REPO_ROOT / name) - before[name])
    ]
    assert not added, "tests wrote files under the repo's run output (use tmp_path): " + ", ".join(added)


@pytest.fixture
def init_ledger(tmp_path):
    """The zeroed ledger at tmp_path/ledger.json, made the way `budget init` makes it. A test that needs a ledger
    requests this, since a missing ledger is refused and none appears on its own."""
    return create_ledger(tmp_path / "ledger.json")


def pytest_configure(config):
    config.addinivalue_line("markers", "docker: runs the real docker CLI; needs CHEATPROOF_DOCKER_TESTS=1")


def pytest_collection_modifyitems(config, items):
    if os.environ.get("CHEATPROOF_DOCKER_TESTS") == "1":
        return
    skip = pytest.mark.skip(reason="live Docker test: set CHEATPROOF_DOCKER_TESTS=1")
    for item in items:
        if item.get_closest_marker("docker"):
            item.add_marker(skip)
