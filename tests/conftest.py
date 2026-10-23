import os

import pytest

from cheatproof.budget import create_ledger


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
