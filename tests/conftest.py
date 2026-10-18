import os

import pytest


def pytest_configure(config):
    config.addinivalue_line("markers", "docker: runs the real docker CLI; needs CHEATPROOF_DOCKER_TESTS=1")


def pytest_collection_modifyitems(config, items):
    if os.environ.get("CHEATPROOF_DOCKER_TESTS") == "1":
        return
    skip = pytest.mark.skip(reason="live Docker test: set CHEATPROOF_DOCKER_TESTS=1")
    for item in items:
        if item.get_closest_marker("docker"):
            item.add_marker(skip)
