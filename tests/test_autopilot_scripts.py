import importlib.util
from pathlib import Path

import pytest

AUTOPILOT = Path(__file__).resolve().parents[1] / "docs" / "autopilot"


def load(name):
    spec = importlib.util.spec_from_file_location(name, AUTOPILOT / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


lock = load("lock")
T0 = "2026-10-18T10:00:00-05:00"


def run(capsys, *argv):
    code = lock.main(list(argv))
    return code, capsys.readouterr().out.strip()


def test_acquire_then_second_run_skips_without_touching_lock(tmp_path, capsys):
    path = str(tmp_path / "lock")
    assert run(capsys, "acquire", "--lock", path, "--now", T0)[0] == 0
    before = Path(path).read_text()
    code, out = run(capsys, "acquire", "--lock", path, "--now", "2026-10-18T11:00:00-05:00")
    assert code == 3 and out.startswith("HELD")
    assert Path(path).read_text() == before


def test_only_the_owner_can_release_or_heartbeat(tmp_path, capsys):
    path = str(tmp_path / "lock")
    start = run(capsys, "acquire", "--lock", path, "--now", T0)[1].split()[1]
    assert run(capsys, "release", "--lock", path, "--start", "2026-01-01T00:00:00+00:00")[0] == 4
    assert run(capsys, "heartbeat", "--lock", path, "--start", "2026-01-01T00:00:00+00:00")[0] == 4
    assert Path(path).read_text().split()[0] == start
    assert (
        run(capsys, "heartbeat", "--lock", path, "--start", start, "--now", "2026-10-18T10:30:00-05:00")[0]
        == 0
    )
    assert Path(path).read_text().split() == [start, "2026-10-18T10:30:00-05:00"]
    assert run(capsys, "release", "--lock", path, "--start", start)[0] == 0
    assert Path(path).exists() and Path(path).read_text() == ""


@pytest.mark.parametrize("content", ["2026-10-18T07:00:00-05:00 2026-10-18T07:09:00-05:00\n", "garbage\n"])
def test_stale_or_broken_lock_is_taken_over(tmp_path, capsys, content):
    path = tmp_path / "lock"
    path.write_text(content)
    code, out = run(capsys, "acquire", "--lock", str(path), "--now", T0, "--stale-min", "170")
    assert code == 0 and "took stale lock" in out
    assert path.read_text().split()[0] == "2026-10-18T10:00:00-05:00"


def test_fresh_heartbeat_keeps_lock_held(tmp_path, capsys):
    path = tmp_path / "lock"
    path.write_text("2026-10-18T05:00:00-05:00 2026-10-18T09:00:00-05:00\n")
    assert run(capsys, "acquire", "--lock", str(path), "--now", T0)[0] == 3
