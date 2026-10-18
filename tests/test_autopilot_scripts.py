import importlib.util
import os
import re
import shutil
import stat
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

AUTOPILOT = Path(__file__).resolve().parents[1] / "docs" / "autopilot"
LOCK = AUTOPILOT / "lock.py"
NEXT_RUN = AUTOPILOT / "next_run.py"
PROGRESS = AUTOPILOT / "progress.py"
LEAKCHECK = AUTOPILOT / "leakcheck.py"
PRE_PUSH = AUTOPILOT / "pre-push"
ZERO = "0" * 40


def load(name):
    spec = importlib.util.spec_from_file_location(name, AUTOPILOT / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


lock = load("lock")
T0 = "2026-10-18T10:00:00-05:00"


def cli(*argv):
    return subprocess.run(
        [sys.executable, *map(str, argv)], check=False, capture_output=True, text=True, timeout=120
    )


def run(capsys, *argv):
    code = lock.main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out.strip(), captured.err.strip()


def test_acquire_then_second_run_skips_without_touching_lock(tmp_path, capsys):
    path = str(tmp_path / "lock")
    assert run(capsys, "acquire", "--lock", path, "--now", T0)[0] == 0
    before = Path(path).read_text()
    code, out, err = run(capsys, "acquire", "--lock", path, "--now", "2026-10-18T11:00:00-05:00")
    assert code == 3 and out == "" and err.startswith("HELD")
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
    code, out, err = run(capsys, "acquire", "--lock", str(path), "--now", T0, "--stale-min", "170")
    assert code == 0 and out == f"START {T0}"
    assert "took stale lock" in err
    assert path.read_text().split()[0] == T0


def test_fresh_heartbeat_keeps_lock_held(tmp_path, capsys):
    path = tmp_path / "lock"
    path.write_text("2026-10-18T05:00:00-05:00 2026-10-18T09:00:00-05:00\n")
    assert run(capsys, "acquire", "--lock", str(path), "--now", T0)[0] == 3


def test_acquire_stdout_is_exactly_the_start_line(tmp_path):
    r = cli(LOCK, "acquire", "--lock", tmp_path / "lock", "--now", T0)
    assert r.returncode == 0
    assert r.stdout == f"START {T0}\n"
    assert r.stderr == ""


def test_missing_parent_folder_is_created_owner_only(tmp_path, capsys):
    path = tmp_path / "state" / "routine" / "lock"
    assert run(capsys, "acquire", "--lock", str(path), "--now", T0)[0] == 0
    assert path.exists()
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_forty_concurrent_acquires_exactly_one_wins(tmp_path):
    path = tmp_path / "state" / "lock"
    argv = [sys.executable, str(LOCK), "acquire", "--lock", str(path), "--now", T0, "--stale-min", "100000"]
    procs = [
        subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(40)
    ]
    results = [p.communicate(timeout=120) for p in procs]
    codes = [p.returncode for p in procs]
    assert codes.count(0) == 1 and codes.count(3) == 39
    winner_out = [out for (out, _), code in zip(results, codes) if code == 0]
    assert winner_out == [f"START {T0}\n"]
    assert all(err.startswith("HELD ") for (_, err), code in zip(results, codes) if code == 3)


def test_gate_runs_once_the_wake_time_has_passed(tmp_path):
    wake = tmp_path / "next-wake"
    wake.write_text("2026-10-18T09:00:00-05:00\n")
    r = cli(NEXT_RUN, "--gate", wake, "--now", T0)
    assert (r.returncode, r.stdout) == (0, "RUN\n")


def test_gate_skips_before_the_wake_time(tmp_path):
    wake = tmp_path / "next-wake"
    wake.write_text("2026-10-18T12:00:00-05:00\n")
    r = cli(NEXT_RUN, "--gate", wake, "--now", T0)
    assert (r.returncode, r.stdout) == (3, "SKIP\n")


def test_gate_uses_the_real_clock_when_now_is_omitted(tmp_path):
    past = tmp_path / "past"
    past.write_text("2000-01-01T00:00:00+00:00\n")
    future = tmp_path / "future"
    future.write_text("2100-01-01T00:00:00+00:00\n")
    assert cli(NEXT_RUN, "--gate", past).stdout == "RUN\n"
    r = cli(NEXT_RUN, "--gate", future)
    assert (r.returncode, r.stdout) == (3, "SKIP\n")


def test_write_stores_the_wake_time_and_prints_it(tmp_path):
    wake = tmp_path / "next-wake"
    r = cli(
        NEXT_RUN,
        "--write",
        wake,
        "--now",
        T0,
        "--w",
        "10",
        "--f",
        "10",
        "--weekly-reset",
        "2026-10-25T00:00:00-05:00",
        "--five-hour-reset",
        "2026-10-18T14:00:00-05:00",
        "--runnable",
        "3",
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout == "2026-10-18T10:15:00-05:00\n"
    assert wake.read_text() == r.stdout


def test_write_without_now_uses_the_real_clock(tmp_path):
    wake = tmp_path / "next-wake"
    before = datetime.now(UTC)
    r = cli(
        NEXT_RUN,
        "--write",
        wake,
        "--w",
        "10",
        "--f",
        "10",
        "--weekly-reset",
        "2100-01-01T00:00:00+00:00",
        "--five-hour-reset",
        "2100-01-01T00:00:00+00:00",
        "--runnable",
        "3",
    )
    assert r.returncode == 0, r.stderr
    woke = datetime.fromisoformat(r.stdout.strip())
    assert woke.tzinfo is not None
    assert before + timedelta(minutes=14) <= woke <= datetime.now(UTC) + timedelta(minutes=16)
    assert wake.read_text() == r.stdout


def test_progress_task_count_matches_the_documented_grep():
    lines = (AUTOPILOT / "QUEUE.md").read_text(encoding="utf-8").splitlines()
    # Python twin of: grep '^### .* — size [SML] — ' docs/autopilot/QUEUE.md | grep -vc superseded
    heads = [line for line in lines if re.search(r"^### .* — size [SML] — ", line)]
    expected = sum("superseded" not in line for line in heads)
    r = cli(PROGRESS)
    m = re.search(r"\((\d+)/(\d+) tasks done", r.stdout)
    assert r.returncode == 0 and m, r.stdout
    assert int(m.group(2)) == expected > 0


FAKE = "fakekey-0123456789ab"  # 20 characters; a test fixture, not a real key


def leak_env(tmp_path, text):
    env = tmp_path / "fake_keys.conf"
    env.write_text(text, encoding="utf-8")
    return env


def test_leaking_file_is_named_and_the_value_is_never_printed(tmp_path):
    env = leak_env(tmp_path, f'# fixture\nexport TEST_TOKEN="{FAKE}"\n')
    leaky = tmp_path / "leaky.md"
    leaky.write_text(f"note: {FAKE}\n")
    clean = tmp_path / "clean.md"
    clean.write_text("nothing to see\n")
    r = cli(LEAKCHECK, "--env", env, clean, leaky)
    assert r.returncode == 1
    assert r.stdout == f"{leaky}\n"
    assert FAKE not in r.stdout + r.stderr
    assert "TEST_TOKEN" not in r.stdout + r.stderr


def test_clean_files_exit_zero_with_no_output(tmp_path):
    env = leak_env(tmp_path, f"TEST_TOKEN={FAKE}\n")
    clean = tmp_path / "clean.md"
    clean.write_text("nothing to see\n")
    r = cli(LEAKCHECK, "--env", env, clean)
    assert (r.returncode, r.stdout, r.stderr) == (0, "", "")


def test_values_under_twelve_characters_are_ignored(tmp_path):
    env = leak_env(tmp_path, "SHORT=elevenchars\n")
    f = tmp_path / "f.md"
    f.write_text("elevenchars\n")
    r = cli(LEAKCHECK, "--env", env, f)
    assert (r.returncode, r.stdout) == (0, "")


def test_twelve_characters_are_checked_and_quotes_are_stripped(tmp_path):
    env = leak_env(tmp_path, "export EDGE='abcdefghijkl'\nexport QUOTED=\"quoted-secret-value\"\n")
    edge = tmp_path / "edge.md"
    edge.write_text("abcdefghijkl\n")
    quoted = tmp_path / "quoted.md"
    quoted.write_text("x quoted-secret-value y\n")
    r = cli(LEAKCHECK, "--env", env, edge, quoted)
    assert r.returncode == 1
    assert r.stdout == f"{edge}\n{quoted}\n"


def test_commented_out_values_are_ignored(tmp_path):
    env = leak_env(tmp_path, f"# OLD_TOKEN={FAKE}\n\n")
    f = tmp_path / "f.md"
    f.write_text(FAKE + "\n")
    assert cli(LEAKCHECK, "--env", env, f).returncode == 0


def test_missing_env_file_exits_two_without_contents(tmp_path):
    f = tmp_path / "x.md"
    f.write_text("x\n")
    r = cli(LEAKCHECK, "--env", tmp_path / "absent.conf", f)
    assert r.returncode == 2 and r.stdout == ""


def test_env_path_that_is_a_directory_exits_two(tmp_path):
    f = tmp_path / "x.md"
    f.write_text("x\n")
    r = cli(LEAKCHECK, "--env", tmp_path, f)
    assert r.returncode == 2 and r.stdout == ""


def test_missing_env_option_is_a_usage_error(tmp_path):
    f = tmp_path / "x.md"
    f.write_text("x\n")
    assert cli(LEAKCHECK, f).returncode == 2


needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


def commit(repo, files, message):
    for name, text in files.items():
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    path = tmp_path / "repo"
    path.mkdir()
    git(path, "init", "-q", "-b", "main")
    for key, value in (
        ("user.name", "test"),
        ("user.email", "test@example.invalid"),
        ("commit.gpgsign", "false"),
        ("core.hooksPath", str(tmp_path / "no-hooks")),
    ):
        git(path, "config", key, value)
    commit(path, {"STATUS.md": "status\n", "src.py": "x = 1\n"}, "base")
    return path


def push(repo, *lines):
    stdin = "".join(line + "\n" for line in lines)
    return subprocess.run(
        [str(PRE_PUSH), "origin", "https://example.invalid/cheatproof.git"],
        check=False,
        input=stdin,
        capture_output=True,
        text=True,
        cwd=repo,
        timeout=120,
    )


def test_pre_push_hook_is_executable_posix_sh():
    assert os.access(PRE_PUSH, os.X_OK)
    assert PRE_PUSH.read_text().startswith("#!/bin/sh\n")


@needs_git
def test_main_push_touching_only_allowed_files_passes(repo):
    base = git(repo, "rev-parse", "HEAD")
    new = commit(
        repo,
        {"docs/autopilot/QUEUE.md": "q\n", "docs/autopilot/LOG.md": "l\n", "STATUS.md": "s\n"},
        "allowed",
    )
    r = push(repo, f"refs/heads/main {new} refs/heads/main {base}")
    assert r.returncode == 0, r.stderr


@needs_git
@pytest.mark.parametrize(
    "files",
    [
        {"src.py": "x = 2\n"},
        {"docs/autopilot/CYCLE.md": "c\n"},
        {"docs/autopilot/QUEUE.md.bak": "b\n"},
        {"sub/STATUS.md": "s\n"},
        {"x STATUS.md": "s\n"},
        {"STATUS.md": "s2\n", "src.py": "x = 2\n"},
    ],
)
def test_main_push_with_another_path_is_rejected(repo, files):
    base = git(repo, "rev-parse", "HEAD")
    new = commit(repo, files, "not allowed")
    r = push(repo, f"refs/heads/main {new} refs/heads/main {base}")
    assert r.returncode == 1
    assert "pre-push" in r.stderr
    for name in files:
        if name != "STATUS.md":
            assert name in r.stderr


@needs_git
def test_push_to_another_branch_is_allowed(repo):
    new = commit(repo, {"src.py": "x = 3\n"}, "feature work")
    r = push(repo, f"refs/heads/feature {new} refs/heads/feature {ZERO}")
    assert r.returncode == 0, r.stderr


@needs_git
def test_creating_main_on_the_remote_is_rejected(repo):
    new = git(repo, "rev-parse", "HEAD")
    r = push(repo, f"refs/heads/main {new} refs/heads/main {ZERO}")
    assert r.returncode == 1 and "creating main" in r.stderr


@needs_git
def test_deleting_main_is_rejected(repo):
    base = git(repo, "rev-parse", "HEAD")
    r = push(repo, f"(delete) {ZERO} refs/heads/main {base}")
    assert r.returncode == 1 and "deleting main" in r.stderr


@needs_git
def test_last_line_without_a_newline_is_still_checked(repo):
    base = git(repo, "rev-parse", "HEAD")
    new = commit(repo, {"src.py": "x = 4\n"}, "bad")
    r = subprocess.run(
        [str(PRE_PUSH), "origin", "https://example.invalid/cheatproof.git"],
        check=False,
        input=f"refs/heads/main {new} refs/heads/main {base}",
        capture_output=True,
        text=True,
        cwd=repo,
        timeout=120,
    )
    assert r.returncode == 1 and "src.py" in r.stderr


@needs_git
def test_unknown_remote_sha_fails_closed(repo):
    new = commit(repo, {"STATUS.md": "s3\n"}, "allowed but unverifiable")
    r = push(repo, f"refs/heads/main {new} refs/heads/main {'1' * 40}")
    assert r.returncode == 1
