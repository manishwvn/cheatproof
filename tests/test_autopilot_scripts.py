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
    env = leak_env(tmp_path, f"SHORT=elevenchars\nLONG={FAKE}\n")
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
    env = leak_env(tmp_path, f"# OLD_TOKEN={FAKE}\nNEW_TOKEN=fresh-value-0123\n")
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


def write_bytes(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    return path


@pytest.mark.parametrize("text", ["", "# only a comment\nSHORT=abc\n"])
def test_env_file_without_a_long_value_exits_two(tmp_path, text):
    env = leak_env(tmp_path, text)
    f = write_bytes(tmp_path, "f.md", "abc\n")
    r = cli(LEAKCHECK, "--env", env, f)
    assert (r.returncode, r.stdout, r.stderr.strip()) == (2, "", "leakcheck: no values to check")


def test_unreadable_target_exits_two_and_names_only_the_file(tmp_path):
    env = leak_env(tmp_path, f"TEST_TOKEN={FAKE}\n")
    leaky = write_bytes(tmp_path, "leaky.md", f"{FAKE}\n")
    locked = tmp_path / "locked-dir"  # a directory cannot be opened for reading
    locked.mkdir()
    r = cli(LEAKCHECK, "--env", env, leaky, locked)
    assert r.returncode == 2
    assert r.stdout == f"{leaky}\n"
    assert r.stderr == f"leakcheck: cannot read {locked}\n"
    assert FAKE not in r.stdout + r.stderr


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root can read a mode 000 file")
def test_mode_000_target_exits_two(tmp_path):
    env = leak_env(tmp_path, f"TEST_TOKEN={FAKE}\n")
    locked = write_bytes(tmp_path, "locked.md", "nothing\n")
    locked.chmod(0)
    try:
        r = cli(LEAKCHECK, "--env", env, locked)
    finally:
        locked.chmod(0o600)
    assert (r.returncode, r.stdout) == (2, "")
    assert r.stderr == f"leakcheck: cannot read {locked}\n"


def test_binary_target_with_the_value_is_detected(tmp_path):
    env = leak_env(tmp_path, f"TEST_TOKEN={FAKE}\n")
    blob = write_bytes(tmp_path, "blob.bin", b"\x00\xff\xfe caf\xe9 " + FAKE.encode() + b"\x80\x81")
    r = cli(LEAKCHECK, "--env", env, blob)
    assert (r.returncode, r.stdout) == (1, f"{blob}\n")


def test_inline_comment_is_not_part_of_the_value(tmp_path):
    env = leak_env(tmp_path, f"TEST_TOKEN={FAKE} # rotate this later\n")
    leaky = write_bytes(tmp_path, "leaky.md", f"key {FAKE}\n")
    comment_only = write_bytes(tmp_path, "comment.md", "rotate this later\n")
    r = cli(LEAKCHECK, "--env", env, leaky, comment_only)
    assert (r.returncode, r.stdout) == (1, f"{leaky}\n")


def test_quoted_value_with_a_comment_is_checked(tmp_path):
    env = leak_env(tmp_path, f'TEST_TOKEN="{FAKE}"  # note\n')
    leaky = write_bytes(tmp_path, "leaky.md", f"{FAKE}\n")
    assert cli(LEAKCHECK, "--env", env, leaky).returncode == 1


def test_multi_line_double_quoted_value_is_checked_and_parsing_resumes(tmp_path):
    env = leak_env(tmp_path, 'PEM="first-line-secret\nsecond-line-secret"\nLATER=laterlongsecret1\n')
    pem = write_bytes(tmp_path, "pem.md", "first-line-secret\nsecond-line-secret\n")
    later = write_bytes(tmp_path, "later.md", "laterlongsecret1\n")
    r = cli(LEAKCHECK, "--env", env, pem, later)
    assert (r.returncode, r.stdout) == (1, f"{pem}\n{later}\n")


def test_double_quote_escapes_are_decoded_and_raw_text_is_checked(tmp_path):
    env = leak_env(tmp_path, 'ESC="say \\"hi-there\\" \\\\ back\\nend"\n')
    decoded = write_bytes(tmp_path, "decoded.md", 'say "hi-there" \\ back\nend\n')
    raw = write_bytes(tmp_path, "raw.md", 'say \\"hi-there\\" \\\\ back\\nend\n')
    r = cli(LEAKCHECK, "--env", env, decoded, raw)
    assert (r.returncode, r.stdout) == (1, f"{decoded}\n{raw}\n")


def test_single_quotes_are_literal(tmp_path):
    env = leak_env(tmp_path, "LIT='lit\\nlit-secret-val'\n")
    literal = write_bytes(tmp_path, "literal.md", "lit\\nlit-secret-val\n")
    newline = write_bytes(tmp_path, "newline.md", "lit\nlit-secret-val\n")
    r = cli(LEAKCHECK, "--env", env, literal, newline)
    assert (r.returncode, r.stdout) == (1, f"{literal}\n")


def test_utf16_targets_are_detected_in_both_byte_orders(tmp_path):
    env = leak_env(tmp_path, f"TEST_TOKEN={FAKE}\n")
    le = write_bytes(tmp_path, "le.txt", FAKE.encode("utf-16-le"))
    be = write_bytes(tmp_path, "be.txt", b"\xfe\xff" + FAKE.encode("utf-16-be"))
    r = cli(LEAKCHECK, "--env", env, le, be)
    assert (r.returncode, r.stdout) == (1, f"{le}\n{be}\n")


def test_internal_error_prints_a_generic_message_only(tmp_path, capsys, monkeypatch):
    leakcheck = load("leakcheck")

    def boom(_pairs):
        raise RuntimeError(FAKE)

    monkeypatch.setattr(leakcheck, "needles", boom)
    env = leak_env(tmp_path, f"TEST_TOKEN={FAKE}\n")
    f = write_bytes(tmp_path, "f.md", "x\n")
    assert leakcheck.main(["--env", str(env), str(f)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "leakcheck: internal error; the check did not finish\n"


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


PUBLIC = "fakepublic-model-0123"  # 21 characters; a public value, like the model IDs in .env.example


def origin_main_repo(tmp_path, env_example):
    """Git repo whose origin/main commit holds env_example. Returns the repo path."""
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
    commit(path, {".env.example": env_example}, "base")
    git(path, "update-ref", "refs/remotes/origin/main", "HEAD")
    return path


@needs_git
def test_value_in_origin_main_env_example_is_not_flagged(tmp_path):
    repo = origin_main_repo(tmp_path, f"MODEL={PUBLIC}\n")
    env = leak_env(repo, f"MODEL={PUBLIC}\nTEST_TOKEN={FAKE}\n")
    cert = write_bytes(repo, "cert.md", f"model: {PUBLIC}\n")
    r = cli(LEAKCHECK, "--env", env, cert)
    assert (r.returncode, r.stdout, r.stderr) == (0, "", "")


@needs_git
def test_secret_absent_from_origin_main_is_still_flagged_in_the_same_run(tmp_path):
    repo = origin_main_repo(tmp_path, f"MODEL={PUBLIC}\n")
    env = leak_env(repo, f"MODEL={PUBLIC}\nTEST_TOKEN={FAKE}\n")
    cert = write_bytes(repo, "cert.md", f"model: {PUBLIC}\n")
    leaky = write_bytes(repo, "leaky.md", f"model: {PUBLIC} key: {FAKE}\n")
    r = cli(LEAKCHECK, "--env", env, cert, leaky)
    assert (r.returncode, r.stdout) == (1, f"{leaky}\n")
    assert FAKE not in r.stdout + r.stderr


@needs_git
def test_value_only_in_edited_working_tree_env_example_is_still_flagged(tmp_path):
    repo = origin_main_repo(tmp_path, "OTHER=unrelated-public-value\n")
    (repo / ".env.example").write_text(f"TEST_TOKEN={FAKE}\n", encoding="utf-8")  # edited, never committed
    env = leak_env(repo, f"TEST_TOKEN={FAKE}\n")
    leaky = write_bytes(repo, "leaky.md", f"{FAKE}\n")
    r = cli(LEAKCHECK, "--env", env, leaky)
    assert (r.returncode, r.stdout) == (1, f"{leaky}\n")


@pytest.mark.parametrize("kind", ["not-a-repo", "git-missing"])
def test_without_git_no_value_is_public(tmp_path, monkeypatch, kind):
    env = leak_env(tmp_path, f"MODEL={PUBLIC}\nTEST_TOKEN={FAKE}\n")
    (tmp_path / ".env.example").write_text(f"MODEL={PUBLIC}\n", encoding="utf-8")  # never consulted
    cert = write_bytes(tmp_path, "cert.md", f"model: {PUBLIC}\n")
    leaky = write_bytes(tmp_path, "leaky.md", f"{FAKE}\n")
    if kind == "git-missing":
        empty_bin = tmp_path / "empty-bin"
        empty_bin.mkdir()
        monkeypatch.setenv("PATH", str(empty_bin))
    else:
        monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))
    r = cli(LEAKCHECK, "--env", env, cert, leaky)
    assert (r.returncode, r.stdout, r.stderr) == (1, f"{cert}\n{leaky}\n", "")


@pytest.mark.parametrize("failure", ["timeout", "missing", "nonzero"])
def test_git_timeout_or_failure_means_no_public_values(tmp_path, capsys, monkeypatch, failure):
    leakcheck = load("leakcheck")
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        if failure == "timeout":
            raise subprocess.TimeoutExpired(args, kwargs["timeout"])
        if failure == "missing":
            raise FileNotFoundError("git")
        return subprocess.CompletedProcess(args, 128, stdout=b"", stderr=b"")

    monkeypatch.setattr(leakcheck.subprocess, "run", fake_run)
    env = leak_env(tmp_path, f"MODEL={PUBLIC}\nTEST_TOKEN={FAKE}\n")
    cert = write_bytes(tmp_path, "cert.md", f"model: {PUBLIC}\n")
    assert leakcheck.main(["--env", str(env), str(cert)]) == 1
    assert capsys.readouterr().out == f"{cert}\n"
    ((args, kwargs),) = calls
    assert args == ["git", "-C", os.path.realpath(tmp_path), "show", "origin/main:.env.example"]
    assert (kwargs["check"], kwargs["timeout"], kwargs["capture_output"]) == (False, 10, True)


@needs_git
def test_explicit_public_file_replaces_the_origin_main_default(tmp_path):
    repo = origin_main_repo(tmp_path, f"MODEL={PUBLIC}\n")
    env = leak_env(repo, f"MODEL={PUBLIC}\nTEST_TOKEN={FAKE}\n")
    cert = write_bytes(repo, "cert.md", f"model: {PUBLIC}\n")
    unrelated = write_bytes(tmp_path, "unrelated.env", "OTHER=unrelated-public-value\n")
    assert cli(LEAKCHECK, "--env", env, "--public", unrelated, cert).returncode == 1
    explicit = write_bytes(tmp_path, "public.env", f"MODEL={PUBLIC}\n")
    r = cli(LEAKCHECK, "--env", env, "--public", explicit, cert)
    assert (r.returncode, r.stdout, r.stderr) == (0, "", "")


@pytest.mark.parametrize("kind", ["missing", "directory"])
def test_unreadable_explicit_public_file_exits_two_without_contents(tmp_path, kind):
    env = leak_env(tmp_path, f"TEST_TOKEN={FAKE}\n")
    leaky = write_bytes(tmp_path, "leaky.md", f"{FAKE}\n")
    public = tmp_path / "absent.env"
    if kind == "directory":
        public = tmp_path / "public-dir"
        public.mkdir()
    r = cli(LEAKCHECK, "--env", env, "--public", public, leaky)
    assert (r.returncode, r.stdout) == (2, "")
    assert r.stderr == "leakcheck: cannot read public file\n"
    assert FAKE not in r.stdout + r.stderr


@needs_git
def test_substring_of_a_public_value_is_still_checked(tmp_path):
    part = "fakepublic-model"  # 16 characters; a substring of PUBLIC, not a public value itself
    repo = origin_main_repo(tmp_path, f"MODEL={PUBLIC}\n")
    env = leak_env(repo, f"MODEL={PUBLIC}\nPART={part}\n")
    hit = write_bytes(repo, "hit.md", f"see {part} here\n")
    r = cli(LEAKCHECK, "--env", env, hit)
    assert (r.returncode, r.stdout) == (1, f"{hit}\n")


@needs_git
def test_public_value_with_escapes_is_skipped_by_its_decoded_form(tmp_path):
    line = 'MODEL="fakepublic-line-one\\nfakepublic-line-two"\n'  # the file holds backslash and n
    repo = origin_main_repo(tmp_path, line)
    env = leak_env(repo, line + f"TEST_TOKEN={FAKE}\n")
    decoded = write_bytes(repo, "decoded.md", "fakepublic-line-one\nfakepublic-line-two\n")
    raw = write_bytes(repo, "raw.md", "fakepublic-line-one\\nfakepublic-line-two\n")
    r = cli(LEAKCHECK, "--env", env, decoded, raw)
    assert (r.returncode, r.stdout, r.stderr) == (0, "", "")


@needs_git
def test_commented_out_public_line_does_not_make_its_value_public(tmp_path):
    repo = origin_main_repo(tmp_path, f"# MODEL={PUBLIC}\n")
    env = leak_env(repo, f"MODEL={PUBLIC}\nTEST_TOKEN={FAKE}\n")
    cert = write_bytes(repo, "cert.md", f"model: {PUBLIC}\n")
    r = cli(LEAKCHECK, "--env", env, cert)
    assert (r.returncode, r.stdout) == (1, f"{cert}\n")


@needs_git
def test_env_whose_values_are_all_public_exits_two_with_its_own_message(tmp_path):
    repo = origin_main_repo(tmp_path, f"MODEL={PUBLIC}\n")
    env = leak_env(repo, f"MODEL={PUBLIC}\n")
    cert = write_bytes(repo, "cert.md", f"model: {PUBLIC}\n")
    r = cli(LEAKCHECK, "--env", env, cert)
    assert (r.returncode, r.stdout, r.stderr.strip()) == (
        2,
        "",
        "leakcheck: no values to check (all values are public)",
    )


def test_pre_push_hook_is_executable_posix_sh():
    assert os.access(PRE_PUSH, os.X_OK)
    text = PRE_PUSH.read_text()
    assert text.startswith("#!/bin/sh\n")
    assert '"$(git rev-parse --git-path hooks)/pre-push"' in text


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


@needs_git
def test_rename_from_a_disallowed_path_into_the_log_is_rejected(repo):
    base = git(repo, "rev-parse", "HEAD")
    (repo / "docs" / "autopilot").mkdir(parents=True)
    git(repo, "mv", "src.py", "docs/autopilot/LOG.md")
    git(repo, "commit", "-q", "-m", "move src into the log")
    new = git(repo, "rev-parse", "HEAD")
    r = push(repo, f"refs/heads/main {new} refs/heads/main {base}")
    assert r.returncode == 1 and "src.py" in r.stderr


@needs_git
def test_bad_main_line_is_rejected_even_when_it_is_the_second_ref(repo):
    base = git(repo, "rev-parse", "HEAD")
    git(repo, "branch", "feature", base)
    new = commit(repo, {"src.py": "x = 5\n"}, "bad for main")
    r = push(
        repo,
        f"refs/heads/feature {base} refs/heads/feature {ZERO}",
        f"refs/heads/main {new} refs/heads/main {base}",
    )
    assert r.returncode == 1 and "src.py" in r.stderr


@needs_git
def test_merge_commit_on_main_that_brings_in_a_disallowed_change_is_rejected(repo):
    base = git(repo, "rev-parse", "HEAD")
    git(repo, "checkout", "-q", "-b", "feature")
    commit(repo, {"src.py": "x = 6\n"}, "feature change")
    git(repo, "checkout", "-q", "main")
    commit(repo, {"STATUS.md": "s4\n"}, "allowed on main")
    git(repo, "merge", "-q", "--no-ff", "-m", "merge feature", "feature")
    new = git(repo, "rev-parse", "HEAD")
    r = push(repo, f"refs/heads/main {new} refs/heads/main {base}")
    assert r.returncode == 1 and "src.py" in r.stderr


@needs_git
def test_non_fast_forward_push_to_main_is_rejected(repo):
    base = git(repo, "rev-parse", "HEAD")
    remote_tip = commit(repo, {"STATUS.md": "remote\n"}, "remote tip")
    git(repo, "reset", "-q", "--hard", base)
    local_tip = commit(repo, {"STATUS.md": "local\n"}, "diverged")
    r = push(repo, f"refs/heads/main {local_tip} refs/heads/main {remote_tip}")
    assert r.returncode == 1 and "non-fast-forward push to main" in r.stderr


@needs_git
def test_submodule_pointer_change_on_main_is_rejected_even_when_diff_ignores_submodules(repo):
    base = git(repo, "rev-parse", "HEAD")
    git(repo, "config", "diff.ignoreSubmodules", "all")
    git(repo, "update-index", "--add", "--cacheinfo", f"160000,{base},vendor/lib")
    git(repo, "commit", "-q", "-m", "pin a submodule")
    new = git(repo, "rev-parse", "HEAD")
    r = push(repo, f"refs/heads/main {new} refs/heads/main {base}")
    assert r.returncode == 1 and "vendor/lib" in r.stderr
