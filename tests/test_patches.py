"""Tests for rewardseal/patches.py (T06).

Most tests use fake sessions: nothing there runs a shell, git, docker or the network. The real-git tests at the end
run the generated scripts with `sh -c` in a tmp_path repository. They need git on the scripts' PATH and touch no
network. Their git calls get a clean environment with no system or global config.
"""

import json
import os
import re
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from rewardseal.budget import BudgetExceeded
from rewardseal.executor import EnvSpec, ExecutorRefused, ExecutorUnavailable, Result, Session
from rewardseal.exposure import HOLE_GIT_HISTORY, HOLE_NETWORK, HOLE_TEST_EDIT
from rewardseal.grader import GIT_PREFIX, STEP_TIMEOUT_S
from rewardseal.patches import (
    _SCRIPT_PATH,
    HOLE_PATCHES,
    PATCH_NETWORK_OFF,
    PATCH_ORDER,
    PATCH_STRIP_GIT,
    PATCH_TEST_GUARD,
    PatchOutcome,
    apply_patches,
    env_for,
    grade_kwargs,
    patches_for,
    unpatched,
)
from rewardseal.tasks import TaskSpec

BASE = "71fb12cefda5a3e1e223ed837bca468f8bdab874"
FUTURE = "9676c1085a90cf604df7cc56977abe773bae86b1"
IMAGE = "python:3.12-slim"
GUARD_NOTE = "enforced at grade time (reject_test_edits)"
VERIFY_NEEDLE = "--batch-all-objects"
STRIP_NEEDLE = "repack"
CHECK_NEEDLE = "cat-file -e"
MARKER = re.compile(r"rewardseal-strip ([0-9a-f]{32}) done")
FORBIDDEN_GIT_SUBCOMMANDS = re.compile(r"\b(checkout|reset|clean|stash|add|rm|restore|switch|apply)\b")
SCRUB_LINE = (
    f"PATH={_SCRIPT_PATH}; export PATH; unset -f git sort comm sed find wc head cat rm mkdir tr grep "
    "2>/dev/null; hash -r 2>/dev/null"
)
UNSET_LINE = (
    "unset GIT_DIR GIT_COMMON_DIR GIT_WORK_TREE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES "
    "GIT_INDEX_FILE GIT_NAMESPACE GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS GIT_EXEC_PATH GIT_GRAFT_FILE "
    "GIT_SHALLOW_FILE GIT_NO_REPLACE_OBJECTS GIT_CEILING_DIRECTORIES"
)
GIT_TEST_ENV = {
    **{key: value for key, value in os.environ.items() if not key.startswith("GIT_")},
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
}
GIT_BIN = shutil.which("git", path=_SCRIPT_PATH)
needs_git = pytest.mark.skipif(GIT_BIN is None, reason="git is not on the scripts' PATH")


def make_task(**overrides) -> TaskSpec:
    fields = {
        "instance_id": "fixture__task-1",
        "repo": "fixture/repo",
        "base_commit": BASE,
        "image": IMAGE,
        "fail_to_pass": ("tests/test_calc.py::test_add",),
        "pass_to_pass": ("tests/test_calc.py::test_add_zero",),
        "gold_patch": "",
        "test_patch": "",
        "source": "fixture",
    }
    fields.update(overrides)
    return TaskSpec(**fields)


def token_of(cmd: str) -> str:
    match = MARKER.search(cmd)
    assert match, "every strip script ends with its marker line"
    return match.group(1)


def done_reply(cmd: str) -> Result:
    return Result(0, f"rewardseal-strip {token_of(cmd)} done\n", "", 0.0)


def check_reply(head: str = BASE):
    """A reply for the base commit check: it prints HEAD (empty when unresolved) and the completion line."""

    def answer(cmd: str) -> Result:
        token = token_of(cmd)
        return Result(0, f"rewardseal-strip {token} head={head}\nrewardseal-strip {token} done\n", "", 0.0)

    return answer


# The verification output for a clean strip. Each test overrides one value.
CLEAN = {
    "extra_commits": "0",
    "tags": "0",
    "refs": "0",
    "loose_refs": "0",
    "remote_keys": "0",
    "unreachable_objects": "0",
    "head": BASE,
    "submodules": "0",
}


def verify_reply(changes=None, *, done=True):
    """A reply for the verification script. A list value prints one line per item; None omits the key."""
    values = {**CLEAN, **(changes or {})}

    def answer(cmd: str) -> Result:
        token = token_of(cmd)
        lines = []
        for key, value in values.items():
            if value is None:
                continue
            for item in value if isinstance(value, list) else (value,):
                lines.append(f"rewardseal-strip {token} {key}={item}")
        if done:
            lines.append(f"rewardseal-strip {token} done")
        return Result(0, "\n".join(lines) + "\n", "", 0.0)

    return answer


class FakeSession(Session):
    """Stands in for a sandbox. Records every command and its timeout; runs nothing. First matching rule wins."""

    def __init__(self, rules=()):
        self.rules = list(rules)
        self.commands: list[str] = []
        self.timeouts: list[float] = []

    def run(self, cmd, timeout):
        self.commands.append(cmd)
        self.timeouts.append(timeout)
        for needle, answer in self.rules:
            if needle in cmd:
                return answer(cmd) if callable(answer) else answer
        return Result(0, "", "", 0.0)

    def write_file(self, path, data):
        raise NotImplementedError

    def diff(self):
        raise NotImplementedError

    def reset(self):
        raise NotImplementedError

    def close(self):
        pass


class RaisingSession(FakeSession):
    """Every call raises the given error, as a sandbox might when it is closed, broke or ran out of budget."""

    def __init__(self, error: BaseException):
        super().__init__()
        self.error = error

    def run(self, cmd, timeout):
        self.commands.append(cmd)
        raise self.error


def clean_rules(verify=None, head=BASE):
    return [
        (VERIFY_NEEDLE, verify_reply(verify)),
        (STRIP_NEEDLE, done_reply),
        (CHECK_NEEDLE, check_reply(head)),
    ]


def strip_session(*, verify=None, first=()) -> FakeSession:
    """A session where all three strip steps finish cleanly. first rules are tried before the clean ones."""
    return FakeSession([*first, *clean_rules(verify)])


def strip(session: FakeSession, task: TaskSpec | None = None, workdir: str = "/testbed") -> PatchOutcome:
    (outcome,) = apply_patches(session, task or make_task(), [PATCH_STRIP_GIT], workdir=workdir)
    return outcome


# names, mapping and the labels-to-patches helpers


def test_patch_names_order_and_hole_mapping():
    assert PATCH_ORDER == (PATCH_STRIP_GIT, PATCH_TEST_GUARD, PATCH_NETWORK_OFF)
    assert HOLE_PATCHES == {
        HOLE_GIT_HISTORY: (PATCH_STRIP_GIT,),
        HOLE_TEST_EDIT: (PATCH_TEST_GUARD,),
        HOLE_NETWORK: (PATCH_NETWORK_OFF,),
        "hard-code": (),
    }


@pytest.mark.parametrize(
    ("labels", "expected"),
    [
        (
            [HOLE_NETWORK, HOLE_TEST_EDIT, HOLE_GIT_HISTORY],
            (PATCH_STRIP_GIT, PATCH_TEST_GUARD, PATCH_NETWORK_OFF),
        ),
        (
            [HOLE_NETWORK, HOLE_NETWORK, HOLE_GIT_HISTORY, HOLE_GIT_HISTORY],
            (PATCH_STRIP_GIT, PATCH_NETWORK_OFF),
        ),
        (["hard-code"], ()),
        (["unclassified", "no-such-hole"], ()),
        ([HOLE_TEST_EDIT, "hard-code"], (PATCH_TEST_GUARD,)),
        ([], ()),
    ],
)
def test_patches_for_orders_dedupes_and_skips_labels_without_a_patch(labels, expected):
    assert patches_for(labels) == expected


def test_unpatched_keeps_input_order_and_drops_duplicates():
    labels = ["hard-code", HOLE_GIT_HISTORY, "unclassified", "hard-code", "no-such-hole"]
    assert unpatched(labels) == ("hard-code", "unclassified", "no-such-hole")


def test_unpatched_is_empty_when_every_label_has_a_patch():
    assert unpatched([HOLE_GIT_HISTORY, HOLE_NETWORK, HOLE_TEST_EDIT]) == ()


def test_env_for_network_off_turns_the_network_off_and_keeps_the_rest():
    spec = EnvSpec(image=IMAGE, network=True, cpus=1.5)
    out = env_for(spec, [PATCH_STRIP_GIT, PATCH_NETWORK_OFF])
    assert out == EnvSpec(image=IMAGE, network=False, cpus=1.5)
    assert spec.network is True  # the input is not changed


def test_env_for_other_names_leave_the_spec_alone():
    spec = EnvSpec(image=IMAGE, network=True)
    assert env_for(spec, [PATCH_STRIP_GIT, PATCH_TEST_GUARD]) == spec
    assert env_for(spec, []) == spec


def test_env_for_unknown_name_raises():
    with pytest.raises(ValueError, match="unknown patch 'network-on'"):
        env_for(EnvSpec(image=IMAGE), ["network-on"])


def test_grade_kwargs_asks_for_test_edit_rejection_only_with_the_guard():
    assert grade_kwargs([PATCH_TEST_GUARD]) == {"reject_test_edits": True}
    assert grade_kwargs([PATCH_STRIP_GIT, PATCH_NETWORK_OFF]) == {}
    assert grade_kwargs([]) == {}


def test_grade_kwargs_unknown_name_raises():
    with pytest.raises(ValueError, match="unknown patch"):
        grade_kwargs([PATCH_TEST_GUARD, "guard"])


def test_to_dict_is_json_ready():
    outcome = PatchOutcome(PATCH_NETWORK_OFF, False, ("connected to 1.1.1.1:53 (python3)",))
    assert outcome.to_dict() == {
        "name": PATCH_NETWORK_OFF,
        "ok": False,
        "notes": ["connected to 1.1.1.1:53 (python3)"],
    }
    assert json.loads(json.dumps(outcome.to_dict())) == outcome.to_dict()


# apply_patches: dispatch and ordering


def test_unknown_name_raises_before_any_command():
    session = FakeSession()
    with pytest.raises(ValueError, match="unknown patch 'strip-git'"):
        apply_patches(session, make_task(), [PATCH_TEST_GUARD, "strip-git"])
    assert session.commands == []


def test_test_edit_guard_runs_no_command():
    session = FakeSession()
    (outcome,) = apply_patches(session, make_task(), [PATCH_TEST_GUARD])
    assert outcome == PatchOutcome(PATCH_TEST_GUARD, True, (GUARD_NOTE,))
    assert session.commands == []


def test_outcomes_follow_patch_order_and_each_name_runs_once():
    session = FakeSession([*clean_rules(), ("python3 -c", Result(1, "", "OSError", 0.0))])
    outcomes = apply_patches(
        session,
        make_task(),
        [PATCH_NETWORK_OFF, PATCH_TEST_GUARD, PATCH_STRIP_GIT, PATCH_NETWORK_OFF],
    )
    assert [outcome.name for outcome in outcomes] == [PATCH_STRIP_GIT, PATCH_TEST_GUARD, PATCH_NETWORK_OFF]
    assert sum("python3 -c" in cmd for cmd in session.commands) == 1


def test_no_names_runs_nothing():
    session = FakeSession()
    assert apply_patches(session, make_task(), []) == []
    assert session.commands == []


# strip-future-git: verdicts from the verification output


def test_clean_strip_is_ok_with_no_notes():
    session = strip_session()
    outcome = strip(session)
    assert outcome == PatchOutcome(PATCH_STRIP_GIT, True, ())
    assert len(session.commands) == 3  # base check, strip, verification


def test_extra_commit_fails_and_names_its_sha():
    outcome = strip(strip_session(verify={"extra_commits": "1", "extra": [FUTURE]}))
    assert outcome.ok is False
    assert outcome.notes[0] == f"1 commit(s) past base still in the object store: {FUTURE}"


def test_extra_commit_samples_are_capped_and_non_sha_lines_are_dropped():
    many = [f"{n:040x}" for n in range(8)]
    outcome = strip(strip_session(verify={"extra_commits": "8", "extra": [*many, "not-a-sha"]}))
    assert outcome.ok is False
    listed = outcome.notes[0].split(": ", 1)[1].split(", ")
    assert listed == many[:5]


@pytest.mark.parametrize(
    ("changes", "note"),
    [
        ({"tags": "1"}, "1 tag object(s) left in the object store"),
        ({"refs": "2"}, "2 ref(s) left after the strip"),
        ({"loose_refs": "1"}, "1 loose ref file(s) left"),
        ({"remote_keys": "2"}, "2 remote config key(s) left"),
        ({"unreachable_objects": "3"}, "3 unreachable blob/tree object(s) left after prune"),
        ({"leftover": ["packed-refs", "logs"]}, "still present in .git: packed-refs, logs"),
        ({"head": FUTURE}, f"HEAD is not at base: {FUTURE}"),
        ({"head": None}, "HEAD is not at base: no value printed"),
    ],
)
def test_each_left_over_ref_object_or_config_fails_the_patch(changes, note):
    outcome = strip(strip_session(verify=changes))
    assert outcome.ok is False
    assert note in outcome.notes


def test_submodule_dirs_are_a_note_not_a_failure():
    outcome = strip(strip_session(verify={"submodules": "1"}))
    assert outcome.ok is True
    assert "submodule git dirs under .git/modules were not stripped" in outcome.notes


def test_a_count_that_is_not_a_number_fails_closed():
    outcome = strip(strip_session(verify={"extra_commits": "many"}))
    assert outcome.ok is False
    assert outcome.notes == ("unverified: strip verification printed no usable extra_commits",)


def test_a_missing_count_fails_closed():
    outcome = strip(strip_session(verify={"tags": None}))
    assert outcome.ok is False
    assert outcome.notes == ("unverified: strip verification printed no usable tags",)


def test_a_missing_unreachable_count_fails_closed():
    outcome = strip(strip_session(verify={"unreachable_objects": None}))
    assert outcome.ok is False
    assert outcome.notes == ("unverified: strip verification printed no usable unreachable_objects",)


def test_lines_with_another_runs_token_are_ignored():
    def with_forged_line(cmd: str) -> Result:
        genuine = verify_reply()(cmd)
        return Result(0, f"rewardseal-strip {'f' * 32} extra_commits=5\n" + genuine.stdout, "", 0.0)

    assert strip(strip_session(first=[(VERIFY_NEEDLE, with_forged_line)])).ok is True


def test_login_profile_noise_before_the_result_is_ignored():
    def noisy(cmd):
        clean = verify_reply()(cmd)
        return Result(0, "profile says hi\n" + clean.stdout, "", 0.0)

    assert strip(strip_session(first=[(VERIFY_NEEDLE, noisy)])).ok is True


# strip-future-git: HEAD must be base before anything changes


def test_head_off_base_refuses_before_any_change():
    session = strip_session(first=[(CHECK_NEEDLE, check_reply(FUTURE))])
    outcome = strip(session)
    assert outcome == PatchOutcome(
        PATCH_STRIP_GIT, False, (f"HEAD is {FUTURE}, not the task base; refusing to strip",)
    )
    assert len(session.commands) == 1  # only the read-only check ran


def test_unresolved_head_refuses_before_any_change():
    session = strip_session(first=[(CHECK_NEEDLE, check_reply(""))])
    outcome = strip(session)
    assert outcome.notes == ("HEAD is unresolved, not the task base; refusing to strip",)
    assert len(session.commands) == 1


def test_base_check_without_a_head_line_fails_closed():
    session = strip_session(first=[(CHECK_NEEDLE, done_reply)])
    outcome = strip(session)
    assert outcome.notes == ("unverified: base commit check printed no HEAD",)
    assert len(session.commands) == 1


# strip-future-git: failed, timed out or truncated steps


@pytest.mark.parametrize(
    ("needle", "label"),
    [(CHECK_NEEDLE, "base commit check"), (STRIP_NEEDLE, "strip"), (VERIFY_NEEDLE, "strip verification")],
)
def test_a_step_that_exits_non_zero_fails_with_the_stderr_tail(needle, label):
    session = strip_session(first=[(needle, Result(1, "", "fatal: boom\n", 0.0))])
    outcome = strip(session)
    assert outcome.ok is False
    assert outcome.notes == (f"{label} failed (exit 1): fatal: boom",)
    assert len(session.commands) >= 1


@pytest.mark.parametrize("needle", [CHECK_NEEDLE, STRIP_NEEDLE, VERIFY_NEEDLE])
def test_a_timed_out_step_fails(needle):
    first = [(needle, Result(137, "", "", 0.0, timed_out=True))]
    outcome = strip(strip_session(first=first))
    assert outcome.ok is False
    assert "timed out after" in outcome.notes[0]


@pytest.mark.parametrize("needle", [CHECK_NEEDLE, STRIP_NEEDLE, VERIFY_NEEDLE])
def test_a_truncated_step_fails(needle):
    first = [(needle, Result(0, "partial", "", 0.0, truncated=True))]
    outcome = strip(strip_session(first=first))
    assert outcome.ok is False
    assert outcome.notes[0].endswith("output was cut at the executor cap")


def test_verification_without_its_completion_line_fails():
    outcome = strip(strip_session(verify={}, first=[(VERIFY_NEEDLE, verify_reply(done=False))]))
    assert outcome.ok is False
    assert outcome.notes == ("unverified: strip verification printed no completion line",)


def test_strip_without_its_completion_line_fails():
    first = [(STRIP_NEEDLE, Result(0, "", "", 0.0))]
    outcome = strip(strip_session(first=first))
    assert outcome.ok is False
    assert outcome.notes == ("unverified: strip printed no completion line",)


def test_a_bad_base_commit_fails_before_any_command():
    session = FakeSession()
    outcome = strip(session, make_task(base_commit="REDACTED"))
    assert outcome.ok is False
    assert outcome.notes[0].startswith("invalid commit id 'REDACTED'")
    assert session.commands == []


def test_a_short_base_commit_fails_before_any_command():
    session = FakeSession()
    outcome = strip(session, make_task(base_commit=BASE[:12]))
    assert outcome.ok is False
    assert outcome.notes == ("base commit must be a full 40-character id",)
    assert session.commands == []


def test_base_commit_that_is_missing_stops_before_the_strip():
    session = strip_session(first=[(CHECK_NEEDLE, Result(128, "", "fatal: bad object", 0.0))])
    outcome = strip(session)
    assert outcome.ok is False
    assert outcome.notes == ("base commit check failed (exit 128): fatal: bad object",)
    assert len(session.commands) == 1


# strip-future-git: exceptions


@pytest.mark.parametrize(
    "error",
    [BudgetExceeded("total cap reached"), ExecutorUnavailable("no docker"), ExecutorRefused("low disk")],
)
def test_budget_and_executor_errors_propagate_from_a_strip_step(error):
    with pytest.raises(type(error), match=str(error)):
        apply_patches(RaisingSession(error), make_task(), [PATCH_STRIP_GIT])


@pytest.mark.parametrize(
    "error",
    [BudgetExceeded("daily cap reached"), ExecutorUnavailable("daemon down"), ExecutorRefused("no disk")],
)
def test_budget_and_executor_errors_propagate_from_the_network_probe(error):
    with pytest.raises(type(error), match=str(error)):
        apply_patches(RaisingSession(error), make_task(), [PATCH_NETWORK_OFF])


@pytest.mark.parametrize("error", [RuntimeError("session is closed"), OSError("broken pipe")])
def test_sandbox_call_errors_become_unverified_not_success(error):
    (outcome,) = apply_patches(RaisingSession(error), make_task(), [PATCH_STRIP_GIT])
    assert outcome.ok is False
    assert outcome.notes == (f"unverified: base commit check could not run: {error}",)


# strip-future-git: the commands themselves


def test_every_strip_step_runs_with_the_step_timeout():
    session = strip_session()
    strip(session)
    assert session.timeouts == [STEP_TIMEOUT_S, STEP_TIMEOUT_S, STEP_TIMEOUT_S]


def test_base_is_quoted_in_the_base_check():
    session = strip_session()
    strip(session)
    assert shlex.quote(f"{BASE}^{{commit}}") in session.commands[0]


def test_every_script_starts_by_fixing_path_and_dropping_shadowed_tools():
    session = strip_session()
    strip(session)
    for cmd in session.commands:
        assert cmd.splitlines()[0] == SCRUB_LINE


def test_scripts_unset_every_variable_that_could_redirect_git():
    session = strip_session()
    strip(session)
    for cmd in session.commands:
        assert UNSET_LINE in cmd.splitlines()


def test_every_line_that_calls_git_carries_the_grader_prefix():
    session = strip_session()
    strip(session)
    for cmd in session.commands:
        git_lines = [
            line for line in cmd.splitlines() if re.search(r"\bgit\b", line) and "unset -f" not in line
        ]
        assert git_lines, "each step calls git"
        for line in git_lines:
            assert GIT_PREFIX in line, line


def test_no_command_checks_out_resets_hard_or_cleans():
    session = strip_session()
    strip(session)
    for cmd in session.commands:
        assert "--hard" not in cmd
        assert not re.search(r"\bclean\b", cmd)
        for line in cmd.splitlines():
            if GIT_PREFIX in line:
                assert not FORBIDDEN_GIT_SUBCOMMANDS.search(line.replace(GIT_PREFIX, "")), line


def test_index_is_rebuilt_from_base_with_read_tree_before_the_repack():
    session = strip_session()
    strip(session)
    strip_script = session.commands[1]
    read_tree_lines = [line for line in strip_script.splitlines() if "read-tree" in line]
    assert read_tree_lines == [f"{GIT_PREFIX}read-tree {BASE}"]
    assert strip_script.index("read-tree") < strip_script.index("repack -a -d")


def test_scripts_use_posix_sh_only():
    session = strip_session()
    strip(session)
    for cmd in session.commands:
        assert "[[" not in cmd and "pipefail" not in cmd and "<(" not in cmd and "$'" not in cmd


def test_scratch_dir_is_host_chosen_and_removed_on_exit():
    session = strip_session()
    strip(session)
    token = token_of(session.commands[0])
    assert re.fullmatch(r"[0-9a-f]{32}", token)
    scratch = f"/tmp/rewardseal-{token}"
    for cmd in session.commands[1:]:
        assert f"trap 'rm -rf -- {scratch}' EXIT" in cmd
        assert f"mkdir -m 700 -- {scratch}" in cmd


def test_the_strip_removes_refs_reflogs_grafts_alternates_and_state_files():
    session = strip_session()
    strip(session)
    strip_script = session.commands[1]
    assert f"update-ref --no-deref HEAD {BASE}" in strip_script
    assert "update-ref --no-deref -d" in strip_script
    for name in ("logs", "info/grafts", "packed-refs", "worktrees", "ORIG_HEAD", "FETCH_HEAD"):
        assert f'"$gitdir/{name}"' in strip_script or f'"$common/{name}"' in strip_script, name
    for name in ("COMMIT_EDITMSG", "MERGE_MSG", "SQUASH_MSG", "TAG_EDITMSG", "MERGE_MODE"):
        assert f'"$gitdir/{name}"' in strip_script, name
    assert '"$common/objects/pack/multi-pack-index.d"' in strip_script
    assert "objects/info/alternates" in strip_script
    assert "*.keep" in strip_script and "*.promisor" in strip_script
    assert "remove-section" in strip_script and '"$gitdir/config.worktree"' in strip_script
    assert "repack -a -d" in strip_script and "prune --expire=now" in strip_script


def test_workdir_is_quoted_in_every_step():
    session = strip_session()
    strip(session, workdir="/work space")
    assert len(session.commands) == 3
    assert all("cd '/work space'" in cmd for cmd in session.commands)


def test_verification_checks_base_against_the_fetched_history_and_gates_on_head():
    session = strip_session()
    strip(session)
    verify = session.commands[2]
    assert f"rev-list {BASE} >" in verify
    assert "comm -23" in verify and "LC_ALL=C sort -u" in verify
    assert f'[ "$head_sha" = {BASE} ] || ' in verify and "exit 1" in verify


def test_every_generated_script_passes_sh_n():
    session = strip_session()
    strip(session)
    assert len(session.commands) == 3
    for cmd in session.commands:
        done = subprocess.run(["sh", "-n", "-c", cmd], capture_output=True, text=True, check=False)
        assert done.returncode == 0, done.stderr


# network-off: the probe verdict


def test_unreachable_network_is_ok():
    session = FakeSession([("python3 -c", Result(1, "", "OSError", 0.0))])
    (outcome,) = apply_patches(session, make_task(), [PATCH_NETWORK_OFF])
    assert outcome == PatchOutcome(PATCH_NETWORK_OFF, True, ("no connection to 1.1.1.1:53",))


def test_reachable_network_fails_with_the_probe_evidence():
    session = FakeSession([("python3 -c", Result(0, "", "", 0.0))])
    (outcome,) = apply_patches(session, make_task(), [PATCH_NETWORK_OFF])
    assert outcome == PatchOutcome(PATCH_NETWORK_OFF, False, ("connected to 1.1.1.1:53 (python3)",))


def test_probe_with_no_program_available_fails_as_unverified():
    rules = [
        ("python3 -c", Result(127, "", "", 0.0)),
        ("python -c", Result(127, "", "", 0.0)),
        ("/dev/tcp", Result(127, "", "", 0.0)),
    ]
    (outcome,) = apply_patches(FakeSession(rules), make_task(), [PATCH_NETWORK_OFF])
    assert outcome.ok is False
    assert outcome.notes == ("unverified: probe unavailable (python3, python and bash /dev/tcp all missing)",)


def test_probe_killed_by_the_host_fails():
    session = FakeSession([("python3 -c", Result(137, "", "", 0.0, timed_out=True))])
    (outcome,) = apply_patches(session, make_task(), [PATCH_NETWORK_OFF])
    assert outcome.ok is False
    assert outcome.notes[0].startswith("unverified: network probe (python3) failed (exit 137)")


def test_probe_that_cannot_run_becomes_unverified():
    (outcome,) = apply_patches(RaisingSession(RuntimeError("closed")), make_task(), [PATCH_NETWORK_OFF])
    assert outcome == PatchOutcome(
        PATCH_NETWORK_OFF, False, ("unverified: network probe could not run: closed",)
    )


# strip-future-git against real git. Each test builds a repo in tmp_path and runs the generated scripts with sh -c.


def _text(value: bytes | str | None) -> str:
    if value is None:
        return ""
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else value


class LocalSession(Session):
    """Runs each command with sh -c in a local directory, so the generated scripts meet real git."""

    def __init__(self, workdir: Path) -> None:
        self.workdir = workdir

    def run(self, cmd: str, timeout: float) -> Result:
        started = time.monotonic()
        try:
            done = subprocess.run(
                ["sh", "-c", cmd],
                cwd=self.workdir,
                env=GIT_TEST_ENV,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return Result(
                124, _text(exc.stdout), _text(exc.stderr), time.monotonic() - started, timed_out=True
            )
        return Result(done.returncode, _text(done.stdout), _text(done.stderr), time.monotonic() - started)

    def write_file(self, path, data):
        target = self.workdir / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)

    def diff(self):
        raise NotImplementedError("LocalSession does not build diffs")

    def reset(self):
        raise NotImplementedError("LocalSession cannot reset")

    def close(self):
        pass


def git(repo: Path, *args: str) -> str:
    """Runs git in repo for the fixture. Raises if git fails."""
    return _git_run(repo, args).stdout.strip()


def git_exit(repo: Path, *args: str) -> int:
    return _git_run(repo, args, check=False).returncode


def _git_run(repo: Path, args: tuple[str, ...], *, check: bool = True) -> subprocess.CompletedProcess:
    argv = [GIT_BIN, "-C", str(repo), "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid"]
    return subprocess.run(
        [*argv, *args], env=GIT_TEST_ENV, capture_output=True, text=True, check=check, timeout=60
    )


def snapshot(root: Path) -> dict[str, bytes]:
    """Every file under root, by relative path. Equal snapshots mean the tree did not change."""
    return {
        path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob("*") if path.is_file()
    }


@dataclass(frozen=True)
class Fixture:
    repo: Path
    base: str
    future: str
    tag_object: str
    secret_blob: str


def build_repo(root: Path) -> Fixture:
    """A repo with HEAD on base and every kind of future state the strip must remove."""
    repo = root / "repo"
    repo.mkdir()
    gitdir = repo / ".git"
    git(repo, "init", "-q")
    git(repo, "symbolic-ref", "HEAD", "refs/heads/main")
    (repo / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    git(repo, "add", "calc.py")
    git(repo, "commit", "-q", "-m", "base")
    base = git(repo, "rev-parse", "HEAD")
    # The future commit lives on its own branch, with an annotated tag on it.
    git(repo, "checkout", "-q", "-b", "future")
    (repo / "future.py").write_text("FIX = 1\n")
    git(repo, "add", "future.py")
    git(repo, "commit", "-q", "-m", "fix")
    future = git(repo, "rev-parse", "HEAD")
    git(repo, "tag", "-a", "v1", "-m", "release")
    tag_object = git(repo, "rev-parse", "refs/tags/v1")
    git(repo, "checkout", "-q", "main")
    # A stash entry, a note on base, and a replace ref that hides the future commit.
    (repo / "calc.py").write_text("def add(a, b):\n    return a - b\n")
    git(repo, "stash", "push", "-q", "-m", "wip")
    git(repo, "notes", "add", "-m", "a note", base)
    git(repo, "replace", future, base)
    # Everything into one pack, then a .keep marker on it, which the strip must remove before the repack.
    git(repo, "repack", "-a", "-d", "-q")
    (pack,) = (gitdir / "objects/pack").glob("pack-*.pack")
    pack.with_suffix(".keep").write_text("")
    # A blob staged in the index only. It stays reachable through the index until the strip rebuilds it.
    (repo / "secret.txt").write_text("staged from the future\n")
    git(repo, "add", "secret.txt")
    secret_blob = git(repo, "rev-parse", ":secret.txt")
    # Commit text and merge state, a multi-pack-index chain directory, and remote sections in both config files.
    (gitdir / "COMMIT_EDITMSG").write_text("fix\n")
    for name in ("MERGE_MSG", "SQUASH_MSG", "TAG_EDITMSG"):
        (gitdir / name).write_text("text\n")
    (gitdir / "MERGE_MODE").write_text("")
    (gitdir / "objects/pack/multi-pack-index.d").mkdir()
    git(repo, "config", "remote.origin.url", "https://example.invalid/origin.git")
    git(repo, "config", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*")
    git(
        repo,
        "config",
        "--file",
        str(gitdir / "config.worktree"),
        "remote.wt.url",
        "https://example.invalid/wt",
    )
    return Fixture(repo=repo, base=base, future=future, tag_object=tag_object, secret_blob=secret_blob)


def strip_local(fx: Fixture, task: TaskSpec) -> PatchOutcome:
    (outcome,) = apply_patches(LocalSession(fx.repo), task, [PATCH_STRIP_GIT], workdir=str(fx.repo))
    return outcome


@needs_git
def test_strip_removes_future_history_refs_and_state(tmp_path):
    fx = build_repo(tmp_path)
    gitdir = fx.repo / ".git"
    # The fixture really holds the future state, so the checks after the strip cannot pass vacuously.
    assert git(fx.repo, "rev-parse", "HEAD") == fx.base
    assert git_exit(fx.repo, "cat-file", "-e", fx.future) == 0
    assert git_exit(fx.repo, "cat-file", "-e", fx.tag_object) == 0
    assert git_exit(fx.repo, "cat-file", "-e", fx.secret_blob) == 0
    assert len(git(fx.repo, "for-each-ref").splitlines()) >= 4  # main, future, tag v1, stash, notes, replace
    assert git(fx.repo, "stash", "list") != ""
    assert list((gitdir / "objects/pack").glob("*.keep"))
    assert (gitdir / "COMMIT_EDITMSG").exists()
    assert 'remote "origin"' in (gitdir / "config").read_text()
    assert 'remote "wt"' in (gitdir / "config.worktree").read_text()

    outcome = strip_local(fx, make_task(base_commit=fx.base))
    assert outcome == PatchOutcome(PATCH_STRIP_GIT, True, ())
    assert git(fx.repo, "rev-parse", "HEAD") == fx.base
    assert git(fx.repo, "for-each-ref") == ""
    for obj in (fx.future, fx.tag_object, fx.secret_blob):
        assert git_exit(fx.repo, "cat-file", "-e", obj) != 0, obj
    for name in ("COMMIT_EDITMSG", "MERGE_MSG", "SQUASH_MSG", "TAG_EDITMSG", "MERGE_MODE"):
        assert not (gitdir / name).exists(), name
    assert not list((gitdir / "objects/pack").glob("*.keep"))
    assert not (gitdir / "objects/pack/multi-pack-index.d").exists()
    assert 'remote "origin"' not in (gitdir / "config").read_text()
    worktree_config = gitdir / "config.worktree"
    assert not worktree_config.exists() or 'remote "wt"' not in worktree_config.read_text()


@needs_git
def test_head_off_base_refuses_and_leaves_the_repo_unchanged(tmp_path):
    fx = build_repo(tmp_path)
    git(fx.repo, "commit", "-q", "--allow-empty", "-m", "child of base")
    child = git(fx.repo, "rev-parse", "HEAD")
    before = snapshot(fx.repo / ".git")
    outcome = strip_local(fx, make_task(base_commit=fx.base))
    assert outcome == PatchOutcome(
        PATCH_STRIP_GIT, False, (f"HEAD is {child}, not the task base; refusing to strip",)
    )
    assert snapshot(fx.repo / ".git") == before
    assert git_exit(fx.repo, "cat-file", "-e", fx.future) == 0
