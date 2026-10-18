"""Tests for cheatproof/patches.py (T06). Fake sessions only: nothing here runs a shell, git, docker or the network."""

import json
import re
import shlex

import pytest

from cheatproof.budget import BudgetExceeded
from cheatproof.executor import EnvSpec, ExecutorRefused, ExecutorUnavailable, Result, Session
from cheatproof.exposure import HOLE_GIT_HISTORY, HOLE_NETWORK, HOLE_TEST_EDIT
from cheatproof.grader import GIT_PREFIX, STEP_TIMEOUT_S
from cheatproof.patches import (
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
from cheatproof.tasks import TaskSpec

BASE = "71fb12cefda5a3e1e223ed837bca468f8bdab874"
FUTURE = "9676c1085a90cf604df7cc56977abe773bae86b1"
IMAGE = "python:3.12-slim"
GUARD_NOTE = "enforced at grade time (reject_test_edits)"
NO_CHANGE_NOTE = "unreachable blobs/trees left: 0 (a note, not a failure)"
# The needles that route a fake reply to one strip step. Each script contains exactly one of the first two.
VERIFY_NEEDLE = "--batch-all-objects"
STRIP_NEEDLE = "repack"
CHECK_NEEDLE = "cat-file -e"
MARKER = re.compile(r"cheatproof-strip ([0-9a-f]{32}) done")
FORBIDDEN_GIT_SUBCOMMANDS = re.compile(
    r"\b(checkout|reset|clean|read-tree|stash|add|rm|restore|switch|apply)\b"
)


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
    return Result(0, f"cheatproof-strip {token_of(cmd)} done\n", "", 0.0)


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
                lines.append(f"cheatproof-strip {token} {key}={item}")
        if done:
            lines.append(f"cheatproof-strip {token} done")
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


def clean_rules(verify=None):
    return [(VERIFY_NEEDLE, verify_reply(verify)), (STRIP_NEEDLE, done_reply), (CHECK_NEEDLE, done_reply)]


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


def test_clean_strip_is_ok_and_reports_zero_unreachable_as_a_note():
    session = strip_session()
    outcome = strip(session)
    assert outcome == PatchOutcome(PATCH_STRIP_GIT, True, (NO_CHANGE_NOTE,))
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
        ({"leftover": ["packed-refs", "logs"]}, "still present in .git: packed-refs, logs"),
        ({"head": FUTURE}, f"HEAD is not at base: {FUTURE}"),
        ({"head": None}, "HEAD is not at base: no value printed"),
    ],
)
def test_each_left_over_ref_object_or_config_fails_the_patch(changes, note):
    outcome = strip(strip_session(verify=changes))
    assert outcome.ok is False
    assert note in outcome.notes


def test_unreachable_blobs_and_trees_are_a_note_not_a_failure():
    outcome = strip(strip_session(verify={"unreachable_objects": "3"}))
    assert outcome.ok is True
    assert "unreachable blobs/trees left: 3 (a note, not a failure)" in outcome.notes


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


def test_lines_with_another_runs_token_are_ignored():
    def with_forged_line(cmd: str) -> Result:
        genuine = verify_reply()(cmd)
        return Result(0, f"cheatproof-strip {'f' * 32} extra_commits=5\n" + genuine.stdout, "", 0.0)

    assert strip(strip_session(first=[(VERIFY_NEEDLE, with_forged_line)])).ok is True


def test_login_profile_noise_before_the_result_is_ignored():
    def noisy(cmd):
        clean = verify_reply()(cmd)
        return Result(0, "profile says hi\n" + clean.stdout, "", 0.0)

    assert strip(strip_session(first=[(VERIFY_NEEDLE, noisy)])).ok is True


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


def test_every_line_that_calls_git_carries_the_grader_prefix():
    session = strip_session()
    strip(session)
    for cmd in session.commands:
        git_lines = [line for line in cmd.splitlines() if re.search(r"\bgit\b", line)]
        assert git_lines, "each step calls git"
        for line in git_lines:
            assert GIT_PREFIX in line, line


def test_no_command_checks_out_resets_hard_cleans_or_touches_the_index():
    session = strip_session()
    strip(session)
    for cmd in session.commands:
        assert "--hard" not in cmd
        assert not re.search(r"\bclean\b", cmd)
        for line in cmd.splitlines():
            if GIT_PREFIX in line:
                assert not FORBIDDEN_GIT_SUBCOMMANDS.search(line.replace(GIT_PREFIX, "")), line


def test_scripts_use_posix_sh_only():
    session = strip_session()
    strip(session)
    for cmd in session.commands:
        assert "[[" not in cmd and "pipefail" not in cmd and "<(" not in cmd and "$'" not in cmd


def test_scripts_unset_the_variables_that_could_redirect_git():
    session = strip_session()
    strip(session)
    for cmd in session.commands:
        assert "unset GIT_DIR " in cmd and "GIT_ALTERNATE_OBJECT_DIRECTORIES" in cmd


def test_scratch_dir_is_host_chosen_and_removed_on_exit():
    session = strip_session()
    strip(session)
    token = token_of(session.commands[0])
    assert re.fullmatch(r"[0-9a-f]{32}", token)
    scratch = f"/tmp/cheatproof-{token}"
    for cmd in session.commands[1:]:
        assert f"trap 'rm -rf -- {scratch}' EXIT" in cmd
        assert f"mkdir -m 700 -- {scratch}" in cmd


def test_the_strip_removes_refs_reflogs_grafts_alternates_and_keeps_marks_out():
    session = strip_session()
    strip(session)
    strip_script = session.commands[1]
    assert f"update-ref --no-deref HEAD {BASE}" in strip_script
    assert "update-ref --no-deref -d" in strip_script
    for name in ("logs", "info/grafts", "packed-refs", "worktrees", "ORIG_HEAD", "FETCH_HEAD"):
        assert f'"$gitdir/{name}"' in strip_script or f'"$common/{name}"' in strip_script, name
    assert "objects/info/alternates" in strip_script
    assert "*.keep" in strip_script and "*.promisor" in strip_script
    assert "remove-section" in strip_script
    assert "repack -a -d" in strip_script and "prune --expire=now" in strip_script


def test_workdir_is_quoted_in_every_step():
    session = strip_session()
    strip(session, workdir="/work space")
    assert len(session.commands) == 3
    assert all("cd '/work space'" in cmd for cmd in session.commands)


def test_verification_checks_base_against_the_fetched_history():
    session = strip_session()
    strip(session)
    verify = session.commands[2]
    assert f"rev-list {BASE} >" in verify
    assert "comm -23" in verify and "LC_ALL=C sort -u" in verify


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
