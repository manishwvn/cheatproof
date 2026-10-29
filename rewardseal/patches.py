"""In-session hardening patches for one task (queue T06, ADR 0002). Code only, no model.

Each patch closes one hole that rewardseal/exposure.py reports:
  strip-future-git  git-history. Refuses unless HEAD is exactly the task base. Then deletes every ref, reflog,
                    pseudo-ref, graft, alternate and object that base cannot reach, so the fix cannot be read from
                    .git. A verification run then checks the result.
  test-edit-guard   test-edit. Runs no command. The grader refuses a candidate that edits a test file when it is
                    graded with reject_test_edits=True (grade_kwargs returns that flag).
  network-off       network. EnvSpec.network=False turns the network off at start (env_for). Here a probe checks
                    that the network is really unreachable.
hard-code has no patch. A special case for the visible test inputs is not a file or a setting that a rule can
close. unpatched() reports it, and only the hidden-test gate can catch it.

Why patches run again after every reset: reset() destroys the sandbox and starts a fresh one from the image, so
every in-session change is lost. Call apply_patches after each reset, and build the EnvSpec with env_for for each
start.

Safety. Every command is POSIX sh (run through sh -lc), with each argument shlex-quoted. Each script first sets PATH
to fixed system directories and drops the shell functions and git variables that the image's login profile may
have set (see _SCRUB_LINE and _UNSET_GIT_ENV). Every git call carries grader.GIT_PREFIX, which turns off hooks,
fsmonitor, external diff and the system and global config. The strip never runs checkout, reset --hard or clean,
and never writes the working tree. It rebuilds the index from base with read-tree, which replaces only the index.
The output is parsed strictly: a step that exits non-zero, times out, is truncated, or does not finish its output
gives ok=False, and nothing is read as success. BudgetExceeded and the executor errors propagate. Only RuntimeError
and OSError from a sandbox call become ok=False.

Residual risk. A sandbox with a trojaned /usr/bin/git can still lie. The fixed PATH and the strict output parse do
not stop a git that fakes its answers. The exposure scan in harden is the second check, and that residual risk is
stated here, not closed.

Limits. Only the workdir's repository is stripped, and its alternates are removed after the repack, so base objects
that live in a borrowed store are copied first. Submodule git dirs under .git/modules and other clones in the image
are not stripped; the verification reports submodules as a note. The image's login profile runs before each
script's first line, so the scrub and the exposure scan are the only limits on what it can change.
"""

from __future__ import annotations

import re
import shlex
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from rewardseal.budget import BudgetExceeded
from rewardseal.executor import EnvSpec, ExecutorRefused, ExecutorUnavailable, Result, Session
from rewardseal.exposure import HOLE_GIT_HISTORY, HOLE_NETWORK, HOLE_TEST_EDIT, _network
from rewardseal.grader import DEFAULT_WORKDIR, GIT_PREFIX, STEP_TIMEOUT_S, checked_sha, error_tail

if TYPE_CHECKING:
    from rewardseal.tasks import TaskSpec

PATCH_STRIP_GIT = "strip-future-git"
PATCH_TEST_GUARD = "test-edit-guard"
PATCH_NETWORK_OFF = "network-off"
PATCH_ORDER: tuple[str, ...] = (PATCH_STRIP_GIT, PATCH_TEST_GUARD, PATCH_NETWORK_OFF)
HOLE_PATCHES: dict[str, tuple[str, ...]] = {
    HOLE_GIT_HISTORY: (PATCH_STRIP_GIT,),
    HOLE_TEST_EDIT: (PATCH_TEST_GUARD,),
    HOLE_NETWORK: (PATCH_NETWORK_OFF,),
    "hard-code": (),  # no rule patch: see the module docstring
}

FULL_SHA_LEN = 40
FULL_SHA_RE = re.compile(r"[0-9a-f]{40}")
MAX_EXTRA_SHAS = 5  # leftover commit SHAs quoted in a note

# The path every script uses, and the tools they may call. The image's login profile runs before a script's first
# line and may have set PATH or defined shell functions with these names, so the first line resets both. tr and grep
# are not called yet. They stay on the list so a later edit cannot pick up a shadowed copy.
_SCRIPT_PATH = "/usr/local/bin:/usr/bin:/bin"
_SCRUBBED_TOOLS = "git sort comm sed find wc head cat rm mkdir tr grep"
_SCRUB_LINE = f"PATH={_SCRIPT_PATH}; export PATH; unset -f {_SCRUBBED_TOOLS} 2>/dev/null; hash -r 2>/dev/null"
# Environment that would point git at another repository or inject config. Every script unsets these before its
# first git call.
_UNSET_GIT_ENV = (
    "GIT_DIR GIT_COMMON_DIR GIT_WORK_TREE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES "
    "GIT_INDEX_FILE GIT_NAMESPACE GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS GIT_EXEC_PATH GIT_GRAFT_FILE "
    "GIT_SHALLOW_FILE GIT_NO_REPLACE_OBJECTS GIT_CEILING_DIRECTORIES"
)
# The same path in a plain clone. For a linked worktree the per-worktree dir and the common dir differ.
_GIT_ROOTS = ("$gitdir", "$common")
# Removed from both git roots. Reflogs, linked-worktree state, leftover operation state, grafts, the dumb-HTTP ref
# list and the packed refs all name objects or refs. commit-graph and multi-pack-index (file or .d chain) can name
# pruned commits.
_STALE_NAMES = (
    "logs",
    "worktrees",
    "lost-found",
    "rebase-merge",
    "rebase-apply",
    "sequencer",
    "packed-refs",
    "info/grafts",
    "info/refs",
    "objects/info/packs",
    "objects/info/commit-graph",
    "objects/info/commit-graphs",
    "objects/pack/multi-pack-index",
    "objects/pack/multi-pack-index.d",
)
# Pseudo-refs that can name a commit or tree. Only the per-worktree git dir holds them.
_PSEUDO_REFS = (
    "ORIG_HEAD",
    "FETCH_HEAD",
    "MERGE_HEAD",
    "CHERRY_PICK_HEAD",
    "REVERT_HEAD",
    "AUTO_MERGE",
    "REBASE_HEAD",
    "BISECT_HEAD",
)
# Per-worktree files that hold commit or tag text, or merge state. Commit text can name objects, so they go too.
_EDIT_FILES = ("COMMIT_EDITMSG", "MERGE_MSG", "SQUASH_MSG", "TAG_EDITMSG", "MERGE_MODE")
_PER_WORKTREE_FILES = (*_PSEUDO_REFS, *_EDIT_FILES)
# Paths the verification must find absent. Alternates are removed after the repack, not in the strip's first pass.
_LEFTOVER_NAMES = (
    *_STALE_NAMES,
    *_PER_WORKTREE_FILES,
    "objects/info/alternates",
    "objects/info/http-alternates",
)
# Remote config keys. A remote section names a URL and fetch refspecs, so the strip removes every such section,
# from .git/config and from the per-worktree config.worktree.
_REMOTE_KEY_RE = shlex.quote("^remote[.]")
_WORKTREE_CONFIG = '"$gitdir/config.worktree"'
_SECTION_SED = shlex.quote("s/[.][^.]*$//")  # drops the last key component, leaving the section name
_REF_FORMAT = shlex.quote("--format=%(refname)")
_COMMIT_SED = shlex.quote("s/^commit //p")
_TAG_SED = shlex.quote("s/^tag //p")
# rev-list --objects prints "<sha> <path>", or only "<sha>" for a commit.
_OBJECT_ID_SED = shlex.quote("s/ .*//")
_BLOB_SED = shlex.quote("s/^blob //p")
_TREE_SED = shlex.quote("s/^tree //p")
_BATCH_CHECK = shlex.quote("--batch-check=%(objecttype) %(objectname)")


@dataclass(frozen=True)
class PatchOutcome:
    name: str
    ok: bool
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "notes": list(self.notes)}


class _StepFailed(Exception):
    """A step did not finish or did not print what it must. Its message becomes the patch's only note."""


def _checked_names(names: Iterable[str]) -> frozenset[str]:
    chosen = frozenset(names)
    unknown = sorted(chosen.difference(PATCH_ORDER))
    if unknown:
        raise ValueError(f"unknown patch {unknown[0]!r}: use one of {', '.join(PATCH_ORDER)}")
    return chosen


def patches_for(labels: Iterable[str]) -> tuple[str, ...]:
    """The patches the hole labels need, in PATCH_ORDER with no duplicates. A label without a patch adds nothing."""
    needed = {patch for label in labels for patch in HOLE_PATCHES.get(label, ())}
    return tuple(name for name in PATCH_ORDER if name in needed)


def unpatched(labels: Iterable[str]) -> tuple[str, ...]:
    """The input labels that map to no patch (hard-code, unclassified, unknown), deduplicated in input order."""
    return tuple(label for label in dict.fromkeys(labels) if not HOLE_PATCHES.get(label))


def env_for(spec: EnvSpec, names: Iterable[str]) -> EnvSpec:
    """The EnvSpec to start with. network-off turns the network off; other names leave the spec as it is."""
    chosen = _checked_names(names)
    return replace(spec, network=False) if PATCH_NETWORK_OFF in chosen else spec


def grade_kwargs(names: Iterable[str]) -> dict[str, bool]:
    """Keyword arguments for grade(): reject_test_edits=True when test-edit-guard is among the names."""
    return {"reject_test_edits": True} if PATCH_TEST_GUARD in _checked_names(names) else {}


def apply_patches(
    session: Session, task: TaskSpec, names: Iterable[str], *, workdir: str = DEFAULT_WORKDIR
) -> list[PatchOutcome]:
    """Run the in-session work for each name, in PATCH_ORDER. Call it after every reset.

    An unknown name raises ValueError before any command runs. A failed or unverifiable step gives ok=False.
    BudgetExceeded and the executor errors propagate.
    """
    chosen = _checked_names(names)
    outcomes: list[PatchOutcome] = []
    for name in PATCH_ORDER:
        if name not in chosen:
            continue
        if name == PATCH_STRIP_GIT:
            outcomes.append(_strip_future_git(session, task, workdir))
        elif name == PATCH_TEST_GUARD:
            outcomes.append(PatchOutcome(name, True, ("enforced at grade time (reject_test_edits)",)))
        else:
            outcomes.append(_network_off(session))
    return outcomes


def _network_off(session: Session) -> PatchOutcome:
    try:
        reachable, evidence = _network(session)
    except (BudgetExceeded, ExecutorRefused, ExecutorUnavailable):
        raise
    except (RuntimeError, OSError) as exc:
        return PatchOutcome(PATCH_NETWORK_OFF, False, (f"unverified: network probe could not run: {exc}",))
    if reachable:
        return PatchOutcome(PATCH_NETWORK_OFF, False, tuple(evidence) or ("network still reachable",))
    return PatchOutcome(PATCH_NETWORK_OFF, True, ("no connection to 1.1.1.1:53",))


def _strip_future_git(session: Session, task: TaskSpec, workdir: str) -> PatchOutcome:
    try:
        base = checked_sha(task.base_commit).lower()
    except ValueError as exc:
        return PatchOutcome(PATCH_STRIP_GIT, False, (str(exc),))
    if len(base) != FULL_SHA_LEN:
        return PatchOutcome(
            PATCH_STRIP_GIT, False, (f"base commit must be a full {FULL_SHA_LEN}-character id",)
        )
    token = uuid.uuid4().hex  # tags every line this strip prints, so stray output cannot pass for a result
    try:
        _check_head(session, workdir, base, token)
        _step(session, _strip_script(workdir, base, token), token, "strip")
        fields = _step(session, _verify_script(workdir, base, token), token, "strip verification")
        failures, notes = _judge(fields, base)
    except _StepFailed as exc:
        return PatchOutcome(PATCH_STRIP_GIT, False, (str(exc),))
    return PatchOutcome(PATCH_STRIP_GIT, not failures, (*failures, *notes))


def _check_head(session: Session, workdir: str, base: str, token: str) -> None:
    """Refuses the strip unless HEAD is exactly base. The check only reads, so a refusal changes nothing."""
    fields = _step(session, _check_script(workdir, base, token), token, "base commit check")
    head = fields.get("head", [])
    if len(head) != 1:
        raise _StepFailed("unverified: base commit check printed no HEAD")
    if head[0] != base:
        raise _StepFailed(f"HEAD is {head[0] or 'unresolved'}, not the task base; refusing to strip")


def _run(session: Session, cmd: str, label: str) -> Result:
    try:
        res = session.run(cmd, STEP_TIMEOUT_S)
    except (BudgetExceeded, ExecutorRefused, ExecutorUnavailable):
        raise
    except (RuntimeError, OSError) as exc:
        raise _StepFailed(f"unverified: {label} could not run: {exc}") from exc
    if res.timed_out:
        raise _StepFailed(f"unverified: {label} timed out after {STEP_TIMEOUT_S}s")
    if res.truncated:
        raise _StepFailed(f"unverified: {label} output was cut at the executor cap")
    if res.exit_code != 0:
        raise _StepFailed(f"{label} failed (exit {res.exit_code}): {error_tail(res)}")
    return res


def _step(session: Session, cmd: str, token: str, label: str) -> dict[str, list[str]]:
    res = _run(session, cmd, label)
    fields = _fields(res.stdout, token)
    if fields.get("done") != [""]:
        raise _StepFailed(f"unverified: {label} printed no completion line")
    return fields


def _fields(stdout: str, token: str) -> dict[str, list[str]]:
    """The key=value lines this run printed with its token, as key -> values. Any other line is ignored."""
    prefix = f"rewardseal-strip {token} "
    fields: dict[str, list[str]] = {}
    for line in stdout.splitlines():
        if line.startswith(prefix):
            key, _, value = line[len(prefix) :].partition("=")
            fields.setdefault(key.strip(), []).append(value.strip())
    return fields


def _count(fields: dict[str, list[str]], key: str) -> int:
    values = fields.get(key, [])
    if len(values) != 1 or not re.fullmatch(r"[0-9]+", values[0]):
        raise _StepFailed(f"unverified: strip verification printed no usable {key}")
    return int(values[0])


def _judge(fields: dict[str, list[str]], base: str) -> tuple[list[str], list[str]]:
    """(failures, notes) from the verification output. Every count and the HEAD must match, or the patch fails."""
    failures: list[str] = []
    extra = _count(fields, "extra_commits")
    if extra:
        shas = [sha for sha in fields.get("extra", []) if FULL_SHA_RE.fullmatch(sha)][:MAX_EXTRA_SHAS]
        failures.append(f"{extra} commit(s) past base still in the object store: {', '.join(shas)}")
    for key, what in (
        ("tags", "tag object(s) left in the object store"),
        ("refs", "ref(s) left after the strip"),
        ("loose_refs", "loose ref file(s) left"),
        ("remote_keys", "remote config key(s) left"),
        ("unreachable_objects", "unreachable blob/tree object(s) left after prune"),
    ):
        count = _count(fields, key)
        if count:
            failures.append(f"{count} {what}")
    leftover = fields.get("leftover", [])
    if leftover:
        failures.append("still present in .git: " + ", ".join(leftover))
    head = fields.get("head", [])
    if head != [base]:
        failures.append(f"HEAD is not at base: {head[0] if head else 'no value printed'}")
    notes: list[str] = []
    if _count(fields, "submodules"):
        notes.append("submodule git dirs under .git/modules were not stripped")
    return failures, notes


def _git(args: str) -> str:
    """One git call in the sandbox, with the grader's hardening on the same line."""
    return f"{GIT_PREFIX}{args}"


def _scratch(token: str) -> str:
    return f"/tmp/rewardseal-{token}"  # host-chosen and unguessable; the script removes it on exit


def _header(workdir: str) -> list[str]:
    return [_SCRUB_LINE, "set -eu", f"unset {_UNSET_GIT_ENV}", f"cd {shlex.quote(workdir)}"]


def _done(token: str) -> str:
    return f'echo "rewardseal-strip {token} done"'


def _remote_key_lines(out: str) -> list[str]:
    """Shell lines that write every remote.* key name, from .git/config and config.worktree, to out."""
    local = _git(f"config --local --name-only --get-regexp {_REMOTE_KEY_RE} > {out}")
    worktree = _git(f"config --file {_WORKTREE_CONFIG} --name-only --get-regexp {_REMOTE_KEY_RE} >> {out}")
    # Exit 1 means no key matched, which is fine. Anything above 1 is a read failure.
    return [
        "rc=0",
        f"{local} || rc=$?",
        f"if [ -f {_WORKTREE_CONFIG} ]; then {worktree} || rc=$?; fi",
        'if [ "$rc" -gt 1 ]; then echo "config read failed" >&2; exit 1; fi',
    ]


def _check_script(workdir: str, base: str, token: str) -> str:
    base_rev = shlex.quote(f"{base}^{{commit}}")
    # Read-only. It prints HEAD so _check_head can refuse the strip before anything is changed.
    head = f"head_sha=$({_git('rev-parse --verify --quiet HEAD')} || true)"
    return "\n".join(
        [
            *_header(workdir),
            _git(f"cat-file -e {base_rev}"),
            head,
            f'echo "rewardseal-strip {token} head=$head_sha"',
            _done(token),
        ]
    )


def _strip_script(workdir: str, base: str, token: str) -> str:
    scratch = _scratch(token)
    delete_ref = _git('update-ref --no-deref -d "$ref"')
    stale = " ".join(f'"{root}/{name}"' for name in _STALE_NAMES for root in _GIT_ROOTS)
    per_worktree = " ".join(f'"$gitdir/{name}"' for name in _PER_WORKTREE_FILES)
    remote_keys = f"{scratch}/remote-keys"
    sections = f"{scratch}/remote-sections"
    # A section that is already gone is fine. A section that survives is caught by the verification.
    remove_local = _git('config --local --remove-section "$sec"') + " || true"
    remove_worktree = _git(f'config --file {_WORKTREE_CONFIG} --remove-section "$sec"') + " || true"
    remove_sections = (
        f"while IFS= read -r sec; do {remove_local}; "
        f"if [ -f {_WORKTREE_CONFIG} ]; then {remove_worktree}; fi; done < {sections}"
    )
    return "\n".join(
        [
            *_header(workdir),
            f"gitdir=$({_git('rev-parse --absolute-git-dir')})",
            f"common=$({_git('rev-parse --git-common-dir')})",
            f"mkdir -m 700 -- {scratch}",
            f"trap 'rm -rf -- {scratch}' EXIT",
            # Refs: delete each one, point HEAD at base detached, then wipe what is left of refs/ and packed-refs.
            _git(f"for-each-ref {_REF_FORMAT} > {scratch}/refs"),
            f"while IFS= read -r ref; do {delete_ref}; done < {scratch}/refs",
            _git(f"update-ref --no-deref HEAD {base}"),
            'rm -rf -- "$gitdir/refs" "$common/refs"',
            'mkdir -p -- "$gitdir/refs/heads" "$gitdir/refs/tags" "$common/refs/heads" "$common/refs/tags"',
            f"rm -rf -- {stale}",
            f'rm -f -- {per_worktree} "$gitdir"/BISECT_*',
            *_remote_key_lines(remote_keys),
            f"sed {_SECTION_SED} {remote_keys} > {sections}.raw",
            f"LC_ALL=C sort -u {sections}.raw > {sections}",
            remove_sections,
            # Index: rebuild it from base, so a blob staged from the future is no longer referenced. read-tree
            # replaces only the index. The working tree and HEAD are not touched.
            _git(f"read-tree {base}"),
            # Expire, then drop keep and promisor marks so the repack can drop objects, then repack and prune.
            _git("reflog expire --expire=now --all"),
            'rm -f -- "$common"/objects/pack/*.keep "$common"/objects/pack/*.promisor',
            # -n: repack would otherwise rewrite info/refs and the pack list.
            _git("-c gc.auto=0 repack -a -d -q -n"),
            # Alternates go after the repack: repack copies the base-reachable objects it borrows from them.
            'rm -f -- "$common/objects/info/alternates" "$common/objects/info/http-alternates"',
            _git("-c gc.auto=0 prune --expire=now"),
            _done(token),
        ]
    )


def _verify_script(workdir: str, base: str, token: str) -> str:
    s = _scratch(token)
    base_rev = shlex.quote(f"{base}^{{commit}}")
    names = " ".join(_LEFTOVER_NAMES)
    leftover_loop = (
        f'for name in {names}; do if [ -e "$gitdir/$name" ] || [ -e "$common/$name" ]; then '
        f'echo "rewardseal-strip {token} leftover=$name"; fi; done'
    )
    pack_loop = (
        'for f in "$common"/objects/pack/*.keep "$common"/objects/pack/*.promisor "$gitdir"/BISECT_*; do '
        f'if [ -e "$f" ]; then echo "rewardseal-strip {token} leftover=pack-keep-promisor-bisect"; fi; done'
    )
    submodules = (
        'if [ -e "$gitdir/modules" ] || [ -e "$common/modules" ]; then '
        f'echo "rewardseal-strip {token} submodules=1"; else echo "rewardseal-strip {token} submodules=0"; fi'
    )
    # The last check: HEAD must still be base. Exit 1 fails the step, whatever the printed counts say.
    head_gate = (
        f'[ "$head_sha" = {shlex.quote(base)} ] || '
        '{ echo "HEAD is not the task base after the strip" >&2; exit 1; }'
    )
    return "\n".join(
        [
            *_header(workdir),
            f"gitdir=$({_git('rev-parse --absolute-git-dir')})",
            f"common=$({_git('rev-parse --git-common-dir')})",
            f"mkdir -m 700 -- {s}",
            f"trap 'rm -rf -- {s}' EXIT",
            _git(f"cat-file --batch-all-objects {_BATCH_CHECK} > {s}/objects"),
            _git(f"rev-list {base} > {s}/base-list"),
            _git(f"rev-list --objects {base} > {s}/base-objects"),
            _git(f"for-each-ref > {s}/refs"),
            _git(f"rev-parse --verify --quiet HEAD > {s}/head"),
            *_remote_key_lines(f"{s}/remote"),
            # Commits in the object store that base cannot reach are the extra ones.
            f"LC_ALL=C sort -u {s}/base-list > {s}/base-commits",
            f"sed -n {_COMMIT_SED} {s}/objects > {s}/commit-ids",
            f"LC_ALL=C sort -u {s}/commit-ids > {s}/commits",
            f"LC_ALL=C comm -23 {s}/commits {s}/base-commits > {s}/extra-commits",
            f"head -n {MAX_EXTRA_SHAS} {s}/extra-commits > {s}/extra-sample",
            f"sed -n {_TAG_SED} {s}/objects > {s}/tags",
            # Blobs and trees the store holds that base's history does not reach. Left after the prune, they fail.
            f"sed {_OBJECT_ID_SED} {s}/base-objects > {s}/base-object-ids",
            f"LC_ALL=C sort -u {s}/base-object-ids > {s}/base-objs",
            f"sed -n -e {_BLOB_SED} -e {_TREE_SED} {s}/objects > {s}/object-ids",
            f"LC_ALL=C sort -u {s}/object-ids > {s}/odb-objs",
            f"LC_ALL=C comm -23 {s}/odb-objs {s}/base-objs > {s}/extra-objs",
            f'find "$gitdir/refs" "$common/refs" -type f -o -type l > {s}/loose',
            f"extra=$(wc -l < {s}/extra-commits)",
            f"tags=$(wc -l < {s}/tags)",
            f"refs=$(wc -l < {s}/refs)",
            f"loose=$(wc -l < {s}/loose)",
            f"remote=$(wc -l < {s}/remote)",
            f"unreachable=$(wc -l < {s}/extra-objs)",
            f"head_sha=$(cat {s}/head)",
            f'echo "rewardseal-strip {token} extra_commits=$extra"',
            f'while IFS= read -r sha; do echo "rewardseal-strip {token} extra=$sha"; done < {s}/extra-sample',
            f'echo "rewardseal-strip {token} tags=$tags"',
            f'echo "rewardseal-strip {token} refs=$refs"',
            f'echo "rewardseal-strip {token} loose_refs=$loose"',
            f'echo "rewardseal-strip {token} remote_keys=$remote"',
            f'echo "rewardseal-strip {token} unreachable_objects=$unreachable"',
            f'echo "rewardseal-strip {token} head=$head_sha"',
            leftover_loop,
            pack_loop,
            submodules,
            _git(f"cat-file -e {base_rev}"),
            head_gate,
            _done(token),
        ]
    )
