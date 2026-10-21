# ADR 0002: execution model (Token Factory Sandboxes, local Docker as fallback)

**Status:** accepted, 2026-10-18. Facts marked `VERIFY` are confirmed by T02 with recorded fixtures. The final
executor is chosen at the go/no-go on 2026-10-21.

## Context
Cheatproof runs untrusted code on purpose: a dishonest agent gets a shell inside each SWE environment, and the gold,
empty and attacker gates run the task's tests. That code must never run on the host. Every model call must go
through Token Factory (hard requirement), and every paid action through `cheatproof/budget.py` (ADR 0001).

Known on 2026-10-18:
- **Token Factory Sandboxes** (beta): access is gated (U3). Checkpoints and branches, about 7,000 preloaded SWE
  environments, 50 concurrent operations, root inside the VM, networking only on or off, only stdout and stderr
  captured. Per-run price is not documented. SDK: `contree-sdk` 0.3.6. `VERIFY`: networking flag, file upload,
  checkpoint and branch calls, timeout, preloaded image naming, cost per run.
- **The dev machine** is an arm64 Mac with Docker installed but the daemon stopped, and 16 GB of free disk. SWE-bench
  and SWE-rebench images are linux/amd64 (`VERIFY`), so they run under emulation, slower, and each image is about
  1–3 GB (`VERIFY`). Routines cannot remove images (`docker rmi` is denied), so disk only shrinks.

## Decision
One executor interface in `cheatproof/executor.py`, chosen by `EXECUTOR=sandbox|docker`:

```
start(env) -> Session      # from a task image (Sandboxes: a checkpoint)
Session.run(cmd, timeout) -> Result(exit_code, stdout, stderr, duration)
Session.write_file(path, data)
Session.diff() -> str      # files changed since start
Session.reset()            # back to the start state (Sandboxes: a new branch)
Session.close()
```

1. **Primary: Token Factory Sandboxes.** One checkpoint per task after setup; the attacker, the gold gate and the
   empty gate each run on their own branch; each hardening patch gets its own branch. Network off by default.
2. **Fallback: local Docker.** `docker run --rm --network none` with CPU, memory and time limits and no host mounts.
   `/tmp` is a tmpfs sized by `DOCKER_TMPFS_MB`. A fresh container replaces each branch. Guards in code: free disk at
   least `MIN_FREE_DISK_GB` (10) at every session start and reset, local image or not; at most `DOCKER_IMAGE_CAP` (6)
   distinct images, checked only before a pull; small pure-Python images first. With 16 GB free, the Docker fallback
   covers a subset, not all 40 tasks, until the owner frees disk (U7).
3. Every session start calls `budget.reserve_sandbox_run()` on both backends, so the run cap and the money caps
   apply the same way. All model calls go through `cheatproof/llm.py` on either backend.
4. The network-fetch attack is the only experiment that turns network on; it runs on its own branch or container.

## Options considered
- **GitHub Actions runners as a remote Docker host** (x86_64, about 14 GB disk, free minutes): native images and no
  local disk pressure, but the Nebius key would have to live in a repository secret and private-repo minutes are
  limited. Not chosen; the owner may revisit if both Sandboxes and local disk fail.
- **Sandboxes only:** the best story ("native to Nebius"), but access is gated and the timeline is unknown.

## Consequences
- Switching backends is a config flag, so the go/no-go can pick whichever works on Oct 21.
- With Docker only, the pitch says "Sandbox-ready" honestly and loses the preloaded-environment claim.
- Results always record which executor produced them.

## Implementation (T02)
`cheatproof/executor.py` holds the interface (`EnvSpec`, `Result`, `Session`, `Executor`, `start()`), the local Docker
backend and the Sandboxes stub, which raises `ExecutorUnavailable("Sandboxes access pending (U3)")` and imports no
`contree_sdk`. `EXECUTOR` (`docker` default, or `sandbox`) picks the backend. `EnvSpec.image` must match
`[A-Za-z0-9][A-Za-z0-9_./:@-]*`, and docker receives it after `--`. Each container is named `cheatproof-<uuid>`,
labelled `cheatproof=1` and `cheatproof.owner=<pid>`, and runs with `--cap-drop ALL`, no swap and `nofile=1024`. A
failed start removes it; `close()` and `reset()` raise if `docker rm -f` fails, other than "No such container", and keep
the name for a retry. `MIN_FREE_DISK_GB` (default 10) is checked before every start and reset, before Docker is opened.
`DOCKER_IMAGE_CAP` (default 6) guards only a new image pull. Both refuse without deleting anything; unusable values fall
back to the defaults. `DOCKER_TMPFS_MB` (default 512, clamped to 4096) sizes the `/tmp` tmpfs. Tmpfs pages count against
the container memory limit, so a full `/tmp` can OOM-kill the command rather than fail with ENOSPC. `harden` first runs
`sweep_leftovers()`: it removes `cheatproof=1` containers whose owner pid is dead on this host, or whose owner label is
missing or garbage, so a concurrent `harden` keeps its live container. It never touches images, volumes or the build
cache. The host reads each stream through a pipe up to 64 KiB plus 4 KiB; past that it kills the client and marks the
result `truncated`. `Session.diff()` builds the patch from a fresh index read from the start commit (`add -A -f`,
`--no-replace-objects`, no system git config, no external diff or textconv), so a replace ref, assume-unchanged bit or
commit made in the sandbox cannot hide a change. It raises above 8 MiB instead of truncating. `run()` caps the timeout
at 1800 s and wraps the command in `timeout -s KILL` when the image has it. If the host must kill `docker exec` (10 s
after that timeout), the result is `timed_out` and the sandbox is reset: the container and every process in it are
removed, and files written earlier in the session are lost. Sandbox VERIFY items stay open until U3.

## 2026-10-21 update
- Go/no-go: Token Factory Sandboxes work. `sandbox` is the default `EXECUTOR`; `EXECUTOR=docker` stays the explicit
  local fallback.
- Sandbox runs are count-only at $0 (ADR 0001, 2026-10-21 update).
- Network is off with `unshare -n`. A probe runs at session start and fails closed if it cannot confirm that.
- swebench images come from `images.oci`. No swebench images are pulled locally, to protect disk.
- Sandboxes cannot delete images server-side, so image cleanup is not available through the executor.
