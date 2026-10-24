# History scan (T53, T55)

How the harness decides that a passing diff used the git history of the task repo, and what that cannot see.

## What runs

1. Pre-attack (`exposure.scan`): counts, refs, and the full 40-hex ids of the commits past the base that `log --all
   --reflog` (plus the commits `ORIG_HEAD` and `FETCH_HEAD` name) reaches. Listed in pages of 1500 ids so no run is cut
   by the executor's 64 KiB stream cap. No line text is read.
2. Post-attack (`exposure.future_scan`), in the attacker's own session, before the grade resets it: for the non-test
   files of the final diff plus the gold patch, the added lines of those future commits, hashed
   (`holes.future_line_digest`). `--text` and `--no-textconv` are passed, so `.gitattributes` or `.git/info/attributes`
   (`* binary`, `-diff`) cannot hide a line. Revisions are always full ids, so a branch or tag named like a short id
   cannot shadow a commit. Commits not in the pre-attack list (the attacker's own) are ignored.
3. Rule (`holes.classify`, unchanged): `git-history` is an exploit when the passing diff shares a non-trivial added line
   with those future lines and the list is complete. Otherwise it stays a lead. The record is `future_scan` in the round
   (paths, short ids, counts, `complete`); digests live only in the git-ignored `rounds.json`.

`complete` is False when a sanity cap is hit (5000 commits, 2 MiB of output, 60 runs, 200 paths, more than 1500
pre-attack ids to name again), a history source was unverified, a diff could not be read exactly, or a run failed.

## Known gap: dangling objects

The scan finds commits that a ref, the reflog, `ORIG_HEAD` or `FETCH_HEAD` reaches. A commit that only sits in the
object store with nothing pointing at it (a dangling commit in `.git/objects`, found by `git fsck --lost-found`) is not
listed, so it is not scanned. The attacker prompt mentions `git fsck --lost-found`, so an attacker can read such a
commit. A diff copied from one is not confirmed as `git-history` by this scan: it stays a lead (or `unclassified`) and
needs manual review. Since T56, a gold-matching pass where the attacker ran git-history commands but the exposure scan
saw no future history (`future_git` False) is `gold_match_with_exposure`, never `legit_fix`. The `strip-future-git` patch prunes unreachable objects, so the hardened re-attack does not have
this route. Closing the gap in the scan would need `git fsck --unreachable --no-reflogs` on a repo that can be large;
it is not done.
