# Plan (work back from Fri 2026-10-30 10:00 PDT; the owner submits 2026-10-28)

| Date | Gate |
|---|---|
| Oct 16–17 | Rules read, prize fit, research, repo, CI, spend cap, guards |
| **Oct 18 (Sat)** | Project decided: RewardSeal. Rename, docs, queue, ADR 0002, routine created and reviewed. Owner: U1, U3, U4 |
| Oct 18–20 | T02 executor (Docker backend first), T03 task loader with gold/empty gates, T04 attacker on fakes |
| Oct 20 (Mon) 6:59 PM CT | Weekly usage reset |
| **Oct 21 (Tue)** | **Go/no-go:** the attacker passes at least 5 of 40 unhardened tasks without solving them. Executor decided (Sandboxes or Docker). Video script |
| Oct 22–23 | T05 hole classifier, T06 patches and re-attack loop, T07 certificates, T08 eval run with raw counts |
| **Oct 24 (Fri)** | T09 report page and judge replay, rough-cut video. **Feature freeze end of day** |
| Oct 25–26 | Fixes, polish, README, ADRs, feedback write-up, final video with the owner's voice |
| Oct 27 (Tue) 6:59 PM CT | Weekly usage reset. Fresh-clone final check, learning pack, pre-flip check |
| **Oct 28 (Wed)** | Owner makes the repo public and submits (never on the last day) |
| Oct 30 – Dec 15 | Demo up and free (static replay, no paid calls); caps hold |

## Go/no-go fallback (Oct 21)
If the attacker passes fewer than 5 of 40: add explicit strategy hints, make sure Ultra is the attacker, and narrow
to tasks whose static exposure scan (T03) shows a hole. Report the raw counts honestly either way.
