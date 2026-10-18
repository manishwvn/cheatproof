#!/usr/bin/env python3
"""Pick the routine's next wake-up time from usage. --gate: exit 0 run, exit 3 skip. --write: store the time.

--now is optional and defaults to the real clock in local time. Callers pass `date -Iseconds` output
(for example 2026-10-18T10:00:00-05:00). Do not pass `date +%z` output (-0500): Python 3.9 cannot parse it.
"""
import argparse
import re
import sys
from datetime import datetime, timedelta, timezone


def next_run(now, w, f, cap, weekly_reset, five_hour_reset, runnable, next_after=None, f_cap=80):
    if w >= cap:  # weekly budget spent: sleep until it resets
        return weekly_reset + timedelta(minutes=10)
    if f >= f_cap:  # 5-hour window spent: sleep until it rolls over
        return max(five_hour_reset + timedelta(minutes=5), now + timedelta(minutes=15))
    if runnable:  # work left and budget left: continue soon
        return now + timedelta(minutes=15)
    if next_after:  # only date-gated tasks: earliest date, but at least daily
        return min(max(next_after, now + timedelta(hours=1)), now + timedelta(hours=24))
    return now + timedelta(hours=6)


def when(text):
    # Python 3.9 rejects a trailing Z and some fractional seconds
    t = datetime.fromisoformat(re.sub(r"\.\d+", "", text.strip()).replace("Z", "+00:00"))
    return t if t.tzinfo else t.astimezone()


def gate(path, now):
    try:
        with open(path) as fh:
            return now >= when(fh.read())
    except (OSError, ValueError):
        return True  # fail open: a broken wake file must not stop the routine


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    for name in ("--gate", "--write"):
        p.add_argument(name)
    for name in ("--now", "--weekly-reset", "--five-hour-reset", "--next-after"):
        p.add_argument(name, type=when)
    for name in ("--w", "--f"):
        p.add_argument(name, type=float)
    p.add_argument("--cap", type=float, default=80)
    p.add_argument("--f-cap", type=float, default=80)
    p.add_argument("--runnable", type=int)
    a = p.parse_args()
    now = a.now if a.now is not None else datetime.now(timezone.utc).astimezone().replace(microsecond=0)
    if a.gate:
        ok = gate(a.gate, now)
        print("RUN" if ok else "SKIP")
        sys.exit(0 if ok else 3)
    missing = [n for n in ("w", "f", "weekly_reset", "five_hour_reset", "runnable") if getattr(a, n) is None]
    if missing:
        p.error("missing: " + ", ".join("--" + n.replace("_", "-") for n in missing))
    out = next_run(now, a.w, a.f, a.cap, a.weekly_reset, a.five_hour_reset, a.runnable, a.next_after,
                   a.f_cap).isoformat()
    if a.write:
        with open(a.write, "w") as fh:
            fh.write(out + "\n")
    print(out)
