#!/usr/bin/env python3
"""Routine lock: one line `<start ISO> <heartbeat ISO>` in the lock file; empty means free.

acquire:   exit 0 and print `START <iso>` on stdout when the lock was free or stale. Stdout then holds nothing else;
           a stale takeover is noted on stderr. Exit 3 and print `HELD <line>` on stderr when another run holds it.
heartbeat: rewrite the heartbeat if the lock still holds --start; exit 4 (`LOST`) if another run owns it.
release:   empty the file only if it holds --start; exit 4 (`NOT-OURS`) and leave it untouched otherwise.
Read, check and write happen under an OS lock on `<lock>.guard`, so two runs cannot both take the lock.
A missing parent folder of the lock is created with mode 0o700. The lock file itself is never deleted.
Works on Python 3.9+ (the system python3 runs it).
"""
import argparse
import fcntl
import os
import re
import sys
from datetime import datetime, timedelta, timezone


def when(text):
    # Python 3.9 rejects a trailing Z and some fractional seconds
    t = datetime.fromisoformat(re.sub(r"\.\d+", "", text.strip()).replace("Z", "+00:00"))
    return t if t.tzinfo else t.astimezone()


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def is_stale(line, now, stale_min):
    parts = line.split()
    if len(parts) != 2:
        return True  # broken content must not lock the routine out forever
    try:
        return now - when(parts[1]) >= timedelta(minutes=stale_min)
    except ValueError:
        return True


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("action", choices=("acquire", "heartbeat", "release"))
    p.add_argument("--lock", required=True)
    p.add_argument("--start")
    p.add_argument("--stale-min", type=float, default=170)
    p.add_argument("--now", type=when)
    a = p.parse_args(argv)
    if a.action != "acquire" and not a.start:
        p.error("--start is required for " + a.action)
    now = a.now or when(now_iso())
    stamp = now.isoformat(timespec="seconds")
    os.makedirs(os.path.dirname(os.path.abspath(a.lock)), mode=0o700, exist_ok=True)
    with open(a.lock + ".guard", "a") as guard:
        fcntl.flock(guard, fcntl.LOCK_EX)
        try:
            with open(a.lock) as fh:
                line = fh.read().strip()
        except FileNotFoundError:
            line = ""
        first = line.split()[0] if line else ""
        if a.action == "acquire":
            if line and not is_stale(line, now, a.stale_min):
                print("HELD " + line, file=sys.stderr)
                return 3
            with open(a.lock, "w") as fh:
                fh.write(stamp + " " + stamp + "\n")
            if line:
                print("took stale lock: " + line, file=sys.stderr)
            print("START " + stamp)
            return 0
        if first != a.start:
            print(("LOST " if a.action == "heartbeat" else "NOT-OURS ") + (line or "(empty)"))
            return 4
        with open(a.lock, "w") as fh:
            fh.write(a.start + " " + stamp + "\n" if a.action == "heartbeat" else "")
        print("HEARTBEAT " + stamp if a.action == "heartbeat" else "RELEASED")
        return 0


if __name__ == "__main__":
    sys.exit(main())
