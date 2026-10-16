#!/usr/bin/env python3
"""Weighted completion percent from QUEUE.md: S=1, M=3, L=8; superseded excluded; status starting with done/merged
1.0; in progress 0.5; in review 0.8; [NN%] overrides; anything else 0."""
import re
import sys
from datetime import date
from pathlib import Path

WEIGHT = {"S": 1, "M": 3, "L": 8}
HEAD = re.compile(r"^### (\S+) .*? — size ([SML]) — (.*)$")
SUBMIT = date(2026, 10, 28)  # owner submits two days before the deadline


def credit(status):
    s = status.lower()
    if "superseded" in s:
        return None
    m = re.search(r"\[(\d{1,3})%\]", s)
    if m:
        return min(int(m.group(1)), 100) / 100
    if s.startswith(("in progress", "in-progress")):
        return 0.5
    if s.startswith("in review"):
        return 0.8
    return 1.0 if re.match(r"(done|merged)\b", s) else 0.0  # only a status that starts with done/merged


if __name__ == "__main__":
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("QUEUE.md")
    total = earned = 0.0
    done = count = 0
    for line in path.read_text().splitlines():
        m = HEAD.match(line)
        if not m:
            continue
        c = credit(m.group(3))
        if c is None:
            continue
        w = WEIGHT[m.group(2)]
        total, earned, count, done = total + w, earned + w * c, count + 1, done + (c == 1.0)
    pct = round(100 * earned / total) if total else 0
    print(f"progress {pct}% ({done}/{count} tasks done, {(SUBMIT - date.today()).days} days to submit)")
