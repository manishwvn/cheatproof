#!/usr/bin/env python3
"""Leak check: name each given file that contains a literal value from an env file.

Usage: python3 docs/autopilot/leakcheck.py --env <env file> <file>...

The env file holds KEY=VALUE lines. Blank lines and # comments are ignored; an optional `export ` prefix and
optional matching quotes are stripped. Only values of 12 or more characters are checked, as literal text.
Stdout holds the name of each given file that contains one of those values, and nothing else: never a value and
never a key name. Exit codes: 0 clean, 1 at least one file leaks, 2 usage error, missing or unreadable env file,
or a file that cannot be read (messages on stderr carry no file contents).

Run it before any alert, LOG block, PR body, commit or learn-*.txt write.
"""
import argparse
import re
import sys

MIN_LEN = 12


def env_values(path):
    values = []
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            line = re.sub(r"^export\s+", "", line)
            value = line.split("=", 1)[1].strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            if len(value) >= MIN_LEN:
                values.append(value)
    return values


def main(argv=None):
    p = argparse.ArgumentParser(description="Report which files contain a literal value from an env file.")
    p.add_argument("--env", required=True, help="env file with KEY=VALUE lines")
    p.add_argument("files", nargs="+", help="files to check")
    a = p.parse_args(argv)
    try:
        values = env_values(a.env)
    except FileNotFoundError:
        print("leakcheck: env file not found", file=sys.stderr)
        return 2
    except (OSError, UnicodeDecodeError):
        print("leakcheck: cannot read env file", file=sys.stderr)
        return 2
    leaks, unreadable = [], []
    for name in a.files:
        try:
            with open(name, "rb") as fh:
                data = fh.read()
        except OSError:
            unreadable.append(name)
            continue
        if any(v.encode("utf-8") in data for v in values):
            leaks.append(name)
    for name in leaks:
        print(name)
    for name in unreadable:
        print("leakcheck: cannot read " + name, file=sys.stderr)
    if leaks:
        return 1
    return 2 if unreadable else 0


if __name__ == "__main__":
    sys.exit(main())
