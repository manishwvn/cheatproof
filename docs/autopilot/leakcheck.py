#!/usr/bin/env python3
"""Leak check: name each given file that contains a literal value from an env file.

Usage: python3 docs/autopilot/leakcheck.py --env <env file> <file>...

The env file is parsed the way python-dotenv parses it: an optional `export ` prefix; single quotes are
literal; double quotes may span lines and decode backslash escapes; an unquoted value ends before an inline
` #` comment; lines starting with # are ignored. Only values of 12 or more characters are checked. Each one
is searched for in its decoded and its raw text, encoded as UTF-8, UTF-16-LE and UTF-16-BE. Target files
are read as bytes.

Stdout holds the name of each given file that contains one of those values, and nothing else: never a value
and never a key name. Exit codes: 0 clean, 1 at least one file leaks, 2 usage error, a missing or unreadable
env file, an env file with no value of 12+ characters, a target that cannot be read, or an internal error.
Messages on stderr carry no file contents.

Run it before any alert, LOG block, PR body, commit or learn-*.txt write.
"""
import argparse
import re
import sys

MIN_LEN = 12
ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "a": "\a", "b": "\b", "f": "\f", "v": "\v"}
ESCAPES.update({'"': '"', "'": "'", "\\": "\\"})
KEY = re.compile(r"[ \t]*(?:export[ \t]+)?[^=#\s]+[ \t]*=[ \t]*")
# Raw body of a double-quoted value, through its closing quote. A backslash always escapes the next character.
DOUBLE = re.compile(r'([^"\\]*(?:\\.[^"\\]*)*)"', re.S)
SINGLE = re.compile(r"([^']*)'")  # literal body of a single-quoted value, through its closing quote
INLINE_COMMENT = re.compile(r"(?:^|\s)#")


def unescape(raw):
    return re.sub(r"\\(.)", lambda m: ESCAPES.get(m.group(1), m.group(0)), raw, flags=re.S)


def unquoted(text):
    return INLINE_COMMENT.split(text, maxsplit=1)[0].strip()


def next_line(text, pos):
    eol = text.find("\n", pos)
    return len(text) if eol == -1 else eol + 1


def env_pairs(text):
    """Return (decoded, raw) for each assignment; raw differs from decoded only for double-quoted values."""
    pairs = []
    pos, end = 0, len(text)
    while pos < end:
        eol = text.find("\n", pos)
        eol = end if eol == -1 else eol
        key = KEY.match(text, pos, eol)
        if key is None:  # blank, comment or other line without an assignment
            pos = eol + 1
            continue
        start = key.end()
        opener = text[start : start + 1]
        if opener == '"':
            body = DOUBLE.match(text, start + 1)
            if body:
                pairs.append((unescape(body.group(1)), body.group(1)))
                pos = next_line(text, body.end())
                continue
        elif opener == "'":
            body = SINGLE.match(text, start + 1)
            if body:
                pairs.append((body.group(1), body.group(1)))
                pos = next_line(text, body.end())
                continue
        # Unquoted, or a quote with no closing quote (python-dotenv then reads the rest of the line).
        value = unquoted(text[start:eol])
        pairs.append((value, value))
        if value[:1] in ('"', "'"):
            pairs.append((value[1:], value[1:]))
        pos = eol + 1
    return pairs


def needles(pairs):
    found = set()
    for decoded, raw in pairs:
        if len(decoded) < MIN_LEN:
            continue
        for form in {decoded, raw}:
            for codec in ("utf-8", "utf-16-le", "utf-16-be"):
                found.add(form.encode(codec))
    return found


def check(argv):
    p = argparse.ArgumentParser(description="Report which files contain a literal value from an env file.")
    p.add_argument("--env", required=True, help="env file with KEY=VALUE lines")
    p.add_argument("files", nargs="+", help="files to check")
    a = p.parse_args(argv)
    try:
        with open(a.env, encoding="utf-8-sig") as fh:
            text = fh.read()
    except FileNotFoundError:
        print("leakcheck: env file not found", file=sys.stderr)
        return 2
    except (OSError, UnicodeDecodeError):
        print("leakcheck: cannot read env file", file=sys.stderr)
        return 2
    values = needles(env_pairs(text))
    if not values:
        print("leakcheck: no values to check", file=sys.stderr)
        return 2
    leaks, unreadable = [], []
    for name in a.files:
        try:
            with open(name, "rb") as fh:
                data = fh.read()
        except OSError:
            unreadable.append(name)
            continue
        if any(v in data for v in values):
            leaks.append(name)
    for name in leaks:
        print(name)
    for name in unreadable:
        print("leakcheck: cannot read " + name, file=sys.stderr)
    if unreadable:
        return 2
    return 1 if leaks else 0


def main(argv=None):
    try:
        return check(argv)
    except Exception:  # generic message only: exception text could echo a value
        print("leakcheck: internal error; the check did not finish", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
