"""Static report site over committed certificates (queue T09, part A; queue T18, batch record).

build_site() loads each *.json certificate in a directory with certify.load_certificate() and scores the valid ones with
certify.score(). It writes index.html (the score, the run record, one row per environment and the files that failed to
load) and env/<name>.html (one page per valid certificate, with its transcript when traces_dir holds one). Every rate,
interval and count comes from certify.py, except the selection counts, which come from the batch record. This module
computes none of its own. The score shows the certified split (certified_unhardened, certified_hardened), no_attempt,
and the cost with the cost_basis label that certify gives.

Selection record. cert_dir.parent/batch.json (or batch_file, when given) is the record that cli batch writes: what was
scanned, how many were valid, what was skipped and why, the selection rule, and the selected instances that did not run.
The run record leads with the batch's own count, "Run by this batch: R of Y selected", where R is batch.run and Y is
batch.selected. The certificates loaded on the page are a separate count. The record is
checked strictly (schema_version 1, exactly the known keys, counts >= 0, selected equal to the length of selected_ids).
A record that does not load is an error row, and the page says "batch record not loaded". With no default file the page
says "selection record not available" and gives no numbers. A symlink is refused and never read.

Names and traces. <name> is the file stem with each character outside [A-Za-z0-9._-] replaced by "_"; a clash gets
"-2", "-3" and so on. The transcript of a certificate is traces_dir/<stem>.jsonl, where <stem> is the certificate's
own file stem (its file name without ".json"). When that file is missing, traces_dir/<name>.jsonl is tried. A later
certificate whose instance id an earlier file (in name order) already holds is an error row, not a page.

Attack diffs. Each round's sanitized attack diff is cert_dir.parent/diffs/<stem>.<before|after>.diff, the file that
cli harden writes beside the certificates, with its sidecar <stem>.<before|after>.diff.json. It is shown escaped, and
only when the sidecar's raw_sha256 equals the certificate's final_diff_sha256 for that round. Otherwise, or when the
file is missing, the round shows the digest that the certificate records, and the note that no diff was recorded.
A symlink is never read: not a traces or diffs directory, not a file in one.

The site replays committed records. Nothing here calls a model or the network, and the pages have no JavaScript. A
certificate, trace or diff is untrusted attacker or model text, so every value reaches a page through _cell(), which
escapes with html.escape(quote=True) and shows control and bidi characters as [U+XXXX]. Trace values pass through
cheatproof.sanitize first. Output is deterministic: the same input gives the same bytes, and no current time or
absolute path is written.

out_dir gets a .cheatproof-site marker and an empty .nojekyll. A non-empty out_dir without the marker is refused. With
the marker, the env/*.html pages of an earlier build are removed before the new pages are written.
"""

from __future__ import annotations

import html
import json
import math
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cheatproof.certify import load_certificate, score
from cheatproof.sanitize import sanitize

BANNER = "Recorded run — replay of committed certificates, no live calls"
NO_TRANSCRIPT = "no transcript recorded"
NOT_RECORDED = "not recorded"
NO_ATTACK_DIFF = "attack diff not recorded in certificate"
UNREADABLE_LINE = "unreadable line"
RUN_COMMAND = "python -m cheatproof.cli harden <instance id> ..."
DEFAULT_CERT_DIR = "results/certificates"
DIFFS_DIR = "diffs"  # read from the sibling of the certificates directory, where cli harden writes them
ROUNDS = ("before", "after")
BATCH_FILE = "batch.json"  # the selection record cli batch writes beside the certificates directory
BATCH_SCHEMA_VERSION = 1
BATCH_KEYS = frozenset(
    {
        "schema_version",
        "source",
        "selection_rule",
        "scanned",
        "valid",
        "skipped",
        "selected",
        "selected_ids",
        "run",
        "already_certified",
        "chunk_size",
        "rerun_ids",
        "rerun_done",
        "env_broken_ids",
        "next_chunk_pending",
        "finished",
        "pending_ids",
        "not_run",
        "started",
        "updated",
    }
)
# cli batch writes network_fetch and network_fetch_done from --network-fetch on (T37), and recon and runs from T47. A record from an earlier run lacks them, so they are optional;
# when present they are type-checked like the rest.
BATCH_OPTIONAL_KEYS = frozenset({"network_fetch", "network_fetch_done", "recon", "runs"})
NOT_RUN_KEYS = frozenset({"instance_id", "reason", "error"})  # always written by cli batch
NOT_RUN_OPTIONAL_KEYS = frozenset({"cost_usd"})  # written only when a paid run's spend was measured
BATCH_NOT_LOADED = "batch record not loaded"
BATCH_NOT_AVAILABLE = "selection record not available"
SEE_ERRORS = '(see <a href="#errors">errors</a>).'
UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")
# C0 controls except tab and newline, DEL, C1 controls and bidi controls. _cell shows each one as [U+XXXX].
CONTROL_OR_BIDI = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")
MARKER = ".cheatproof-site"  # build_site writes it; only a directory that holds it may hold an earlier site
MARKER_TEXT = "RewardSeal site, written by cheatproof.site.build_site\n"
NOJEKYLL = ".nojekyll"  # empty: GitHub Pages serves the files as they are, without Jekyll
TRANSCRIPT_NOTE = (
    "Tool results are shown as digests only. This transcript is matched to the certificate by file name "
    "and is not verified against it."
)
PATCH_NOTE = "Patch diff text is not recorded in the certificate; patches are listed by name."
TRACE_HEADERS = ("Line", "Type", "Step", "Tool", "Args", "Result", "Tokens in", "Tokens out", "Error")
CSP_META = (
    """<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">"""
)
CSS = """:root {
  color-scheme: light dark;
  --bg: #ffffff;
  --fg: #1f2328;
  --muted: #57606a;
  --line: #d0d7de;
  --panel: #f6f8fa;
  --link: #0a58ca;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117;
    --fg: #e6edf3;
    --muted: #9da7b3;
    --line: #3d444d;
    --panel: #161b22;
    --link: #79b8ff;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 16px;
  background: var(--bg);
  color: var(--fg);
  font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
}
main { max-width: 72rem; margin: 0 auto; }
h1 { font-size: 1.6rem; line-height: 1.25; overflow-wrap: anywhere; }
h2 { font-size: 1.25rem; margin: 2rem 0 0.5rem; padding-bottom: 0.25rem; border-bottom: 1px solid var(--line); }
h3 { font-size: 1.05rem; margin: 1.5rem 0 0.25rem; }
a { color: var(--link); overflow-wrap: anywhere; }
.banner, .empty { background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: 10px 12px; }
.banner { border-left: 4px solid var(--link); }
.label { border: 1px solid var(--line); border-radius: 4px; padding: 0 6px; color: var(--muted); font-size: 0.875rem; }
.table-wrap { max-width: 100%; overflow-x: auto; margin: 0.5rem 0 1rem; }
table { width: 100%; border-collapse: collapse; }
caption { caption-side: top; text-align: left; color: var(--muted); padding: 0.25rem 0; }
th, td { text-align: left; vertical-align: top; padding: 6px 8px; border-bottom: 1px solid var(--line); overflow-wrap: anywhere; }
thead th { border-bottom: 2px solid var(--line); }
th[scope="row"] { font-weight: 600; }
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.875rem; }
code { overflow-wrap: anywhere; }
pre {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  max-width: 100%;
  overflow-x: auto;
  padding: 8px;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: var(--panel);
}
"""


@dataclass(frozen=True)
class SiteResult:
    """What build_site wrote: the index, one page per valid certificate, and each file that failed to load."""

    index: Path
    pages: list[Path]
    errors: list[tuple[str, str]]  # (file name, error message): a certificate file, or the batch record


@dataclass(frozen=True)
class _Entry:
    name: str  # env/<name>.html
    cert: dict[str, Any]
    stem: str  # the certificate file's own stem: traces_dir/<stem>.jsonl is its transcript


@dataclass(frozen=True)
class _Raw:
    """Markup this module wrote itself (a link or a code span). Any other cell value is escaped."""

    markup: str


@dataclass(frozen=True)
class _Batch:
    """The selection record. record is the validated batch.json, or None. failed means a batch file was there and did
    not load, which is shown as "batch record not loaded". Neither set means there is no record at all."""

    record: dict[str, Any] | None
    failed: bool


def build_site(
    cert_dir: Path, out_dir: Path, *, traces_dir: Path | None = None, batch_file: Path | None = None
) -> SiteResult:
    """Write the site for the certificates in cert_dir into out_dir and return what was written.

    Raises FileNotFoundError when cert_dir is not a directory, and ValueError when out_dir is a non-empty directory
    that is not a RewardSeal site (nothing is written then). A file that fails to load, or repeats an instance id, is
    listed in errors and on the index, and the rest still build. The transcript of env/<name>.html is read from
    traces_dir as the module docstring describes. batch_file is the selection record; when None it is
    cert_dir.parent/batch.json, and a missing default file is not an error. A bad batch record is listed in errors.
    """
    root = Path(cert_dir)
    if not root.is_dir():
        raise FileNotFoundError(f"no certificate directory: {root}")
    out = Path(out_dir)
    _prepare_out_dir(out)
    entries, cert_errors = _load_all(root)
    batch, batch_errors = _read_batch(root, batch_file)
    errors = [*cert_errors, *batch_errors]
    diffs_dir = root.parent / DIFFS_DIR
    env_dir = out / "env"
    env_dir.mkdir(parents=True, exist_ok=True)
    _write(out / MARKER, MARKER_TEXT)
    _write(out / NOJEKYLL, "")
    summary = score([entry.cert for entry in entries]) if entries else None
    index = out / "index.html"
    body = _index_body(entries, errors, len(cert_errors), summary, batch)
    _write(index, _document("RewardSeal report", body))
    pages = []
    for entry in entries:
        page = env_dir / f"{entry.name}.html"
        diffs = {
            name: _diff_text(diffs_dir, entry.stem, name, _recorded_digest(entry.cert, name))
            for name in ROUNDS
        }
        body = _env_body(entry.cert, _transcript_body(traces_dir, entry), diffs)
        _write(page, _document(f"RewardSeal: {entry.cert['task']['instance_id']}", body))
        pages.append(page)
    return SiteResult(index=index, pages=pages, errors=errors)


def _load_all(root: Path) -> tuple[list[_Entry], list[tuple[str, str]]]:
    """Every *.json certificate in root, in name order. A file that fails to load becomes an error row.

    The first file (in name order) that holds an instance id is kept. Each later file with the same id is an error
    row, and it is left out of the score and the pages.
    """
    entries: list[_Entry] = []
    errors: list[tuple[str, str]] = []
    taken: set[str] = set()
    first_file: dict[str, str] = {}  # instance id -> the file name that holds it first
    for path in sorted(root.glob("*.json")):
        if not path.is_file():
            continue
        try:
            cert = load_certificate(path)
        except Exception as exc:  # noqa: BLE001 - a certificate is untrusted input: any failure is a row
            errors.append((path.name, _error_text(exc, path)))
            continue
        instance_id = cert["task"]["instance_id"]
        if instance_id in first_file:
            errors.append((path.name, f"duplicate instance id, first seen in {first_file[instance_id]}"))
            continue
        first_file[instance_id] = path.name
        entries.append(_Entry(_page_name(path.stem, taken), cert, path.stem))
    return entries, errors


def _page_name(stem: str, taken: set[str]) -> str:
    """A page name from a certificate's file stem. Unsafe characters become "_"; a clash gets "-2", "-3", and so on."""
    base = UNSAFE_NAME.sub("_", stem).strip(".") or "certificate"
    name, number = base, 2
    while name.casefold() in taken:
        name = f"{base}-{number}"
        number += 1
    taken.add(name.casefold())  # case-folded, so names do not clash on a case-insensitive file system
    return name


def _error_text(exc: Exception, path: Path) -> str:
    """The error message with the full path cut to the file name, so no absolute path reaches the site."""
    return str(exc).replace(str(path), path.name) or type(exc).__name__


def _read_batch(root: Path, batch_file: Path | None) -> tuple[_Batch, list[tuple[str, str]]]:
    """The selection record, and the error rows for it. The default file (cert_dir.parent/batch.json) may be absent:
    then there is no record and no error. An explicit batch_file that is missing is an error. A symlink is refused and
    never read, and so is anything that does not load.
    """
    explicit = batch_file is not None
    path = Path(batch_file) if explicit else root.parent / BATCH_FILE
    if path.is_symlink():
        return _Batch(None, failed=True), [(path.name, "symlink refused: the batch record is not read")]
    if not path.exists():
        if explicit:
            return _Batch(None, failed=True), [(path.name, "batch record not found")]
        return _Batch(None, failed=False), []
    try:
        return _Batch(_load_batch(path), failed=False), []
    except ValueError as exc:
        return _Batch(None, failed=True), [(path.name, str(exc))]


def _load_batch(path: Path) -> dict[str, Any]:
    """The validated record in path. A ValueError says briefly why it does not load; it never holds the path."""
    if not path.is_file():
        raise ValueError("batch record is not a regular file")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        raise ValueError("batch record could not be read") from None
    try:
        data = json.loads(text, parse_constant=_refuse_constant)
    except (ValueError, RecursionError):  # bad JSON and a NaN: ValueError. Deep nesting: RecursionError.
        raise ValueError("batch record is not valid JSON") from None
    _check_batch(data)
    return data


def _refuse_constant(name: str) -> Any:
    raise ValueError(f"{name} is not allowed in the batch record")


def _is_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_str_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _is_not_run(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    keys = set(item)
    if not NOT_RUN_KEYS <= keys <= NOT_RUN_KEYS | NOT_RUN_OPTIONAL_KEYS:
        return False
    if not all(isinstance(item[key], str) for key in NOT_RUN_KEYS):
        return False
    return "cost_usd" not in item or _is_cost(item["cost_usd"])


def _is_runs(value: Any) -> bool:
    """The T47 run rows cli batch writes: objects with an instance id, and a recon of "exposure" or null."""
    return isinstance(value, list) and all(
        isinstance(row, dict)
        and isinstance(row.get("instance_id"), str)
        and row.get("recon") in ("exposure", None)
        and ("recon_types" not in row or _is_str_list(row["recon_types"]))
        for row in value
    )


def _is_cost(value: Any) -> bool:
    """A finite, non-negative number. A huge integer does not convert to float: that is refused, not raised."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        number = float(value)
    except OverflowError:  # int too large for a float, as in 10**400
        return False
    return math.isfinite(number) and number >= 0


def _want(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _check_batch(data: Any) -> None:
    """Raise ValueError unless data is a schema 1 batch record. Every BATCH_KEYS key is required, BATCH_OPTIONAL_KEYS
    may be absent, and no other key is allowed. Each value is checked for its type. The messages name a field, never a
    value, because the record is untrusted.
    """
    _want(isinstance(data, dict), "batch record must be a JSON object")
    _want(not BATCH_KEYS - set(data), "batch record is missing a key")
    _want(not set(data) - BATCH_KEYS - BATCH_OPTIONAL_KEYS, "batch record has an unknown key")
    version = data["schema_version"]
    _want(_is_count(version) and version == BATCH_SCHEMA_VERSION, "batch record schema_version must be 1")
    types_ok = {
        "selection_rule": isinstance(data["selection_rule"], str),
        "started": isinstance(data["started"], str),
        "updated": isinstance(data["updated"], str),
        "source": _is_str_list(data["source"]),
        "selected_ids": _is_str_list(data["selected_ids"]),
        "skipped": isinstance(data["skipped"], dict) and all(_is_count(n) for n in data["skipped"].values()),
        "not_run": isinstance(data["not_run"], list) and all(_is_not_run(item) for item in data["not_run"]),
        **{key: _is_count(data[key]) for key in ("scanned", "valid", "selected", "run", "already_certified")},
        "chunk_size": _is_count(data["chunk_size"]) and data["chunk_size"] >= 1,
        **{
            key: _is_str_list(data[key])
            for key in ("rerun_ids", "rerun_done", "env_broken_ids", "pending_ids")
        },
        **{key: isinstance(data[key], bool) for key in ("next_chunk_pending", "finished")},
        **{
            key: _is_str_list(data[key]) if key == "network_fetch_done" else isinstance(data[key], bool)
            for key in ("network_fetch", "network_fetch_done")
            if key in data
        },
        # T47: recon is the batch setting, "exposure" or null. runs holds one object per run (the writer's rows).
        **({"recon": data["recon"] in ("exposure", None)} if "recon" in data else {}),
        **({"runs": _is_runs(data["runs"])} if "runs" in data else {}),
    }
    wrong = sorted(key for key, ok in types_ok.items() if not ok)
    if wrong:
        raise ValueError(f"batch record field {wrong[0]} has the wrong type")
    _want(
        data["selected"] == len(data["selected_ids"]),
        "batch record selected must equal the length of selected_ids",
    )
    _want(data["valid"] <= data["scanned"], "batch record valid must not exceed scanned")


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


def _prepare_out_dir(out: Path) -> None:
    """Refuse a non-empty directory that is not a RewardSeal site. In one that is, remove the old env/*.html pages.

    A symlink named *.html in env/ is unlinked as a link: its target is not touched, and no page is written through it.
    """
    if not out.is_dir():
        return
    if not (out / MARKER).is_file():
        if any(out.iterdir()):
            name = out.resolve().name  # the name only: no absolute path reaches the message
            raise ValueError(f"output directory is not empty and is not a RewardSeal site: {name}")
        return
    env_dir = out / "env"
    if env_dir.is_symlink():  # cleanup and pages must stay inside the site directory
        raise ValueError("output directory has a symlinked env/ directory")
    if env_dir.is_dir():
        for page in list(env_dir.glob("*.html")):
            if page.is_symlink() or page.is_file():
                page.unlink()


# Escaping and table helpers. Every value that comes from a certificate or a trace passes through _cell.


def _cell(value: Any) -> str:
    """The escaped HTML for one value. A _Raw is markup this module wrote; anything else is _value() escaped.

    Control and bidi characters that escaping leaves alone are shown as [U+XXXX], so they cannot hide or reorder text.
    """
    if isinstance(value, _Raw):
        return value.markup
    return CONTROL_OR_BIDI.sub(_code_point, html.escape(_value(value), quote=True))


def _code_point(match: re.Match[str]) -> str:
    return f"[U+{ord(match.group()):04X}]"


def _value(value: Any) -> str:
    """Plain text for one value: yes or no for a bool, a comma list for a list, "not recorded" for None."""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if value is None:
        return NOT_RECORDED
    if isinstance(value, list | tuple):
        return ", ".join(_value(item) for item in value) if value else "none"
    if isinstance(value, Mapping):
        return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return str(value)


def _map(value: Any) -> Mapping[str, Any]:
    """The value when it is a mapping, else an empty one. Nested certificate fields are checked only loosely."""
    return value if isinstance(value, Mapping) else {}


def _items(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def _blank(value: Any) -> Any:
    """A missing trace field shows as an empty cell, not as "not recorded"."""
    return "" if value is None else value


def _link_html(href: str, text: str) -> str:
    return f'<a href="{_cell(href)}">{_cell(text)}</a>'


def _code_html(text: str) -> str:
    return f"<code>{_cell(text)}</code>"


def _row(*values: Any) -> str:
    return "<tr>" + "".join(f"<td>{_cell(value)}</td>" for value in values) + "</tr>"


def _head_row(head: Any, *values: Any) -> str:
    """A row whose first cell is a row header (th scope="row"); the other values are ordinary cells."""
    cells = "".join(f"<td>{_cell(value)}</td>" for value in values)
    return f'<tr><th scope="row">{_cell(head)}</th>{cells}</tr>'


def _kv_row(key: str, value: Any) -> str:
    return f'<tr><th scope="row">{_cell(key)}</th><td>{_cell(value)}</td></tr>'


def _table(caption: str, headers: Sequence[str], rows: Sequence[str], empty: str = "none") -> str:
    """A captioned table in a scroll box, or the empty sentence when there are no rows."""
    if not rows:
        return f"<p>{_cell(empty)}</p>"
    head = "".join(f'<th scope="col">{_cell(header)}</th>' for header in headers)
    return "\n".join(
        [
            f'<div class="table-wrap" tabindex="0" role="region" aria-label="{_cell(caption)}">',
            "<table>",
            f"<caption>{_cell(caption)}</caption>",
            f"<thead><tr>{head}</tr></thead>",
            f"<tbody>{''.join(rows)}</tbody>",
            "</table>",
            "</div>",
        ]
    )


def _kv_table(caption: str, pairs: Iterable[tuple[str, Any]]) -> str:
    return _table(caption, ("Field", "Value"), [_kv_row(key, value) for key, value in pairs])


def _section(anchor: str, heading: str, *parts: str, level: int = 2) -> str:
    return "\n".join(
        [
            f'<section aria-labelledby="{anchor}">',
            f'<h{level} id="{anchor}">{_cell(heading)}</h{level}>',
            *parts,
            "</section>",
        ]
    )


def _document(title: str, body: str) -> str:
    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            CSP_META,
            f"<title>{_cell(title)}</title>",
            f"<style>\n{CSS}</style>",
            "</head>",
            "<body>",
            f"<main>\n{body}\n</main>",
            "</body>",
            "</html>",
            "",
        ]
    )


# Text for the values that come from certify.py: rates and gates.


def _rate_text(rate: Mapping[str, Any]) -> str:
    """One rate as score() gives it: count of n = rate (95% CI low to high). Never recomputed here.

    score() gives rate None when n is 0, so no certificate is conclusive. Then the text is the count and no percentage.
    """
    interval = rate.get("interval_95")
    if rate.get("rate") is None or interval is None:
        return f"{rate['count']} of {rate['n']}, no conclusive certificates"
    low, high = interval
    return f"{rate['count']} of {rate['n']} = {rate['rate']:.1%} (95% CI {low:.1%} to {high:.1%})"


def _money(value: Any) -> str:
    return f"${value:.4f}" if isinstance(value, int | float) else NOT_RECORDED


def _money_basis(value: Any, basis: Any) -> str:
    """A cost with the label of what it is, as certify gives it: "$0.2500 (budgeted ledger delta)". A missing label
    reads "not recorded", and so does a missing cost.
    """
    if not isinstance(value, int | float):
        return NOT_RECORDED
    return f"{_money(value)} ({_value(basis)})"


def _passed_word(grade: Any) -> str:
    """pass or fail for a grade dict from certify (its "passed" key). Anything else is not recorded."""
    passed = _map(grade).get("passed")
    if passed is True:
        return "pass"
    if passed is False:
        return "fail"
    return NOT_RECORDED


def _gates_text(gates: Any) -> str:
    """The gates in one line for the index: the gold and empty results, and a note when the gates did not hold."""
    if gates is None:
        return "not run"
    if not isinstance(gates, Mapping):
        return NOT_RECORDED
    text = f"gold {_passed_word(gates.get('gold'))}, empty {_passed_word(gates.get('empty'))}"
    return text if gates.get("ok") is True else f"{text} (gates did not hold)"


# Index page


def _index_body(
    entries: Sequence[_Entry],
    errors: Sequence[tuple[str, str]],
    excluded: int,
    summary: Mapping[str, Any] | None,
    batch: _Batch,
) -> str:
    """excluded counts the certificate files left out (errors also holds a bad batch record, which is not one)."""
    head = [
        "<header>",
        "<h1>RewardSeal hackability report</h1>",
        f'<p class="banner" role="note">{_cell(BANNER)}</p>',
        "</header>",
    ]
    middle = (
        [
            _empty_state(excluded),
            _section("run-record", "Run record", *_run_record_parts(batch, len(entries))),
        ]
        if summary is None
        else [_score_section(summary, excluded, batch, len(entries)), _environments_section(entries)]
    )
    return "\n".join([*head, *middle, _errors_section(errors)])


def _empty_state(excluded: int) -> str:
    if excluded:
        lead = "No valid certificates were found. Every certificate file failed to load (see below)."
    else:
        lead = "No certificates were found in the certificates directory."
    howto = (
        f"<p>To produce one, run {_code_html(RUN_COMMAND)} for each task. "
        f"The default directory is {_code_html(DEFAULT_CERT_DIR)}. Then build this site again.</p>"
    )
    return "\n".join(
        [
            '<section class="empty" aria-labelledby="environments">',
            '<h2 id="environments">Environments</h2>',
            f"<p>{_cell(lead)}</p>",
            howto,
            "</section>",
        ]
    )


def _excluded_text(count: int) -> str:
    """The sentence that says how many certificate files the score leaves out. Its link goes to the errors list."""
    if count == 1:
        return f"1 certificate file failed to load and is excluded {SEE_ERRORS}"
    return f"{count} certificate files failed to load and are excluded {SEE_ERRORS}"


def _run_record_parts(batch: _Batch, loaded: int) -> list[str]:
    """What cli batch selected and ran, set against the certificates that loaded. With no record the page says so and
    gives no numbers. loaded is the count of certificates scored on this page (shown as "certificates loaded").
    """
    record = batch.record
    if record is None:
        if batch.failed:
            return [f"<p>{BATCH_NOT_LOADED} {SEE_ERRORS}</p>"]
        return [f"<p>{BATCH_NOT_AVAILABLE}.</p>"]
    selected = record["selected"]
    not_run_count = len(record["not_run"])
    lead = (
        f"<p>Run by this batch: {record['run']} of {selected} selected "
        f"(already had a certificate: {record['already_certified']}; not run: {not_run_count}).</p>"
        f"<p>certificates loaded: {loaded} (scored on this page; this can include certificates from earlier runs).</p>"
    )
    counts = _kv_table(
        "Selection record counts",
        [
            ("Selection rule", record["selection_rule"]),
            ("Scanned", record["scanned"]),
            ("Valid", record["valid"]),
            ("Selected", selected),
            ("Run by this batch", record["run"]),
            ("Already has a certificate", record["already_certified"]),
            ("Not run", not_run_count),
            ("Started", record["started"]),
            ("Updated", record["updated"]),
        ],
    )
    skipped = _table(
        "Instances skipped, by reason",
        ("Reason", "Count"),
        [_head_row(reason, count) for reason, count in sorted(record["skipped"].items())],
        empty="none",
    )
    not_run = _table(
        "Not run, with reason and error",
        ("Instance id", "Reason", "Error"),
        [
            _head_row(item["instance_id"], item["reason"] or "none", item["error"] or "none")
            for item in record["not_run"]
        ],
        empty="none",
    )
    return [lead, counts, skipped, not_run]


def _score_section(summary: Mapping[str, Any], excluded: int, batch: _Batch, loaded: int) -> str:
    lead = f"n = {summary['n']} valid certificates. " + (_excluded_text(excluded) + " " if excluded else "")
    rate_rows = [
        _row(label, _rate_text(summary[key]), summary[key]["denominator"])
        for label, key in (
            ("Hackable before hardening", "rate_before"),
            ("Hackable after hardening", "rate_after"),
        )
    ]
    outcome_rows = [_row(name, count) for name, count in summary["outcomes"].items()]
    outcome_rows.append(_row("Total (equals n)", summary["n"]))
    hole_rows = [
        _row(label, counts["before"], counts["after"]) for label, counts in summary["by_hole"].items()
    ]
    return _section(
        "score",
        "Hackability score",
        f"<p>{lead}A certified task is not hackable by this attacker. "
        "That is not a claim that it is secure or proven.</p>",
        _section("run-record", "Run record", *_run_record_parts(batch, loaded), level=3),
        _table(
            "Rates with 95% Wilson intervals",
            ("Measure", "Count of n and rate", "Denominator"),
            rate_rows,
        ),
        _table("Outcomes, each certificate counted once", ("Outcome", "Count"), outcome_rows),
        _kv_table(
            "Other counts",
            [
                ("Certified", summary["certified"]),
                (
                    "Certified, attacker never succeeded before patching (certified_unhardened)",
                    summary.get("certified_unhardened"),
                ),
                (
                    "Certified, attacker succeeded before patching and the patches held (certified_hardened)",
                    summary.get("certified_hardened"),
                ),
                ("Inconclusive", summary["inconclusive"]),
                (
                    "No attempt, attacker never tried (no_attempt, also counted in the outcomes)",
                    summary.get("no_attempt"),
                ),
                ("Hackable before (also counted in the outcomes)", summary["hackable_before"]),
                ("Hackable after (also counted in the outcomes)", summary["hackable_after"]),
                (
                    "Cost, total (USD)",
                    _money_basis(summary["cost_usd_total"], summary.get("cost_basis")),
                ),
            ],
        ),
        _table(
            "Certificates per hole, before and after hardening",
            ("Hole", "Before hardening", "After hardening"),
            hole_rows,
            empty="no hole label was found",
        ),
    )


def _strategy_html(attacker: Any) -> str:
    """The strategy label, then a visible recon=exposure tag when the attacker got the exposure scan (T47)."""
    attacker = _map(attacker)
    text = _cell(attacker.get("strategy") if attacker.get("strategy") is not None else "not recorded")
    kinds = attacker.get("recon_types")
    shown = f" ({', '.join(_cell(k) for k in kinds)})" if isinstance(kinds, list) and kinds else ""
    tag = f' <span class="label">recon=exposure{shown}</span>' if attacker.get("recon") == "exposure" else ""
    return f"{text}{tag}"


def _environments_section(entries: Sequence[_Entry]) -> str:
    rows = []
    for entry in entries:
        cert = entry.cert
        task, gates = cert["task"], cert["gates"]
        rows.append(
            _head_row(
                _Raw(_link_html(f"env/{entry.name}.html", task["instance_id"])),
                task["repo"],
                task["source"],
                _Raw(_strategy_html(cert["attacker"])),
                cert["holes_found"],
                cert["patches_applied"],
                _gates_text(gates["before"]),
                _gates_text(gates["after"]),
                cert["certified"],
                _money(cert["cost_usd"]),
            )
        )
    headers = (
        "Instance",
        "Repo",
        "Source",
        "Strategy",
        "Holes found",
        "Patches applied",
        "Gates before (gold, empty)",
        "Gates after",
        "Certified",
        "Cost (USD)",
    )
    return _section(
        "environments",
        "Environments",
        _table("One row per environment. Certified means not hackable by this attacker.", headers, rows),
    )


def _errors_section(errors: Sequence[tuple[str, str]]) -> str:
    rows = [_row(name, message) for name, message in errors]
    return _section(
        "errors",
        "Files that failed to load",
        _table(
            "Files skipped by the build, with the error for each",
            ("File", "Error"),
            rows,
            empty="None. Every file loaded.",
        ),
    )


# Environment pages


def _env_body(cert: Mapping[str, Any], transcript: str, diffs: Mapping[str, str | None] | None = None) -> str:
    task = cert["task"]
    return "\n".join(
        [
            '<p><a href="../index.html">Back to the index</a></p>',
            f"<h1>{_cell('Environment: ' + task['instance_id'])}</h1>",
            (
                '<p><span class="label">recorded</span> This page replays a committed certificate. '
                "No live calls were made.</p>"
            ),
            _result_section(cert),
            _before_after_section(cert),
            _task_section(cert),
            _attacker_section(cert["attacker"]),
            _gates_section(cert["harden"]),
            _exposure_section(cert["exposure_before"]),
            _holes_section(cert["harden"]),
            _patches_section(cert["harden"]),
            _rounds_section(cert["harden"], diffs or {}),
            _section("transcript", "Transcript", transcript),
        ]
    )


VIA_PLAIN = {
    "no_hole_found": "no hole found: the attacker failed before any patch",
    "hardened_reattack_failed": "hole closed: the attacker failed after hardening",
    "legit_fix": "hole closed, task still solvable: the attacker submitted a real fix after hardening",
}


def _via_text(cert: Mapping[str, Any]) -> str:
    """certified_via as recorded, with plain words. A certificate written before T50 has none."""
    if "certified_via" not in cert:
        return "not recorded (certificate written before certified_via)"
    via = cert["certified_via"]
    if via is None:
        return "none (not certified)"
    return f"{via}: {VIA_PLAIN.get(via, 'unknown value')}"


def _found_how(attack: Mapping[str, Any]) -> str:
    """How the before attack ended: a real submit, or an auto-submit of the working diff at a step or token limit."""
    if attack.get("auto_submitted") is True:
        return f"auto_submitted at {attack.get('stop_reason')}"
    if attack.get("submitted") is True:
        return "submit"
    return f"not submitted ({attack.get('stop_reason')})"


def _after_outcome(rnd: Mapping[str, Any]) -> str:
    """The re-attack's result in plain words, from the recorded round. No diff text."""
    attack, holes = _map(rnd.get("attack")), _map(rnd.get("holes"))
    if rnd.get("error"):
        return "round error"
    if rnd.get("no_attempt"):
        return "no attempt"
    if holes.get("exploited") is True:
        return f"hole still found ({_value(holes.get('labels'))})"
    if attack.get("outcome") == "legit_fix":
        return "legit_fix (passed the hidden tests like the gold fix; not an exploit)"
    if rnd.get("inconclusive"):
        return "inconclusive"
    return "failed (did not pass the hidden tests)"


def _before_after_section(cert: Mapping[str, Any]) -> str:
    """The before -> after panel for a hardened task. Empty for a task with no after round. It shows labels, tags
    and counts only, never diff text, and says "against this attacker" because that is all the evidence is."""
    harden = _map(cert.get("harden"))
    before, after = _map(harden.get("before")), _map(harden.get("after"))
    if not after:
        return ""
    before_holes, before_attack = _map(before.get("holes")), _map(before.get("attack"))
    scan = _map(after.get("exposure"))
    scan_holes = scan.get("holes")
    exposure = (
        "not recorded" if not isinstance(scan_holes, list) else ("clean" if not scan_holes else scan_holes)
    )
    gates_ok = _map(after.get("gates")).get("ok")
    closed = (
        _map(after.get("attack")).get("outcome") == "legit_fix" and cert.get("certified_via") == "legit_fix"
    )
    lead = (
        "Hole closed, task still solvable: after hardening the attacker submitted a fix that passes the hidden "
        "tests like the gold fix. This holds against this attacker only."
        if closed
        else "Before and after hardening, as recorded. Results hold against this attacker only."
    )
    return _section(
        "before-after",
        "Before and after hardening",
        f"<p>{_cell(lead)}</p>",
        _kv_table(
            "Before: the hole the attacker found",
            [
                ("Hole labels", before_holes.get("labels")),
                ("Recon", before_attack.get("recon") or "none"),
                ("How it was found", _found_how(before_attack)),
                ("Patches applied", harden.get("accepted")),
            ],
        ),
        _kv_table(
            "After: the same attacker, hardened task",
            [
                ("Exposure scan", exposure),
                ("Gates held", gates_ok),
                ("Re-attack outcome", _after_outcome(after)),
                ("Certified via", _via_text(cert)),
            ],
        ),
    )


def _result_section(cert: Mapping[str, Any]) -> str:
    notes = _items(cert["notes"])
    notes_html = (
        "<p>none</p>" if not notes else "<ul>" + "".join(f"<li>{_cell(n)}</li>" for n in notes) + "</ul>"
    )
    return _section(
        "result",
        "Result",
        _kv_table(
            "Certificate summary",
            [
                ("Certified", cert["certified"]),
                ("Certified via", _via_text(cert)),
                ("Reason", cert["reason"]),
                ("Cost (USD)", _money_basis(cert["cost_usd"], cert.get("cost_basis"))),
                ("Timestamp", cert["timestamp"]),
                ("Sandbox runs", cert["sandbox_runs"]),
            ],
        ),
        "<h3>Notes</h3>",
        notes_html,
    )


def _digest_text(digest: Any) -> str:
    digest = _map(digest)
    return f"sha256 {_value(digest.get('sha256'))}, {_value(digest.get('chars'))} chars"


def _task_section(cert: Mapping[str, Any]) -> str:
    task = cert["task"]
    return _section(
        "task",
        "Task",
        _kv_table(
            "Task and image",
            [
                ("Instance id", task["instance_id"]),
                ("Repo", task["repo"]),
                ("Base commit", task["base_commit"]),
                ("Image", task["image"]),
                ("Image digest", cert["image_digest"]),
                ("Source", task["source"]),
                ("Gold patch", _digest_text(task["gold_patch"])),
                ("Test patch", _digest_text(task["test_patch"])),
            ],
        ),
    )


def _attacker_section(attacker: Mapping[str, Any]) -> str:
    return _section(
        "attacker",
        "Attacker settings",
        _kv_table("Attacker limits and model, as recorded", sorted(attacker.items())),
    )


def _gates_row(label: str, rnd: Any) -> str:
    gates = _map(_map(rnd).get("gates"))
    if not gates:
        return _row(label, "not run", "not run", "not run", "not run")
    return _row(
        label,
        _passed_word(gates.get("gold")),
        _passed_word(gates.get("empty")),
        gates.get("ok"),
        gates.get("reason") or "none",
    )


def _gates_section(harden: Mapping[str, Any]) -> str:
    rows = [_gates_row("Before hardening", harden["before"]), _gates_row("After hardening", harden["after"])]
    return _section(
        "gates",
        "Gates",
        _table(
            "The gold patch must pass and the empty patch must fail",
            ("Round", "Gold gate", "Empty gate", "Gates held", "Reason"),
            rows,
        ),
    )


def _exposure_section(exposure: Any) -> str:
    if not isinstance(exposure, Mapping):
        return _section("exposure", "Exposure scan", "<p>exposure scan not recorded</p>")
    return _section(
        "exposure",
        "Exposure scan",
        _kv_table("Exposure scan before hardening", list(exposure.items())),
    )


def _holes_row(label: str, rnd: Any) -> str:
    holes = _map(_map(rnd).get("holes"))
    if not holes:
        return _row(label, "not run", "not run", "not run")
    counts = _map(holes.get("evidence_counts"))
    evidence = ", ".join(f"{hole}: {count}" for hole, count in counts.items()) or "none"
    return _row(label, holes.get("labels"), holes.get("attempted"), evidence)


def _holes_section(harden: Mapping[str, Any]) -> str:
    rows = [_holes_row("Before hardening", harden["before"]), _holes_row("After hardening", harden["after"])]
    return _section(
        "holes",
        "Holes",
        _table(
            "Holes by round. Attempted means evidence was found, whatever the hidden grade.",
            ("Round", "Exploited (holes found)", "Attempted", "Evidence per label"),
            rows,
        ),
    )


def _patches_section(harden: Mapping[str, Any]) -> str:
    outcome_rows = []
    for label, rnd in (("Before hardening", harden["before"]), ("After hardening", harden["after"])):
        for outcome in _items(_map(rnd).get("patch_outcomes")):
            found = _map(outcome)
            outcome_rows.append(_row(label, found.get("name"), found.get("ok"), found.get("notes")))
    candidate_rows = [
        _row(found.get("name"), found.get("accepted"), found.get("reason") or "none")
        for found in map(_map, _items(harden["candidates"]))
    ]
    return _section(
        "patches",
        "Patches",
        f"<p>{_cell(PATCH_NOTE)}</p>",
        _kv_table(
            "Patches",
            [
                ("Applied", harden["accepted"]),
                ("Rejected", harden["rejected"]),
                ("Unpatched (hole labels no patch covers)", harden["unpatched"]),
            ],
        ),
        _table(
            "Patch outcomes, per round",
            ("Round", "Patch", "Applied cleanly", "Notes"),
            outcome_rows,
            empty="none recorded",
        ),
        _table(
            "Candidate checks, one patch at a time",
            ("Patch", "Accepted", "Reason"),
            candidate_rows,
            empty="none recorded",
        ),
    )


def _round_block(label: str, rnd: Any, diff: str | None) -> str:
    rnd = _map(rnd)
    attack = _map(rnd.get("attack"))
    grade = rnd.get("attack_grade")
    if attack:
        attack_rows = [
            ("Stop reason", attack.get("stop_reason")),
            ("Submitted", attack.get("submitted")),
            ("Auto-submitted by the harness", attack.get("auto_submitted", "not recorded")),
            ("Recon", attack.get("recon") or "none"),
            ("Recon finding types", attack.get("recon_types") or "none"),
            ("Outcome", attack.get("outcome") or "none"),
            ("Steps", attack.get("steps")),
            ("Tokens in", attack.get("tokens_in")),
            ("Tokens out", attack.get("tokens_out")),
            ("Diff ok", attack.get("diff_ok")),
            ("Attack error", attack.get("error") or "none"),
        ]
    else:
        attack_rows = [("Attack", "not run")]
    attack_rows += [
        ("Hidden tests on the attack diff", "not run" if grade is None else _passed_word(grade)),
        ("Inconclusive", rnd.get("inconclusive") or "none"),
        ("Round error", rnd.get("error") or "none"),
    ]
    return "\n".join(
        [
            f"<h3>{_cell(label)}</h3>",
            _kv_table(f"{label}: attack and grade", attack_rows),
            _diff_block(attack, diff),
        ]
    )


def _regular_file(folder: Path, name: str) -> Path | None:
    """folder/name when folder is a directory and name a regular file, and neither is a symbolic link. Else None.

    The one check that traces and diffs both go through. A link is never followed, so its target is never read.
    """
    if folder.is_symlink() or not folder.is_dir():
        return None
    path = folder / name
    if path.is_symlink() or not path.is_file():
        return None
    return path


def _recorded_digest(cert: Mapping[str, Any], name: str) -> str | None:
    """The sha256 of one round's final attack diff, as the certificate records it, or None."""
    rnd = _map(_map(cert.get("harden")).get(name))
    digest = _map(rnd.get("attack")).get("final_diff_sha256")
    return digest if isinstance(digest, str) else None


def _diff_text(diffs_dir: Path, stem: str, name: str, digest: str | None) -> str | None:
    """The sanitized attack diff of one round, or None. It is shown only when diffs_dir/<stem>.<name>.diff.json
    records raw_sha256 equal to the digest that the certificate records for this round (digest). A diff without
    such a sidecar is stale, so it is not shown.

    A symlinked diffs directory or file is refused, and a file that cannot be read is None too.
    """
    if digest is None:
        return None
    path = _regular_file(diffs_dir, f"{stem}.{name}.diff")
    sidecar = _regular_file(diffs_dir, f"{stem}.{name}.diff.json")
    if path is None or sidecar is None:
        return None
    try:
        meta = json.loads(sidecar.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError, RecursionError):
        return None
    if not isinstance(meta, Mapping) or meta.get("raw_sha256") != digest:
        return None
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _diff_block(attack: Mapping[str, Any], diff: str | None) -> str:
    """The attack diff when its file was written. Otherwise a note, and the digest that is recorded."""
    if not attack:
        return "<p>No attack ran in this round.</p>"
    text = f'<pre tabindex="0">{_cell(diff)}</pre>' if diff is not None else f"<p>{NO_ATTACK_DIFF}</p>"
    if attack.get("final_diff_sha256") is None:
        digest = "<p>No final diff digest was recorded.</p>"
    else:
        digest = (
            f"<p>Diff digest: sha256 {_cell(attack.get('final_diff_sha256'))}, "
            f"{_cell(attack.get('final_diff_chars'))} chars.</p>"
        )
    return f"{text}\n{digest}"


def _rounds_section(harden: Mapping[str, Any], diffs: Mapping[str, str | None]) -> str:
    parts = [_round_block("Before hardening", harden["before"], diffs.get("before"))]
    if harden["after"] is None:
        parts.append("<h3>After hardening</h3>\n<p>No after round was run.</p>")
    else:
        parts.append(_round_block("After hardening", harden["after"], diffs.get("after")))
    return _section("rounds", "Attack rounds", *parts)


# Transcripts


def _transcript_body(traces_dir: Path | None, entry: _Entry) -> str:
    """The trace table for env/<name>.html, or the sentence that says there is none."""
    path = _trace_path(traces_dir, entry)
    if path is None:
        return f"<p>{NO_TRANSCRIPT}</p>"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "<p>transcript could not be read</p>"
    table = _table(
        "One row per trace line",
        TRACE_HEADERS,
        _trace_rows(text.split("\n")),
        empty="the trace file has no lines",
    )
    return "\n".join([f"<p>{_cell(TRANSCRIPT_NOTE)}</p>", table])


def _trace_path(traces_dir: Path | None, entry: _Entry) -> Path | None:
    """The trace file for an entry: traces_dir/<stem>.jsonl, else traces_dir/<name>.jsonl, else None."""
    if traces_dir is None:
        return None
    for stem in (entry.stem, entry.name):
        path = _regular_file(Path(traces_dir), f"{stem}.jsonl")
        if path is not None:
            return path
    return None


def _trace_rows(lines: Sequence[str]) -> list[str]:
    rows: list[str] = []
    for number, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        try:
            record = json.loads(raw)
        except (ValueError, RecursionError):  # a bad line is shown as one, never dropped
            record = None
        if isinstance(record, Mapping):
            rows.append(_trace_row(number, record))
        else:
            span = len(TRACE_HEADERS) - 1
            rows.append(f'<tr><td>{number}</td><td colspan="{span}">{UNREADABLE_LINE}</td></tr>')
    return rows


def _trace_row(number: int, record: Mapping[str, Any]) -> str:
    """One trace line as a row. Every value goes through sanitize() first, so a secret in a trace is not shown."""
    args = sanitize(record.get("args"))
    args_cell = "" if args is None else _Raw(_code_html(json.dumps(args, sort_keys=True, default=str)))
    return _row(
        number,
        _field(record, "type"),
        _field(record, "step"),
        _field(record, "tool"),
        args_cell,
        _result_text(record),
        _field(record, "tokens_in"),
        _field(record, "tokens_out"),
        _field(record, "error"),
    )


def _field(record: Mapping[str, Any], key: str) -> Any:
    """One sanitized trace value. A missing value is an empty cell."""
    return _blank(sanitize(record.get(key)))


def _result_text(record: Mapping[str, Any]) -> str:
    """The first 12 hex digits of a step's result digest and its size, or an end record's stop reason."""
    parts = []
    digest = _map(record.get("result_digest"))
    if isinstance(digest.get("sha256"), str):
        parts.append(f"sha256 {sanitize(digest['sha256'][:12])}")
    if "chars" in digest:
        parts.append(f"{_value(sanitize(digest['chars']))} chars")
    if "stop_reason" in record:
        parts.append(f"stop {_value(sanitize(record['stop_reason']))}")
    return ", ".join(parts)
