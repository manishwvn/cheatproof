"""Static report site over committed certificates (queue T09, part A; queue T18, batch record).

build_site() loads each *.json certificate in a directory with certify.load_certificate() and scores the valid ones with
certify.score(). It writes index.html (the score, the run record, one row per environment and the files that failed to
load) and env/<name>.html (one page per valid certificate, with its transcript when traces_dir holds one). Rates,
intervals and attack counts come from certify.py and confirm.py; audit counts come from audit.exposure_summary.
This module reconciles selection ids and certificate files. The score shows the certified split
(certified_unhardened, certified_hardened), no_attempt, and the cost with the cost_basis label that certify gives.

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

The site replays committed records. Nothing here calls a model or the network. Only the explorer uses an external
script for optional filtering; every other page has no JavaScript. A
certificate, trace or diff is untrusted attacker or model text, so every value reaches a page through _cell(), which
escapes with html.escape(quote=True) and shows control and bidi characters as [U+XXXX]. Trace values pass through
rewardseal.sanitize first. Output is deterministic: the same input gives the same bytes, and no current time or
absolute path is written.

out_dir gets a .rewardseal-site marker and an empty .nojekyll. A non-empty out_dir without the marker is refused. With
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

from rewardseal import confirm
from rewardseal.certify import load_certificate, score
from rewardseal.sanitize import sanitize

BANNER = "Recorded run — replay of committed certificates, no live calls"
NO_TRANSCRIPT = (
    "No transcript is committed on this site. For the one confirmed case the recorded commands of steps 12 to 15 "
    "are in the evidence file."
)
NOT_RECORDED = "not recorded"
NO_ATTACK_DIFF = "attack diff not recorded in certificate"
UNREADABLE_LINE = "unreadable line"
RUN_COMMAND = "python -m rewardseal.cli harden <instance id> ..."
DEFAULT_CERT_DIR = "results/certificates"
GITHUB_BLOB = "https://github.com/manishwvn/rewardseal/blob/main/"
# Evidence files committed beside the certificates: task id -> path in the repo.
EVIDENCE_FILES = {"CycloneDX__cyclonedx-python-348": "results/evidence/348-causal.md"}
NOT_RELEASE_APPROVED = "Certified is not release-approved; same-recon re-attack not exercised."
CERTIFIED_MEANING = (
    "Certified (k=1) = one completed attack failed under the recorded conditions, with exposure removed, "
    "gold pass and empty fail checked by code."
)
LEGACY_CAVEAT = (
    "This describes the hardened 348 result. The three legacy certificates record a failed initial attack "
    "with no hole found; they do not record exposure removal or a hardened re-attack."
)
LEAD_REASON_NOTE = (
    "the reason text above is the recorded classifier output. Manual review (see Hole status) found the only "
    "matching write came before the history reads, so history use stays an unconfirmed lead, not a confirmed cause."
)
REPLICATION_NOTE_348 = (
    "The site's replication line counts only runs that finished a judged before attack under the T54 rule; the four "
    "T55 replication runs are excluded as unfinished or inconclusive, so it reads 0/3. Across the 9 committed Super "
    "before-rounds through T55 (docs/results.md, Audited 348 before-rounds), the history-use pattern appeared in 1 of 9 "
    "(1 of 7 excluding 2 HTTP 503 errors); the other 8 show no further confirmation. The uncommitted chunk 2 run "
    "and earlier 348 attacks are excluded. Use is inferred; follow-up is unequal, not a rate. Including the null "
    "replay1 gives 1 of 10 committed rounds (1 of 8 excluding the same 2 errors)."
)
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
MARKER = ".rewardseal-site"  # build_site writes it; only a directory that holds it may hold an earlier site
MARKER_TEXT = "RewardSeal site, written by rewardseal.site.build_site\n"
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
.headline { font-size: 2rem; font-weight: 700; line-height: 1.2; margin: 0.25rem 0; }
.exposure-audit.lead { font-size: 1.05rem; font-weight: 500; line-height: 1.45; margin: 0.25rem 0 1rem; }
.finding-label { margin: 1rem 0 0; font-weight: 600; }
.label { border: 1px solid var(--line); border-radius: 4px; padding: 0 6px; color: var(--muted); font-size: 0.875rem; }
.path { padding-left: 1.2rem; }
.path li { margin: 0.35rem 0; }
details pre { max-height: 24rem; overflow: auto; }
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
    cert_dir: Path,
    out_dir: Path,
    *,
    traces_dir: Path | None = None,
    batch_file: Path | None = None,
    confirmations_file: Path | None = None,
    replications_dir: Path | None = None,
    exposure_dir: Path | None = None,
) -> SiteResult:
    """Write the site for the certificates in cert_dir into out_dir and return what was written.

    Raises FileNotFoundError when cert_dir is not a directory, and ValueError when out_dir is a non-empty directory
    that is not a RewardSeal site (nothing is written then), or when the confirmations manifest is not valid
    (confirm.ConfirmationError is a ValueError; nothing is written then either). A file that fails to load, or repeats
    an instance id, is listed in errors and on the index, and the rest still build. The transcript of env/<name>.html is
    read from traces_dir as the module docstring describes. batch_file is the selection record; when None it is
    cert_dir.parent/batch.json, and a missing default file is not an error. A bad batch record is listed in errors.
    confirmations_file is the manual-check manifest (default cert_dir.parent/confirmations.json; a missing default is
    an empty manifest, a missing explicit file is refused). replications_dir defaults to cert_dir.parent/replications;
    a refused replication file is listed in errors and no replication number is shown. exposure_dir (T57) defaults to
    cert_dir.parent/exposure: the audit records behind the hero block's exposure paragraph; without any, the paragraph
    falls back to the certificates and says so; a malformed record is listed in errors and no number is shown.
    """
    root = Path(cert_dir)
    if not root.is_dir():
        raise FileNotFoundError(f"no certificate directory: {root}")
    manifest_path = (
        Path(confirmations_file)
        if confirmations_file is not None
        else root.parent / confirm.CONFIRMATIONS_FILE
    )
    if confirmations_file is not None and not manifest_path.exists():
        raise confirm.ConfirmationError(f"{manifest_path.name}: confirmations file not found")
    replications_path = (
        Path(replications_dir) if replications_dir is not None else root.parent / confirm.REPLICATIONS_DIR
    )
    manifest = confirm.load_manifest(manifest_path, replications_path)
    out = Path(out_dir)
    _prepare_out_dir(out)
    entries, cert_errors = _load_all(root)
    batch, batch_errors = _read_batch(root, batch_file)
    replications = confirm.load_replications(replications_path)
    errors = [*cert_errors, *batch_errors, *[(f"replications/{n}", m) for n, m in replications.problems]]
    exposure_summary = _exposure_summary(
        root, Path(exposure_dir) if exposure_dir is not None else root.parent / "exposure", errors
    )
    exposure_path = Path(exposure_dir) if exposure_dir is not None else root.parent / "exposure"
    try:
        blob = _blob_base(root.parent)
    except ValueError as exc:
        errors.append(("PINNED_SHA", str(exc)))
        blob = GITHUB_BLOB
    reconciliation = _reconciliation(entries, batch, exposure_path)
    sample = _second_audit(root, errors)
    diffs_dir = root.parent / DIFFS_DIR
    env_dir = out / "env"
    env_dir.mkdir(parents=True, exist_ok=True)
    _write(out / MARKER, MARKER_TEXT)
    _write(out / NOJEKYLL, "")
    summary = score([entry.cert for entry in entries]) if entries else None
    certs = [entry.cert for entry in entries]
    confirmation = confirm.summarize(certs, manifest) if entries else None
    statuses = {c["task"]["instance_id"]: confirm.hole_status(c, manifest) for c in certs}
    index = out / "index.html"
    from rewardseal import site_extras

    site_extras.write_pages(root.parent, out, entries, errors, blob, exposure_path, manifest)
    body = _index_body(
        entries,
        errors,
        len(cert_errors),
        summary,
        batch,
        confirmation,
        manifest,
        replications,
        statuses,
        exposure_summary,
        _start_here(entries, root.parent / "evidence", blob),
        _numbers_key(confirmation, exposure_summary, replications, manifest, sample),
        reconciliation,
        blob,
        _web_exposure_section(
            root.parent / "web-exposure",
            Path(exposure_dir) if exposure_dir is not None else root.parent / "exposure",
            errors,
        ),
    )
    _write(index, _document("Recorded attack-check report | RewardSeal", body, blob, csp=""))
    _write(
        out / "verify.html",
        _document(
            "Evidence verifier",
            '<p><a href="index.html">Back to the index</a></p><h1>Evidence verifier</h1>'
            "<p>The browser verifier is added by the Pages workflow, next to manifest.json. In a local build this is a "
            "placeholder: open docs/verify/index.html from the repository, or run "
            "<code>python -m rewardseal.manifest verify</code>.</p>"
            f'<p><a href="{_cell(blob)}docs/verify/index.html">docs/verify/index.html on GitHub</a></p>',
            blob,
        ),
    )
    pages = []
    not_exercised = site_extras.not_exercised_ids(root.parent)
    for entry in entries:
        page = env_dir / f"{entry.name}.html"
        diffs = {
            name: _diff_text(diffs_dir, entry.stem, name, _recorded_digest(entry.cert, name))
            for name in ROUNDS
        }
        body = _env_body(
            entry.cert,
            _transcript_body(traces_dir, entry),
            diffs,
            statuses[entry.cert["task"]["instance_id"]],
            entry.stem,
            blob,
            entry.cert["task"]["instance_id"] in not_exercised,
        )
        body += site_extras.environment_change(entry.cert, root.parent / "evidence")
        _write(page, _document(f"RewardSeal: {entry.cert['task']['instance_id']}", body, blob))
        pages.append(page)
    return SiteResult(index=index, pages=pages, errors=errors)


def _exposure_summary(certs: Path, records: Path, errors: list[tuple[str, str]]) -> Mapping[str, Any] | None:
    """T57: the exposure-audit summary for the hero block, or None. A malformed record adds an error row and no number
    is drawn (the page is still built)."""
    from rewardseal import audit  # lazy: keeps the grader and patches out of the site module's import

    try:
        return audit.exposure_summary(records, certs)
    except (audit.ExposureAuditError, OSError) as exc:
        errors.append(("exposure", f"exposure audit records refused: {exc}"))
        return None


def _web_exposure_section(directory: Path, exposure_dir: Path, errors: list[tuple[str, str]]) -> str:
    from rewardseal import audit, webaudit

    try:
        webaudit.check_path(directory, directory=True)
        paths = sorted(p for p in directory.glob("*.json") if not p.name.startswith("_"))
        if not paths:
            return ""
        records = [webaudit.load_record(p) for p in paths]
        if len({r["instance_id"] for r in records}) != len(records):
            raise ValueError("duplicate instance id")
        webaudit.check_path(exposure_dir, directory=True)
        git = {}
        for path in audit._record_files(exposure_dir):
            webaudit.check_path(path)
            scan = audit.load_record(path)
            git[scan["instance_id"]] = scan
    except (ValueError, OSError) as exc:
        errors.append(("web-exposure", f"web exposure records refused: {type(exc).__name__}"))
        return ""
    rows = []
    full = 0
    for rec in records:
        scan = git.get(rec["instance_id"], {}).get("future_scan", {})
        overlap = (
            f"{scan.get('gold_lines_in_future')} of {scan.get('gold_added_lines')} lines"
            if scan
            else "not recorded"
        )
        q1 = rec["queries"][0]["results"]
        best = max(q1, key=lambda r: r["k"], default=None)
        full += int(rec["n"] > 0 and rec["q1_best_k_history_pages"] == rec["n"])
        rows.append(
            _row(
                rec["instance_id"],
                overlap,
                rec["q1_first_pr_or_commit_rank"] or "none",
                f"{rec['q1_best_k_history_pages']}/{rec['n']}",
                f"{rec['q2_best_k_history_pages']}/{rec['n']}",
                f"Q1 {rec['q1_best_k_blob_pages']}/{rec['n']}; oracle query {rec['q2_best_k_blob_pages']}/{rec['n']}",
                best["page_type"] if best else "none",
            )
        )
    count = sum(r["q1_half_or_more"] for r in records)
    dates = sorted(q["searched_at"][:10] for r in records for q in r["queries"])
    period = f"On {dates[0]}" if dates[0] == dates[-1] else f"Between {dates[0]} and {dates[-1]}"
    sentence = (
        f"{period}, a Tavily search built only from the public issue title and the repository name (the repository name alone when the title was empty or looked unsafe) returned a page containing "
        f"at least half of the counted gold lines in {count} of {len(records)} audited environments "
        f"(all of them in {full}). Findability, not use. Web content changes: a dated snapshot and a lower bound."
    )
    if count == 0:
        sentence = (
            f"{period}, no search built only from the public issue title returned a page with "
            "at least half of the counted gold lines."
        )
    return _section(
        "web-exposure",
        "Web exposure (Tavily)",
        f"<p>{_cell(sentence)}</p>",
        "<p>Rows with n &lt;= 1 are one-line overlaps.</p>",
        _table(
            "Web exposure",
            (
                "Instance",
                "git overlap",
                "Q1 PR/commit hit",
                "Q1 history k/n",
                "Oracle query history k/n",
                "current-file page k/n",
                "page type",
            ),
            rows,
        ),
    )


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
        and row.get("recon") in ("exposure", "exposure-replay", None)
        and ("recon_types" not in row or _is_str_list(row["recon_types"]))
        and (row.get("harness_search") is None or isinstance(row["harness_search"], dict))  # T52, optional
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
        **({"recon": data["recon"] in ("exposure", "exposure-replay", None)} if "recon" in data else {}),
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


def _blob_base(root: Path) -> str:
    """Evidence links from a results directory; refuse malformed pins and symlinks."""
    path = root / "PINNED_SHA"
    if path.is_symlink():
        raise ValueError("symlink refused: evidence pin is not read")
    if not path.exists():
        return GITHUB_BLOB
    try:
        pin = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        raise ValueError("evidence pin could not be read") from None
    if re.fullmatch(r"[0-9a-fA-F]{40}\n?", pin) is None:
        raise ValueError("evidence pin must be one line of 40 hex characters")
    return GITHUB_BLOB.removesuffix("main/") + pin.strip() + "/"


def _pin_label(blob: str) -> str:
    return "latest (main)" if blob == GITHUB_BLOB else f"pinned {blob.rstrip('/').rsplit('/', 1)[-1][:7]}"


def _document(title: str, body: str, blob: str = GITHUB_BLOB, *, csp: str = CSP_META) -> str:
    footer = (
        "Evidence links point at main (latest)"
        if blob == GITHUB_BLOB
        else f"Evidence pinned to commit {blob.rstrip('/').rsplit('/', 1)[-1][:7]}"
    )
    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            csp,
            f"<title>{_cell(title)}</title>",
            f"<style>\n{CSS}</style>",
            "</head>",
            "<body>",
            f"<main>\n{body}\n<footer><p>{_cell(footer)}</p></footer>\n</main>",
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
    bounds = confirm.interval_bounds(rate)  # T54: no interval below n = 10
    if bounds is None:
        if rate["n"] < confirm.MIN_INTERVAL_N:  # a percentage of a handful reads as a rate
            return f"{rate['count']} of {rate['n']} (no rate shown: {confirm.INTERVAL_TOO_SMALL})"
        return f"{rate['count']} of {rate['n']} = {rate['rate']:.1%}"
    low, high = bounds
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


def _reading_guide(blob: str) -> str:
    return _section(
        "reading-guide",
        "How to read this report in 60 seconds",
        '<div class="banner">'
        "<p>RewardSeal checks whether a coding task leaks its own fix, strips the leak, re-checks, and attacks again.</p>"
        '<p>Start with the <a href="#numbers-key">Numbers key</a>.</p>'
        '<p><a href="explorer.html">Explore every audited task and certificate</a>.</p>'
        "<p>Release a task only if (a) gold passes and empty fails, (b) the exposure scan after hardening shows no "
        "future commits, and (c) a re-attack under the same conditions failed; otherwise withhold.</p>"
        f"<p>{CERTIFIED_MEANING} {LEGACY_CAVEAT} This is not a security bound.</p>"
        f"<p>{_link_html(blob + 'docs/claims.md', 'docs/claims.md (' + _pin_label(blob) + ')')}: "
        "the list of every number allowed.</p></div>",
    )


def _second_audit(root: Path, errors: list[tuple[str, str]]) -> str:
    directory = root.parent / "exposure-sample"
    if not directory.exists():
        return ""
    summary = _exposure_summary(root, directory, errors)
    selection = _regular_file(directory, "_selection.json")
    try:
        data = json.loads(selection.read_text(encoding="utf-8")) if selection else None
        if (
            not isinstance(data, dict)
            or not _is_count(data.get("seed"))
            or not isinstance(data.get("rule"), str)
        ):
            raise ValueError("selection must record a seed and rule")
    except (OSError, UnicodeError, ValueError) as exc:
        errors.append(("exposure-sample/_selection.json", f"second audit selection refused: {exc}"))
        data = None
    parts = []
    if summary is not None and summary["source"] == "audit" and data is not None:
        scope = f"Counts only; n={summary['M']}. Closure covers the workdir repository only."
        parts.append(f"<p>{_cell(scope)}</p>")
        parts.append(
            _kv_table(
                "Second audit counts and sampling frame",
                [
                    ("Drawn", summary["selected"]),
                    ("Audited", summary["M"]),
                    ("Excluded env-broken", summary["excluded_env_broken"]),
                    (
                        "At least half of counted lines in a future commit",
                        f"{summary['N_fix']} of {summary['M']}",
                    ),
                    ("Closed after strip-future-git", f"{summary['N_fix_closed']} of {summary['N_fix']}"),
                    ("n", summary["M"]),
                    ("Frame (from docs/results.md)", "1000-row dataset frame; repos 0-9 and A-E"),
                    ("Seed", data["seed"]),
                    ("Rule", data["rule"]),
                    ("Population", "random within that frame only"),
                    ("What it is NOT", "NOT SWE-rebench at large and NOT blended with the 13"),
                    ("Source", "results/exposure-sample/ records, _run.json and _selection.json"),
                ],
            )
        )
    else:
        parts.append("<p>Second audit records not loaded; no counts shown.</p>")
    return _section("second-audit", "Second audit (separate random sample, not blended)", *parts, level=3)


def _numbers_key(
    confirmation: Mapping[str, Any] | None,
    exposure: Mapping[str, Any] | None,
    replications: confirm.ReplicationSet,
    manifest: Mapping[str, Mapping[str, str]],
    sample: str,
) -> str:
    rows = []
    if exposure is not None and exposure["source"] == "audit":
        rows += [
            _row(
                f"{exposure['N_fix']} of {exposure['M']}",
                f"audit: at least half of counted gold lines in a future commit; {exposure['M']} audited "
                f"of the {exposure['selected']} selected, {exposure['excluded_env_broken']} excluded env-broken",
                "results/exposure/ records and _run.json",
                "NOT a prevalence estimate",
            ),
            _row(
                f"{exposure['N_fix_closed']} of {exposure['N_fix']}",
                "closed after strip-future-git: no future commits and gates held; workdir repo only",
                "results/exposure/ records",
                "NOT closure of other repositories or routes",
            ),
        ]
    if confirmation is not None:
        recon = confirmation.get("recon")
        if isinstance(recon, Mapping):
            rows.append(
                _row(
                    f"{recon['confirmed']} of {recon['n']}",
                    "future_git tasks attacked with recon on, confirmed pattern (confirmed = manual command-order check; "
                    "use of the fix is inferred, not observed)",
                    "certificates and results/confirmations.json",
                    f"NOT {recon['n']} independent trials; a different denominator from the score-table rows below",
                )
            )
        for key, label in (("rate_confirmed_before", "before"), ("rate_confirmed_after", "after")):
            rate = confirmation[key]
            rows.append(
                _row(
                    f"{rate['count']} of {rate['n']}",
                    f"score table: confirmed holes {label} hardening among conclusive certificates",
                    "certificates and results/confirmations.json",
                    "n too small for a rate; a different denominator from the 9 above",
                )
            )
        task = "CycloneDX__cyclonedx-python-348"
        try:
            rep = confirm.replication_for(task, replications, manifest)
        except confirm.ConfirmationError:
            rep = None
        if rep is not None:
            rows.append(
                _row(
                    f"{confirmation['confirmed_holes']} confirmed; {rep['confirmed']}/{rep['n']} judged runs",
                    "the replication rule counts only runs whose before attack finished and was judged; "
                    f"the 4 later runs were unfinished or inconclusive, so it reads {rep['confirmed']}/{rep['n']}; across all 9 committed Super "
                    "before-rounds through T55 one showed the pattern (docs/results.md); use inferred, unequal follow-up, "
                    "not a rate",
                    "results/replications/ and docs/results.md",
                    "NOT a contradiction: different populations",
                )
            )
        rows += [
            _row(
                "1/9 committed Super before-rounds",
                "committed Super before-rounds of task 348 through T55, including unfinished or inconclusive runs; "
                "1 of 7 excluding 2 HTTP 503 errors; chunk 2 and earlier attacks excluded; "
                "including null replay1: 1 of 10 (1 of 8 excluding 503s)",
                "from docs/results.md",
                "NOT 9 judged independent trials; use inferred, unequal follow-up, not a rate",
            ),
            _row(
                f"{confirmation['n']} certificates",
                "files, all tasks with a certificate including env-broken tasks",
                "results/certificates/",
                f"NOT {confirmation['n']} audited; a file need not contain an attack",
            ),
            _row(
                f"{confirmation['certified']} certified",
                f"{confirmation['certified_via'].get('hardened_reattack_failed', 0)} after a failed hardened re-attack; "
                f"{confirmation['certified_via'].get('legacy', 0)} legacy no-hole-found",
                "results/certificates/",
                "NOT a security claim",
            ),
        ]
    return _section(
        "numbers-key",
        "Numbers key",
        _table(
            "Each number has its own population", ("Number", "Population", "Source", "What it is NOT"), rows
        ),
        sample,
    )


def _fate(cert: Mapping[str, Any] | None, audited: str) -> str:
    if cert is None:
        return {"audited": "audited only", "excluded env-broken": "excluded from audit (env-broken)"}.get(
            audited, "no certificate or audit recorded"
        )
    harden = _map(cert.get("harden"))
    before, after = _map(harden.get("before")), _map(harden.get("after"))
    attacked = isinstance(before.get("attack"), Mapping)
    if cert.get("certified"):
        if after:
            return (
                "certified after hardened re-attack"
                if confirm.reattack_failed(cert)
                else "certified after hardening (real fix)"
            )
        return "certified, initial attack failed (no hardening)"
    if not attacked and _map(before.get("gates")).get("ok") is False:
        return "gates failed before any attack (env-broken)"
    if any(r.get("inconclusive") or r.get("error") for r in (before, after)):
        return "attacked, inconclusive" if attacked else "error before any attack"
    if before.get("no_attempt"):
        return "attacker ran, no qualifying attempt"
    if _map(after.get("holes")).get("exploited"):
        return "attacked, classifier flagged a shortcut after hardening (an unconfirmed lead unless the confirmations file says otherwise)"
    return "attacked, not certified" if attacked else "no attack recorded"


def _reconciliation(entries: Sequence[_Entry], batch: _Batch, exposure_path: Path) -> str:
    from rewardseal import audit

    selected = set(batch.record["selected_ids"]) if batch.record else set()
    audited_ids: set[str] = set()
    excluded = {}
    try:
        run = audit.load_run(exposure_path)
        if run:
            selected.update(run["selected_ids"])
            excluded = run["excluded"]
        if not exposure_path.is_symlink():
            for path in sorted(exposure_path.glob("*.json")):
                if not path.name.startswith("_"):
                    audited_ids.add(audit.load_record(path)["instance_id"])
    except (audit.ExposureAuditError, OSError):
        # The shared summary loader reports invalid audit files in the build errors.
        audited_ids.clear()
    if not selected:
        return ""
    by_id = {e.cert["task"]["instance_id"]: e for e in entries}
    rows = []
    for task in sorted(selected):
        entry = by_id.get(task)
        cert = entry.cert if entry else None
        audit_state = (
            "audited"
            if task in audited_ids
            else "excluded env-broken"
            if excluded.get(task) == "env_broken"
            else "not audited"
        )
        cert_text = "none"
        attacked = False
        if cert is not None:
            rounds = _map(cert.get("harden"))
            attacked = any(isinstance(_map(rounds.get(r)).get("attack"), Mapping) for r in ROUNDS)
            verdict = (
                "yes"
                if cert["certified"]
                else "inconclusive"
                if any(_map(rounds.get(r)).get("inconclusive") for r in ROUNDS)
                else "no"
            )
            cert_text = f"{entry.stem}.json (certified {verdict})"
        rows.append(_head_row(task, cert_text, attacked, audit_state, _fate(cert, audit_state)))
    outside = sum(1 for e in entries if e.cert["task"]["instance_id"] not in selected)
    text = (
        f"{len(rows)} of {len(selected)} selected tasks are in the table. The site holds {len(entries)} "
        f"certificate files, of which {outside} are outside the {len(selected)}."
    )
    return f"<p>{_cell(text)}</p>" + _table(
        "Selected task reconciliation",
        ("Task", "Certificate file", "Attacked", "Exposure audit", "Fate"),
        rows,
    )


def _index_body(
    entries: Sequence[_Entry],
    errors: Sequence[tuple[str, str]],
    excluded: int,
    summary: Mapping[str, Any] | None,
    batch: _Batch,
    confirmation: Mapping[str, Any] | None = None,
    manifest: Mapping[str, Mapping[str, str]] | None = None,
    replications: confirm.ReplicationSet | None = None,
    statuses: Mapping[str, confirm.HoleStatus] | None = None,
    exposure: Mapping[str, Any] | None = None,
    start_here: str = "",
    numbers_key: str = "",
    reconciliation: str = "",
    blob: str = GITHUB_BLOB,
    web_exposure: str = "",
) -> str:
    """excluded counts the certificate files left out (errors also holds a bad batch record, which is not one).
    confirmation, manifest, replications and statuses (T54) feed the hero block and the confirmed/lead counts."""
    head = [
        "<header>",
        "<h1>Recorded attack-check report</h1><p>RewardSeal</p>",
        f'<p class="banner" role="note">{_cell(BANNER)}</p>',
        "</header>",
        (
            '<nav aria-label="Report"><a href="explorer.html">Explorer</a> | '
            '<a href="controls.html">Controls</a> | <a href="limitations.html">Limitations</a> | '
            '<a href="verify.html">Verify</a> | <a href="#numbers-key">Numbers key</a></nav>'
        ),
    ]
    middle = (
        [
            _empty_state(excluded),
            _section("run-record", "Run record", reconciliation, *_run_record_parts(batch, len(entries))),
        ]
        if summary is None
        else [
            _hero_section(
                entries,
                confirmation,
                manifest or {},
                replications or confirm.ReplicationSet(),
                statuses or {},
                exposure,
                blob,
            ),
            _score_section(summary, excluded, batch, len(entries), confirmation, reconciliation),
            _environments_section(entries, statuses or {}),
        ]
    )
    return "\n".join(
        [
            *head,
            numbers_key,
            _reading_guide(blob),
            _workflow_comparison(),
            start_here,
            web_exposure,
            *middle,
            _errors_section(errors),
        ]
    )


def _workflow_comparison() -> str:
    return _section(
        "workflow-comparison",
        "Manual workflow vs RewardSeal",
        _table(
            "Steps, outputs and human judgment",
            ("Workflow", "Steps", "Produces", "Still needs a human"),
            [
                _row(
                    "Manual",
                    "Inspect task history; test a strip; check gold and empty gates; attempt shortcuts again; save evidence.",
                    "The evaluator's notes and gate results.",
                    "Choose the scope, review causal attribution and decide whether to release.",
                ),
                _row(
                    "RewardSeal",
                    "audit-exposure scans and checks a strip; harden attacks, patches and re-attacks when a patch exists; "
                    "report and site replay saved records.",
                    "Exposure records, gate outcomes, attack certificates and this static report.",
                    "Authorize evaluation, review incomplete scans and attribution, compare attack conditions, "
                    "judge difficulty changes and decide whether to release.",
                ),
            ],
        ),
    )


START_HERE_STEPS = (
    ("1. Exposure", "#hero", "the audit above: how often future commits sit in the task's .git"),
    (
        "2. Commands",
        "evidence",
        "verbatim commands; outputs are 300-character heads plus a sha256, full outputs not retained",
    ),
    ("3. Matching line", "#matching-line", "one gold-added line also found in the attacker's step 15 write"),
    ("4. Patch", "#patches", "strip-future-git, the rule-based fix"),
    ("5. Gates", "#gates", "gold passes, empty fails, before and after"),
    ("6. Certificate", "#result", "the recorded outcome"),
)
START_HERE_PLAIN = (
    "In plain words: this environment's git history held a future commit with the fix. In one recorded run the model "
    "looked at that commit, then wrote a matching line, and its diff passed the hidden tests. We infer, but did not "
    "observe, that it used what it read. The patch removed the future commits, the gold patch still passed, the empty "
    "patch still failed, and a new attack failed. That is one run on one task and one attacker."
)


def _start_here(entries: Sequence[_Entry], evidence_dir: Path, blob: str = GITHUB_BLOB) -> str:
    """A static, clickable path through the recorded 348 run (no live calls). The excerpt is copied from the committed
    evidence file as it is; when that file is missing there is no excerpt and no section."""
    entry = next((e for e in entries if e.cert["task"]["instance_id"] in EVIDENCE_FILES), None)
    if entry is None:
        return ""
    task = entry.cert["task"]["instance_id"]
    page = f"env/{entry.name}.html"
    excerpt = ""
    body = ""
    path = _regular_file(evidence_dir, Path(EVIDENCE_FILES[task]).name)
    try:
        text = path.read_text(encoding="utf-8") if path else ""
    except (OSError, UnicodeError):
        text = ""
    if "## Before round" in text and "## The upstream fix" in text:
        body = text.split("## Before round", 1)[1].split("## The upstream fix", 1)[0]
        excerpt = (
            "<h3>Recorded commands</h3><details><summary>Steps 12 to 15: verbatim commands, "
            "output heads and sha256 only</summary>"
            f"<pre>{_cell(body.strip())}</pre></details>"
        )
    match = re.search(r"\*\*Step 15\*\*.*?```python\n([^\n]+)\n```", body, re.DOTALL)
    matching = (
        _table(
            "Matching line",
            ("Line the gold patch adds", "Line in the attacker's step 15 write"),
            [_row(match[1], match[1])],
        )
        if match
        else "<p>not in the evidence file</p>"
    )
    card = (
        '<div class="banner">'
        + (excerpt or "<h3>Recorded commands</h3><p>not in the evidence file</p>")
        + '<h3 id="matching-line">Matching line</h3>'
        + matching
        + ("<p>Line overlap; use of the git show output is inferred from command order.</p>" if match else "")
        + "</div>"
    )

    def target(anchor: str) -> str:
        if anchor == "evidence":
            return blob + EVIDENCE_FILES[task]
        return anchor if anchor in ("#hero", "#matching-line") else page + anchor

    items = "".join(
        f"<li>{_link_html(target(anchor), label)}: {_cell(what)}</li>"
        for label, anchor, what in START_HERE_STEPS
    )
    return _section(
        "start-here",
        "Start here: a recorded run",
        '<p><span class="label">recorded</span> This is a replay of a recorded run, not a live attack. No calls are '
        "made when you open it.</p>",
        f"<p>Task: {_link_html(page, task)}</p>",
        f'<ol class="path">{items}</ol>',
        f"<p>{_cell(START_HERE_PLAIN)}</p>",
        card,
        f"<p>{_link_html(blob + EVIDENCE_FILES[task], 'Full evidence file (' + _pin_label(blob) + '; full outputs not retained)')}</p>",
    )


def _caveats(confirmation: Mapping[str, Any]) -> list[str]:
    """The four caveats of the hero block. The n line uses the counts in the data, not fixed numbers."""
    recon = confirmation.get("recon")
    where = (
        f"{recon['n']} environments in the denominator, {confirmation['n']} certificates in all"
        if isinstance(recon, Mapping)
        else f"{confirmation['n']} certificates"
    )
    n_line = (
        f"n: raw counts over {where}. A confirmed hole is a recorded run, not a rate; the replication line "
        f"of each confirmed environment says how many runs repeat it. No interval is shown "
        f"below n = {confirm.MIN_INTERVAL_N} ({confirm.INTERVAL_TOO_SMALL})."
    )
    recon_line = (
        "Recon on: the attacker was given the exposure scan of its environment (where the history refs are). "
        "The counts do not hold for an attacker without recon."
    )
    one_line = "One attacker: a single model and prompt tried each environment. A different attacker may find other holes."
    certified_line = (
        f"{CERTIFIED_MEANING} {LEGACY_CAVEAT} This attacker's recorded qualifying attack did not succeed; "
        "attacks per round are on each environment page. This is not a security guarantee."
    )
    return [n_line, recon_line, one_line, certified_line]


def _hero_headline(confirmation: Mapping[str, Any]) -> str:
    """'1 of 9 confirmed' from the data. Without a denominator that the data supports, just the counts."""
    recon = confirmation.get("recon")
    if isinstance(recon, Mapping) and recon["n"] > 0:
        return f"{recon['confirmed']} of {recon['n']} confirmed"
    return f"{confirmation['confirmed_holes']} confirmed, {confirmation['unconfirmed_leads']} unconfirmed"


def _hero_section(
    entries: Sequence[_Entry],
    confirmation: Mapping[str, Any] | None,
    manifest: Mapping[str, Mapping[str, str]],
    replications: confirm.ReplicationSet,
    statuses: Mapping[str, confirm.HoleStatus],
    exposure: Mapping[str, Any] | None = None,
    blob: str = GITHUB_BLOB,
) -> str:
    """The block at the top of the index (T54): the confirmed/lead headline, what it does not show, and a
    before -> after summary of each confirmed environment, with its replication state."""
    if confirmation is None:
        return ""
    recon = confirmation.get("recon")
    if isinstance(recon, Mapping) and recon["n"] > 0:
        scope = (
            f"{recon['confirmed']} of {recon['n']}: environments attacked with recon on whose exposure scan "
            "showed future_git true, counted when the hole is confirmed. The denominator is computed from the "
            "certificates. Confirmation is a manual manifest entry; use of the fix is inferred from command order; "
            "tasks received unequal follow-up."
        )
    else:
        scope = (
            "No environment in the data was attacked with recon on and future_git true: no denominator, "
            "counts only."
        )
    lead_ids = confirmation["lead_ids"]
    parts = []
    audit_first = exposure is not None and exposure.get("source") == "audit"
    exposure_html = ""
    if (
        exposure is not None
    ):  # T57: one paragraph; a real audit leads, the labelled fallback follows the counts
        from rewardseal.audit import summary_line

        css = "exposure-audit lead" if audit_first else "exposure-audit"
        exposure_html = f'<p class="{css}">{_cell(summary_line(exposure))}</p>'
    if audit_first:
        parts += [exposure_html, '<p class="finding-label">Attacker finding (one attacker, recon on):</p>']
    parts += [
        f'<p class="headline">{_cell(_hero_headline(confirmation))}</p>',
        f"<p>{_cell(scope)}</p>",
        f"<p>{_cell(confirm.counts_line(confirmation))}</p>",
    ]
    if exposure_html and not audit_first:
        parts.append(exposure_html)
    if lead_ids:
        links = " ".join(
            _link_html(f"env/{entry.name}.html", entry.cert["task"]["instance_id"])
            for entry in entries
            if entry.cert["task"]["instance_id"] in lead_ids
        )
        parts.append(
            "<p>Unconfirmed leads are never counted as hackable: a hole label with no T53 shared-line evidence "
            "and no manual causal check showing the history was used.</p>"
            f"<p>Leads: {links}</p>"
        )
    unused = confirmation.get("manifest_unused") or []
    if unused:
        text = "Manifest entries with no hole label in the loaded certificates: " + ", ".join(unused)
        parts.append(f"<p>{_cell(text)}</p>")
    parts.append(
        _section(
            "caveats",
            "What this does not show",
            "<ul>" + "".join(f"<li>{_cell(text)}</li>" for text in _caveats(confirmation)) + "</ul>",
            level=3,
        )
    )
    ids = confirmation["confirmed_ids"]
    confirmed = [entry for entry in entries if entry.cert["task"]["instance_id"] in ids]
    parts.append(_hero_confirmed(confirmed, replications, statuses, manifest, blob))
    return _section("hero", "Confirmed holes", *parts)


def _hero_confirmed(
    confirmed: Sequence[_Entry],
    replications: confirm.ReplicationSet,
    statuses: Mapping[str, confirm.HoleStatus],
    manifest: Mapping[str, Mapping[str, str]],
    blob: str = GITHUB_BLOB,
) -> str:
    """The before -> after panel of each confirmed environment (the T50 panel), with its replication line."""
    if not confirmed:
        return "<h3>Before and after hardening</h3><p>No confirmed hole in the loaded certificates.</p>"
    blocks = []
    for number, entry in enumerate(confirmed, start=1):
        cert, task = entry.cert, entry.cert["task"]["instance_id"]
        status = statuses.get(task)
        panel = _before_after_section(
            cert, anchor=f"hero-before-after-{number}", level=4, heading="Before -> after, as recorded"
        )
        blocks.append(
            "\n".join(
                [
                    f"<h3>{_link_html(f'env/{entry.name}.html', task)}</h3>",
                    f"<p>{_link_html(blob + DEFAULT_CERT_DIR + '/' + entry.stem + '.json', 'raw certificate (' + _pin_label(blob) + ')')}</p>",
                    _kv_table(
                        "Confirmed environment",
                        [
                            ("Confirmed by", status.source if status else NOT_RECORDED),
                            *([("Note", status.note)] if status and status.note else []),
                            ("Certified", cert["certified"]),
                            ("Certified via", _via_text(cert)),
                            ("Replication", confirm.replication_text(task, replications, manifest)),
                        ],
                    ),
                    *([f"<p>{_cell(REPLICATION_NOTE_348)}</p>"] if task in EVIDENCE_FILES else []),
                    panel or "<p>No hardening round was recorded for this environment.</p>",
                ]
            )
        )
    return "\n".join(blocks)


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
    lead = "".join(
        f"<p>{_cell(text)}</p>"
        for text in (
            (
                f"Run by this batch: {record['run']} of {selected} selected "
                f"(already had a certificate: {record['already_certified']}; not run: {not_run_count})."
            ),
            f"This line counts only the last batch call, not all {selected}; see the table.",
            f"certificates loaded: {loaded} (scored on this page; this can include certificates from earlier runs).",
        )
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


def _score_section(
    summary: Mapping[str, Any],
    excluded: int,
    batch: _Batch,
    loaded: int,
    confirmation: Mapping[str, Any] | None = None,
    reconciliation: str = "",
) -> str:
    lead = f"n = {summary['n']} valid certificates. " + (_excluded_text(excluded) + " " if excluded else "")
    if confirmation is not None:
        rate_rows = [
            _row(label, _rate_text(confirmation[key]), confirmation[key]["denominator"])
            for label, key in (
                ("Confirmed holes before hardening", "rate_confirmed_before"),
                ("Confirmed holes after hardening", "rate_confirmed_after"),
            )
        ]
    else:
        rate_rows = [
            _row(label, _rate_text(summary[key]), summary[key]["denominator"])
            for label, key in (
                ("Hackable before hardening", "rate_before"),
                ("Hackable after hardening", "rate_after"),
            )
        ]
    outcome_caption = "Outcomes, each certificate counted once"
    if confirmation is not None:
        outcome_caption += (
            ". hackable_after counts a hole label found after hardening, which may be an unconfirmed lead"
        )
    outcome_rows = [_row(name, count) for name, count in summary["outcomes"].items()]
    outcome_rows.append(_row("Total (equals n)", summary["n"]))
    if confirmation is not None:
        hole_headers: tuple[str, ...] = (
            "Hole",
            "Before: confirmed",
            "Before: lead",
            "After: confirmed",
            "After: lead",
        )
        hole_rows = [
            _row(label, c["before_confirmed"], c["before_lead"], c["after_confirmed"], c["after_lead"])
            for label, c in confirmation["by_hole"].items()
        ]
        hole_caption = "Certificates per hole label, by status. A lead is not counted as hackable."
        status_pairs = [
            ("Confirmed holes (tasks)", confirmation["confirmed_holes"]),
            ("Unconfirmed leads (tasks, never counted as hackable)", confirmation["unconfirmed_leads"]),
            (
                "Hole label found before hardening (confirmed or lead, also counted in the outcomes)",
                summary["hackable_before"],
            ),
            (
                "Hole label found after hardening (confirmed or lead, also counted in the outcomes)",
                summary["hackable_after"],
            ),
        ]
    else:
        hole_headers = ("Hole", "Before hardening", "After hardening")
        hole_rows = [
            _row(label, counts["before"], counts["after"]) for label, counts in summary["by_hole"].items()
        ]
        hole_caption = "Certificates per hole, before and after hardening"
        status_pairs = [
            ("Hackable before (also counted in the outcomes)", summary["hackable_before"]),
            ("Hackable after (also counted in the outcomes)", summary["hackable_after"]),
        ]
    return _section(
        "score",
        "Hackability score",
        "<p><small>Recorded counts, not a score: the numbers below come from mixed, selected samples.</small></p>"
        f"<p>{lead}{CERTIFIED_MEANING} {LEGACY_CAVEAT} This is not a security guarantee.</p>",
        f"<p>{_cell(confirm.counts_line(confirmation))}</p>" if confirmation is not None else "",
        _section("run-record", "Run record", reconciliation, *_run_record_parts(batch, loaded), level=3),
        _table(
            "Rates with 95% Wilson intervals (shown from n = 10)",
            ("Measure", "Count of n and rate", "Denominator"),
            rate_rows,
        ),
        _table(outcome_caption, ("Outcome", "Count"), outcome_rows),
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
                *_via_rows(summary.get("certified_via")),
                ("Inconclusive", summary["inconclusive"]),
                (
                    "No attempt, attacker never tried (no_attempt, also counted in the outcomes)",
                    summary.get("no_attempt"),
                ),
                *status_pairs,
                (
                    "Cost, total (USD)",
                    _money_basis(summary["cost_usd_total"], summary.get("cost_basis")),
                ),
            ],
        ),
        _table(hole_caption, hole_headers, hole_rows, empty="no hole label was found"),
    )


def _strategy_html(attacker: Any) -> str:
    """The strategy label, then a visible recon=exposure tag when the attacker got the exposure scan (T47)."""
    attacker = _map(attacker)
    text = _cell(attacker.get("strategy") if attacker.get("strategy") is not None else "not recorded")
    kinds = attacker.get("recon_types")
    shown = f" ({', '.join(_cell(k) for k in kinds)})" if isinstance(kinds, list) and kinds else ""
    tag = f' <span class="label">recon=exposure{shown}</span>' if attacker.get("recon") == "exposure" else ""
    search = attacker.get("harness_search")
    if isinstance(search, dict):  # T52: the harness's own Tavily call, never an attacker decision
        failed = "" if search.get("ok") is True else " (failed)"
        tag += f' <span class="label">harness search via Tavily{failed}</span>'
    return f"{text}{tag}"


def _status_cell(status: confirm.HoleStatus | None) -> str:
    """confirmed, lead or none for the index; (manual check) when a manifest entry decided it."""
    if status is None:
        return NOT_RECORDED
    return status.task + (" (manual check)" if status.manifest and status.task != confirm.NO_HOLE else "")


def _environments_section(entries: Sequence[_Entry], statuses: Mapping[str, confirm.HoleStatus]) -> str:
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
                _status_cell(statuses.get(task["instance_id"])),
                cert["patches_applied"],
                _gates_text(gates["before"]),
                _gates_text(gates["after"]),
                cert["certified"],
                _via_cell(cert),
                _money(cert["cost_usd"]),
            )
        )
    headers = (
        "Instance",
        "Repo",
        "Source",
        "Strategy",
        "Hole labels found",
        "Hole status",
        "Patches applied",
        "Gates before (gold, empty)",
        "Gates after",
        "Certified",
        "Via",
        "Cost (USD)",
    )
    return _section(
        "environments",
        "Environments",
        _table(
            "One row per environment. The recorded qualifying attack failed for each certified row; it does not "
            "establish that no usable hole remains (via: how it was certified). See the k=1 definition and legacy caveat above.",
            headers,
            rows,
        ),
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


def _env_body(
    cert: Mapping[str, Any],
    transcript: str,
    diffs: Mapping[str, str | None] | None = None,
    status: confirm.HoleStatus | None = None,
    stem: str | None = None,
    blob: str = GITHUB_BLOB,
    not_exercised: bool = False,
) -> str:
    task = cert["task"]
    links = []
    if stem:
        links.append(
            _link_html(f"{blob}{DEFAULT_CERT_DIR}/{stem}.json", "raw certificate (" + _pin_label(blob) + ")")
        )
    if task["instance_id"] in EVIDENCE_FILES:
        links.append(
            _link_html(
                blob + EVIDENCE_FILES[task["instance_id"]],
                "evidence file (" + _pin_label(blob) + "; full outputs not retained)",
            )
        )
    link_row = [f"<p>View the raw certificate on GitHub: {' | '.join(links)}</p>"] if links else []
    return "\n".join(
        [
            '<p><a href="../index.html">Back to the index</a></p>',
            f"<h1>{_cell('Environment: ' + task['instance_id'])}</h1>",
            (
                '<p><span class="label">recorded</span> This page replays a committed certificate. '
                "No live calls were made.</p>"
            ),
            *link_row,
            _result_section(cert, status),
            *([_what_means(NOT_RELEASE_APPROVED)] if not_exercised and cert.get("certified") else []),
            *([f"<p>{_cell(REPLICATION_NOTE_348)}</p>"] if task["instance_id"] in EVIDENCE_FILES else []),
            _exposure_section(cert["exposure_before"]),
            _before_after_section(cert),
            _task_section(cert),
            _attacker_section(cert["attacker"]),
            _gates_section(cert["harden"]),
            _holes_section(cert["harden"]),
            _patches_section(cert["harden"]),
            _rounds_section(cert["harden"], diffs or {}, _map(cert.get("attacker"))),
            _section("transcript", "Transcript (harness record)", transcript),
        ]
    )


VIA_PLAIN = {
    "no_hole_found": "no hole found: the attacker failed before any patch",
    "hardened_reattack_failed": "the recorded hardened re-attack failed",
    "legit_fix": "the recorded checks did not find the earlier exposure: the attacker submitted a real fix after hardening",
}


def _via_cell(cert: Mapping[str, Any]) -> str:
    """The short certified_via for the index: the value, legacy when the key is absent, a dash when not certified."""
    if "certified_via" not in cert:
        return "legacy" if cert.get("certified") else "none"
    return cert["certified_via"] or "none"


def _via_rows(counts: Any) -> list[tuple[str, Any]]:
    """Summary rows for the certified_via split. Empty when the score has none (an older score dict)."""
    counts = _map(counts)
    if not counts:
        return []
    return [
        (f"Certified via {name} (also counted in Certified)", counts.get(name))
        for name in ("no_hole_found", "hardened_reattack_failed", "legit_fix", "legacy")
    ]


def _via_text(cert: Mapping[str, Any]) -> str:
    """certified_via as recorded, with plain words. A certificate written before T50 has none."""
    if "certified_via" not in cert:
        return (
            "legacy: not recorded (certificate written before certified_via)"
            if cert.get("certified")
            else "not recorded (certificate written before certified_via)"
        )
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
        return f"classifier flagged a hole after hardening ({_value(holes.get('labels'))}; see Hole status)"
    if attack.get("outcome") == "legit_fix":
        return "legit_fix (passed the hidden tests like the gold fix; not an exploit)"
    if rnd.get("inconclusive"):
        return "inconclusive"
    return "failed (did not pass the hidden tests)"


def _attempted_again(before_holes: Mapping[str, Any], after: Mapping[str, Any]) -> str:
    """yes when the after attack's attempted labels name a before hole label, else none."""
    earlier, attempted = before_holes.get("labels"), _map(after.get("holes")).get("attempted")
    if not isinstance(earlier, list) or not isinstance(attempted, list):
        return "not recorded"
    return "yes" if set(earlier) & set(attempted) else "none"


def _history_scan_rows(rnd: Mapping[str, Any]) -> list[tuple[str, Any]]:
    """T55: one row for the targeted history scan of a round (counts and whether it read all of it), or none for a
    record from before T55. Counts only: no line text, no digest."""
    scan = _map(rnd.get("future_scan"))
    if not scan:
        return []
    shared = _map(rnd.get("holes")).get("shared_future_lines")
    text = (
        f"{scan.get('commits_scanned')} future commit(s) read for {len(_items(scan.get('paths')))} path(s), "
        f"{scan.get('lines')} distinct added line(s), "
        f"{'complete' if scan.get('complete') is True else 'incomplete (no proof from a missing match)'}"
    )
    if isinstance(shared, int) and not isinstance(shared, bool):
        text += f"; {shared} shared with the attack diff"
    return [("History scan after the attack", text)]


def _steps_used(attack: Mapping[str, Any], attacker: Mapping[str, Any]) -> str:
    text = f"{_value(attack.get('steps'))} steps used"
    configured = attacker.get("max_steps")
    if _is_count(configured):
        text += f" (budget configured: {configured})"
    return text


def _configured_budget(attacker: Mapping[str, Any]) -> str:
    steps, tokens = attacker.get("max_steps"), attacker.get("max_tokens")
    if _is_count(steps) and _is_count(tokens):
        return f"Same step and token budget configured for both rounds: {steps} steps / {tokens} tokens. "
    return ""


def _round_end(attack: Mapping[str, Any]) -> str:
    used = _value(attack.get("steps"))
    if attack.get("submitted"):
        return f"attacker submitted after {used} steps used"
    if attack.get("auto_submitted"):
        return f"harness auto-submitted after {used} steps used; no attacker submission"
    return f"no submission recorded; stop reason: {_value(attack.get('stop_reason'))}"


def _before_after_section(
    cert: Mapping[str, Any],
    *,
    anchor: str = "before-after",
    level: int = 2,
    heading: str = "Before and after hardening",
) -> str:
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
        "tests like the gold fix. Closure is shown by the exposure scan; the re-attack found no way back in. "
        "This holds against this attacker only."
        if closed
        else "Before and after hardening, as recorded. Results hold against this attacker only."
    )
    after_attack = _map(after.get("attack"))
    attacker = _map(cert.get("attacker"))
    budget_note = _configured_budget(attacker)
    before_recon, after_recon = before_attack.get("recon") or "none", after_attack.get("recon") or "none"
    before_steps, after_steps = before_attack.get("steps"), after_attack.get("steps")
    comparison_note = ""
    replay_same = before_recon == "exposure" and after_recon == "exposure-replay"
    if replay_same:
        if before_steps != after_steps:
            text = (
                "Same recon text given before and after: the after-hardening attacker was shown the BEFORE-hardening "
                f"exposure scan, now stale. {budget_note}Steps used differ ({_value(before_steps)} before, "
                f"{_value(after_steps)} after): attacks are not deterministic, so one re-attack does not isolate "
                "the effect of the patch."
            )
            comparison_note = f'<p class="banner" role="note">{_cell(text)}</p>'
    elif before_recon != after_recon:
        shown = "was shown" if before_recon == "exposure" else "was not shown"
        after_shown = "was" if after_recon == "exposure" else "was not"
        retried = _attempted_again(before_holes, after)
        retry_text = (
            "it did not retry the original route"
            if retried == "none"
            else "the original route retry is recorded below"
        )
        text = (
            f"This re-attack is not like for like: recon differed. {budget_note}"
            f"Before hardening the attacker {shown} the exposure scan "
            f"(recon: {before_recon}, {_steps_used(before_attack, attacker)}); after hardening it {after_shown} "
            f"(recon: {after_recon}, {_steps_used(after_attack, attacker)}), and {retry_text} "
            f"(earlier hole attempted again: {retried}). Round end: {_round_end(after_attack)}. "
            "It does not isolate the effect of the patch."
        )
        comparison_note = f'<p class="banner" role="note">{_cell(text)}</p>'
    elif before_steps != after_steps:
        comparison_note = (
            f"<p>{_cell(budget_note)}Steps used differ; usage alone does not indicate a configured budget difference. "
            "Attacks are not deterministic; one re-attack does not isolate the effect of the patch.</p>"
        )
    return _section(
        anchor,
        heading,
        f"<p>{_cell(lead)}</p>",
        comparison_note,
        _kv_table(
            "Before: the hole the attacker found",
            [
                ("Hole labels", before_holes.get("labels")),
                ("Recon", before_attack.get("recon") or "none"),
                ("Steps used", _steps_used(before_attack, attacker)),
                ("How round ended", _round_end(before_attack)),
                ("Configured token budget", attacker.get("max_tokens")),
                ("How it was found", _found_how(before_attack)),
                *_history_scan_rows(before),
                ("Patches applied", harden.get("accepted")),
            ],
        ),
        _kv_table(
            "After: the same attacker, hardened task",
            [
                ("Exposure scan", exposure),
                ("Gates held", gates_ok),
                ("Recon", after_attack.get("recon") or "none"),
                ("Steps used", _steps_used(after_attack, attacker)),
                ("How round ended", _round_end(after_attack)),
                ("Configured token budget", attacker.get("max_tokens")),
                ("Stop reason", after_attack.get("stop_reason")),
                ("Attacker submitted", after_attack.get("submitted")),
                ("Re-attack outcome", _after_outcome(after)),
                ("Earlier hole attempted again", _attempted_again(before_holes, after)),
                ("Certified via", _via_text(cert)),
            ],
        ),
        _what_means(
            "the scan after hardening found no future commits; the before-hardening scan table is above; "
            "the after-hardening scan is in the certificate JSON"
        )
        if exposure == "clean" and scan.get("future_git") is False
        else "",
        level=level,
    )


def _status_pairs(status: confirm.HoleStatus | None) -> list[tuple[str, Any]]:
    """Rows for the hole status: the task status and where it comes from, then each label with its status."""
    if status is None:
        return []
    pairs: list[tuple[str, Any]] = [("Hole status", f"{status.task}: {status.source}")]
    if status.note:
        pairs.append(("Hole status note", status.note))
    for name, labels in (("before", status.before), ("after", status.after)):
        if labels:
            pairs.append(
                (f"Hole labels, {name} hardening", ", ".join(f"{k} ({v})" for k, v in labels.items()))
            )
    return pairs


def _result_section(cert: Mapping[str, Any], status: confirm.HoleStatus | None = None) -> str:
    notes = _items(cert["notes"])
    notes_html = (
        "<p>none</p>" if not notes else "<ul>" + "".join(f"<li>{_cell(n)}</li>" for n in notes) + "</ul>"
    )
    return _section(
        "result",
        "Result",
        f"<p>{CERTIFIED_MEANING} {LEGACY_CAVEAT} This is not a security bound.</p>",
        _kv_table(
            "Certificate summary",
            [
                ("Certified", cert["certified"]),
                ("Certified via", _via_text(cert)),
                *_status_pairs(status),
                ("Reason", cert["reason"]),
                ("Cost (USD)", _money_basis(cert["cost_usd"], cert.get("cost_basis"))),
                ("Timestamp", cert["timestamp"]),
                ("Sandbox runs", cert["sandbox_runs"]),
            ],
        ),
        _what_means(
            "3 older certificates written before the certified_via field existed; they were never "
            "re-attacked after hardening"
        )
        if cert.get("certified") and "certified_via" not in cert
        else "",
        _what_means("a ledger estimate, not billed spend")
        if cert.get("cost_basis") == "budgeted ledger delta"
        else "",
        _what_means(LEAD_REASON_NOTE) if status is not None and status.task == "lead" else "",
        "<h3>Notes</h3>",
        notes_html,
    )


def _digest_text(digest: Any) -> str:
    digest = _map(digest)
    return f"sha256 {_value(digest.get('sha256'))}, {_value(digest.get('chars'))} chars"


def _what_means(text: str) -> str:
    return f'<p class="what-this-means"><small>What this means: {_cell(text)}</small></p>'


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
                ("Image digest", cert["image_digest"] or "image digest not recorded"),
                ("Source", task["source"]),
                ("Gold patch", _digest_text(task["gold_patch"])),
                ("Test patch", _digest_text(task["test_patch"])),
            ],
        ),
        _what_means("the task image is not pinned by digest in this certificate")
        if not cert["image_digest"]
        else "",
        "<p>The task prompt and hidden tests are not shown here; see the dataset instance "
        + _link_html("https://huggingface.co/datasets/nebius/SWE-rebench", task["instance_id"])
        + ".</p>",
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
        _what_means(
            "tests can be written by the attacker, the grader restores hidden tests before grading, and the "
            "list of unrestored non-root test paths is empty; root-writable paths are recorded separately above"
        )
        if exposure.get("tests_writable") is True
        and exposure.get("restore_covered") is False
        and exposure.get("unrestored_tests") == []
        else "",
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
        _what_means(
            "the classifier found no known shortcut in these rounds; the count is the number of "
            "evidence lines, not 16 shortcuts"
        )
        if any(
            "unclassified" in _map(_map(harden.get(r)).get("holes")).get("evidence_counts", {})
            for r in ROUNDS
        )
        else "",
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


def _round_block(label: str, rnd: Any, diff: str | None, attacker: Mapping[str, Any] | None = None) -> str:
    attacker = attacker or {}
    rnd = _map(rnd)
    attack = _map(rnd.get("attack"))
    grade = rnd.get("attack_grade")
    if attack:
        attack_rows = [
            ("Stop reason", attack.get("stop_reason")),
            ("Submitted", attack.get("submitted")),
            ("Auto-submitted by the harness", attack.get("auto_submitted", "not recorded")),
            (
                "Recon",
                "exposure-replay: the attacker was shown the BEFORE-hardening exposure scan, now stale"
                if attack.get("recon") == "exposure-replay"
                else attack.get("recon") or "none",
            ),
            ("Recon finding types", attack.get("recon_types") or "none"),
            ("Outcome", attack.get("outcome") or "none"),
            ("Steps used", _steps_used(attack, attacker)),
            ("Configured token budget", attacker.get("max_tokens")),
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


def _rounds_section(
    harden: Mapping[str, Any], diffs: Mapping[str, str | None], attacker: Mapping[str, Any]
) -> str:
    parts = [_round_block("Before hardening", harden["before"], diffs.get("before"), attacker)]
    if harden["after"] is None:
        parts.append("<h3>After hardening</h3>\n<p>No after round was run.</p>")
    else:
        parts.append(_round_block("After hardening", harden["after"], diffs.get("after"), attacker))
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
