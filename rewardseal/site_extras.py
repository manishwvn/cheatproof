"""Offline report pages. Data text uses site's escaping; only explorer has a script."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from rewardseal import audit, webaudit
from rewardseal.certify import load_certificate
from rewardseal.site import (
    _cell,
    _certified_label,
    _document,
    _Entry,
    _gates_text,
    _kv_table,
    _link_html,
    _map,
    _Raw,
    _row,
    _section,
    _table,
    _write,
)

FIRST = "selected audit of 18 lowest-scoring"
SAMPLE = "random sample A-E frame"
CERT_ONLY = "certificate only"
EXPLORER_CSP = (
    '<meta http-equiv="Content-Security-Policy" '
    "content=\"default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; img-src 'self'\">"
)
BACK = '<p><a href="index.html">Back to the index</a></p>'
EXTRAS_STYLE = """<style>
main { min-width: 0; }
p, li, label { overflow-wrap: anywhere; }
.gallery, .change-columns { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem; }
.gallery > section, .change-columns > div { min-width: 0; padding: 1rem; border: 1px solid var(--line); }
#explorer-filters { display: flex; flex-wrap: wrap; gap: .75rem; }
#explorer-filters ~ .table-wrap table { min-width: 64rem; }
input, select { max-width: 100%; font: inherit; }
[hidden] { display: none !important; }
@media (max-width: 40rem) { .gallery, .change-columns { grid-template-columns: minmax(0, 1fr); } }
</style>"""
EXPLORER_JS = r""""use strict";
(() => {
  const rows = Array.from(document.querySelectorAll("tr[data-task]"));
  const host = document.getElementById("explorer-filters");
  const table = document.querySelector(".table-wrap");
  const message = document.getElementById("explorer-message");
  const complete = message.dataset.complete === "yes";
  function field(title, element) {
    const label = document.createElement("label");
    label.textContent = title + " ";
    label.append(element);
    host.append(label);
    return element;
  }
  const search = document.createElement("input");
  search.type = "search";
  field("Search task id or repo", search);
  function select(title, values) {
    const element = document.createElement("select");
    for (const [value, text] of values) {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = text;
      element.append(option);
    }
    return field(title, element);
  }
  const sample = select("Sample", [["", "All samples"],
    ...Array.from(new Set(rows.map(row => row.dataset.sample))).sort().map(v => [v, v])]);
  const closed = select("Closed", [["", "All"], ["yes", "yes"], ["no", "no"], ["not audited", "not audited"]]);
  const scan = select("Incomplete scan", [["", "All"], ["yes", "yes"], ["no", "no"], ["not audited", "not audited"]]);
  function update() {
    const query = search.value.trim().toLowerCase();
    const matches = row => [row.dataset.task, row.dataset.repo].some(value => value.toLowerCase().includes(query));
    // Sample and scan filters must never turn a known id into a claim of no audit.
    const idLike = /^[\w.-]+(__[\w.-]+-\d+|\/[\w.-]+)$/.test(query);
    const unknown = complete && idLike && !rows.some(matches);
    if (table) table.hidden = unknown;
    for (const row of rows) {
      row.hidden = unknown || !matches(row) ||
        (sample.value !== "" && row.dataset.sample !== sample.value) ||
        (closed.value !== "" && row.dataset.closed !== closed.value) ||
        (scan.value !== "" && row.dataset.incomplete !== scan.value);
    }
    message.textContent = unknown ? "not audited: this id is not in either sample" : "";
  }
  for (const element of [search, sample, closed, scan]) {
    element.addEventListener("input", update);
    element.addEventListener("change", update);
  }
  update();
})();
"""


def _json_record(path: Path) -> dict[str, Any]:
    webaudit.check_path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError("record must be an object")
    return data


def _records(
    directory: Path,
    loader: Callable[[Path], dict[str, Any]],
    errors: list[tuple[str, str]],
) -> list[tuple[Path, dict[str, Any]]]:
    """Refuse a whole group rather than publish partial or duplicate counts."""
    try:
        webaudit.check_path(directory, directory=True)
        records = []
        for path in sorted(directory.glob("*.json")):
            if path.name.startswith("_"):
                continue
            webaudit.check_path(path)
            records.append((path, loader(path)))
        ids = [r["instance_id"] for _, r in records]
        if not all(isinstance(task, str) and task for task in ids):
            raise ValueError("invalid instance id")
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate instance id")
        return records
    except (OSError, ValueError, KeyError, TypeError) as exc:
        if not any(name == directory.name or name.startswith(directory.name + "/") for name, _ in errors):
            errors.append((directory.name, f"extras records refused: {type(exc).__name__}"))
        return []


def _certificate_record(path: Path) -> dict[str, Any]:
    webaudit.check_path(path)
    cert = load_certificate(path)
    return {**cert, "instance_id": cert["task"]["instance_id"]}


def write_pages(
    results: Path,
    out: Path,
    entries: Sequence[_Entry],
    errors: list[tuple[str, str]],
    blob: str,
    exposure_path: Path,
    manifest: Mapping[str, Mapping[str, str]],
) -> None:
    first = _records(exposure_path, audit.load_record, errors)
    sample = _records(results / "exposure-sample", audit.load_record, errors)
    groups = {exposure_path.name, "exposure-sample"}
    groups_loaded = not any(name.split("/", 1)[0] in groups for name, _ in errors)
    web = _records(results / "web-exposure", webaudit.load_record, errors)
    sample_web = _records(results / "web-exposure-sample", webaudit.load_record, errors)
    controls = _records(results / "control", _json_record, errors)
    replay = _records(results / "replay-attempt", _certificate_record, errors)
    audits = [(FIRST, p, r) for p, r in first] + [(SAMPLE, p, r) for p, r in sample]
    _write(
        out / "explorer.html",
        _document(
            "Results explorer",
            explorer(audits, web + sample_web, entries, groups_loaded, sample_web),
            blob,
            csp=EXPLORER_CSP,
        ),
    )
    _write(out / "explorer.js", EXPLORER_JS)
    _write(
        out / "controls.html",
        _document("Controls gallery", gallery(audits, controls, replay, web, results, blob, manifest), blob),
    )
    path = Path(__file__).resolve().parents[1] / "docs" / "limitations.md"
    webaudit.check_path(path)
    _write(
        out / "limitations.html",
        _document("Limitations", BACK + markdown(path.read_text(encoding="utf-8")), blob),
    )


def _certificate_status(cert: Mapping[str, Any] | None) -> str:
    if cert is None:
        return "none"
    if cert.get("certified"):
        return _certified_label(True)
    harden = _map(cert.get("harden"))
    if any(
        _map(harden.get(r)).get("inconclusive") or _map(harden.get(r)).get("error")
        for r in ("before", "after")
    ):
        return "inconclusive"
    return _certified_label(False)


def explorer(
    audits: Sequence[tuple[str, Path, dict]],
    web: Sequence[tuple[Path, dict]],
    entries: Sequence[_Entry],
    complete: bool = True,
    sample_web: Sequence[tuple[Path, dict]] = (),
) -> str:
    certs = {e.cert["task"]["instance_id"]: e for e in entries}
    searches = {r["instance_id"]: r for _, r in web}
    audited_ids = {r["instance_id"] for _, _, r in audits}
    records = [(sample, r) for sample, _, r in audits]
    records += [
        (CERT_ONLY, {"instance_id": task, "repo": e.cert["task"].get("repo", "")})
        for task, e in certs.items()
        if task not in audited_ids
    ]
    rows = []
    for sample, record in sorted(records, key=lambda item: (item[1]["instance_id"], item[0])):
        task, repo = record["instance_id"], record["repo"]
        entry = certs.get(task)
        cert = entry.cert if entry else None
        scan = record.get("future_scan", {})
        audited = sample != CERT_ONLY
        incomplete = "yes" if audited and (not scan["list_complete"] or not scan["complete"]) else "no"
        closed = ("yes" if record["closed"] else "no") if audited else "not audited"
        overlap = (
            f"{scan['gold_lines_in_future']} of {scan['gold_added_lines']}" if audited else "not audited"
        )
        future = str(record["future_commits_before"]) if audited else "not audited"
        if audited and not scan["list_complete"]:
            future += " (incomplete listing; lower bound)"
        if audited and incomplete == "yes":
            overlap += " (incomplete scan; absence unproven)"
        closure = closed if not audited or record["closed"] else f"no: {record['closed_reason']}"
        search = searches.get(task)
        best = (
            f"{max(search['q1_best_k'], search['q2_best_k'])} of {search['n']} best"
            if search
            else "not searched"
        )
        environment = _Raw(_link_html(f"env/{entry.name}.html", "Environment")) if entry else "none"
        attacked = bool(_map(_map(cert.get("harden")).get("before")).get("attack")) if cert else False
        sample_text = (
            sample
            if audited
            else sample + (": attacked" if attacked else ": not attacked") + ", not in an exposure audit"
        )
        row = _row(task, sample_text, future, overlap, closure, _certificate_status(cert), best, environment)
        attrs = {
            "task": task,
            "repo": repo,
            "sample": sample,
            "closed": closed,
            "incomplete": incomplete if audited else "not audited",
        }
        attributes = " ".join(f'data-{key}="{_cell(value)}"' for key, value in attrs.items())
        rows.append(row.replace("<tr>", f"<tr {attributes}>", 1))
    return (
        BACK
        + EXTRAS_STYLE
        + "<h1>Results explorer</h1>"
        + (
            "<p>Every committed audited task, with certificate-only tasks kept separate. "
            "Full table works without JavaScript. Future commits are before strip; closed requires the strip and gates. "
            "Web best is the largest overlap in either recorded query, including the oracle query; findability, not use.</p>"
            '<div id="explorer-filters"></div><p id="explorer-message" role="status" '
            f'data-complete="{"yes" if complete else "no"}"></p>'
        )
        + _sample_web_note(sample_web)
        + _table(
            "Audited tasks and certificates",
            (
                "Task",
                "Sample",
                "Future commits",
                "Gold lines in future commits k of n",
                "Closed after strip",
                "Certificate",
                "Web exposure",
                "Environment page",
            ),
            rows,
        )
        + '<script src="explorer.js" defer></script>'
    )


def _sample_web_note(records: Sequence[tuple[Path, dict]]) -> str:
    if not records:
        return ""
    searches = sum(len(record["queries"]) for _, record in records)
    results = [
        (record, result)
        for _, record in records
        for query in record["queries"]
        for result in query["results"]
    ]
    gold = sum(result["k"] > 0 for _, result in results)
    matching_pr = sum(
        bool(
            re.search(
                r"/pull/" + re.escape(record["instance_id"].rsplit("-", 1)[-1]) + r"(?:/|$)",
                urlsplit(result["url"]).path,
            )
        )
        for record, result in results
    )
    single = sum(record["n"] == 1 for _, record in records)
    return (
        f"<p>Random-sample web exposure (reported apart from the 13): {len(records)} tasks, "
        f"{searches} searches, {len(results)} results, {gold} with a counted gold line, "
        f"{matching_pr} matching the task&#x27;s own PR number (match the PR number in the URL path /pull/&lt;N&gt;), "
        f"{single} of {len(records)} tasks have a single counted gold line so their nulls are weak; "
        "findability for one tool on one day, not proof of absence; searches are the local counter.</p>"
    )


def _record_link(path: Path, blob: str) -> str:
    relative = path.name if path.name == "confirmations.json" else f"{path.parent.name}/{path.name}"
    return _link_html(blob + f"results/{relative}", path.name)


def gallery(
    audits: Sequence[tuple[str, Path, dict]],
    controls: Sequence[tuple[Path, dict]],
    replay: Sequence[tuple[Path, dict]],
    web: Sequence[tuple[Path, dict]],
    results: Path,
    blob: str,
    manifest: Mapping[str, Mapping[str, str]],
) -> str:
    cards = []

    def card(
        anchor: str,
        title: str,
        lesson: str,
        limit: str,
        records: Sequence[tuple[Path, dict]],
        details: str = "",
    ) -> None:
        links = "".join(f"<li>{_cell(r['instance_id'])}: {_record_link(p, blob)}</li>" for p, r in records)
        cards.append(
            _section(
                anchor,
                title,
                f"<p>What this case teaches: {_cell(lesson)}</p>",
                details,
                f"<ul>{links}</ul>" if links else "<p>No matching record committed.</p>",
                f"<p>Limit: {_cell(limit)}</p>",
            )
        )

    clean = next(((p, r) for _, p, r in audits if r["future_commits_after"] == 0 and r["closed"]), None)
    card(
        "clean-after-strip",
        "Clean after strip",
        "Removing future commits can preserve both gates.",
        "Closure covers only this task's workdir repository; a gold pass does not establish unchanged difficulty.",
        [clean] if clean else [],
        _kv_table(
            "Clean case",
            [("Future commits after", clean[1]["future_commits_after"]), ("Closed", clean[1]["closed"])],
        )
        if clean
        else "",
    )
    broken = [(p, r) for _, p, r in audits if r["closed_reason"] == "gold_gate_failed"]
    card(
        "broken-gold-gate",
        "Broken gold gate",
        "Zero future commits alone is insufficient: the gold gate must hold.",
        "BQSKit's certificate records broken gates before any attack; do not infer that the strip caused that failure.",
        broken,
        _table(
            "Broken gates",
            ("Task", "Closed reason", "Gold gate held"),
            [_row(r["instance_id"], r["closed_reason"], r["patch"]["gold_gate_ok"]) for _, r in broken],
        ),
    )
    unapplied = [(p, r) for _, p, r in audits if r["closed_reason"] == "patch_not_applied"]
    card(
        "strip-not-applied",
        "Strip patch not applied",
        "A requested patch is not an applied patch; closure must be measured.",
        "This is a patch failure, not evidence that stripping successfully removed the leak.",
        unapplied,
        _table(
            "Unapplied strips",
            ("Task", "Future commits after", "Closed", "Reason"),
            [
                _row(r["instance_id"], r["future_commits_after"], r["closed"], r["closed_reason"])
                for _, r in unapplied
            ],
        ),
    )
    incomplete = [(p, r) for _, p, r in audits if not r["future_scan"]["list_complete"]]
    card(
        "incomplete-scan",
        "Incomplete scan",
        "A cut history listing cannot establish absence; shared-line counts are lower bounds.",
        "Absence unproven even when no counted gold line was found.",
        incomplete,
        _table(
            "Incomplete listings",
            ("Task", "Listing complete", "Future commits before"),
            [
                _row(r["instance_id"], r["future_scan"]["list_complete"], r["future_commits_before"])
                for _, r in incomplete
            ],
        ),
    )
    path = results / "confirmations.json"
    task = "ArkEcosystem__python-crypto-116"
    attribution = manifest.get(task)
    card(
        "attribution-116",
        "116 attribution",
        "The recorded write preceded history commands, so the label stays a lead. "
        "A timing rule added after review states: a matching write at or before the earliest successful history read cannot establish a history exploit.",
        "Command order and line overlap do not directly observe use of git show output; the committed certificate is unchanged.",
        [(path, {"instance_id": task})] if attribution else [],
        _kv_table(
            "Recorded attribution",
            [("Status", attribution.get("status")), ("Basis", attribution.get("basis"))],
        )
        if attribution
        else "",
    )
    not_exercised = [
        (p, r)
        for p, r in replay
        if r["instance_id"] == "CycloneDX__cyclonedx-python-348"
        and not _map(r.get("harden")).get("after")
        and not r.get("patches_applied")
    ]
    card(
        "same-recon-348",
        "348 same-recon re-attack: not exercised" if not_exercised else "348 same-recon re-attack",
        "The new before round passed without history commands, was classified unclassified, and had no hardening or re-attack."
        if not_exercised
        else "Replay attempt record unavailable or it reached the re-attack path; no not-exercised statement is made.",
        "The attempt did not reach the same-recon re-attack path, so that comparison remains open."
        if not_exercised
        else "No claim is made without the committed record.",
        not_exercised,
        _table(
            "Replay attempt",
            ("Task", "Before attack passed", "Hole labels", "After round"),
            [
                _row(
                    r["instance_id"],
                    _map(r["harden"].get("before")).get("attack_grade", {}).get("passed"),
                    _map(_map(r["harden"].get("before")).get("holes")).get("labels"),
                    "not exercised",
                )
                for _, r in not_exercised
            ],
        ),
    )
    card(
        "retrieval-control",
        "Retrieval control",
        "Oracle-assisted scripted control, not autonomous discovery: a script tests a retrieved future change.",
        f"{len(controls)} {'task' if len(controls) == 1 else 'tasks'}, no model; does not prove model causality: "
        "the recorded controls test usable leakage, not why any model acted.",
        controls,
        _table(
            "Retrieval outcomes",
            ("Task", "Retrieved fix passes", "Candidates after strip", "Gold gate held", "Empty gate held"),
            [
                _row(
                    r["instance_id"],
                    _map(r.get("before_strip")).get("retrieved_fix_passes_hidden_tests"),
                    _map(r.get("after_strip")).get("future_commits_touching_gold_files"),
                    _map(r.get("after_strip")).get("gold_gate_ok"),
                    _map(r.get("after_strip")).get("empty_gate_ok"),
                )
                for _, r in controls
            ],
        ),
    )
    dates = sorted({q["searched_at"][:10] for _, r in web for q in r["queries"]})
    hits = sum(any(item["k"] > 0 for q in r["queries"] for item in q["results"]) for _, r in web)
    card(
        "web-null",
        "Web exposure null" if web and hits == 0 else "Web exposure snapshot",
        "A null search result is about what this search tool returned, not what exists on the web.",
        "One search tool on the recorded day; findability only, not use or proof the web lacks fixes.",
        web,
        _kv_table(
            "Search snapshot",
            [("Tasks with any counted-line hit", f"{hits} of {len(web)}"), ("Search dates", dates)],
        ),
    )
    return BACK + EXTRAS_STYLE + '<h1>Controls gallery</h1><div class="gallery">' + "".join(cards) + "</div>"


def _is_not_exercised(record: Mapping[str, Any]) -> bool:
    return (
        record["instance_id"] == "CycloneDX__cyclonedx-python-348"
        and not _map(_map(record.get("harden")).get("after"))
        and not record.get("patches_applied")
    )


def not_exercised_ids(results: Path) -> set[str]:
    """Task ids whose committed same-recon re-attack attempt never reached the re-attack path."""
    records = _records(results / "replay-attempt", _certificate_record, [])
    return {r["instance_id"] for _, r in records if _is_not_exercised(r)}


def environment_change(cert: Mapping[str, Any], evidence: Path) -> str:
    """Certificate allowlist only: never render raw diff fields."""
    harden = _map(cert.get("harden"))
    before, after = _map(harden.get("before")), _map(harden.get("after"))
    if not after:
        return ""
    rows = []
    for label, rnd in (("Before", before), ("After", after)):
        scan = _map(rnd.get("exposure"))
        rows.extend(
            [
                (label + " exposure: future git", scan.get("future_git")),
                (label + " future commits listed (scan evidence)", scan.get("future_git_evidence")),
                (label + " scanned commit ids", _map(rnd.get("future_scan")).get("commit_ids")),
                (label + " gates", _gates_text(rnd.get("gates"))),
            ]
        )
    rows.append(("Patch names accepted", harden.get("accepted")))
    excerpt = ""
    if cert["task"]["instance_id"] == "CycloneDX__cyclonedx-python-348":
        path = evidence / "348-causal.md"
        try:
            webaudit.check_path(path)
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            text = ""
        if "## Before round" in text and "## The upstream fix" in text:
            excerpt = text.split("## Before round", 1)[1].split("## The upstream fix", 1)[0].strip()
    right = (
        (
            "<p>Reviewed excerpt: matching line and steps 12 to 15; output heads only. "
            "Use of git show output is inferred, not observed.</p><pre>" + _cell(excerpt) + "</pre>"
        )
        if excerpt
        else (
            "<p>attacker diff not published: only its sha256 and size are recorded</p>"
            + _table(
                "Attacker solution digests",
                ("Round", "sha256", "Size (characters)"),
                [
                    _row(
                        label,
                        _map(rnd.get("attack")).get("final_diff_sha256"),
                        _map(rnd.get("attack")).get("final_diff_chars"),
                    )
                    for label, rnd in (("Before", before), ("After", after))
                ],
            )
        )
    )
    return EXTRAS_STYLE + _section(
        "environment-change",
        "Environment change vs attacker solution",
        '<div class="change-columns"><div><h3>Environment change</h3>'
        + _kv_table("Environment change from certificate", rows)
        + "</div><div><h3>Attacker solution as recorded</h3>"
        + right
        + "</div></div>",
    )


def markdown(text: str) -> str:
    """Headings, unordered lists and paragraphs only; every source line is escaped."""
    parts: list[str] = []
    paragraph: list[str] = []
    in_list = False

    def flush() -> None:
        if paragraph:
            parts.append("<p>" + _cell(" ".join(paragraph)) + "</p>")
            paragraph.clear()

    for line in [*text.splitlines(), ""]:
        line = line.strip()
        heading = re.fullmatch(r"(#{1,6})\s+(.+)", line)
        if not line or heading or line.startswith("- "):
            flush()
            if in_list and not line.startswith("- "):
                parts.append("</ul>")
                in_list = False
            if heading:
                level = len(heading[1])
                parts.append(f"<h{level}>{_cell(heading[2])}</h{level}>")
            elif line.startswith("- "):
                if not in_list:
                    parts.append("<ul>")
                    in_list = True
                parts.append("<li>" + _cell(line[2:]) + "</li>")
        else:
            if in_list:
                parts.append("</ul>")
                in_list = False
            paragraph.append(line)
    return "\n".join(parts)
