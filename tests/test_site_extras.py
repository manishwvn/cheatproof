"""Offline extras checks against isolated copies of the committed records."""

import html
import json
import re
import shutil
from pathlib import Path

import pytest

from rewardseal import site, site_extras

RESULTS = Path(__file__).resolve().parents[1] / "results"
TASK = "CycloneDX__cyclonedx-python-348"
LINE = "if isinstance(package_data.get('hashes'), list):"


@pytest.fixture
def records(tmp_path):
    root = tmp_path / "results"
    root.mkdir()
    for name in (
        "certificates",
        "exposure",
        "exposure-sample",
        "web-exposure",
        "web-exposure-sample",
        "control",
        "replay-attempt",
        "evidence",
        "replications",
    ):
        shutil.copytree(RESULTS / name, root / name)
    shutil.copyfile(RESULTS / "confirmations.json", root / "confirmations.json")
    return root


def build(root):
    result = site.build_site(root / "certificates", root.parent / "site")
    assert result.errors == []
    return result.index.parent


def rows(page):
    return [
        (
            dict(re.findall(r'data-([\w-]+)="([^"]*)"', attrs)),
            [html.unescape(re.sub(r"<[^>]+>", "", cell)) for cell in re.findall(r"<td>(.*?)</td>", body)],
        )
        for attrs, body in re.findall(r"<tr ([^>]+)>(.*?)</tr>", page)
    ]


def section(page, anchor):
    return page.split(f'id="{anchor}"', 1)[1].split("</section>", 1)[0]


def test_explorer_lists_every_audit_and_certificate_with_recorded_values(records):
    out = build(records)
    page = (out / "explorer.html").read_text()
    actual = {(attrs["sample"], cells[0]): (attrs, cells) for attrs, cells in rows(page)}
    expected = set()
    audited = set()
    for folder, label in (("exposure", site_extras.FIRST), ("exposure-sample", site_extras.SAMPLE)):
        for path in (records / folder).glob("*.json"):
            if path.name.startswith("_"):
                continue
            record = json.loads(path.read_text())
            task = record["instance_id"]
            audited.add(task)
            expected.add((label, task))
            attrs, cells = actual[label, task]
            scan = record["future_scan"]
            assert cells[2].startswith(str(record["future_commits_before"]))
            assert cells[3].startswith(f"{scan['gold_lines_in_future']} of {scan['gold_added_lines']}")
            assert cells[4] == ("yes" if record["closed"] else "no: " + record["closed_reason"])
            assert attrs["incomplete"] == ("no" if scan["list_complete"] and scan["complete"] else "yes")
            assert attrs["closed"] == ("yes" if record["closed"] else "no")
            if not scan["list_complete"]:
                assert "lower bound" in cells[2]
            if attrs["incomplete"] == "yes":
                assert "absence unproven" in cells[3]
    for path in (records / "certificates").glob("*.json"):
        cert = json.loads(path.read_text())
        task = cert["task"]["instance_id"]
        if task not in audited:
            expected.add((site_extras.CERT_ONLY, task))
            attrs, cells = actual[site_extras.CERT_ONLY, task]
            assert "not in an exposure audit" in cells[1]
            assert cells[2:5] == ["not audited"] * 3
            assert attrs["incomplete"] == "not audited"
    assert set(actual) == expected
    for href in re.findall(r'href="(env/[^"]+)"', page):
        assert (out / href).is_file()
    assert "certified yes" in page and "certified no" in page and "inconclusive" in page
    assert "not attacked, not in an exposure audit" in page


def test_attacked_certificate_only_row_and_web_best(records):
    # Reuse a real certificate but omit its audit from this isolated build.
    next((records / "exposure").glob("*348*.json")).rename(records / "omitted-audit.json")
    path = next((records / "web-exposure").glob("*348*.json"))
    record = json.loads(path.read_text())
    out = build(records)
    actual = {cells[0]: cells for _, cells in rows((out / "explorer.html").read_text())}
    assert actual[TASK][1] == "certificate only: attacked, not in an exposure audit"
    assert actual[TASK][6] == f"{max(record['q1_best_k'], record['q2_best_k'])} of {record['n']} best"
    assert site_extras._certificate_status(None) == "none"


def test_scripts_and_csp_are_scoped_to_explorer(records):
    out = build(records)
    explorer = (out / "explorer.html").read_text()
    assert '<script src="explorer.js" defer></script>' in explorer
    assert len(re.findall(r"<script\b", explorer)) == 1
    assert site_extras.EXPLORER_CSP in explorer
    script = (out / "explorer.js").read_text()
    assert "innerHTML" not in script and "textContent" in script
    assert "not audited: this id is not in either sample" in script
    for path in out.rglob("*.html"):
        text = path.read_text()
        if path.name == "explorer.html":
            continue
        assert "<script" not in text
        if path.name == "index.html":
            assert "Content-Security-Policy" not in text
        else:
            assert site.CSP_META in text


def test_index_links_and_workflow_comparison(records):
    out = build(records)
    index = (out / "index.html").read_text()
    nav = index.split('<nav aria-label="Report">', 1)[1].split("</nav>", 1)[0]
    for target in ("explorer.html", "controls.html", "limitations.html", "verify.html", "#numbers-key"):
        assert f'href="{target}"' in nav
    assert 'href="explorer.html"' in section(index, "reading-guide")
    comparison = section(index, "workflow-comparison")
    assert all(
        text in comparison
        for text in ("Manual", "RewardSeal", "Still needs a human", "audit-exposure", "harden")
    )
    assert (
        index.index('id="reading-guide"')
        < index.index('id="workflow-comparison"')
        < index.index('id="start-here"')
    )
    stub = (
        out / "verify.html"
    ).read_text()  # local placeholder; the Pages workflow replaces it with the verifier
    assert "<script" not in stub and "placeholder" in stub


def test_controls_gallery_uses_correct_cases_and_record_links(records):
    out = build(records)
    page = (out / "controls.html").read_text()
    expected = {
        "clean-after-strip": ["12rambau__sepal_ui-518"],
        "broken-gold-gate": [
            "AzureAD__microsoft-authentication-library-for-python-186",
            "BQSKit__bqskit-134",
            "gold_gate_failed",
        ],
        "strip-not-applied": ["Becksteinlab__numkit-8", "55", "patch_not_applied"],
        "incomplete-scan": ["CS-SI__eodag-249", "Azure__azure-cli-1876", "Absence unproven"],
        "attribution-116": [
            "ArkEcosystem__python-crypto-116",
            "timing rule added after review",
            "lead",
            "step 31",
        ],
        "same-recon-348": [TASK, "not exercised", "unclassified"],
        "retrieval-control": [
            "Dorthu__openapi3-75",
            "no model",
            "Oracle-assisted scripted control, not autonomous discovery",
            "does not prove model causality",
        ],
        "web-null": ["0 of 13", "2026-10-29", "One search tool"],
    }
    for anchor, texts in expected.items():
        card = section(page, anchor)
        assert all(text in card for text in texts)
        assert "What this case teaches:" in card and "Limit:" in card
        links = re.findall(r'href="([^"]+)"', card)
        assert links
        for link in links:
            relative = link.split("/blob/main/", 1)[1]
            assert (RESULTS.parent / relative).is_file()
    assert "BQSKit&#x27;s certificate records broken gates before any attack" in page


def test_limitations_disclosure_and_escaped_markdown(records, monkeypatch):
    docs = records.parent / "docs"
    docs.mkdir()
    source = (RESULTS.parent / "docs" / "limitations.md").read_text()
    (docs / "limitations.md").write_text(source + "\nUntrusted <script> & text.\n")
    monkeypatch.setattr(site_extras, "__file__", str(records.parent / "rewardseal" / "site_extras.py"))
    out = build(records)
    page = (out / "limitations.html").read_text()
    assert "This tool is for authorized evaluation environments." in page
    assert "Do not use findings to cheat on benchmarks or leaderboards." in page
    assert "unpublished fixes, secrets or private data" in page
    assert "github.com/manishwvn/rewardseal/issues" in page
    assert "Untrusted &lt;script&gt; &amp; text." in page and "<script>" not in page
    rendered = site_extras.markdown(
        "# Title <x>\n\nText <script>\ncontinues & ends.\n\n- Item <img>\n- Other\n\n## Next\n"
    )
    assert "<h1>Title &lt;x&gt;</h1>" in rendered
    assert "<p>Text &lt;script&gt; continues &amp; ends.</p>" in rendered
    assert "<ul>\n<li>Item &lt;img&gt;</li>\n<li>Other</li>\n</ul>" in rendered
    assert rendered.endswith("<h2>Next</h2>")
    assert site_extras.markdown("- last") == "<ul>\n<li>last</li>\n</ul>"


def test_environment_viewer_uses_reviewed_evidence_or_digests_only(records):
    out = build(records)
    cert = json.loads(next((records / "certificates").glob("*348*.json")).read_text())
    block = section(next((out / "env").glob("*348*.html")).read_text(), "environment-change")
    assert html.escape(LINE, quote=True) in block
    for step in range(12, 16):
        assert f"**Step {step}**" in block
    assert "inferred, not observed" in block
    assert "## The upstream fix" not in block
    assert "378 commit(s) past base reachable from refs" in block
    assert "strip-future-git" in block
    assert "gold pass, empty fail" in block
    cert = json.loads(next((records / "certificates").glob("*116*.json")).read_text())
    for rnd in ("before", "after"):
        cert["harden"][rnd]["attack"]["final_diff"] = "UNPUBLISHED_DIFF_SENTINEL"
        cert["harden"][rnd]["diff"] = "UNPUBLISHED_DIFF_SENTINEL"
    block = site_extras.environment_change(cert, records / "evidence")
    assert "attacker diff not published: only its sha256 and size are recorded" in block
    assert "UNPUBLISHED_DIFF_SENTINEL" not in block
    for rnd in ("before", "after"):
        attack = cert["harden"][rnd]["attack"]
        assert attack["final_diff_sha256"] in block
        assert str(attack["final_diff_chars"]) in block
    assert site_extras.environment_change({"harden": {"after": None}}, records / "evidence") == ""


def test_new_data_is_escaped_in_cells_attributes_and_evidence(records):
    payload = '<script>"unsafe"</script>\u202e'
    path = records / "control" / "Dorthu__openapi3-75-retrieval-control.json"
    record = json.loads(path.read_text())
    record["instance_id"] = payload
    path.write_text(json.dumps(record))
    evidence = records / "evidence" / "348-causal.md"
    evidence.write_text(evidence.read_text().replace(LINE, payload))
    out = build(records)
    escaped = "&lt;script&gt;&quot;unsafe&quot;&lt;/script&gt;[U+202E]"
    assert escaped in (out / "controls.html").read_text()
    assert escaped in next((out / "env").glob("*348*.html")).read_text()
    record = json.loads(next((records / "exposure").glob("*348*.json")).read_text())
    record["instance_id"], record["repo"] = payload, payload
    page = site_extras.explorer([(site_extras.FIRST, path, record)], [], [])
    assert f'data-task="{escaped}"' in page and f'data-repo="{escaped}"' in page
    assert payload not in page


@pytest.mark.parametrize("kind", ["invalid", "symlink", "duplicate"])
def test_refused_extra_records_report_errors_without_partial_counts(records, kind):
    folder = records / "control"
    path = folder / "Dorthu__openapi3-75-retrieval-control.json"
    if kind == "invalid":
        (folder / "bad.json").write_text("{")
    elif kind == "symlink":
        (folder / "bad.json").symlink_to(path)
    else:
        shutil.copyfile(path, folder / "duplicate.json")
    result = site.build_site(records / "certificates", records.parent / "site")
    assert [name for name, _ in result.errors] == ["control"]
    card = section((result.index.parent / "controls.html").read_text(), "retrieval-control")
    assert "No matching record committed." in card
    assert "Dorthu__openapi3-75" not in card


def test_unknown_id_claim_needs_complete_groups_and_full_id_pattern(records):
    page = (build(records) / "explorer.html").read_text()
    assert 'id="explorer-message" role="status" data-complete="yes"' in page
    js = (build(records) / "explorer.js").read_text()
    assert "complete && idLike" in js
    assert r"/^[\w.-]+(__[\w.-]+-\d+|\/[\w.-]+)$/" in js
    (records / "exposure-sample" / "_selection.json").write_text("{}")
    broken = next((records / "exposure-sample").glob("[!_]*.json"))
    broken.write_text("{}")
    result = site.build_site(records / "certificates", records.parent / "site2")
    assert result.errors
    assert 'data-complete="no"' in (result.index.parent / "explorer.html").read_text()


def test_replay_card_states_nothing_without_the_record(records):
    for path in (records / "replay-attempt").glob("*.json"):
        path.unlink()
    page = (build(records) / "controls.html").read_text()
    card = section(page, "same-recon-348")
    assert "not exercised" not in card.lower() or "no not-exercised statement" in card
    assert "No matching record committed." in card


def test_cold_read_wording_fixes(records):
    out = build(records)
    page = (out / "env" / "ArkEcosystem__python-crypto-116-cb6ec271.html").read_text()
    assert "unconfirmed lead, not a confirmed cause" in page
    assert "hole still found" not in page
    page348 = (out / "env" / "CycloneDX__cyclonedx-python-348-93d44b30.html").read_text()
    assert "Certified is not release-approved; same-recon re-attack not exercised." in page348
    assert "Certified is not release-approved" not in page
    assert "Recorded counts, not a score" in (out / "index.html").read_text()


def test_random_sample_web_exposure_and_refusal(records):
    sample = [
        json.loads(p.read_text())
        for p in (records / "web-exposure-sample").glob("*.json")
        if not p.name.startswith("_")
    ]
    out = build(records)
    explorer = (out / "explorer.html").read_text()
    actual = {cells[0]: cells for _, cells in rows(explorer)}
    record = sample[0]
    assert (
        actual[record["instance_id"]][6]
        == f"{max(record['q1_best_k'], record['q2_best_k'])} of {record['n']} best"
    )
    assert "9 tasks, 18 searches, 90 results, 0 with a counted gold line, 0 matching" in explorer
    assert "4 of 9 tasks have a single counted gold line" in explorer
    assert "0 of 13" in (out / "controls.html").read_text()
    index = (out / "index.html").read_text()
    assert "Random-sample web exposure" not in index
    folder = records / "web-exposure-sample"
    omitted = records / "omitted-web-sample"
    folder.rename(omitted)
    comparison = site.build_site(records / "certificates", records.parent / "without-sample")
    assert comparison.errors == []
    assert comparison.index.read_text() == index
    assert (comparison.index.parent / "controls.html").read_text() == (out / "controls.html").read_text()
    omitted.rename(folder)
    (folder / "bad.json").write_text("{}")
    result = site.build_site(records / "certificates", records.parent / "bad-site")
    assert any(name == "web-exposure-sample" for name, _ in result.errors)
    assert "Random-sample web exposure" not in (result.index.parent / "explorer.html").read_text()
    bad_rows = {cells[0]: cells for _, cells in rows((result.index.parent / "explorer.html").read_text())}
    assert bad_rows[record["instance_id"]][6] == "not searched"


def test_index_intro_and_order(records):
    index = (build(records) / "index.html").read_text()
    assert (
        "RewardSeal audits coding-agent training tasks for exposed fixes and other reward-hacking shortcuts, strips what it can, re-checks, and records one attacker&#x27;s results."
        in index
    )
    assert (
        "Built with Nebius Token Factory, NVIDIA Nemotron (nemotron-3-super-120b-a12b), Nebius Sandboxes, Tavily"
        in index
    )
    assert '<a href="https://github.com/manishwvn/rewardseal">Repository</a>' in index
    assert index.index('id="reading-guide"') < index.index('id="numbers-key"')


def test_sample_note_counts_pr_path_numbers_exactly():
    record = {
        "instance_id": "owner__repo-12",
        "n": 1,
        "queries": [
            {
                "results": [
                    {"k": 1, "url": "https://example.com/owner/repo/pull/12/files"},
                    {"k": 0, "url": "https://example.com/owner/repo/pull/123"},
                    {"k": 0, "url": "https://example.com/other?redirect=/pull/12"},
                ]
            }
        ],
    }
    note = site_extras._sample_web_note([(Path("sample.json"), record)])
    assert "1 tasks, 1 searches, 3 results, 1 with a counted gold line, 1 matching" in note
    assert "1 of 1 tasks have a single counted gold line" in note


def test_long_unbroken_text_wraps_on_every_page(records):
    out = build(records)
    for name in ("index.html", "limitations.html", "explorer.html", "controls.html"):
        assert "p, li { overflow-wrap: anywhere; }" in (out / name).read_text(), name
