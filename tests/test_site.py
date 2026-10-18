"""Tests for cheatproof/site.py (queue T09, part A).

Certificates come from the fixture builders in test_certify.py and are written with certify.write_certificate. Traces
are written by hand. No model, network or sandbox run.
"""

import dataclasses
import json
import re
from pathlib import Path

import pytest
from test_certify import cert_for, clean_report, fixed_report, still_report

from cheatproof.certify import score_directory, write_certificate
from cheatproof.site import build_site

CSP_META = (
    """<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">"""
)
PAYLOAD = "<script>alert(1)</script>"
ATTR_PAYLOAD = '"onload=alert(1)'
NAMES = ["owner__repo-1.html", "owner__repo-2.html", "owner__repo-3.html"]


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def write_certs(directory: Path, *reports) -> list[Path]:
    """One certificate per report, written into directory. Returns the paths."""
    return [write_certificate(cert_for(report), directory) for report in reports]


def fixture_dir(tmp_path: Path) -> Path:
    """Three environments: exploited and then fixed, clean, and exploited with no fix."""
    cert_dir = tmp_path / "certs"
    write_certs(
        cert_dir,
        fixed_report("owner__repo-1"),
        clean_report("owner__repo-2"),
        still_report("owner__repo-3"),
    )
    return cert_dir


def write_trace(traces: Path, name: str, lines: list[str]) -> None:
    traces.mkdir(parents=True, exist_ok=True)
    (traces / f"{name}.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")


def trace_lines(payload: str = f"{PAYLOAD} {ATTR_PAYLOAD}") -> list[str]:
    """A header, a step with a digest, a bad line, a step with no keys, and an end record."""
    step = {
        "type": "step",
        "step": 1,
        "tool": "run",
        "args": {"cmd": "cat .git/packed-refs", "note": payload},
        "result_digest": {"sha256": "ab" * 32, "head": "ok", "chars": 2},
        "error": None,
        "tokens_in": 120,
        "tokens_out": 30,
    }
    return [
        json.dumps({"type": "header", "model": "nvidia/nemotron-test", "max_steps": 20}),
        json.dumps(step),
        "not json at all {",
        json.dumps({"type": "step"}),
        json.dumps({"type": "end", "stop_reason": "submit", "steps": 1, "tokens_in": 120, "tokens_out": 30}),
    ]


def test_index_lists_each_environment_with_working_relative_links(tmp_path):
    cert_dir = fixture_dir(tmp_path)
    out = tmp_path / "site"
    result = build_site(cert_dir, out)
    index = read(result.index)
    assert result.index == out / "index.html"
    assert [page.name for page in result.pages] == NAMES
    links = re.findall(r'<a href="(env/[^"]+)">', index)
    assert links == [f"env/{name}" for name in NAMES]
    for link in links:
        page = out / link
        assert page.is_file()
        assert (page.parent / "../index.html").resolve() == result.index.resolve()


def test_env_page_shows_gates_holes_patches_and_the_recorded_label(tmp_path):
    cert_dir = fixture_dir(tmp_path)
    out = tmp_path / "site"
    build_site(cert_dir, out)
    page = read(out / "env" / "owner__repo-1.html")
    assert page.count("<h1>") == 1
    assert '<html lang="en">' in page
    assert '<span class="label">recorded</span>' in page
    assert (
        "<td>Before hardening</td><td>pass</td><td>fail</td><td>yes</td>" in page
    )  # gold passes, empty fails
    assert "<td>git-history</td>" in page  # the exploited hole
    assert "<td>strip-future-git</td>" in page  # the accepted patch
    assert "<td>After hardening</td><td>pass</td><td>fail</td><td>yes</td>" in page
    assert '<th scope="row">Image digest</th><td>not recorded</td>' in page
    assert "attack diff not recorded in certificate" in page
    assert '<a href="../index.html">' in page


def test_clean_environment_shows_no_after_round(tmp_path):
    cert_dir = fixture_dir(tmp_path)
    out = tmp_path / "site"
    build_site(cert_dir, out)
    page = read(out / "env" / "owner__repo-2.html")
    assert "No after round was run." in page
    assert "<td>After hardening</td><td>not run</td>" in page
    assert '<th scope="row">Certified</th><td>yes</td>' in page  # clean_report is certified


def test_empty_directory_shows_the_empty_state(tmp_path):
    cert_dir = tmp_path / "certs"
    cert_dir.mkdir()
    out = tmp_path / "site"
    result = build_site(cert_dir, out)
    index = read(result.index)
    assert result.pages == []
    assert result.errors == []
    assert "No certificates were found" in index
    assert "python -m cheatproof.cli harden" in index
    assert "Hackability score" not in index
    assert list((out / "env").iterdir()) == []


def test_bad_files_are_listed_and_the_valid_ones_still_build(tmp_path):
    cert_dir = tmp_path / "certs"
    write_certs(cert_dir, fixed_report("owner__repo-1"))
    (cert_dir / "broken.json").write_text("{not json", encoding="utf-8")
    (cert_dir / "wrong.json").write_text('{"schema": "other"}', encoding="utf-8")
    out = tmp_path / "site"
    result = build_site(cert_dir, out)
    assert [name for name, _ in result.errors] == ["broken.json", "wrong.json"]
    assert all(message for _, message in result.errors)
    assert [page.name for page in result.pages] == ["owner__repo-1.html"]
    index = read(result.index)
    assert "Files that failed to load" in index
    assert "broken.json" in index
    assert "wrong.json" in index
    assert "owner__repo-1" in index
    assert str(tmp_path) not in index  # no absolute path reaches the site
    assert all(str(tmp_path) not in message for _, message in result.errors)


def test_script_and_attribute_payloads_appear_only_escaped(tmp_path):
    report = dataclasses.replace(fixed_report("owner__repo-1"), notes=(PAYLOAD,))
    cert_dir = tmp_path / "certs"
    write_certs(cert_dir, report)
    traces = tmp_path / "traces"
    write_trace(traces, "owner__repo-1", trace_lines())
    out = tmp_path / "site"
    result = build_site(cert_dir, out, traces_dir=traces)
    page = read(result.pages[0])
    index = read(result.index)
    for text in (page, index):
        assert PAYLOAD not in text
        assert '"onload=' not in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page  # the certificate note
    assert "&quot;onload=alert(1)" in page  # the trace argument


def test_transcript_renders_each_line_and_flags_the_bad_one(tmp_path):
    cert_dir = fixture_dir(tmp_path)
    traces = tmp_path / "traces"
    write_trace(traces, "owner__repo-1", trace_lines(payload="plain"))
    out = tmp_path / "site"
    build_site(cert_dir, out, traces_dir=traces)
    page = read(out / "env" / "owner__repo-1.html")
    assert "no transcript recorded" not in page
    assert page.count("unreadable line") == 1
    assert '<td colspan="8">unreadable line</td>' in page  # the bad third line
    assert "cat .git/packed-refs" in page
    assert f"sha256 {'ab' * 6}, 2 chars" in page
    assert "stop submit" in page
    assert "<td>120</td><td>30</td>" in page  # tokens of the step
    assert "<td>4</td><td>step</td>" in page  # a step with no keys still gets a row


def test_missing_transcript_says_no_transcript_recorded(tmp_path):
    cert_dir = fixture_dir(tmp_path)
    out = tmp_path / "no_traces"
    build_site(cert_dir, out)
    assert "no transcript recorded" in read(out / "env" / "owner__repo-1.html")
    empty_traces = tmp_path / "empty_traces"
    empty_traces.mkdir()
    out2 = tmp_path / "empty_traces_site"
    build_site(cert_dir, out2, traces_dir=empty_traces)
    assert "no transcript recorded" in read(out2 / "env" / "owner__repo-1.html")


def test_two_builds_give_identical_bytes(tmp_path):
    cert_dir = fixture_dir(tmp_path)
    traces = tmp_path / "traces"
    write_trace(traces, "owner__repo-1", trace_lines())
    first, second = tmp_path / "first", tmp_path / "second"
    build_site(cert_dir, first, traces_dir=traces)
    build_site(cert_dir, second, traces_dir=traces)
    files = sorted(path.relative_to(first) for path in first.rglob("*") if path.is_file())
    assert len(files) == 1 + len(NAMES)
    for relative in files:
        assert (first / relative).read_bytes() == (second / relative).read_bytes()
    before = (first / "index.html").read_bytes()
    build_site(cert_dir, first, traces_dir=traces)  # rebuilding over the same output changes nothing
    assert (first / "index.html").read_bytes() == before


def test_missing_certificate_directory_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        build_site(tmp_path / "nope", tmp_path / "site")


def test_no_script_element_anywhere_in_the_output(tmp_path):
    report = dataclasses.replace(fixed_report("owner__repo-1"), notes=(PAYLOAD,))
    cert_dir = tmp_path / "certs"
    write_certs(cert_dir, report, clean_report("owner__repo-2"))
    traces = tmp_path / "traces"
    write_trace(traces, "owner__repo-1", trace_lines())
    out = tmp_path / "site"
    build_site(cert_dir, out, traces_dir=traces)
    outputs = [path for path in out.rglob("*") if path.is_file()]
    assert len(outputs) == 3
    for path in outputs:
        assert "<script" not in read(path).lower()


def test_index_shows_the_score_exactly_as_certify_gives_it(tmp_path):
    cert_dir = fixture_dir(tmp_path)
    out = tmp_path / "site"
    build_site(cert_dir, out)
    index = read(out / "index.html")
    summary = score_directory(cert_dir)
    assert f"n = {summary['n']} valid certificates" in index
    low, high = summary["rate_before"]["interval_95"]
    assert f"(95% CI {low:.1%} to {high:.1%})" in index
    low, high = summary["rate_after"]["interval_95"]
    assert f"(95% CI {low:.1%} to {high:.1%})" in index
    for name, count in summary["outcomes"].items():
        assert f"<td>{name}</td><td>{count}</td>" in index


def test_pages_have_the_csp_no_javascript_and_an_english_lang(tmp_path):
    cert_dir = fixture_dir(tmp_path)
    out = tmp_path / "site"
    result = build_site(cert_dir, out)
    for text in (read(result.index), read(result.pages[0])):
        assert text.startswith("<!doctype html>")
        assert '<html lang="en">' in text
        assert CSP_META in text
        assert "<script" not in text.lower()
        assert "javascript:" not in text.lower()


def test_an_odd_certificate_file_name_becomes_a_safe_page_name(tmp_path):
    cert_dir = tmp_path / "certs"
    (path,) = write_certs(cert_dir, fixed_report("owner__repo-1"))
    path.rename(cert_dir / "odd name.json")
    out = tmp_path / "site"
    result = build_site(cert_dir, out)
    assert [page.name for page in result.pages] == ["odd_name.html"]
    assert 'href="env/odd_name.html"' in read(result.index)
    assert (out / "env" / "odd_name.html").is_file()
