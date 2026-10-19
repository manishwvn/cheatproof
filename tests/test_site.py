"""Tests for cheatproof/site.py (queue T09, part A).

Certificates come from the fixture builders in test_certify.py and are written with certify.write_certificate. Traces
are written by hand. No model, network or sandbox run.
"""

import dataclasses
import json
import re
from pathlib import Path

import pytest
from test_certify import (
    attack_summary,
    cert_for,
    clean_report,
    exploited,
    fixed_report,
    gate_failed_report,
    still_report,
    with_before,
)

from cheatproof.certify import SCHEMA, score_directory, write_certificate
from cheatproof.site import _page_name, build_site

CSP_META = (
    """<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">"""
)
PAYLOAD = "<script>alert(1)</script>"
ATTR_PAYLOAD = '"onload=alert(1)'
MIXED_PAYLOAD = PAYLOAD + "\"'&"  # a script tag, a double quote, an apostrophe and an ampersand
ESCAPED_TAG = "&lt;script&gt;alert(1)&lt;/script&gt;"
NAMES = ["owner__repo-1.html", "owner__repo-2.html", "owner__repo-3.html"]
MARKER_FILES = (".cheatproof-site", ".nojekyll")


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


def write_diff_file(parent: Path, name: str, text: str, digest: str = "0" * 64) -> Path:
    """A round's sanitized diff in parent/diffs, with the sidecar cli harden writes beside it. The sidecar records
    digest as raw_sha256. attack_summary() records 64 zeros, so the default matches the certificates built here."""
    diffs = parent / "diffs"
    diffs.mkdir(parents=True, exist_ok=True)
    path = diffs / name
    path.write_text(text, encoding="utf-8")
    sidecar = {"raw_sha256": digest, "chars": len(text), "redacted_lines": 0}
    (diffs / f"{name}.json").write_text(json.dumps(sidecar, sort_keys=True), encoding="utf-8")
    return path


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
    assert len(files) == 1 + len(NAMES) + len(MARKER_FILES)
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
    assert len(outputs) == 3 + len(MARKER_FILES)  # the index, two pages and the two marker files
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


@pytest.mark.parametrize("make", [clean_report, gate_failed_report], ids=["only-clean", "only-gate-failed"])
def test_a_directory_with_no_conclusive_certificate_still_builds(tmp_path, make):
    """score() gives rate None when n is 0. The index then shows the count and no percentage, and the build works."""
    cert_dir = tmp_path / "certs"
    write_certs(cert_dir, make("owner__repo-1"))
    result = build_site(cert_dir, tmp_path / "site")
    index = read(result.index)
    assert result.index.is_file()
    assert "<td>Hackable after hardening</td><td>0 of 0, no conclusive certificates</td>" in index
    assert "0 of 0 = " not in index


def test_a_repeated_instance_id_is_an_error_row_and_is_not_scored(tmp_path):
    cert_dir = tmp_path / "certs"
    (path,) = write_certs(cert_dir, fixed_report("owner__repo-1"))
    path.rename(cert_dir / "a.json")
    (cert_dir / "b.json").write_text(read(cert_dir / "a.json"), encoding="utf-8")
    result = build_site(cert_dir, tmp_path / "site")
    assert result.errors == [("b.json", "duplicate instance id, first seen in a.json")]
    assert [page.name for page in result.pages] == ["a.html"]
    index = read(result.index)
    assert "n = 1 valid certificates" in index
    assert "duplicate instance id, first seen in a.json" in index


def test_rebuild_removes_the_page_of_a_certificate_that_is_gone(tmp_path):
    cert_dir = fixture_dir(tmp_path)
    out = tmp_path / "site"
    build_site(cert_dir, out)
    (cert_dir / "owner__repo-3.json").unlink()
    result = build_site(cert_dir, out)
    assert [page.name for page in result.pages] == NAMES[:2]
    assert sorted(path.name for path in (out / "env").iterdir()) == NAMES[:2]


def test_a_non_empty_directory_that_is_not_a_site_is_refused_and_left_alone(tmp_path):
    cert_dir = fixture_dir(tmp_path)
    out = tmp_path / "notes"
    out.mkdir()
    (out / "keep.txt").write_text("mine", encoding="utf-8")
    with pytest.raises(
        ValueError, match="output directory is not empty and is not a cheatproof site: notes$"
    ) as info:
        build_site(cert_dir, out)
    assert str(tmp_path) not in str(info.value)  # the name only, no absolute path
    assert sorted(path.name for path in out.iterdir()) == ["keep.txt"]
    assert read(out / "keep.txt") == "mine"
    empty = tmp_path / "empty"
    empty.mkdir()
    assert build_site(cert_dir, empty).index.is_file()  # an empty directory is fine


def test_a_built_site_has_a_marker_and_an_empty_nojekyll(tmp_path):
    cert_dir = fixture_dir(tmp_path)
    out = tmp_path / "site"
    build_site(cert_dir, out)
    assert (out / ".cheatproof-site").is_file()
    assert (out / ".nojekyll").read_bytes() == b""


def test_a_symlink_in_env_is_unlinked_and_its_target_is_never_written(tmp_path):
    cert_dir = fixture_dir(tmp_path)
    out = tmp_path / "site"
    build_site(cert_dir, out)
    target = tmp_path / "outside.html"
    target.write_text("keep me", encoding="utf-8")
    page = out / "env" / "owner__repo-3.html"
    page.unlink()
    page.symlink_to(target)
    build_site(cert_dir, out)
    assert read(target) == "keep me"
    assert not page.is_symlink()
    assert read(page).startswith("<!doctype html>")


def test_a_symlinked_env_dir_is_refused_and_its_target_is_untouched(tmp_path):
    cert_dir = fixture_dir(tmp_path)
    out = tmp_path / "site"
    build_site(cert_dir, out)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "keep.html").write_text("keep me", encoding="utf-8")
    for page in (out / "env").iterdir():
        page.unlink()
    (out / "env").rmdir()
    (out / "env").symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(ValueError, match="symlinked env"):
        build_site(cert_dir, out)
    assert read(elsewhere / "keep.html") == "keep me"


def test_a_bearer_token_in_trace_args_is_not_shown(tmp_path):
    secret = "Bearer sk-" + "a" * 40
    cert_dir = fixture_dir(tmp_path)
    traces = tmp_path / "traces"
    write_trace(traces, "owner__repo-1", trace_lines(payload=secret))
    out = tmp_path / "site"
    build_site(cert_dir, out, traces_dir=traces)
    page = read(out / "env" / "owner__repo-1.html")
    assert "sk-" + "a" * 40 not in page
    assert "Bearer" not in page
    assert "REDACTED" in page
    assert "cat .git/packed-refs" in page  # the other args are still shown


def test_the_transcript_says_digests_only_above_the_trace_table(tmp_path):
    cert_dir = fixture_dir(tmp_path)
    traces = tmp_path / "traces"
    write_trace(traces, "owner__repo-1", trace_lines(payload="plain"))
    out = tmp_path / "site"
    build_site(cert_dir, out, traces_dir=traces)
    page = read(out / "env" / "owner__repo-1.html")
    note = (
        "Tool results are shown as digests only. This transcript is matched to the certificate by file name "
        "and is not verified against it."
    )
    assert note in page
    assert page.index('id="transcript"') < page.index(note) < page.index("<caption>One row per trace line")


def test_the_patches_section_says_diff_text_is_not_recorded(tmp_path):
    cert_dir = fixture_dir(tmp_path)
    out = tmp_path / "site"
    build_site(cert_dir, out)
    page = read(out / "env" / "owner__repo-1.html")
    note = "Patch diff text is not recorded in the certificate; patches are listed by name."
    assert note in page
    assert page.index('id="patches"') < page.index(note) < page.index('id="rounds"')


def test_tables_and_preformatted_text_are_focusable_and_named(tmp_path):
    report = with_before(fixed_report("owner__repo-1"), attack=attack_summary())
    cert_dir = tmp_path / "certs"
    write_certs(cert_dir, report)
    write_diff_file(tmp_path, "owner__repo-1.before.diff", "+x = 1\n")
    result = build_site(cert_dir, tmp_path / "site")
    index = read(result.index)
    page = read(result.pages[0])
    assert 'aria-label="Rates with 95% Wilson intervals"' in index
    assert '<th scope="row"><a href="env/owner__repo-1.html">owner__repo-1</a></th>' in index
    assert '<td><a href="env/' not in index
    for text in (index, page):
        for tag in re.findall(r'<div class="table-wrap"[^>]*>', text):
            assert re.fullmatch(
                r'<div class="table-wrap" tabindex="0" role="region" aria-label="[^"]+">', tag
            )
        assert "<pre>" not in text
    assert page.count('<pre tabindex="0">') == 1


@pytest.mark.parametrize(
    ("bad", "sentence"),
    [
        (1, "1 certificate file failed to load and is excluded"),
        (2, "2 certificate files failed to load and are excluded"),
    ],
)
def test_the_score_says_how_many_certificate_files_were_left_out(tmp_path, bad, sentence):
    cert_dir = fixture_dir(tmp_path)
    assert "excluded (see" not in read(build_site(cert_dir, tmp_path / "none").index)
    (cert_dir / "broken.json").write_text("{not json", encoding="utf-8")
    if bad == 2:
        (cert_dir / "wrong.json").write_text('{"schema": "other"}', encoding="utf-8")
    index = read(build_site(cert_dir, tmp_path / "site").index)
    link = '(see <a href="#errors">errors</a>).'
    assert f"n = 3 valid certificates. {sentence} {link} A certified task" in index


def test_control_and_bidi_characters_are_shown_as_codes(tmp_path):
    note = "pay\N{RIGHT-TO-LEFT OVERRIDE}load\x07\tend"
    report = dataclasses.replace(fixed_report("owner__repo-1"), notes=(note,))
    cert_dir = tmp_path / "certs"
    write_certs(cert_dir, report)
    out = tmp_path / "site"
    build_site(cert_dir, out)
    page = read(out / "env" / "owner__repo-1.html")
    assert "pay[U+202E]load[U+0007]\tend" in page  # tab is kept; the others become codes
    assert "\N{RIGHT-TO-LEFT OVERRIDE}" not in page
    assert "\x07" not in page


def test_a_trace_is_found_by_the_certificate_file_stem(tmp_path):
    cert_dir = tmp_path / "certs"
    (path,) = write_certs(cert_dir, fixed_report("owner__repo-1"))
    path.rename(cert_dir / "odd name.json")
    traces = tmp_path / "traces"
    write_trace(traces, "odd name", trace_lines(payload="plain"))
    result = build_site(cert_dir, tmp_path / "site", traces_dir=traces)
    assert [page.name for page in result.pages] == ["odd_name.html"]
    page = read(result.pages[0])
    assert "cat .git/packed-refs" in page
    assert "no transcript recorded" not in page


def test_a_trace_falls_back_to_the_page_name(tmp_path):
    cert_dir = tmp_path / "certs"
    (path,) = write_certs(cert_dir, fixed_report("owner__repo-1"))
    path.rename(cert_dir / "odd name.json")
    traces = tmp_path / "traces"
    write_trace(traces, "odd_name", trace_lines(payload="plain"))
    result = build_site(cert_dir, tmp_path / "site", traces_dir=traces)
    assert "cat .git/packed-refs" in read(result.pages[0])


def place_instance_id(cert_dir: Path) -> None:
    write_certs(cert_dir, fixed_report(MIXED_PAYLOAD))


def place_repo(cert_dir: Path) -> None:
    cert = cert_for(fixed_report("owner__repo-1"))
    cert["task"]["repo"] = MIXED_PAYLOAD
    write_certificate(cert, cert_dir)


def place_attacker_field(cert_dir: Path) -> None:
    cert = cert_for(fixed_report("owner__repo-1"))
    cert["attacker"]["note"] = MIXED_PAYLOAD
    write_certificate(cert, cert_dir)


def place_hole_label(cert_dir: Path) -> None:
    # The validator takes any string as a hole label, so the label is kept as it is.
    write_certs(cert_dir, with_before(fixed_report("owner__repo-1"), holes=exploited(MIXED_PAYLOAD)))


def place_error_row(cert_dir: Path) -> None:
    # The error message shows the bad value, so the payload reaches the error row.
    write_certs(cert_dir, fixed_report("owner__repo-1"))
    bad = {"schema": SCHEMA, "schema_version": MIXED_PAYLOAD}
    (cert_dir / "bad.json").write_text(json.dumps(bad), encoding="utf-8")


def place_diff_file(cert_dir: Path) -> None:
    write_certs(cert_dir, with_before(fixed_report("owner__repo-1"), attack=attack_summary()))
    write_diff_file(cert_dir.parent, "owner__repo-1.before.diff", MIXED_PAYLOAD)


@pytest.mark.parametrize(
    "place",
    [
        place_instance_id,
        place_repo,
        place_attacker_field,
        place_hole_label,
        place_error_row,
        place_diff_file,
    ],
    ids=["instance_id", "repo", "attacker", "hole-label", "error-row", "diff-file"],
)
def test_a_payload_is_escaped_wherever_it_is_shown(tmp_path, place):
    cert_dir = tmp_path / "certs"
    place(cert_dir)
    out = tmp_path / "site"
    build_site(cert_dir, out)
    texts = [read(path) for path in out.rglob("*") if path.is_file()]
    assert texts
    for text in texts:
        assert MIXED_PAYLOAD not in text
        assert "<script" not in text.lower()
    assert any(ESCAPED_TAG in text for text in texts)


def test_page_names_are_numbered_when_stems_give_the_same_name():
    taken: set[str] = set()
    assert [_page_name("a", taken), _page_name("a", taken), _page_name("a", taken)] == ["a", "a-2", "a-3"]


def test_names_that_differ_only_in_case_do_not_clash():
    taken: set[str] = set()
    assert _page_name("Owner", taken) == "Owner"
    assert _page_name("owner", taken) == "owner-2"


def test_dot_only_stems_get_a_safe_name():
    assert _page_name(".", set()) == "certificate"
    assert _page_name("..", set()) == "certificate"
    assert _page_name("...", set()) == "certificate"


def test_a_file_named_dot_dot_json_builds_a_page_inside_env(tmp_path):
    cert_dir = tmp_path / "certs"
    (path,) = write_certs(cert_dir, fixed_report("owner__repo-1"))
    path.rename(cert_dir / "..json")
    out = tmp_path / "site"
    result = build_site(cert_dir, out)
    # Path("..json").stem is ".json" or "." depending on the Python version; both give a safe name.
    assert [page.name for page in result.pages] in (["json.html"], ["certificate.html"])
    assert result.pages[0].parent == out / "env"


def test_two_file_names_that_sanitize_to_one_name_get_two_pages(tmp_path):
    cert_dir = tmp_path / "certs"
    first, second = write_certs(cert_dir, fixed_report("owner__repo-1"), clean_report("owner__repo-2"))
    first.rename(cert_dir / "odd name.json")
    second.rename(cert_dir / "odd_name.json")
    result = build_site(cert_dir, tmp_path / "site")
    assert [page.name for page in result.pages] == ["odd_name.html", "odd_name-2.html"]


def test_a_directory_where_every_file_is_bad_shows_the_empty_state(tmp_path):
    cert_dir = tmp_path / "certs"
    cert_dir.mkdir()
    (cert_dir / "broken.json").write_text("{not json", encoding="utf-8")
    (cert_dir / "wrong.json").write_text('{"schema": "other"}', encoding="utf-8")
    out = tmp_path / "site"
    result = build_site(cert_dir, out)
    index = read(result.index)
    assert result.pages == []
    assert [name for name, _ in result.errors] == ["broken.json", "wrong.json"]
    assert "No valid certificates were found. Every certificate file failed to load (see below)." in index
    assert "Hackability score" not in index
    assert list((out / "env").iterdir()) == []


# Attack diffs: read from diffs/ beside the certificates, shown escaped, digest-only when the file is absent.

NO_DIFF_NOTE = "attack diff not recorded in certificate"
DIGEST = "0" * 64  # attack_summary() records this sha256


def with_attack_round(cert_dir: Path) -> None:
    write_certs(cert_dir, with_before(fixed_report("owner__repo-1"), attack=attack_summary()))


def test_round_shows_the_diff_file_escaped(tmp_path):
    cert_dir = tmp_path / "certs"
    with_attack_round(cert_dir)
    write_diff_file(tmp_path, "owner__repo-1.before.diff", f"+{MIXED_PAYLOAD}\n")
    out = tmp_path / "site"
    build_site(cert_dir, out)
    page = read(out / "env" / "owner__repo-1.html")
    assert f'<pre tabindex="0">+{ESCAPED_TAG}' in page
    assert MIXED_PAYLOAD not in page and "<script" not in page.lower()
    assert f"Diff digest: sha256 {DIGEST}" in page  # the recorded digest still sits under the diff


def test_round_without_a_diff_file_shows_the_digest_note(tmp_path):
    cert_dir = tmp_path / "certs"
    with_attack_round(cert_dir)
    out = tmp_path / "site"
    build_site(cert_dir, out)
    page = read(out / "env" / "owner__repo-1.html")
    assert NO_DIFF_NOTE in page
    assert f"Diff digest: sha256 {DIGEST}" in page
    assert '<pre tabindex="0">' not in page


def test_a_diff_file_for_another_stem_is_not_used(tmp_path):
    cert_dir = tmp_path / "certs"
    with_attack_round(cert_dir)
    write_diff_file(tmp_path, "other-stem.before.diff", "+OTHER-MARKER\n")
    out = tmp_path / "site"
    build_site(cert_dir, out)
    assert "OTHER-MARKER" not in read(out / "env" / "owner__repo-1.html")


def test_a_symlinked_diff_file_is_refused_and_its_target_is_not_read(tmp_path):
    secret = tmp_path / "elsewhere.txt"
    secret.write_text("TARGET-MARKER\n", encoding="utf-8")
    cert_dir = tmp_path / "certs"
    with_attack_round(cert_dir)
    diffs = tmp_path / "diffs"
    diffs.mkdir()
    (diffs / "owner__repo-1.before.diff").symlink_to(secret)
    out = tmp_path / "site"
    build_site(cert_dir, out)
    page = read(out / "env" / "owner__repo-1.html")
    assert "TARGET-MARKER" not in page
    assert NO_DIFF_NOTE in page


def test_a_diff_whose_sidecar_digest_is_another_one_is_not_shown(tmp_path):
    cert_dir = tmp_path / "certs"
    with_attack_round(cert_dir)
    write_diff_file(tmp_path, "owner__repo-1.before.diff", "+STALE-MARKER\n", digest="1" * 64)
    out = tmp_path / "site"
    build_site(cert_dir, out)
    page = read(out / "env" / "owner__repo-1.html")
    assert "STALE-MARKER" not in page
    assert NO_DIFF_NOTE in page
    assert f"Diff digest: sha256 {DIGEST}" in page  # the certificate's own digest still shows


def test_a_diff_without_a_sidecar_is_not_shown(tmp_path):
    cert_dir = tmp_path / "certs"
    with_attack_round(cert_dir)
    diffs = tmp_path / "diffs"
    diffs.mkdir()
    (diffs / "owner__repo-1.before.diff").write_text("+OLD-MARKER\n", encoding="utf-8")
    out = tmp_path / "site"
    build_site(cert_dir, out)
    page = read(out / "env" / "owner__repo-1.html")
    assert "OLD-MARKER" not in page
    assert NO_DIFF_NOTE in page


def test_a_symlinked_sidecar_is_refused_and_its_target_is_not_read(tmp_path):
    secret = tmp_path / "elsewhere.json"
    secret.write_text(json.dumps({"raw_sha256": DIGEST}), encoding="utf-8")
    cert_dir = tmp_path / "certs"
    with_attack_round(cert_dir)
    diffs = tmp_path / "diffs"
    diffs.mkdir()
    (diffs / "owner__repo-1.before.diff").write_text("+LINKED-MARKER\n", encoding="utf-8")
    (diffs / "owner__repo-1.before.diff.json").symlink_to(secret)
    out = tmp_path / "site"
    build_site(cert_dir, out)
    page = read(out / "env" / "owner__repo-1.html")
    assert "LINKED-MARKER" not in page
    assert NO_DIFF_NOTE in page


def test_a_symlinked_traces_dir_is_refused_and_its_target_is_not_read(tmp_path):
    real = tmp_path / "real_traces"
    write_trace(real, "owner__repo-1", trace_lines(payload="plain"))
    traces = tmp_path / "traces"
    traces.symlink_to(real, target_is_directory=True)
    cert_dir = tmp_path / "certs"
    write_certs(cert_dir, fixed_report("owner__repo-1"))
    out = tmp_path / "site"
    build_site(cert_dir, out, traces_dir=traces)
    page = read(out / "env" / "owner__repo-1.html")
    assert "cat .git/packed-refs" not in page
    assert "no transcript recorded" in page


def test_a_symlinked_trace_file_is_refused_and_its_target_is_not_read(tmp_path):
    secret = tmp_path / "elsewhere.jsonl"
    secret.write_text("\n".join(trace_lines(payload="plain")) + "\n", encoding="utf-8")
    traces = tmp_path / "traces"
    traces.mkdir()
    (traces / "owner__repo-1.jsonl").symlink_to(secret)
    cert_dir = tmp_path / "certs"
    write_certs(cert_dir, fixed_report("owner__repo-1"))
    out = tmp_path / "site"
    build_site(cert_dir, out, traces_dir=traces)
    page = read(out / "env" / "owner__repo-1.html")
    assert "cat .git/packed-refs" not in page
    assert "no transcript recorded" in page


def test_a_symlinked_diffs_directory_is_refused_and_its_target_is_not_read(tmp_path):
    real = tmp_path / "real_diffs"
    real.mkdir()
    (real / "owner__repo-1.before.diff").write_text("TARGET-MARKER\n", encoding="utf-8")
    (tmp_path / "diffs").symlink_to(real, target_is_directory=True)
    cert_dir = tmp_path / "certs"
    with_attack_round(cert_dir)
    out = tmp_path / "site"
    build_site(cert_dir, out)
    page = read(out / "env" / "owner__repo-1.html")
    assert "TARGET-MARKER" not in page
    assert NO_DIFF_NOTE in page
