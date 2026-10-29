"""Offline tests for the deterministic web audit."""

import json
from dataclasses import replace

import pytest

from rewardseal import cli, holes, webaudit
from rewardseal.tasks import TaskSpec

LINES = [
    "calculate_specific_result(alpha_value, beta_value)",
    "update_existing_state(custom_field, unique_value)",
    "return_custom_response(request_value, response_value)",
]
SENTINEL = "PRIVATE_PAGE_SENTINEL_9172"


def task():
    patch = (
        "diff --git a/example.py b/example.py\n--- a/example.py\n+++ b/example.py\n@@ -0,0 +1,3 @@\n"
        + "\n".join("+" + line for line in LINES)
    )
    return TaskSpec(
        "Owner__repo-123", "Owner/repo", "abcdef0", "image", (), (), patch, "", "test", "Fix the issue"
    )


class Budget:
    def __init__(self):
        self.calls = 0

    def reserve_tavily_call(self):
        self.calls += 1


def client(result, failure=None):
    class Client:
        def __init__(self, key):
            assert key == "fake-key"

        def search(self, query, **kwargs):
            assert kwargs == {"max_results": 5, "include_raw_content": True, "search_depth": "basic"}
            if failure:
                raise failure
            return {"results": result}

    return Client


def record():
    page = {
        "url": "https://github.com/Owner/repo/pull/123",
        "raw_content": "+ " + LINES[0] + "\n+" + LINES[1] + "\n" + SENTINEL,
    }
    budget = Budget()
    search = webaudit.make_tavily_raw_search(budget, "fake-key", client_factory=client([page]))
    result = webaudit.build_record(task(), search, lambda: "2026-01-02T00:00:00+00:00")
    assert budget.calls == 2
    return result


def test_queries_scoring_and_no_page_text(tmp_path):
    rec = record()
    assert rec["queries"][0]["query"] == "Fix the issue Owner/repo"
    assert rec["queries"][1]["query"] == "github.com/Owner/repo/pull/123"
    assert all(line not in q["query"] for line in LINES for q in rec["queries"])
    assert rec["q1_best_k"] == 2 and rec["n"] == 3 and rec["q1_half_or_more"]
    assert rec["q1_first_pr_or_commit_rank"] == 1
    path = webaudit.write_record(rec, tmp_path)
    assert SENTINEL not in path.read_text()
    assert webaudit.load_record(path) == rec
    rec["queries"][0]["results"][0]["text"] = SENTINEL
    with pytest.raises(ValueError):
        webaudit.validate_record(rec)


@pytest.mark.parametrize(
    "url,kind",
    [
        ("https://github.com/a/b/pull/2", "pull"),
        ("https://github.com/a/b/commit/c", "commit"),
        ("https://github.com/a/b/compare/a...b", "compare"),
        ("https://github.com/a/b/blob/main/x", "blob"),
        ("https://raw.githubusercontent.com/a/b/main/x", "raw"),
        ("https://example.com/pull/2", "other"),
    ],
)
def test_page_types(url, kind):
    assert webaudit.page_type(url) == kind


def test_blob_and_trivial():
    gold = frozenset([holes.future_line_digest(LINES[0])])
    result = webaudit.score_result(
        {"url": "https://github.com/Owner/repo/blob/main/a", "raw_content": LINES[0]}, 1, "Owner/repo", gold
    )
    assert result["current_file_page"] and result["trivial"] and result["k"] == 1


def deps_for(fake_budget, factory):
    return replace(
        cli.Deps.for_dry_run(),
        find_tasks=lambda iid, source, cache: [task()],
        make_budget=lambda: fake_budget,
        web_search_factory=factory,
        clock=lambda: "2026-01-02T00:00:00+00:00",
    )


@pytest.mark.parametrize("status", [401, 402, 429])
def test_failure_stops_without_record(tmp_path, status, capsys):
    class Failure(Exception):
        status_code = status

    budget = Budget()
    factory = lambda b: webaudit.make_tavily_raw_search(
        b, "fake-key", client_factory=client([], Failure("secret body"))
    )
    code = cli.main(
        ["audit-web", "--instance-ids", task().instance_id, "--out", str(tmp_path)],
        deps=deps_for(budget, factory),
    )
    assert code == 1 and budget.calls == 1
    assert not list(tmp_path.glob("Owner*.json"))
    assert "secret body" not in capsys.readouterr().err


def test_dry_run_no_key_or_calls(tmp_path, monkeypatch):
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)

    def forbidden(*args):
        raise AssertionError("called during dry run")

    deps = replace(deps_for(Budget(), forbidden), make_budget=forbidden)
    assert (
        cli.main(
            ["audit-web", "--instance-ids", task().instance_id, "--out", str(tmp_path), "--dry-run"],
            deps=deps,
        )
        == 0
    )
    assert not list(tmp_path.iterdir())


def test_site_section(tmp_path):
    from rewardseal import site

    errors = []
    assert site._web_exposure_section(tmp_path / "web", tmp_path / "exposure", errors) == ""
    rec = record()
    for query in rec["queries"]:
        query["results"] = []
    rec.update(
        q1_best_k=0,
        q2_best_k=0,
        q1_first_pr_or_commit_rank=None,
        q1_half_or_more=False,
        q1_best_k_history_pages=0,
        q2_best_k_history_pages=0,
        q1_best_k_blob_pages=0,
        q2_best_k_blob_pages=0,
    )
    webaudit.write_record(rec, tmp_path / "web")
    html = site._web_exposure_section(tmp_path / "web", tmp_path / "exposure", errors)
    assert "Web exposure (Tavily)" in html and "On 2026-01-02" in html
    assert "no search built only from the public issue title returned a page with at least half" in html
    assert "dominant" not in html


@pytest.mark.parametrize("patch_field", ["gold_patch", "test_patch"])
def test_queries_normalize_added_lines_before_checking(patch_field):
    line = "Correct repeated words in error message"
    current = replace(task(), **{patch_field: "+" + line})
    # Case and doubled whitespace cannot hide patch text, even beyond the title limit.
    title = "A harmless prefix " * 12 + line.upper().replace(" ", "  ")
    assert webaudit.queries(replace(current, problem_statement=title))[0] == ("q1", "Owner/repo")


@pytest.mark.parametrize("symbol", list("(){};="))
def test_queries_drop_code_like_title(symbol):
    current = replace(task(), problem_statement=f"Fix issue {symbol} in module")
    assert webaudit.queries(current)[0] == ("q1", "Owner/repo")


def test_queries_keep_plain_title_and_truncate_after_check():
    assert webaudit.queries(task())[0] == ("q1", "Fix the issue Owner/repo")
    current = replace(task(), problem_statement="Ordinary descriptive title " * 15)
    assert webaudit.queries(current)[0][1] == current.problem_statement[:150] + " Owner/repo"


@pytest.mark.parametrize(
    "header",
    [
        "diff --git a/example.py b/example.py",
        "--- a/example.py",
        "+++ b/example.py",
        "@@ -0,0 +1,3 @@",
        "index abc123..def456 100644",
    ],
)
def test_queries_drop_patch_headers(header):
    current = replace(
        task(),
        gold_patch=task().gold_patch + "\n" + header,
        problem_statement="See " + header.upper().replace(" ", "  "),
    )
    assert webaudit.queries(current)[0][1] == "Owner/repo"


@pytest.mark.parametrize(
    "query",
    [
        "github.com/Owner/repo/pull/124",
        "github.com/Other/repo/pull/123",
        "https://github.com/Owner/repo/pull/123",
        "github.com/Owner/repo/pull/123 extra",
    ],
)
def test_validation_requires_exact_oracle_query(query):
    rec = record()
    rec["queries"][1]["query"] = query
    with pytest.raises(ValueError):
        webaudit.validate_record(rec)


@pytest.mark.parametrize("mutation", ["duplicate", "unsorted", "count"])
def test_validation_requires_unique_sorted_digests_and_matching_count(mutation):
    rec = record()
    result = rec["queries"][0]["results"][0]
    if mutation == "duplicate":
        result["matched_line_digests"] = [result["matched_line_digests"][0]] * 2
    elif mutation == "unsorted":
        result["matched_line_digests"].reverse()
    else:
        result["k"] -= 1
    with pytest.raises(ValueError):
        webaudit.validate_record(rec)


def mixed_record(history_lines=1):
    return webaudit.build_record(
        task(),
        lambda query: [
            {"url": "https://github.com/Owner/repo/blob/main/a", "raw_content": "\n".join(LINES)},
            {
                "url": "https://github.com/Owner/repo/compare/a...b",
                "raw_content": "\n".join(LINES[:history_lines]),
            },
            {"url": "https://github.com/Other/repo/pull/123", "raw_content": "\n".join(LINES)},
        ],
        lambda: "2026-01-02T00:00:00Z",
    )


def test_blob_and_history_maxima_are_separate(tmp_path):
    from rewardseal import site

    rec = mixed_record()
    for label in ("q1", "q2"):
        assert rec[f"{label}_best_k"] == 3
        assert rec[f"{label}_best_k_history_pages"] == 1
        assert rec[f"{label}_best_k_blob_pages"] == 3
    assert not rec["q1_half_or_more"]
    webaudit.write_record(rec, tmp_path / "web")
    html = site._web_exposure_section(tmp_path / "web", tmp_path / "exposure", [])
    assert "current-file page k/n" in html
    assert "Q1 3/3; oracle query 3/3" in html
    assert "<td>1/3</td>" in html
    assert "no search built only from the public issue title" in html


@pytest.mark.parametrize("label", ["q1", "q2"])
@pytest.mark.parametrize("group", ["history", "blob"])
def test_validation_checks_separate_maxima(label, group):
    rec = mixed_record()
    rec[f"{label}_best_k_{group}_pages"] += 1
    with pytest.raises(ValueError):
        webaudit.validate_record(rec)


def test_site_uses_entire_date_range_and_existing_index_order(tmp_path):
    from test_certify import cert_for, fixed_report

    from rewardseal import site
    from rewardseal.certify import write_certificate

    rec = mixed_record(history_lines=2)
    rec["queries"][1]["searched_at"] = "2026-01-05T00:00:00Z"
    webaudit.write_record(rec, tmp_path / "web-exposure")
    write_certificate(cert_for(fixed_report("CycloneDX__cyclonedx-python-348")), tmp_path / "certificates")
    result = site.build_site(tmp_path / "certificates", tmp_path / "site")
    assert not result.errors
    html = result.index.read_text()
    assert "Between 2026-01-02 and 2026-01-05" in html
    assert "1 of 1 audited environments" in html
    assert "dominant" not in html
    assert html.index('id="numbers-key"') < html.index('id="start-here"') < html.index('id="web-exposure"')


@pytest.mark.parametrize("ancestor", [False, True])
def test_symlink_parents_refused_by_load_write_skip_and_site(tmp_path, ancestor):
    from rewardseal import site

    real = tmp_path / "real"
    directory = real / "nested" if ancestor else real
    path = webaudit.write_record(record(), directory)
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    linked = link / "nested" if ancestor else link
    with pytest.raises(OSError, match="symbolic link"):
        webaudit.load_record(linked / path.name)
    with pytest.raises(OSError, match="symbolic link"):
        webaudit.write_record(record(), linked)
    errors = []
    assert site._web_exposure_section(linked, tmp_path / "exposure", errors) == ""
    assert errors

    def forbidden(*args):
        pytest.fail("preflight must stop before budget or search construction")

    assert (
        cli.main(
            ["audit-web", "--instance-ids", task().instance_id, "--out", str(linked)],
            deps=deps_for(Budget(), forbidden),
        )
        == 1
    )


@pytest.mark.parametrize("rerun", [False, True])
def test_all_existing_records_validated_before_any_search(tmp_path, rerun):
    later = replace(task(), instance_id="Owner__repo-124")
    # A valid first task must not spend before a corrupt later record is discovered.
    first = webaudit.write_record(record(), tmp_path)
    corrupt = tmp_path / webaudit.audit.record_filename(later.instance_id)
    corrupt.write_text('{"secret body": "invalid"}')
    before = first.read_text()

    def forbidden(*args):
        pytest.fail("corrupt record must stop before budget or search construction")

    deps = replace(
        deps_for(Budget(), forbidden),
        make_budget=forbidden,
        find_tasks=lambda iid, source, cache: [task() if iid == task().instance_id else later],
    )
    argv = ["audit-web", "--instance-ids", task().instance_id, later.instance_id, "--out", str(tmp_path)]
    assert cli.main(argv + (["--rerun"] if rerun else []), deps=deps) == 1
    assert first.read_text() == before
    assert not (tmp_path / "_run.json").exists()


@pytest.mark.parametrize("bad_path", ["out-link", "out-file", "record-link", "manifest-link", "parent-file"])
def test_invalid_output_path_stops_before_search(tmp_path, bad_path):
    output = tmp_path / "out"
    output.mkdir()
    if bad_path == "out-link":
        alias = tmp_path / "alias"
        alias.symlink_to(output, target_is_directory=True)
        output = alias
    elif bad_path == "out-file":
        output = tmp_path / "file"
        output.write_text("existing")
    elif bad_path == "parent-file":
        parent = tmp_path / "file"
        parent.write_text("existing")
        output = parent / "nested"
    else:
        name = (
            "_run.json" if bad_path == "manifest-link" else webaudit.audit.record_filename(task().instance_id)
        )
        (output / name).symlink_to(tmp_path / "absent")

    def forbidden(*args):
        pytest.fail("invalid output must stop before budget or search construction")

    deps = replace(deps_for(Budget(), forbidden), make_budget=forbidden)
    assert cli.main(["audit-web", "--instance-ids", task().instance_id, "--out", str(output)], deps=deps) == 1


@pytest.mark.parametrize("dry_run", [False, True])
def test_default_cli_loads_env_only_for_live_run(tmp_path, monkeypatch, dry_run):
    from rewardseal import envfile

    loaded = []
    budget = Budget()

    def fake_load():
        loaded.append(True)

    def fake_factory(b):
        assert loaded == [True]
        return webaudit.make_tavily_raw_search(b, "fake-key", client_factory=client([]))

    deps = deps_for(budget, fake_factory)
    monkeypatch.setattr(envfile, "load_env", fake_load)
    monkeypatch.setattr(cli.Deps, "for_dry_run", classmethod(lambda cls: deps))
    monkeypatch.setattr(cli.Budget, "from_env", lambda: budget)
    if dry_run:

        def forbidden(*args):
            pytest.fail("dry run must not clean queries or read the API key")

        monkeypatch.setattr(webaudit, "clean_text", forbidden)
        original_get = webaudit.os.environ.get

        def guarded_get(name, *args):
            if name == "TAVILY_API_KEY":
                forbidden()
            return original_get(name, *args)

        monkeypatch.setattr(webaudit.os.environ, "get", guarded_get)
    argv = ["audit-web", "--instance-ids", task().instance_id, "--out", str(tmp_path)]
    assert cli.main(argv + (["--dry-run"] if dry_run else [])) == 0
    assert loaded == ([] if dry_run else [True])
    assert budget.calls == (0 if dry_run else 2)
    if not dry_run:
        manifest = json.loads((tmp_path / "_run.json").read_text())
        assert manifest["total_searches"] == 2
        assert manifest["tasks_searched"] == [task().instance_id]


@pytest.mark.parametrize("failure", ["quota", "budget"])
def test_second_search_failure_never_writes_partial_record(tmp_path, failure, capsys):
    from rewardseal.budget import BudgetExceeded

    budget = Budget()

    def factory(b):
        def search(query):
            b.reserve_tavily_call()
            if budget.calls == 2:
                raise (
                    BudgetExceeded("secret body")
                    if failure == "budget"
                    else RuntimeError("quota secret body")
                )
            return [{"url": "https://github.com/Owner/repo/pull/123", "raw_content": SENTINEL}]

        return search

    assert (
        cli.main(
            ["audit-web", "--instance-ids", task().instance_id, "--out", str(tmp_path)],
            deps=deps_for(budget, factory),
        )
        == 1
    )
    assert budget.calls == 2
    assert not (tmp_path / webaudit.audit.record_filename(task().instance_id)).exists()
    assert "secret body" not in capsys.readouterr().err
    assert all(SENTINEL not in path.read_text() for path in tmp_path.glob("*.json"))


@pytest.mark.parametrize("rerun", [False, True])
def test_valid_existing_record_skip_and_rerun(tmp_path, rerun):
    budget = Budget()
    webaudit.write_record(record(), tmp_path)
    factory = lambda b: webaudit.make_tavily_raw_search(b, "fake-key", client_factory=client([]))
    argv = ["audit-web", "--instance-ids", task().instance_id, "--out", str(tmp_path)]
    assert cli.main(argv + (["--rerun"] if rerun else []), deps=deps_for(budget, factory)) == 0
    assert budget.calls == (2 if rerun else 0)


def test_a_null_or_malformed_results_list_is_an_empty_result_not_a_crash():
    class Budget:
        def reserve_tavily_call(self):
            pass

    class Client:
        def __init__(self, response):
            self.response = response

        def search(self, query, **kwargs):
            return self.response

    for response in ({"results": None}, {"results": "x"}, {}, None, {"results": [None, 3]}):
        search = webaudit.make_tavily_raw_search(
            Budget(), api_key="k", client_factory=lambda key, r=response: Client(r)
        )
        assert search("q") == []
