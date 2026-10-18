import json
from pathlib import Path

import pytest

from cheatproof import tasks
from cheatproof.executor import IMAGE_RE
from cheatproof.tasks import (
    PROBLEM_CHARS,
    PROBLEM_CUT,
    SOURCES,
    RowSkip,
    TaskSpec,
    fetch_rows,
    load_tasks,
    main,
    parse_row,
    parse_rows,
    select_tasks,
)

FIXTURES = Path(__file__).parent / "fixtures" / "tasks"
VERIFIED = SOURCES["swe-bench-verified"]
REBENCH = SOURCES["swe-rebench"]
ASTROPY = "astropy__astropy-7671"  # the one Verified fixture row whose node ids are pytest-shaped
# A full 40-hex commit, built here at runtime. The fixture files hold "REDACTED" instead, because the sanitizer
# redacts any 32-plus-character token in a recorded fixture, so the tests that need a valid row substitute this.
COMMIT = "a" * 40


def _fixture_rows(name: str) -> list[dict]:
    return [item["row"] for item in json.loads((FIXTURES / name).read_text())["rows"]]


def with_commit(row: dict) -> dict:
    return {**row, "base_commit": COMMIT}


RAW_VERIFIED_ROWS = _fixture_rows("swe_bench_verified_rows.json")
RAW_REBENCH_ROWS = _fixture_rows("swe_rebench_rows.json")
VERIFIED_ROWS = [with_commit(row) for row in RAW_VERIFIED_ROWS]
REBENCH_ROWS = [with_commit(row) for row in RAW_REBENCH_ROWS]
VERIFIED_BY_ID = {row["instance_id"]: row for row in VERIFIED_ROWS}
REBENCH_BY_ID = {row["instance_id"]: row for row in REBENCH_ROWS}


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Tests never reach the datasets-server: a call to the real fetcher fails the test."""

    def refuse(*args, **kwargs):
        raise AssertionError("real HTTP fetch in a test")

    monkeypatch.setattr(tasks, "_http_fetch", refuse)


class FakeRowsApi:
    """Serves rows the way the rows API does: offset and length slices, at most 100 per call."""

    def __init__(self, rows):
        self.rows = list(rows)
        self.calls: list[tuple[str, int, int]] = []

    def __call__(self, dataset, config, split, offset, length):
        assert 0 < length <= 100
        self.calls.append((dataset, offset, length))
        batch = self.rows[offset : offset + length]
        return {
            "rows": [{"row_idx": offset + i, "row": row} for i, row in enumerate(batch)],
            "num_rows_total": len(self.rows),
        }


def make_spec(
    instance_id, *, repo="owner/repo", f2p=1, p2p=0, patch="diff --git a/pkg/mod.py b/pkg/mod.py\n"
):
    return TaskSpec(
        instance_id=instance_id,
        repo=repo,
        base_commit="0" * 8,
        image="swebench/sweb.eval.x86_64.x:latest",
        fail_to_pass=tuple(f"t{i}" for i in range(f2p)),
        pass_to_pass=tuple(f"p{i}" for i in range(p2p)),
        gold_patch=patch,
        test_patch="",
        source="swe-rebench",
    )


def test_task_spec_round_trips_through_json():
    spec = parse_row(VERIFIED, VERIFIED_BY_ID[ASTROPY])
    data = json.loads(json.dumps(spec.to_dict()))
    assert data["fail_to_pass"] == json.loads(VERIFIED_BY_ID[ASTROPY]["FAIL_TO_PASS"])
    assert TaskSpec.from_dict(data) == spec


def test_verified_fixture_keeps_only_the_pytest_shaped_row():
    specs, skipped = parse_rows(VERIFIED, VERIFIED_ROWS)
    assert skipped == {"non_pytest_id": 2}  # both django rows name tests as "test_x (module.Class)"
    (spec,) = specs
    row = VERIFIED_BY_ID[ASTROPY]
    assert spec.instance_id == ASTROPY
    assert spec.image == "swebench/sweb.eval.x86_64.astropy_1776_astropy-7671:latest"
    assert spec.repo == "astropy/astropy"
    assert spec.base_commit == COMMIT
    assert spec.source == "swe-bench-verified"
    assert spec.fail_to_pass == tuple(json.loads(row["FAIL_TO_PASS"]))
    assert spec.gold_patch == row["patch"]
    assert spec.test_patch == row["test_patch"]


@pytest.mark.parametrize("instance_id", ["django__django-12419", "django__django-11206"])
def test_django_style_node_ids_are_skipped_as_non_pytest(instance_id):
    with pytest.raises(RowSkip) as skip:
        parse_row(VERIFIED, VERIFIED_BY_ID[instance_id])
    assert skip.value.reason == "non_pytest_id"


def test_rebench_fixture_uses_list_tests_and_its_docker_image_field():
    specs, skipped = parse_rows(REBENCH, REBENCH_ROWS)
    assert skipped == {
        "no_image": 1
    }  # the greentea row has a null docker_image, and SWE-rebench is not derived
    by_id = {s.instance_id: s for s in specs}
    row = REBENCH_BY_ID["ARMmbed__yotta-804"]
    spec = by_id["ARMmbed__yotta-804"]
    assert spec.image == row["docker_image"]
    assert spec.fail_to_pass == tuple(row["FAIL_TO_PASS"])
    assert spec.pass_to_pass == tuple(row["PASS_TO_PASS"])
    assert spec.source == "swe-rebench"


def test_redacted_fixture_commits_are_skipped_as_bad_commit():
    assert all(row["base_commit"] == "REDACTED" for row in RAW_REBENCH_ROWS)
    specs, skipped = parse_rows(REBENCH, RAW_REBENCH_ROWS)
    assert specs == []
    assert skipped == {"bad_commit": len(RAW_REBENCH_ROWS)}


def test_json_string_and_list_test_fields_parse_the_same():
    row = VERIFIED_BY_ID[ASTROPY]
    as_list = {
        **row,
        "FAIL_TO_PASS": json.loads(row["FAIL_TO_PASS"]),
        "PASS_TO_PASS": json.loads(row["PASS_TO_PASS"]),
    }
    assert parse_row(VERIFIED, as_list) == parse_row(VERIFIED, row)


STATEMENT = "Synthetic issue: parsing an empty URL raises instead of returning None."


@pytest.mark.parametrize(
    "source, row",
    [
        (VERIFIED, VERIFIED_BY_ID[ASTROPY]),
        (REBENCH, REBENCH_BY_ID["ARMmbed__yotta-804"]),
    ],
)
def test_problem_statement_is_read_from_the_row_field_of_both_sources(source, row):
    spec = parse_row(source, {**row, "problem_statement": STATEMENT})
    assert spec.problem_statement == STATEMENT


def test_rows_without_the_field_or_with_null_load_with_an_empty_statement():
    # The recorded fixture rows carry no problem_statement. They still parse, with "" as the statement.
    assert all("problem_statement" not in row for row in REBENCH_ROWS + VERIFIED_ROWS)
    specs, skipped = parse_rows(REBENCH, REBENCH_ROWS)
    assert skipped == {"no_image": 1}
    assert [s.problem_statement for s in specs] == ["", ""]
    row = REBENCH_BY_ID["ARMmbed__yotta-804"]
    assert parse_row(REBENCH, {**row, "problem_statement": None}).problem_statement == ""


def test_long_statement_is_cut_to_the_cap_with_a_marker():
    row = VERIFIED_BY_ID[ASTROPY]
    long = parse_row(VERIFIED, {**row, "problem_statement": "x" * (PROBLEM_CHARS + 500)}).problem_statement
    assert len(long) == PROBLEM_CHARS
    assert long.endswith(PROBLEM_CUT)
    exact = "y" * PROBLEM_CHARS  # exactly at the cap: kept whole, no marker
    assert parse_row(VERIFIED, {**row, "problem_statement": exact}).problem_statement == exact


@pytest.mark.parametrize(
    "instance_id, image",
    [
        ("astropy__astropy-7671", "swebench/sweb.eval.x86_64.astropy_1776_astropy-7671:latest"),
        ("Sphinx__Sphinx-7000", "swebench/sweb.eval.x86_64.sphinx_1776_sphinx-7000:latest"),
    ],
)
def test_derived_image_is_lower_case_and_passes_the_executor_regex(instance_id, image):
    row = {**VERIFIED_BY_ID[ASTROPY], "instance_id": instance_id}
    spec = parse_row(VERIFIED, row)
    assert spec.image == image
    assert IMAGE_RE.fullmatch(spec.image)


@pytest.mark.parametrize("image", ["bad image", "--privileged", "img;rm -rf /"])
def test_invalid_image_is_skipped_and_counted(image):
    bad = {**REBENCH_BY_ID["ARMmbed__yotta-804"], "docker_image": image}
    specs, skipped = parse_rows(REBENCH, [bad, REBENCH_BY_ID["12rambau__sepal_ui-518"]])
    assert skipped == {"bad_image": 1}
    assert [s.instance_id for s in specs] == ["12rambau__sepal_ui-518"]


@pytest.mark.parametrize(
    "image",
    [
        "python:3.12-slim",
        "docker.io/library/python:3.12",
        "ghcr.io/swebench/sweb.eval.x86_64.x:latest",
        "Swebench/sweb.eval.x86_64.x:latest",  # the prefix is case-sensitive
    ],
)
def test_image_outside_the_allowed_namespaces_is_skipped_as_bad_image(image):
    bad = {**REBENCH_BY_ID["ARMmbed__yotta-804"], "docker_image": image}
    specs, skipped = parse_rows(REBENCH, [bad])
    assert specs == []
    assert skipped == {"bad_image": 1}


@pytest.mark.parametrize(
    "image", ["swebench/sweb.eval.x86_64.x:latest", "swerebench/sweb.eval.x86_64.x:latest"]
)
def test_both_allowed_namespaces_are_accepted(image):
    row = {**REBENCH_BY_ID["ARMmbed__yotta-804"], "docker_image": image}
    assert parse_row(REBENCH, row).image == image


@pytest.mark.parametrize(
    "change, reason",
    [
        ({"base_commit": None}, "missing_field"),
        ({"base_commit": "REDACTED"}, "bad_commit"),
        ({"base_commit": "71fb12cefda5"}, "bad_commit"),  # an abbreviated id is not a full base commit
        ({"base_commit": "z" * 40}, "bad_commit"),
        ({"patch": ""}, "missing_field"),
        ({"FAIL_TO_PASS": "[not json"}, "bad_tests"),
        ({"PASS_TO_PASS": 7}, "bad_tests"),
        ({"FAIL_TO_PASS": ["-x.py::test_a"]}, "bad_tests"),  # pytest would read it as an option
        ({"PASS_TO_PASS": ["tests/test_a.py::test_b\nrm"]}, "bad_tests"),
        ({"FAIL_TO_PASS": ["test_x (mod.Class)"]}, "non_pytest_id"),
        ({"PASS_TO_PASS": ["tests/test_a.py"]}, "non_pytest_id"),
        ({"FAIL_TO_PASS": ["/abs/tests/test_a.py::test_b"]}, "non_pytest_id"),
        ({"FAIL_TO_PASS": ["../tests/test_a.py::test_b"]}, "non_pytest_id"),
        ({"test_patch": "--- a/../escape.py\n+++ b/../escape.py\n@@ -1 +1 @@\n-a\n+b\n"}, "bad_patch"),
        ({"FAIL_TO_PASS": "[]"}, "no_fail_to_pass"),
        ({"docker_image": None}, "no_image"),
        ({"problem_statement": 42}, "bad_problem_statement"),
        ({"problem_statement": ["issue text"]}, "bad_problem_statement"),
    ],
)
def test_broken_rows_are_skipped_with_a_counted_reason(change, reason):
    row = {**REBENCH_BY_ID["12rambau__sepal_ui-518"], **change}
    specs, skipped = parse_rows(REBENCH, [row])
    assert specs == []
    assert skipped == {reason: 1}


def test_duplicate_instances_are_counted_once():
    specs, skipped = parse_rows(VERIFIED, [VERIFIED_BY_ID[ASTROPY]] * 2)
    assert len(specs) == 1
    assert skipped == {"duplicate": 1}


def test_select_prefers_fewer_tests_then_smaller_patch_then_instance_id():
    big = "diff --git a/pkg/mod.py b/pkg/mod.py\n" + "+x\n" * 20000
    specs = [make_spec("b", f2p=2), make_spec("a", f2p=2), make_spec("c", f2p=1, patch=big), make_spec("d")]
    assert [s.instance_id for s in select_tasks(specs, 4)] == ["d", "a", "b", "c"]


def test_non_python_gold_patch_ranks_last():
    py = make_spec("py", f2p=5)
    c = make_spec("c", f2p=1, patch="diff --git a/src/ext.c b/src/ext.c\n")
    assert [s.instance_id for s in select_tasks([c, py], 2)] == ["py", "c"]


def test_deny_and_allow_lists_filter_repos():
    specs = [
        make_spec("a", repo="astropy/astropy"),
        make_spec("b", repo="owner/pure"),
        make_spec("c", repo="owner/other"),
    ]
    assert [s.instance_id for s in select_tasks(specs, 5)] == [
        "b",
        "c",
    ]  # astropy is in the default deny list
    assert [s.instance_id for s in select_tasks(specs, 5, deny_repos=())] == ["a", "b", "c"]
    assert [s.instance_id for s in select_tasks(specs, 5, allow_repos={"owner/pure"})] == ["b"]


def test_selection_is_deterministic_for_any_input_order():
    specs = [make_spec(f"i{k:02d}", f2p=1 + k % 3) for k in range(12)]
    first = select_tasks(specs, 5)
    assert select_tasks(list(reversed(specs)), 5) == first
    assert select_tasks(specs, 5) == first


def test_negative_n_is_refused():
    with pytest.raises(ValueError):
        select_tasks([], -1)


def test_fetch_rows_pages_by_offset_until_the_split_ends():
    rows = [{"instance_id": f"x__x-{i}"} for i in range(7)]
    api = FakeRowsApi(rows)
    assert fetch_rows(REBENCH, scan_rows=100, fetcher=api, page_size=3) == rows
    # Each page asks for a full length. The last one returns the final row, which reaches the total, so it stops.
    assert api.calls == [(REBENCH.dataset, 0, 3), (REBENCH.dataset, 3, 3), (REBENCH.dataset, 6, 3)]


def test_fetch_rows_stops_at_scan_rows_and_caps_page_length_at_100():
    rows = [{"instance_id": f"x__x-{i}"} for i in range(150)]
    api = FakeRowsApi(rows)
    assert len(fetch_rows(REBENCH, scan_rows=150, fetcher=api, page_size=500)) == 150
    assert api.calls == [(REBENCH.dataset, 0, 100), (REBENCH.dataset, 100, 50)]
    api = FakeRowsApi(rows)
    assert len(fetch_rows(REBENCH, scan_rows=4, fetcher=api, page_size=3)) == 4
    assert api.calls == [(REBENCH.dataset, 0, 3), (REBENCH.dataset, 3, 1)]


def test_load_tasks_selects_from_fixture_rows_and_counts_skips(tmp_path):
    loaded = load_tasks("swe-rebench", fetcher=FakeRowsApi(REBENCH_ROWS), cache_dir=tmp_path)
    assert loaded.scanned == 3
    assert loaded.valid == 2
    assert dict(loaded.skipped) == {"no_image": 1}
    assert [s.instance_id for s in loaded.selected] == ["12rambau__sepal_ui-518", "ARMmbed__yotta-804"]


def test_load_tasks_default_deny_list_drops_native_repos(tmp_path):
    denied = load_tasks("swe-bench-verified", fetcher=FakeRowsApi(VERIFIED_ROWS), cache_dir=tmp_path)
    # The astropy row is a native repo, and the django rows are not pytest-shaped, so nothing is selected.
    assert denied.valid == 1
    assert denied.selected == ()
    allowed = load_tasks(
        "swe-bench-verified", fetcher=FakeRowsApi(VERIFIED_ROWS), cache_dir=tmp_path, deny_repos=()
    )
    assert [s.instance_id for s in allowed.selected] == [ASTROPY]


def test_cache_round_trip_in_tmp_path(tmp_path):
    api = FakeRowsApi(VERIFIED_ROWS)
    first = load_tasks("swe-bench-verified", fetcher=api, cache_dir=tmp_path)
    assert (tmp_path / "swe-bench-verified.json").exists()
    assert len(api.calls) == 1

    def cache_only(*args, **kwargs):
        raise AssertionError("the cache should answer without a fetch")

    assert load_tasks("swe-bench-verified", fetcher=cache_only, cache_dir=tmp_path) == first
    load_tasks("swe-bench-verified", refresh=True, fetcher=api, cache_dir=tmp_path)
    assert len(api.calls) == 2
    load_tasks("swe-bench-verified", fetcher=api, cache_dir=tmp_path, scan_rows=2)  # other scan size: refetch
    assert len(api.calls) == 3


def test_a_cache_from_before_row_checks_is_not_reused(tmp_path):
    stale = {
        "version": 1,
        "source": "swe-rebench",
        "scan_rows": 1000,
        "scanned": 0,
        "skipped": {},
        "tasks": [],
    }
    (tmp_path / "swe-rebench.json").write_text(json.dumps(stale))
    api = FakeRowsApi(REBENCH_ROWS)
    loaded = load_tasks("swe-rebench", fetcher=api, cache_dir=tmp_path)
    assert len(api.calls) == 1
    assert len(loaded.selected) == 2


def test_problem_statement_survives_the_cache_round_trip(tmp_path):
    row = {**REBENCH_BY_ID["ARMmbed__yotta-804"], "problem_statement": STATEMENT}
    first = load_tasks("swe-rebench", fetcher=FakeRowsApi([row]), cache_dir=tmp_path)
    (spec,) = first.selected
    assert spec.problem_statement == STATEMENT
    stored = json.loads((tmp_path / "swe-rebench.json").read_text(encoding="utf-8"))
    assert stored["tasks"][0]["problem_statement"] == STATEMENT

    def cache_only(*args, **kwargs):
        raise AssertionError("the cache should answer without a fetch")

    assert load_tasks("swe-rebench", fetcher=cache_only, cache_dir=tmp_path) == first


def test_a_version_2_cache_without_the_statement_is_refetched(tmp_path):
    # A spec dict without problem_statement still loads, but a v2 cache file is stale: the loader fetches again.
    task = parse_row(REBENCH, REBENCH_BY_ID["ARMmbed__yotta-804"]).to_dict()
    del task["problem_statement"]
    assert TaskSpec.from_dict(task).problem_statement == ""
    payload = {
        "version": 2,
        "source": "swe-rebench",
        "scan_rows": REBENCH.scan_rows,
        "scanned": 1,
        "skipped": {},
        "tasks": [task],
    }
    (tmp_path / "swe-rebench.json").write_text(json.dumps(payload), encoding="utf-8")
    fetched = load_tasks("swe-rebench", fetcher=FakeRowsApi(REBENCH_ROWS), cache_dir=tmp_path)
    assert len(fetched.selected) == 2  # both valid rows from the fetch, not the one cached task
    cached = json.loads((tmp_path / "swe-rebench.json").read_text(encoding="utf-8"))
    assert cached["version"] == tasks.CACHE_VERSION == 3


def test_selection_size_comes_from_the_source_default_or_n(tmp_path):
    default = load_tasks("swe-rebench", fetcher=FakeRowsApi(REBENCH_ROWS), cache_dir=tmp_path)
    assert len(default.selected) == 2  # two valid rows, under the default of 30
    one = load_tasks("swe-rebench", fetcher=FakeRowsApi(REBENCH_ROWS), cache_dir=tmp_path, n=1)
    assert [s.instance_id for s in one.selected] == ["12rambau__sepal_ui-518"]
    assert REBENCH.default_n == 30 and VERIFIED.default_n == 10


def test_unknown_source_is_refused(tmp_path):
    with pytest.raises(ValueError, match="unknown source"):
        load_tasks("swe-bench-lite", fetcher=FakeRowsApi([]), cache_dir=tmp_path)


def test_cli_fetch_writes_the_cache_and_prints_counts(tmp_path, capsys):
    code = main(
        ["fetch", "--source", "swe-bench-verified", "--n", "1", "--deny-repo", "owner/none"],
        fetcher=FakeRowsApi(VERIFIED_ROWS),
        cache_dir=tmp_path,
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "swe-bench-verified: scanned=3 valid=1 selected=1" in out
    assert "skipped by reason: non_pytest_id=2" in out
    assert ASTROPY in out
    assert (tmp_path / "swe-bench-verified.json").exists()


def test_cli_refuses_n_without_a_single_source(tmp_path):
    with pytest.raises(SystemExit) as exc:
        main(["fetch", "--n", "3"], fetcher=FakeRowsApi([]), cache_dir=tmp_path)
    assert exc.value.code == 2
