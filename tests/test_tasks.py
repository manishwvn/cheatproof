import json
from pathlib import Path

import pytest

from cheatproof import tasks
from cheatproof.executor import IMAGE_RE
from cheatproof.tasks import (
    SOURCES,
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
VERIFIED_ROWS = [
    item["row"] for item in json.loads((FIXTURES / "swe_bench_verified_rows.json").read_text())["rows"]
]
REBENCH_ROWS = [item["row"] for item in json.loads((FIXTURES / "swe_rebench_rows.json").read_text())["rows"]]
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
    spec = parse_row(VERIFIED, VERIFIED_BY_ID["django__django-11206"])
    data = json.loads(json.dumps(spec.to_dict()))
    assert data["fail_to_pass"] == json.loads(VERIFIED_BY_ID["django__django-11206"]["FAIL_TO_PASS"])
    assert TaskSpec.from_dict(data) == spec


def test_verified_fixture_rows_parse_with_derived_image():
    specs, skipped = parse_rows(VERIFIED, VERIFIED_ROWS)
    assert skipped == {}
    by_id = {s.instance_id: s for s in specs}
    row = VERIFIED_BY_ID["django__django-12419"]
    spec = by_id["django__django-12419"]
    assert spec.image == "swebench/sweb.eval.x86_64.django_1776_django-12419:latest"
    assert spec.repo == "django/django"
    assert spec.source == "swe-bench-verified"
    assert spec.fail_to_pass == tuple(json.loads(row["FAIL_TO_PASS"]))
    assert spec.gold_patch == row["patch"]
    assert spec.test_patch == row["test_patch"]


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


def test_json_string_and_list_test_fields_parse_the_same():
    row = VERIFIED_BY_ID["django__django-11206"]
    as_list = {
        **row,
        "FAIL_TO_PASS": json.loads(row["FAIL_TO_PASS"]),
        "PASS_TO_PASS": json.loads(row["PASS_TO_PASS"]),
    }
    assert parse_row(VERIFIED, as_list) == parse_row(VERIFIED, row)


@pytest.mark.parametrize(
    "instance_id, image",
    [
        ("django__django-12419", "swebench/sweb.eval.x86_64.django_1776_django-12419:latest"),
        ("Sphinx__Sphinx-7000", "swebench/sweb.eval.x86_64.sphinx_1776_sphinx-7000:latest"),
    ],
)
def test_derived_image_is_lower_case_and_passes_the_executor_regex(instance_id, image):
    row = {**VERIFIED_BY_ID["django__django-12419"], "instance_id": instance_id}
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
    "change, reason",
    [
        ({"base_commit": None}, "missing_field"),
        ({"patch": ""}, "missing_field"),
        ({"FAIL_TO_PASS": "[not json"}, "bad_tests"),
        ({"PASS_TO_PASS": 7}, "bad_tests"),
        ({"FAIL_TO_PASS": "[]"}, "no_fail_to_pass"),
        ({"docker_image": None}, "no_image"),
    ],
)
def test_broken_rows_are_skipped_with_a_counted_reason(change, reason):
    row = {**REBENCH_BY_ID["12rambau__sepal_ui-518"], **change}
    specs, skipped = parse_rows(REBENCH, [row])
    assert specs == []
    assert skipped == {reason: 1}


def test_duplicate_instances_are_counted_once():
    specs, skipped = parse_rows(VERIFIED, [VERIFIED_BY_ID["django__django-12419"]] * 2)
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
    loaded = load_tasks("swe-bench-verified", fetcher=FakeRowsApi(VERIFIED_ROWS), cache_dir=tmp_path)
    assert "astropy__astropy-7671" not in [s.instance_id for s in loaded.selected]
    assert [s.instance_id for s in loaded.selected] == ["django__django-12419", "django__django-11206"]


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


def test_selection_size_comes_from_the_source_default_or_n(tmp_path):
    assert load_tasks("swe-bench-verified", fetcher=FakeRowsApi(VERIFIED_ROWS), cache_dir=tmp_path).selected
    one = load_tasks("swe-bench-verified", fetcher=FakeRowsApi(VERIFIED_ROWS), cache_dir=tmp_path, n=1)
    assert [s.instance_id for s in one.selected] == ["django__django-12419"]
    assert REBENCH.default_n == 30 and VERIFIED.default_n == 10


def test_unknown_source_is_refused(tmp_path):
    with pytest.raises(ValueError, match="unknown source"):
        load_tasks("swe-bench-lite", fetcher=FakeRowsApi([]), cache_dir=tmp_path)


def test_cli_fetch_writes_the_cache_and_prints_counts(tmp_path, capsys):
    code = main(
        ["fetch", "--source", "swe-bench-verified", "--n", "1"],
        fetcher=FakeRowsApi(VERIFIED_ROWS),
        cache_dir=tmp_path,
    )
    out = capsys.readouterr().out
    assert code == 0
    # The native astropy row is valid; the deny list drops it at selection, not at parse.
    assert "swe-bench-verified: scanned=3 valid=3 selected=1" in out
    assert "django__django-12419" in out
    assert (tmp_path / "swe-bench-verified.json").exists()


def test_cli_refuses_n_without_a_single_source(tmp_path):
    with pytest.raises(SystemExit) as exc:
        main(["fetch", "--n", "3"], fetcher=FakeRowsApi([]), cache_dir=tmp_path)
    assert exc.value.code == 2
