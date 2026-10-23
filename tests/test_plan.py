"""T38 batch planning: no network, model or sandbox."""

import dataclasses
import json

import pytest

from cheatproof import certify, plan
from cheatproof.tasks import TaskSpec

SPEC = TaskSpec("x__y-1", "x/y", "a" * 40, "img", ("t::a",), (), "", "", "swe-rebench")


def spec(iid):
    return dataclasses.replace(SPEC, instance_id=iid)


def test_chunk_size_default_and_bounds():
    assert plan.check_chunk_size(None) == plan.MAX_CHUNK == 10
    assert plan.check_chunk_size(1) == 1
    for bad in (0, 11, -3):
        with pytest.raises(plan.PlanError):
            plan.check_chunk_size(bad)


def test_estimate_uses_the_ledger_measured_averages():
    assert plan.estimate(0) == (0, 0)
    trial, sandbox = plan.estimate(10)
    assert (round(trial, 3), round(sandbox, 2)) == (0.56, 0.9)


def test_unreadable_or_odd_certificates_are_no_evidence(tmp_path):
    for iid, text in (("x__y-1", "not json"), ("x__y-2", "[]"), ("x__y-3", '{"exposure_before": 5}')):
        (tmp_path / certify.certificate_filename(iid)).write_text(text, encoding="utf-8")
    tasks = [spec("x__y-1"), spec("x__y-2"), spec("x__y-3"), spec("x__y-4")]  # the last has no file
    assert plan.future_git_revisits(tmp_path, tasks) == []


def test_revisit_needs_the_flag_true_and_no_certified_result(tmp_path):
    for iid, flag, ok in (("x__y-1", True, False), ("x__y-2", True, True), ("x__y-3", False, False)):
        cert = {"certified": ok, "exposure_before": {"future_git": flag}}
        (tmp_path / certify.certificate_filename(iid)).write_text(json.dumps(cert), encoding="utf-8")
    tasks = [spec("x__y-3"), spec("x__y-2"), spec("x__y-1")]
    assert plan.future_git_revisits(tmp_path, tasks) == ["x__y-1"]


def test_order_puts_first_ids_ahead_and_keeps_the_rest_in_order(tmp_path):
    tasks = [spec("x__y-1"), spec("x__y-2"), spec("x__y-3")]
    ordered = plan.order_tasks(tasks, lookup=lambda iid: [], out=tmp_path, first=["x__y-3", "x__y-3"])
    assert [t.instance_id for t in ordered.tasks] == ["x__y-3", "x__y-1", "x__y-2"]
    assert ordered.rerun == frozenset()  # no --rerun: the certificate still skips it
    again = plan.order_tasks(tasks, lookup=lambda iid: [], out=tmp_path, first=["x__y-3"], rerun=True)
    assert again.rerun == {"x__y-3"}


def test_render_plan_marks_boundaries_and_skips():
    tasks = [spec(f"x__y-{i}") for i in range(1, 6)]
    lines = plan.render_plan(tasks, certified={"x__y-1", "x__y-2"}, rerun={"x__y-2"}, chunk_size=2)
    text = "\n".join(lines)
    assert "5 selected, 4 to run, chunk size 2" in text
    assert "x__y-1: already has a certificate, skipped" in text
    assert "x__y-2: run (existing certificate is replaced)" in text
    assert text.count("chunk boundary") == 1
