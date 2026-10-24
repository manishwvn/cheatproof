"""Tests for cheatproof/certify.py (queue T07).

Reports are built by hand. No model, network or sandbox runs.
"""

import dataclasses
import hashlib
import json
import re

import pytest

from cheatproof.attacker import AttackResult
from cheatproof.certify import (
    SCHEMA,
    SCHEMA_VERSION,
    SCORE_SCHEMA_VERSION,
    build_certificate,
    certificate_filename,
    load_certificate,
    score,
    score_directory,
    validate_certificate,
    wilson_interval,
    write_certificate,
)
from cheatproof.exposure import ExposureReport
from cheatproof.grader import GateReport, GradeResult, redact_text
from cheatproof.harden import CandidateCheck, HardenReport, RoundReport
from cheatproof.holes import HoleReport
from cheatproof.patches import PatchOutcome
from cheatproof.tasks import TaskSpec

STRIP = "strip-future-git"
FAILED_BEFORE = "attacker failed before hardening (not hackable by this attacker)"
FIXED = f"attacker failed after hardening with {STRIP} (not hackable by this attacker)"
GOLD = "GOLD-PATCH-MARKER\n+fix = 1\n"
TEST_TEXT = "TEST-PATCH-MARKER\n+assert fix\n"
RAW_DIFF = "diff --git a/src/mod.py b/src/mod.py\n+RAW-DIFF-MARKER = 1\n"
STEP_TEXT = "STEP-TEXT-MARKER cat .git/packed-refs"
LOG = "LOG-TAIL-MARKER pytest output"
EVIDENCE = "EVIDENCE-SNIPPET-MARKER"
TIMESTAMP = "2026-10-18T13:24:20-05:00"
ATTACKER = {"model": "nvidia/nemotron-test", "max_steps": 20, "max_tokens": 4000, "budget_usd": 0.5}
IID = "owner__repo-1"
EXPECTED_KEYS = [
    "schema",
    "schema_version",
    "task",
    "image_digest",
    "attacker",
    "holes_found",
    "patches_applied",
    "patches_rejected",
    "unpatched",
    "gates",
    "certified",
    "reason",
    "exposure_before",
    "cost_usd",
    "cost_basis",
    "sandbox_runs",
    "timestamp",
    "notes",
    "harden",
]
ATTACKER_RUN_KEYS = [
    "executor",
    "attacks_per_round",
    "max_output_tokens",
    "cmd_timeout",
    "strategy",
    "visible_passed_basis",
]
# The attacker block cert_for() writes when the caller gives no run settings: each run setting is null.
ATTACKER_DEFAULTS = {
    **ATTACKER,
    "executor": None,
    "attacks_per_round": 1,
    "max_output_tokens": None,
    "cmd_timeout": None,
    "strategy": None,
    "recon": None,
    "recon_types": [],
    "visible_passed_basis": "PASS_TO_PASS intact",
}


def task_for(iid=IID, source="swe-rebench"):
    return TaskSpec(
        instance_id=iid,
        repo="owner/repo",
        base_commit="a" * 40,
        image="swebench/sweb.eval.x86_64.owner_1776_repo-1:latest",
        fail_to_pass=("tests/test_x.py::test_new",),
        pass_to_pass=(),
        gold_patch=GOLD,
        test_patch=TEST_TEXT,
        source=source,
    )


def grade(passed, *, error=None, applied=True):
    return GradeResult(passed, int(passed), 1, int(passed), 1, applied, error, LOG)


def gates(gold_ok=True):
    gold = grade(True) if gold_ok else grade(False, error="gold broken")
    return GateReport(gold=gold, empty=grade(False))


def exposure(*holes):
    return ExposureReport(
        future_git="git-history" in holes,
        future_git_evidence=["refs/future"] if "git-history" in holes else [],
        tests_writable=False,
        writable_tests=[],
        restore_covered=True,
        unrestored_tests=[],
        writable_as_root=[],
        network="network" in holes,
        network_evidence=[],
        holes=list(holes),
    )


def exploited(*labels):
    return HoleReport(
        primary=labels[0],
        labels=labels,
        attempted=labels,
        evidence={label: (f"{EVIDENCE} {label}",) for label in labels},
        succeeded=True,
        exploited=True,
        skipped_records=0,
    )


def clean():
    return HoleReport(
        primary="none",
        labels=(),
        attempted=(),
        evidence={},
        succeeded=False,
        exploited=False,
        skipped_records=0,
    )


def attack(diff=RAW_DIFF):
    step = {"step": 1, "tool": "run", "args": {"cmd": STEP_TEXT}, "error": None}
    step["result_digest"] = {"head": "ok", "sha256": "0" * 64}
    return AttackResult(
        submitted=True,
        stop_reason="submit",
        steps=[step],
        tokens_in=120,
        tokens_out=30,
        final_diff=diff,
        error="",
        diff_ok=True,
    )


def attack_summary(diff=RAW_DIFF):
    return {
        "submitted": True,
        "stop_reason": "submit",
        "tokens_in": 120,
        "tokens_out": 30,
        "diff_ok": True,
        "error": "",
        "steps": 1,
        "final_diff_sha256": "0" * 64,
        "final_diff_chars": len(diff),
    }


def round_(patches=(), *, holes, scan, inconclusive=None, gold_ok=True):
    return RoundReport(
        patches=tuple(patches),
        patch_outcomes=tuple(PatchOutcome(name, True) for name in patches),
        gates=gates(gold_ok),
        exposure=scan,
        attack=attack_summary(),
        attack_grade=grade(holes.exploited),
        holes=holes,
        inconclusive=inconclusive,
    )


def clean_report(iid=IID):
    """The attacker fails before hardening. Nothing is patched and there is no after round."""
    return HardenReport(
        instance_id=iid,
        before=round_(holes=clean(), scan=exposure()),
        candidates=(),
        accepted=(),
        rejected=(),
        unpatched=(),
        after=None,
        certified=True,
        reason=FAILED_BEFORE,
        sandbox_runs=5,
        attacks=(attack(),),
    )


def fixed_report(iid=IID):
    """Exploited through git history, the strip patch accepted, the after attack fails."""
    candidate = CandidateCheck(STRIP, True, (PatchOutcome(STRIP, True),), grade(True), None)
    return HardenReport(
        instance_id=iid,
        before=round_(holes=exploited("git-history"), scan=exposure("git-history")),
        candidates=(candidate,),
        accepted=(STRIP,),
        rejected=(),
        unpatched=(),
        after=round_((STRIP,), holes=clean(), scan=exposure()),
        certified=True,
        reason=FIXED,
        sandbox_runs=11,
        attacks=(attack(), attack()),
    )


def still_report(iid=IID):
    """Exploited before, and still exploited after the strip patch."""
    candidate = CandidateCheck(STRIP, True, (PatchOutcome(STRIP, True),), grade(True), None)
    return HardenReport(
        instance_id=iid,
        before=round_(holes=exploited("git-history"), scan=exposure("git-history")),
        candidates=(candidate,),
        accepted=(STRIP,),
        rejected=(),
        unpatched=(),
        after=round_((STRIP,), holes=exploited("git-history"), scan=exposure()),
        certified=False,
        reason=f"attacker still exploits after hardening with {STRIP} (git-history)",
        sandbox_runs=11,
        attacks=(attack(), attack()),
    )


def inconclusive_report(iid=IID):
    """The before attack hit its token limit, so it gives no verdict."""
    return HardenReport(
        instance_id=iid,
        before=round_(
            holes=clean(), scan=exposure(), inconclusive="attack ended with stop_reason token_limit"
        ),
        candidates=(),
        accepted=(),
        rejected=(),
        unpatched=(),
        after=None,
        certified=False,
        reason="inconclusive attack: attack ended with stop_reason token_limit",
        sandbox_runs=5,
        attacks=(attack(),),
    )


def after_error_report(iid=IID):
    """Exploited before. The after round raised a model error, so it has no holes and no verdict."""
    candidate = CandidateCheck(STRIP, True, (PatchOutcome(STRIP, True),), grade(True), None)
    after = RoundReport(
        patches=(STRIP,),
        patch_outcomes=(PatchOutcome(STRIP, True),),
        error="RuntimeError: model down",
    )
    return HardenReport(
        instance_id=iid,
        before=round_(holes=exploited("git-history"), scan=exposure("git-history")),
        candidates=(candidate,),
        accepted=(STRIP,),
        rejected=(),
        unpatched=(),
        after=after,
        certified=False,
        reason="round after hardening failed: RuntimeError: model down",
        sandbox_runs=11,
        attacks=(attack(),),
    )


def gate_failed_report(iid=IID):
    """The gold gate fails before hardening, so the task is broken and nothing is judged."""
    return HardenReport(
        instance_id=iid,
        before=round_(holes=clean(), scan=exposure(), gold_ok=False),
        candidates=(),
        accepted=(),
        rejected=(),
        unpatched=(),
        after=None,
        certified=False,
        reason="gates failed before hardening (the task is broken): gold gate failed",
        sandbox_runs=5,
        attacks=(attack(),),
    )


def errored_before_report(iid=IID):
    """The before round raised an error after its gates held. It has no holes and no verdict."""
    before = dataclasses.replace(round_(holes=clean(), scan=exposure()), error="RuntimeError: sandbox down")
    return HardenReport(
        instance_id=iid,
        before=before,
        candidates=(),
        accepted=(),
        rejected=(),
        unpatched=(),
        after=None,
        certified=False,
        reason="round before hardening failed: RuntimeError: sandbox down",
        sandbox_runs=5,
        attacks=(attack(),),
    )


def gateless_error_report(iid=IID):
    """The before round raised an error before any gate ran, so its gates are missing."""
    return HardenReport(
        instance_id=iid,
        before=RoundReport(patches=(), error="RuntimeError: sandbox down"),
        candidates=(),
        accepted=(),
        rejected=(),
        unpatched=(),
        after=None,
        certified=False,
        reason="round before hardening failed: RuntimeError: sandbox down",
        sandbox_runs=0,
        attacks=(),
    )


def rejected_report(iid=IID):
    """Exploited before, and the only patch for the hole was rejected. No after round."""
    candidate = CandidateCheck(STRIP, False, (PatchOutcome(STRIP, False),), grade(False), "did not apply")
    return HardenReport(
        instance_id=iid,
        before=round_(holes=exploited("git-history"), scan=exposure("git-history")),
        candidates=(candidate,),
        accepted=(),
        rejected=(STRIP,),
        unpatched=(),
        after=None,
        certified=False,
        reason="attacker exploited git-history and nothing could be applied; not hardened",
        sandbox_runs=5,
        attacks=(attack(),),
    )


def unpatched_report(iid=IID):
    """Exploited before, and no patch exists for the hole. No candidates and no after round."""
    return HardenReport(
        instance_id=iid,
        before=round_(holes=exploited("network"), scan=exposure("network")),
        candidates=(),
        accepted=(),
        rejected=(),
        unpatched=("network",),
        after=None,
        certified=False,
        reason="attacker exploited network and nothing could be applied; not hardened",
        sandbox_runs=5,
        attacks=(attack(),),
    )


def no_attempt_report(iid=IID):
    """The attacker submitted an empty diff before hardening. It made no attempt, so nothing is certified."""
    report = clean_report(iid)
    before = dataclasses.replace(
        report.before,
        attack=attack_summary(""),
        attack_grade=None,
        no_attempt="the final diff is empty",
    )
    return dataclasses.replace(
        report,
        before=before,
        certified=False,
        reason="attacker made no attempt before hardening (the final diff is empty); not certified",
        attacks=(attack(""),),
    )


def after_no_attempt_report(iid=IID):
    """Exploited before and patched. The after attacker submitted an empty diff, so it made no attempt."""
    report = fixed_report(iid)
    after = dataclasses.replace(
        report.after,
        attack=attack_summary(""),
        attack_grade=None,
        no_attempt="the final diff is empty",
    )
    return dataclasses.replace(
        report,
        after=after,
        certified=False,
        reason=f"attacker made no attempt after hardening with {STRIP} (the final diff is empty); not certified",
    )


def with_before(report, **changes):
    """The report with its before round changed. Reports are frozen, so this returns a new one."""
    return dataclasses.replace(report, before=dataclasses.replace(report.before, **changes))


def with_after(report, **changes):
    """The report with its after round changed. Reports are frozen, so this returns a new one."""
    return dataclasses.replace(report, after=dataclasses.replace(report.after, **changes))


def cert_for(report, *, source="swe-rebench", cost=0.25, image_digest=None):
    return build_certificate(
        report,
        task_for(report.instance_id, source),
        image_digest=image_digest,
        attacker=ATTACKER,
        cost_usd=cost,
        timestamp=TIMESTAMP,
    )


def valid_cert():
    return cert_for(fixed_report())


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def only_outcome(cert):
    """The outcome counts of one certificate, with the zero counts left out."""
    return {name: count for name, count in score([cert])["outcomes"].items() if count}


# Build and round trip


def test_build_takes_its_fields_from_the_report():
    report = fixed_report()
    cert = cert_for(report, image_digest="sha256:abc")
    full = report.to_dict()
    assert cert["schema"] == SCHEMA and cert["schema_version"] == SCHEMA_VERSION == 2
    assert set(cert) == set(EXPECTED_KEYS)
    assert cert["task"] == {
        "instance_id": IID,
        "repo": "owner/repo",
        "base_commit": "a" * 40,
        "image": "swebench/sweb.eval.x86_64.owner_1776_repo-1:latest",
        "source": "swe-rebench",
        "gold_patch": {"sha256": sha(GOLD), "chars": len(GOLD)},
        "test_patch": {"sha256": sha(TEST_TEXT), "chars": len(TEST_TEXT)},
    }
    assert cert["image_digest"] == "sha256:abc"
    assert cert["attacker"] == ATTACKER_DEFAULTS
    assert cert["holes_found"] == ["git-history"]
    assert cert["patches_applied"] == [STRIP] and cert["patches_rejected"] == []
    assert cert["unpatched"] == []
    assert cert["gates"] == {"before": full["before"]["gates"], "after": full["after"]["gates"]}
    assert cert["certified"] is True and cert["reason"] == FIXED
    assert cert["exposure_before"] == full["before"]["exposure"]
    assert cert["cost_usd"] == 0.25 and cert["sandbox_runs"] == 11 and cert["timestamp"] == TIMESTAMP
    assert cert["cost_basis"] == "budgeted ledger delta"
    assert cert["notes"] == []
    assert cert["harden"] == full


def test_clean_certificate_has_no_after_round_and_shows_the_scan():
    cert = cert_for(clean_report())
    assert cert["holes_found"] == [] and cert["patches_applied"] == []
    assert cert["gates"]["after"] is None and cert["harden"]["after"] is None
    assert cert["exposure_before"] is not None and cert["exposure_before"]["holes"] == []
    assert cert["certified"] is True and cert["reason"] == FAILED_BEFORE
    assert "not hackable by this attacker" in cert["reason"]


def test_round_trip_build_write_load(tmp_path):
    cert = valid_cert()
    path = write_certificate(cert, tmp_path)
    assert path == tmp_path / f"{IID}.json"
    assert load_certificate(path) == cert
    assert path.read_text(encoding="utf-8") == json.dumps(cert, sort_keys=True, indent=2) + "\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == [path.name]  # no temp file left behind


def test_schema_version_is_written_and_checked(tmp_path):
    cert = valid_cert()
    assert cert["schema_version"] == 2 and cert["schema"] == "cheatproof.certificate"
    validate_certificate(cert)


def test_raw_diff_steps_and_log_never_reach_the_certificate():
    cert = valid_cert()
    text = json.dumps(cert)
    for marker in (RAW_DIFF, "RAW-DIFF-MARKER", STEP_TEXT, LOG, EVIDENCE, GOLD, TEST_TEXT):
        assert marker not in text
    assert "attacks" not in cert and "attacks" not in cert["harden"]


def test_timestamp_with_z_is_accepted():
    report = clean_report()
    cert = build_certificate(
        report, task_for(), image_digest=None, attacker=ATTACKER, cost_usd=0, timestamp="2026-10-18T13:24:20Z"
    )
    assert cert["timestamp"] == "2026-10-18T13:24:20Z" and cert["cost_usd"] == 0.0


def test_image_digest_may_be_none():
    assert valid_cert()["image_digest"] is None


# Validation


@pytest.mark.parametrize("key", EXPECTED_KEYS)
def test_each_required_key_is_checked(key):
    cert = valid_cert()
    del cert[key]
    with pytest.raises(ValueError, match=re.escape(f"missing required key: {key}")):
        validate_certificate(cert)


@pytest.mark.parametrize("version", [1, 3, 0, "2", True, None])
def test_unknown_schema_version_is_refused(version):
    cert = valid_cert()
    cert["schema_version"] = version
    with pytest.raises(ValueError, match="unknown schema_version"):
        validate_certificate(cert)


def test_wrong_schema_name_is_refused():
    cert = valid_cert()
    cert["schema"] = "cheatproof.report"
    with pytest.raises(ValueError, match="wrong schema"):
        validate_certificate(cert)


def test_non_mapping_is_refused():
    with pytest.raises(ValueError, match="must be a JSON object"):
        validate_certificate([])


@pytest.mark.parametrize(
    ("key", "bad"),
    [
        ("task", "x"),
        ("image_digest", 5),
        ("attacker", ["model"]),
        ("holes_found", "git-history"),
        ("patches_applied", [1]),
        ("patches_rejected", None),
        ("unpatched", "network"),
        ("gates", {"before": None}),
        ("certified", "yes"),
        ("reason", None),
        ("exposure_before", []),
        ("cost_usd", "0.1"),
        ("cost_basis", "measured"),
        ("cost_basis", None),
        ("sandbox_runs", 1.5),
        ("sandbox_runs", True),
        ("timestamp", 1),
        ("notes", "x"),
        ("harden", []),
    ],
)
def test_wrong_type_of_a_top_level_key_is_refused(key, bad):
    cert = valid_cert()
    cert[key] = bad
    with pytest.raises(ValueError, match=key):
        validate_certificate(cert)


def test_unknown_top_level_key_is_refused():
    cert = valid_cert()
    cert["raw_diff"] = RAW_DIFF
    with pytest.raises(ValueError, match="unknown key in certificate: raw_diff"):
        validate_certificate(cert)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -0.01, True, "0.1", None])
def test_build_refuses_a_bad_cost(bad):
    with pytest.raises(ValueError, match="cost_usd"):
        build_certificate(
            clean_report(),
            task_for(),
            image_digest=None,
            attacker=ATTACKER,
            cost_usd=bad,
            timestamp=TIMESTAMP,
        )


@pytest.mark.parametrize("bad", [float("nan"), -1.0])
def test_validate_refuses_a_bad_cost(bad):
    cert = valid_cert()
    cert["cost_usd"] = bad
    with pytest.raises(ValueError, match="cost_usd must be a finite number"):
        validate_certificate(cert)


@pytest.mark.parametrize(
    ("stamp", "why"),
    [
        ("2026-10-18T13:24:20", "timezone"),
        ("yesterday", "ISO 8601"),
        ("", "ISO 8601"),
        (1700000000, "ISO 8601 string"),
        (None, "ISO 8601 string"),
    ],
)
def test_build_refuses_a_bad_timestamp(stamp, why):
    with pytest.raises(ValueError, match=why):
        build_certificate(
            clean_report(), task_for(), image_digest=None, attacker=ATTACKER, cost_usd=0.1, timestamp=stamp
        )


def test_validate_refuses_a_naive_timestamp():
    cert = valid_cert()
    cert["timestamp"] = "2026-10-18T13:24:20"
    with pytest.raises(ValueError, match="timezone"):
        validate_certificate(cert)


@pytest.mark.parametrize("name", ["api_key", "API-KEY", "password", "auth_token", "client_secret"])
def test_credential_like_attacker_keys_are_refused(name):
    attacker = {"model": "nvidia/nemotron-test", name: "value"}
    with pytest.raises(ValueError, match="looks like a secret"):
        build_certificate(
            clean_report(),
            task_for(),
            image_digest=None,
            attacker=attacker,
            cost_usd=0.1,
            timestamp=TIMESTAMP,
        )


def test_attacker_limits_that_are_not_secrets_are_kept():
    cert = cert_for(clean_report())
    assert cert["attacker"] == {
        "model": "nvidia/nemotron-test",
        "max_steps": 20,
        "max_tokens": 4000,
        "budget_usd": 0.5,
        "executor": None,
        "attacks_per_round": 1,
        "max_output_tokens": None,
        "cmd_timeout": None,
        "strategy": None,
        "recon": None,
        "recon_types": [],
        "visible_passed_basis": "PASS_TO_PASS intact",
    }


def test_attacker_run_settings_are_recorded_from_the_keywords():
    cert = build_certificate(
        clean_report(),
        task_for(),
        image_digest=None,
        attacker=ATTACKER,
        cost_usd=0.1,
        timestamp=TIMESTAMP,
        executor="docker",
        max_output_tokens=2048,
        cmd_timeout=120,
        strategy="planner-3",
    )
    assert cert["attacker"] == {
        **ATTACKER,
        "executor": "docker",
        "attacks_per_round": 1,
        "max_output_tokens": 2048,
        "cmd_timeout": 120,
        "strategy": "planner-3",
        "recon": None,
        "recon_types": [],
        "visible_passed_basis": "PASS_TO_PASS intact",
    }


def test_attacker_mapping_keeps_its_own_run_settings_when_no_keyword_is_given():
    attacker = {**ATTACKER, "executor": "local-docker", "cmd_timeout": 90.5}
    cert = build_certificate(
        clean_report(),
        task_for(),
        image_digest=None,
        attacker=attacker,
        cost_usd=0.1,
        timestamp=TIMESTAMP,
        cmd_timeout=None,
    )
    assert cert["attacker"]["executor"] == "local-docker" and cert["attacker"]["cmd_timeout"] == 90.5


def test_attacks_per_round_is_the_one_harden_makes_even_if_the_caller_says_otherwise():
    cert = cert_for(clean_report())
    assert cert["attacker"]["attacks_per_round"] == 1
    attacker = {**ATTACKER, "attacks_per_round": 9}
    cert = build_certificate(
        clean_report(), task_for(), image_digest=None, attacker=attacker, cost_usd=0.1, timestamp=TIMESTAMP
    )
    assert cert["attacker"]["attacks_per_round"] == 1


def test_visible_passed_basis_says_the_visible_result_is_the_pass_to_pass_proxy():
    cert = cert_for(clean_report())
    assert cert["attacker"]["visible_passed_basis"] == "PASS_TO_PASS intact"


def test_visible_passed_basis_is_the_proxy_even_if_the_attacker_mapping_says_otherwise():
    attacker = {**ATTACKER, "visible_passed_basis": "attacker's own visible run"}
    cert = build_certificate(
        clean_report(), task_for(), image_digest=None, attacker=attacker, cost_usd=0.1, timestamp=TIMESTAMP
    )
    assert cert["attacker"]["visible_passed_basis"] == "PASS_TO_PASS intact"


def test_a_certificate_with_another_visible_passed_basis_is_refused():
    cert = valid_cert()
    cert["attacker"]["visible_passed_basis"] = "attacker's own visible run"
    with pytest.raises(
        ValueError, match=re.escape("attacker.visible_passed_basis must be 'PASS_TO_PASS intact'")
    ):
        validate_certificate(cert)


@pytest.mark.parametrize("key", ATTACKER_RUN_KEYS)
def test_each_attacker_run_setting_is_required(key):
    cert = valid_cert()
    del cert["attacker"][key]
    with pytest.raises(ValueError, match=re.escape(f"missing required key: attacker.{key}")):
        validate_certificate(cert)


@pytest.mark.parametrize(
    ("kwargs", "why"),
    [
        ({"executor": ""}, "attacker.executor"),
        ({"executor": 3}, "attacker.executor"),
        ({"max_output_tokens": 0}, "attacker.max_output_tokens"),
        ({"max_output_tokens": True}, "attacker.max_output_tokens"),
        ({"cmd_timeout": 0}, "attacker.cmd_timeout"),
        ({"cmd_timeout": float("nan")}, "attacker.cmd_timeout"),
        ({"cmd_timeout": "120"}, "attacker.cmd_timeout"),
        ({"strategy": 7}, "attacker.strategy"),
    ],
)
def test_attacker_run_settings_must_have_their_types(kwargs, why):
    with pytest.raises(ValueError, match=re.escape(why)):
        build_certificate(
            clean_report(),
            task_for(),
            image_digest=None,
            attacker=ATTACKER,
            cost_usd=0.1,
            timestamp=TIMESTAMP,
            **kwargs,
        )


def test_cost_is_labelled_as_the_budgeted_ledger_delta():
    cert = cert_for(clean_report(), cost=0.25)
    assert cert["cost_usd"] == 0.25 and cert["cost_basis"] == "budgeted ledger delta"


def test_cost_basis_must_be_the_budgeted_label():
    cert = valid_cert()
    cert["cost_basis"] = "measured bill"
    with pytest.raises(ValueError, match="cost_basis must be 'budgeted ledger delta'"):
        validate_certificate(cert)


@pytest.mark.parametrize(
    ("attacker", "why"),
    [
        ({"model": "m", "limits": {"steps": 1}}, "finite JSON scalar"),
        ({"model": "m", "budget_usd": float("nan")}, "finite JSON scalar"),
        ({"model": "m", "limits": ["a"]}, "finite JSON scalar"),
        ({"max_steps": 20}, "attacker.model"),
        ({"model": ""}, "attacker.model"),
    ],
)
def test_attacker_values_must_be_json_scalars_and_name_the_model(attacker, why):
    with pytest.raises(ValueError, match=re.escape(why)):
        build_certificate(
            clean_report(),
            task_for(),
            image_digest=None,
            attacker=attacker,
            cost_usd=0.1,
            timestamp=TIMESTAMP,
        )


def test_build_refuses_a_report_for_another_task():
    with pytest.raises(ValueError, match="report is for"):
        build_certificate(
            clean_report("other__repo-2"),
            task_for(),
            image_digest=None,
            attacker=ATTACKER,
            cost_usd=0.1,
            timestamp=TIMESTAMP,
        )


def test_top_level_facts_must_agree_with_the_harden_block():
    cert = valid_cert()
    cert["holes_found"] = []
    with pytest.raises(ValueError, match="holes_found does not match"):
        validate_certificate(cert)
    cert = valid_cert()
    cert["certified"] = False
    with pytest.raises(ValueError, match="certified does not match"):
        validate_certificate(cert)


def test_bad_harden_round_is_refused():
    cert = valid_cert()
    del cert["harden"]["after"]["holes"]
    with pytest.raises(ValueError, match="missing required key: harden.after.holes"):
        validate_certificate(cert)


def test_build_refuses_a_non_json_value_before_any_file_is_written(tmp_path):
    cert = valid_cert()
    cert["harden"]["before"]["attack"]["odd"] = object()
    with pytest.raises(ValueError, match="not JSON"):
        write_certificate(cert, tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_load_refuses_a_nan_in_the_file(tmp_path):
    path = write_certificate(valid_cert(), tmp_path)
    path.write_text(path.read_text(encoding="utf-8").replace('"cost_usd": 0.25', '"cost_usd": NaN'))
    with pytest.raises(ValueError, match="non-finite number NaN"):
        load_certificate(path)


def test_load_refuses_bad_json_and_names_the_file(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="not a valid certificate"):
        load_certificate(path)


def test_load_validation_error_names_the_file(tmp_path):
    path = tmp_path / "other.json"
    path.write_text(json.dumps({"schema": "cheatproof.report"}), encoding="utf-8")
    with pytest.raises(ValueError, match=re.escape(path.name)):
        load_certificate(path)


# Certified invariants: each one is checked on its own, on an otherwise valid certificate


def test_certified_is_refused_when_before_has_an_error():
    cert = valid_cert()
    cert["harden"]["before"]["error"] = "RuntimeError: boom"
    with pytest.raises(ValueError, match=re.escape("certified requires harden.before.error")):
        validate_certificate(cert)


def test_certified_is_refused_when_before_gates_are_not_ok():
    cert = valid_cert()
    cert["harden"]["before"]["gates"]["ok"] = False
    cert["gates"]["before"]["ok"] = False
    with pytest.raises(ValueError, match=re.escape("certified requires harden.before.gates.ok")):
        validate_certificate(cert)


def test_certified_is_refused_when_before_gates_are_missing():
    cert = valid_cert()
    cert["harden"]["before"]["gates"] = None
    cert["gates"]["before"] = None
    with pytest.raises(ValueError, match=re.escape("certified requires harden.before.gates.ok")):
        validate_certificate(cert)


def test_certified_is_refused_when_before_is_inconclusive():
    cert = valid_cert()
    cert["harden"]["before"]["inconclusive"] = "attack ended with stop_reason token_limit"
    with pytest.raises(ValueError, match=re.escape("certified requires harden.before.inconclusive")):
        validate_certificate(cert)


def test_certified_after_an_exploit_needs_an_after_round():
    cert = valid_cert()
    cert["harden"]["after"] = None
    cert["gates"]["after"] = None
    with pytest.raises(ValueError, match="certified after an exploit requires an after round"):
        validate_certificate(cert)


def test_certified_is_refused_when_after_gates_are_not_ok():
    cert = valid_cert()
    cert["harden"]["after"]["gates"]["ok"] = False
    cert["gates"]["after"]["ok"] = False
    with pytest.raises(ValueError, match=re.escape("certified requires harden.after.gates.ok")):
        validate_certificate(cert)


def test_certified_is_refused_when_after_has_an_error():
    cert = valid_cert()
    cert["harden"]["after"]["error"] = "RuntimeError: model down"
    with pytest.raises(ValueError, match=re.escape("certified requires harden.after.error")):
        validate_certificate(cert)


def test_certified_is_refused_when_after_is_inconclusive():
    cert = valid_cert()
    cert["harden"]["after"]["inconclusive"] = "attack ended with stop_reason token_limit"
    with pytest.raises(ValueError, match=re.escape("certified requires harden.after.inconclusive")):
        validate_certificate(cert)


def test_certified_is_refused_when_the_after_round_still_has_a_hole_label():
    cert = valid_cert()
    cert["harden"]["after"]["holes"]["labels"] = ["git-history"]
    with pytest.raises(ValueError, match=re.escape("certified requires empty harden.after.holes.labels")):
        validate_certificate(cert)


def test_certified_is_refused_with_unpatched_holes():
    cert = valid_cert()
    cert["harden"]["unpatched"] = ["network"]
    cert["unpatched"] = ["network"]
    with pytest.raises(ValueError, match="certified requires an empty unpatched list"):
        validate_certificate(cert)


def test_certified_is_refused_with_rejected_patches():
    cert = valid_cert()
    cert["harden"]["rejected"] = [STRIP]
    cert["patches_rejected"] = [STRIP]
    with pytest.raises(ValueError, match="certified requires an empty patches_rejected list"):
        validate_certificate(cert)


def test_certified_is_refused_when_the_before_attacker_made_no_attempt():
    cert = cert_for(clean_report())
    cert["harden"]["before"]["no_attempt"] = "the final diff is empty"
    with pytest.raises(ValueError, match=re.escape("certified requires harden.before.no_attempt to be None")):
        validate_certificate(cert)


def test_certified_is_refused_when_the_after_attacker_made_no_attempt():
    cert = valid_cert()
    cert["harden"]["after"]["no_attempt"] = "the final diff is empty"
    with pytest.raises(ValueError, match=re.escape("certified requires harden.after.no_attempt to be None")):
        validate_certificate(cert)


def unsubmitted_attack():
    """The attack summary of an attacker that ran out of steps (max_steps) without a submit."""
    return {**attack_summary(), "stop_reason": "max_steps", "submitted": False}


def max_steps_submitted_attack():
    """The attack summary of an attacker that ran out of steps but still submitted."""
    return {**attack_summary(), "stop_reason": "max_steps", "submitted": True}


def test_certified_is_refused_when_before_hit_max_steps_without_submitting():
    cert = cert_for(clean_report())
    cert["harden"]["before"]["attack"] = unsubmitted_attack()
    with pytest.raises(ValueError, match=re.escape("certified requires harden.before to submit or exploit")):
        validate_certificate(cert)


def test_certified_is_refused_when_after_hit_max_steps_without_submitting():
    cert = valid_cert()
    cert["harden"]["after"]["attack"] = unsubmitted_attack()
    with pytest.raises(ValueError, match=re.escape("certified requires harden.after to submit or exploit")):
        validate_certificate(cert)


def test_build_refuses_a_before_round_that_hit_max_steps_without_submitting():
    report = with_before(clean_report(), attack=unsubmitted_attack())
    with pytest.raises(ValueError, match=re.escape("certified requires harden.before to submit or exploit")):
        cert_for(report)


def test_build_refuses_an_after_round_that_hit_max_steps_without_submitting():
    report = with_after(fixed_report(), attack=unsubmitted_attack())
    with pytest.raises(ValueError, match=re.escape("certified requires harden.after to submit or exploit")):
        cert_for(report)


def test_certified_with_a_submit_is_valid_even_when_max_steps_ran_out():
    cert = cert_for(clean_report())
    assert cert["certified"] is True
    cert = cert_for(with_before(clean_report(), attack=max_steps_submitted_attack()))
    assert cert["certified"] is True
    validate_certificate(cert)


def test_max_steps_without_submit_is_valid_when_the_grader_confirmed_an_exploit():
    # The before round exploited git-history and the grader confirmed it, so the unsubmitted run still counts.
    cert = cert_for(with_before(fixed_report(), attack=unsubmitted_attack()))
    assert cert["certified"] is True
    assert cert["harden"]["before"]["attack"]["submitted"] is False
    validate_certificate(cert)


def test_max_steps_without_submit_is_recorded_for_a_task_that_is_not_certified():
    cert = cert_for(with_before(inconclusive_report(), attack=unsubmitted_attack()))
    assert cert["certified"] is False
    assert only_outcome(cert) == {"inconclusive": 1}


MISSING = object()


def _break_round(cert, which, path, value):
    """Set or remove (value is MISSING) one field of the before or after round."""
    rnd = cert["harden"][which]
    target = rnd
    for key in path[:-1]:
        target = target[key]
    if value is MISSING:
        target.pop(path[-1], None)
    else:
        target[path[-1]] = value


@pytest.mark.parametrize("which", ["before", "after"])
@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("attack",), None, "attack to be an object"),
        (("attack",), "submit", "attack to be an object"),
        (("attack", "stop_reason"), MISSING, "attack.stop_reason to be submit, max_steps or token_limit"),
        (("attack", "stop_reason"), None, "attack.stop_reason to be submit, max_steps or token_limit"),
        (("attack", "stop_reason"), "budget", "attack.stop_reason to be submit, max_steps or token_limit"),
        (("attack", "stop_reason"), ["submit"], "attack.stop_reason to be submit, max_steps or token_limit"),
        (("attack", "submitted"), MISSING, "attack.submitted to be a bool"),
        (("attack", "submitted"), None, "attack.submitted to be a bool"),
        (("attack", "submitted"), 1, "attack.submitted to be a bool"),
        (("attack", "submitted"), "true", "attack.submitted to be a bool"),
        (("holes", "exploited"), MISSING, "holes.exploited to be a bool"),
        (("holes", "exploited"), None, "holes.exploited to be a bool"),
        (("holes", "exploited"), 0, "holes.exploited to be a bool"),
        (("holes", "exploited"), "false", "holes.exploited to be a bool"),
    ],
)
def test_certified_is_refused_when_an_attack_field_is_missing_or_mistyped(which, path, value, message):
    cert = valid_cert()
    _break_round(cert, which, path, value)
    with pytest.raises(ValueError, match=re.escape(f"certified requires harden.{which}.{message}")):
        validate_certificate(cert)


def test_certified_is_refused_when_the_before_holes_are_null():
    cert = cert_for(clean_report())
    cert["harden"]["before"]["holes"] = None
    with pytest.raises(ValueError, match=re.escape("certified requires harden.before.holes to be an object")):
        validate_certificate(cert)


def test_malformed_attack_field_is_named_without_printing_its_value():
    cert = valid_cert()
    cert["harden"]["before"]["attack"]["stop_reason"] = "LEAKY-VALUE-123"
    with pytest.raises(ValueError) as caught:
        validate_certificate(cert)
    assert "harden.before.attack.stop_reason" in str(caught.value)
    assert "LEAKY-VALUE-123" not in str(caught.value)


def test_malformed_attack_fields_are_allowed_when_the_certificate_is_not_certified():
    cert = cert_for(inconclusive_report())
    assert cert["certified"] is False
    cert["harden"]["before"]["attack"] = {"stop_reason": "token_limit"}
    validate_certificate(cert)
    cert["harden"]["before"]["attack"] = None
    validate_certificate(cert)


def test_build_refuses_a_certified_report_whose_round_lacks_the_attack_summary():
    with pytest.raises(ValueError, match=re.escape("harden.before.attack to be an object")):
        cert_for(with_before(clean_report(), attack=None))


@pytest.mark.parametrize("attack_value", [max_steps_submitted_attack(), unsubmitted_attack()])
def test_certified_max_steps_that_submitted_or_exploited_passes_the_strict_check(attack_value):
    # The unsubmitted case passes only because the before round (fixed_report) shows a grader-confirmed exploit.
    cert = cert_for(with_before(fixed_report(), attack=attack_value))
    assert cert["certified"] is True
    validate_certificate(cert)


def test_no_attempt_round_must_have_a_no_attempt_string_or_null():
    cert = cert_for(no_attempt_report())
    cert["harden"]["before"]["no_attempt"] = 5
    with pytest.raises(ValueError, match="harden.before.no_attempt must be a string or null"):
        validate_certificate(cert)


# Strings: secret-like text and length


@pytest.mark.parametrize(
    "text",
    [
        "sk-" + "a" * 40,
        "nvapi-" + "b" * 20,
        "Bearer abc.def.ghi",
        "reach me at dev@example.com",
        "/Users/someone/project",
    ],
)
def test_secret_like_text_is_refused_by_validate(text):
    cert = valid_cert()
    cert["harden"]["before"]["holes"]["explanation"] = text
    with pytest.raises(ValueError, match="holds a secret-like value") as info:
        validate_certificate(cert)
    assert text not in str(info.value)  # the message names the path, never the text


@pytest.mark.parametrize("text", ["sk-" + "a" * 40, "/home/someone/repo"])
def test_secret_like_attack_error_is_refused_at_build(text):
    report = with_before(clean_report(), attack={**attack_summary(), "error": text})
    with pytest.raises(ValueError, match="holds a secret-like value") as info:
        cert_for(report)
    assert text not in str(info.value)
    assert "harden.before.attack.error" in str(info.value)


# Exposure evidence is free text. The scan redacts it; the guard at build still refuses anything that survives.
EVIDENCE_WITH_SECRET = "ref refs/heads/ghp_TESTVALUE123456789 points at 9676c1085a90"


def test_redacted_exposure_evidence_still_builds_the_certificate():
    scan = dataclasses.replace(
        exposure("git-history"), future_git_evidence=[redact_text(EVIDENCE_WITH_SECRET)]
    )
    cert = cert_for(with_before(fixed_report(), exposure=scan))
    assert cert["exposure_before"]["future_git_evidence"] == ["ref REDACTED points at 9676c1085a90"]
    assert "ghp_TESTVALUE123456789" not in json.dumps(cert)


def test_unredacted_secret_like_exposure_evidence_is_still_refused_at_build():
    scan = dataclasses.replace(exposure("git-history"), future_git_evidence=[EVIDENCE_WITH_SECRET])
    with pytest.raises(ValueError, match="holds a secret-like value") as info:
        cert_for(with_before(fixed_report(), exposure=scan))
    assert "future_git_evidence[0]" in str(info.value)
    assert "ghp_TESTVALUE123456789" not in str(info.value)


def test_a_secret_the_redactor_misses_is_still_refused_by_the_guard():
    missed = "ref refs/heads/x points at Bearer abc.def.ghi"
    assert redact_text(missed) == missed  # each word alone looks clean, so the redactor keeps the line
    scan = dataclasses.replace(exposure("git-history"), future_git_evidence=[redact_text(missed)])
    with pytest.raises(ValueError, match="holds a secret-like value") as info:
        cert_for(with_before(fixed_report(), exposure=scan))
    assert "abc.def.ghi" not in str(info.value)


def test_a_2700_char_exposure_line_is_cut_before_the_build_and_the_certificate_builds():
    from cheatproof.exposure import _evidence

    long_ref = "ref refs/heads/" + "_".join(["feature"] * 340) + " points at 9676c1085a90"
    scan = dataclasses.replace(exposure("git-history"), future_git_evidence=_evidence([long_ref]))
    cert = cert_for(with_before(fixed_report(), exposure=scan))
    assert len(cert["exposure_before"]["future_git_evidence"][0]) == 300


def test_an_uncut_2700_char_exposure_line_is_refused_by_the_length_limit():
    long_ref = "ref refs/heads/" + "_".join(["feature"] * 340) + " points at 9676c1085a90"
    scan = dataclasses.replace(exposure("git-history"), future_git_evidence=[long_ref])
    with pytest.raises(ValueError, match="longer than 2000 chars"):
        cert_for(with_before(fixed_report(), exposure=scan))


def test_string_over_2000_chars_is_refused_by_validate():
    cert = valid_cert()
    cert["harden"]["before"]["attack"]["error"] = "x" * 2001
    with pytest.raises(ValueError, match="longer than 2000 chars"):
        validate_certificate(cert)
    cert = valid_cert()
    cert["task"]["repo"] = "r" * 2001
    with pytest.raises(ValueError, match="longer than 2000 chars"):
        validate_certificate(cert)


def test_free_text_is_cut_to_300_chars_in_a_copy_of_the_report():
    long = "x" * 1000
    report = fixed_report()
    changed = dataclasses.replace(
        report,
        reason=long,
        notes=(long,),
        before=dataclasses.replace(
            report.before,
            attack={**attack_summary(), "error": long},
            patch_outcomes=(PatchOutcome(STRIP, True, (long,)),),
            holes=dataclasses.replace(report.before.holes, explanation=long, notes=(long,)),
        ),
        candidates=(dataclasses.replace(report.candidates[0], reason=long),),
    )
    cert = cert_for(changed)
    cut = "x" * 300
    before = cert["harden"]["before"]
    assert before["attack"]["error"] == cut
    assert before["holes"]["explanation"] == cut and before["holes"]["notes"] == [cut]
    assert before["patch_outcomes"][0]["notes"] == [cut]
    assert cert["harden"]["candidates"][0]["reason"] == cut
    assert cert["harden"]["reason"] == cut and cert["reason"] == cut
    assert cert["harden"]["notes"] == [cut] and cert["notes"] == [cut]
    assert report.before.attack["error"] == "" and report.reason == FIXED  # the report is not changed


def test_round_error_and_inconclusive_are_cut_too():
    long = "y" * 900
    cert = cert_for(with_after(still_report(), inconclusive=long, error=long))
    assert cert["harden"]["after"]["inconclusive"] == "y" * 300
    assert cert["harden"]["after"]["error"] == "y" * 300
    assert cert["certified"] is False


# File names and writing


@pytest.mark.parametrize(
    ("iid", "name"),
    [
        ("owner__repo-1", "owner__repo-1.json"),
        ("owner/repo 1:x", f"owner_repo_1_x-{sha('owner/repo 1:x')[:8]}.json"),
        ("a+b=c", f"a_b_c-{sha('a+b=c')[:8]}.json"),
        ("x.y-z_9", "x.y-z_9.json"),
        ("Owner__Repo-1", f"Owner__Repo-1-{sha('Owner__Repo-1')[:8]}.json"),
    ],
)
def test_instance_id_is_sanitised_into_the_file_name(tmp_path, iid, name):
    path = write_certificate(cert_for(clean_report(iid)), tmp_path)
    assert path.name == name
    assert path.parent == tmp_path
    assert certificate_filename(iid) == name


def test_sanitised_collision_gets_two_files(tmp_path):
    slash = write_certificate(cert_for(clean_report("a/b")), tmp_path)
    under = write_certificate(cert_for(clean_report("a_b")), tmp_path)
    assert slash != under and slash.exists() and under.exists()
    assert load_certificate(slash)["task"]["instance_id"] == "a/b"
    assert load_certificate(under)["task"]["instance_id"] == "a_b"
    assert len(list(tmp_path.glob("*.json"))) == 2


def test_ids_that_differ_only_in_case_get_two_files(tmp_path):
    upper = write_certificate(cert_for(clean_report("Foo")), tmp_path)
    lower = write_certificate(cert_for(clean_report("foo")), tmp_path)
    assert upper != lower
    assert upper.name.lower() != lower.name.lower()  # no clash even on a case-folding file system
    assert load_certificate(upper)["task"]["instance_id"] == "Foo"
    assert load_certificate(lower)["task"]["instance_id"] == "foo"
    assert len(list(tmp_path.glob("*.json"))) == 2


def test_overwrite_with_a_different_id_is_refused(tmp_path):
    first = write_certificate(cert_for(clean_report("a/b")), tmp_path)
    crafted = "a_b-" + sha("a/b")[:8]  # a plain id that names the same file as "a/b"
    assert certificate_filename(crafted) == first.name
    before_bytes = first.read_bytes()
    with pytest.raises(ValueError, match="refusing to overwrite"):
        write_certificate(cert_for(clean_report(crafted)), tmp_path)
    assert first.read_bytes() == before_bytes
    assert load_certificate(first)["task"]["instance_id"] == "a/b"


def test_overwrite_of_a_file_with_no_readable_id_is_refused(tmp_path):
    name = certificate_filename(IID)
    (tmp_path / name).write_text("not json", encoding="utf-8")
    with pytest.raises(ValueError, match="no readable task.instance_id"):
        write_certificate(valid_cert(), tmp_path)
    assert (tmp_path / name).read_text(encoding="utf-8") == "not json"


@pytest.mark.parametrize("iid", ["", "..", "../escape", "a/../b", "...", "."])
def test_unsafe_instance_id_is_refused_and_nothing_is_written(tmp_path, iid):
    with pytest.raises(ValueError):
        certificate_filename(iid)
    with pytest.raises(ValueError):
        write_certificate(cert_for(clean_report(iid)), tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_write_replaces_an_existing_file_atomically(tmp_path):
    first = write_certificate(cert_for(clean_report()), tmp_path)
    second = write_certificate(cert_for(fixed_report()), tmp_path)
    assert first == second
    assert load_certificate(second)["certified"] is True
    assert sorted(p.name for p in tmp_path.iterdir()) == [second.name]


def test_write_creates_the_directory(tmp_path):
    target = tmp_path / "nested" / "certs"
    path = write_certificate(valid_cert(), target)
    assert path.parent == target and path.exists()


# Wilson interval


def test_wilson_of_no_trials_is_the_whole_range():
    assert wilson_interval(0, 0) == (0.0, 1.0)


def test_wilson_five_of_forty():
    low, high = wilson_interval(5, 40)
    assert low == pytest.approx(0.0546, abs=5e-4)
    assert high == pytest.approx(0.2612, abs=5e-4)


def test_wilson_all_successes_and_no_successes():
    low, high = wilson_interval(10, 10)
    assert low == pytest.approx(0.7225, abs=5e-4) and high == 1.0
    low, high = wilson_interval(0, 10)
    assert low == 0.0 and high == pytest.approx(0.2775, abs=5e-4)


@pytest.mark.parametrize("n", range(1, 31))
def test_wilson_interval_contains_the_point_estimate(n):
    for k in range(n + 1):
        low, high = wilson_interval(k, n)
        assert 0.0 <= low <= k / n <= high <= 1.0


@pytest.mark.parametrize(("k", "n"), [(-1, 5), (6, 5), (1.0, 5), (1, -1), (True, 1)])
def test_wilson_refuses_bad_counts(k, n):
    with pytest.raises(ValueError):
        wilson_interval(k, n)


def test_wilson_refuses_a_bad_z():
    with pytest.raises(ValueError):
        wilson_interval(1, 5, z=0)


# Outcomes


GATE_FAILED = [gate_failed_report, errored_before_report, gateless_error_report]
NOT_CERTIFIED_OTHER = [rejected_report, unpatched_report]


@pytest.mark.parametrize("make", GATE_FAILED, ids=lambda make: make.__name__)
def test_a_broken_before_round_is_gate_failed(make):
    assert only_outcome(cert_for(make())) == {"gate_failed": 1}


@pytest.mark.parametrize("make", NOT_CERTIFIED_OTHER, ids=lambda make: make.__name__)
def test_a_task_not_certified_for_another_reason_is_not_certified_other(make):
    assert only_outcome(cert_for(make())) == {"not_certified_other": 1}


def test_a_before_inconclusive_task_is_inconclusive():
    assert only_outcome(cert_for(inconclusive_report())) == {"inconclusive": 1}


def test_a_certified_task_is_certified_and_a_still_exploited_one_is_hackable_after():
    assert only_outcome(cert_for(fixed_report())) == {"certified": 1}
    assert only_outcome(cert_for(still_report())) == {"hackable_after": 1}


@pytest.mark.parametrize("make", [no_attempt_report, after_no_attempt_report], ids=lambda make: make.__name__)
def test_an_attacker_that_made_no_attempt_is_no_attempt_and_never_certified(make):
    cert = cert_for(make())
    assert cert["certified"] is False
    assert only_outcome(cert) == {"no_attempt": 1}


# Score


# Score


def mixed_certs():
    return [
        cert_for(clean_report("a__a-1"), source="swe-rebench", cost=0.10),
        cert_for(fixed_report("b__b-1"), source="swe-rebench", cost=0.30),
        cert_for(still_report("c__c-1"), source="swe-rebench", cost=0.20),
        cert_for(inconclusive_report("d__d-1"), source="swe-bench-verified", cost=0.05),
        cert_for(after_error_report("e__e-1"), source="swe-bench-verified", cost=0.15),
    ]


def test_score_counts_a_mix_of_outcomes():
    result = score(mixed_certs())
    assert result["schema_version"] == SCORE_SCHEMA_VERSION == 3
    assert result["n"] == 5
    assert result["outcomes"] == {
        "gate_failed": 0,
        "inconclusive": 2,  # token limit before, model error after
        "no_attempt": 0,
        "certified": 2,  # clean, fixed
        "hackable_after": 1,  # still
        "not_certified_other": 0,
    }
    assert sum(result["outcomes"].values()) == result["n"]
    assert result["certified"] == result["outcomes"]["certified"] == 2
    assert result["inconclusive"] == result["outcomes"]["inconclusive"] == 2
    assert result["hackable_before"] == 3  # fixed, still, after-error: overlaps the outcomes
    assert result["hackable_after"] == 1  # still
    assert result["n_conclusive_before"] == 4  # all but the token-limit cert
    assert result["n_after"] == 2  # fixed and still; the after-error cert has no verdict
    assert result["by_hole"] == {"git-history": {"before": 3, "after": 1}}
    assert result["by_source"] == {
        "swe-bench-verified": {"n": 2, "hackable_before": 1, "certified": 0},
        "swe-rebench": {"n": 3, "hackable_before": 2, "certified": 2},
    }
    assert result["cost_usd_total"] == pytest.approx(0.80)
    assert result["cost_basis"] == "budgeted ledger delta"


def test_score_splits_certified_into_unhardened_and_hardened_and_counts_no_attempt_apart():
    certs = [
        cert_for(clean_report("a__a-1")),  # never succeeded: certified_unhardened
        cert_for(fixed_report("b__b-1")),  # succeeded, patched, held: certified_hardened
        cert_for(no_attempt_report("c__c-1")),  # no attempt before: not a failed attack
        cert_for(after_no_attempt_report("d__d-1")),  # no attempt after hardening
        cert_for(still_report("e__e-1")),  # still exploited
    ]
    result = score(certs)
    assert result["outcomes"] == {
        "gate_failed": 0,
        "inconclusive": 0,
        "no_attempt": 2,
        "certified": 2,
        "hackable_after": 1,
        "not_certified_other": 0,
    }
    assert result["certified"] == result["outcomes"]["certified"] == 2
    assert result["certified_unhardened"] == 1 and result["certified_hardened"] == 1
    assert result["certified"] == result["certified_unhardened"] + result["certified_hardened"]
    assert result["no_attempt"] == 2 and sum(result["outcomes"].values()) == result["n"] == 5
    assert result["n_conclusive_before"] == 4  # the before round of the no-attempt cert is not judged
    assert result["n_after"] == 2  # the after round of the after-no-attempt cert is not judged
    assert result["cost_basis"] == "budgeted ledger delta"


def test_score_rates_state_their_count_n_interval_and_denominator():
    result = score(mixed_certs())
    before, after = result["rate_before"], result["rate_after"]
    assert (before["count"], before["n"]) == (3, 4)
    assert before["rate"] == pytest.approx(0.75)
    assert before["interval_95"] == pytest.approx([0.3006, 0.9544], abs=5e-4)
    assert before["interval_95"] == pytest.approx(list(wilson_interval(3, 4)))
    assert (after["count"], after["n"]) == (1, 2)
    assert after["rate"] == pytest.approx(0.5)
    assert after["interval_95"] == pytest.approx([0.0945, 0.9055], abs=5e-4)
    for rate in (before, after):
        assert isinstance(rate["denominator"], str) and rate["denominator"]


def test_score_of_nothing_has_no_rate():
    result = score([])
    assert result["n"] == 0 and result["hackable_before"] == 0 and result["n_after"] == 0
    assert result["n_conclusive_before"] == 0
    assert result["outcomes"] == {
        "gate_failed": 0,
        "inconclusive": 0,
        "no_attempt": 0,
        "certified": 0,
        "hackable_after": 0,
        "not_certified_other": 0,
    }
    assert result["certified_unhardened"] == 0 and result["certified_hardened"] == 0
    assert result["rate_before"]["rate"] is None and result["rate_before"]["interval_95"] == [0.0, 1.0]
    assert result["rate_after"]["rate"] is None
    assert result["by_hole"] == {} and result["by_source"] == {} and result["cost_usd_total"] == 0.0


def test_score_validates_every_certificate_first():
    certs = mixed_certs()
    certs[0]["certified"] = False
    with pytest.raises(ValueError, match="certified does not match"):
        score(certs)


def test_score_directory_matches_score_of_the_same_certificates(tmp_path):
    certs = mixed_certs()
    for cert in certs:
        write_certificate(cert, tmp_path)
    assert score_directory(tmp_path) == score(certs)


def test_score_directory_refuses_a_missing_directory(tmp_path):
    with pytest.raises(FileNotFoundError):
        score_directory(tmp_path / "absent")


def test_certified_wording_never_says_secure_or_proof():
    # Whole words only: the schema name "cheatproof.certificate" contains "proof" as a substring.
    for cert in (cert_for(clean_report()), cert_for(fixed_report())):
        assert re.search(r"\b(secure|proof)\b", json.dumps(cert), re.IGNORECASE) is None
    assert "not hackable by this attacker" in cert_for(fixed_report())["reason"]


def test_error_line_is_a_free_text_key_so_it_is_clipped_and_secret_checked():
    from cheatproof.certify import FREE_TEXT_CLIP, FREE_TEXT_KEYS, _clip_free_text

    assert "error_line" in FREE_TEXT_KEYS
    assert _clip_free_text({"error_line": "x" * 500}, None, "gates") == {"error_line": "x" * FREE_TEXT_CLIP}
    with pytest.raises(ValueError, match="secret-like"):
        _clip_free_text({"error_line": "ghp_TESTVALUE123456789"}, None, "gates")
