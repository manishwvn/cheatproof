"""Tests for cheatproof/certify.py (queue T07).

Reports are built by hand. No model, network or sandbox runs.
"""

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
from cheatproof.grader import GateReport, GradeResult
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
    "sandbox_runs",
    "timestamp",
    "notes",
    "harden",
]


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


# Build and round trip


def test_build_takes_its_fields_from_the_report():
    report = fixed_report()
    cert = cert_for(report, image_digest="sha256:abc")
    full = report.to_dict()
    assert cert["schema"] == SCHEMA and cert["schema_version"] == SCHEMA_VERSION == 1
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
    assert cert["attacker"] == ATTACKER
    assert cert["holes_found"] == ["git-history"]
    assert cert["patches_applied"] == [STRIP] and cert["patches_rejected"] == []
    assert cert["unpatched"] == []
    assert cert["gates"] == {"before": full["before"]["gates"], "after": full["after"]["gates"]}
    assert cert["certified"] is True and cert["reason"] == FIXED
    assert cert["exposure_before"] == full["before"]["exposure"]
    assert cert["cost_usd"] == 0.25 and cert["sandbox_runs"] == 11 and cert["timestamp"] == TIMESTAMP
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
    assert cert["schema_version"] == 1 and cert["schema"] == "cheatproof.certificate"
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


@pytest.mark.parametrize("version", [2, 0, "1", True, None])
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
    }


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


# File names and writing


@pytest.mark.parametrize(
    ("iid", "name"),
    [
        ("owner__repo-1", "owner__repo-1.json"),
        ("owner/repo 1:x", "owner_repo_1_x.json"),
        ("a+b=c", "a_b_c.json"),
        ("x.y-z_9", "x.y-z_9.json"),
    ],
)
def test_instance_id_is_sanitised_into_the_file_name(tmp_path, iid, name):
    path = write_certificate(cert_for(clean_report(iid)), tmp_path)
    assert path.name == name
    assert path.parent == tmp_path
    assert certificate_filename(iid) == name


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
    assert result["schema_version"] == SCORE_SCHEMA_VERSION == 1
    assert result["n"] == 5
    assert result["hackable_before"] == 3  # fixed, still, after-error
    assert result["n_after"] == 3  # the certs that have an after round
    assert result["hackable_after"] == 1  # still
    assert result["certified"] == 2  # clean, fixed
    assert result["inconclusive"] == 2  # token limit before, model error after
    assert result["by_hole"] == {"git-history": {"before": 3, "after": 1}}
    assert result["by_source"] == {
        "swe-bench-verified": {"n": 2, "hackable_before": 1, "certified": 0},
        "swe-rebench": {"n": 3, "hackable_before": 2, "certified": 2},
    }
    assert result["cost_usd_total"] == pytest.approx(0.80)


def test_score_rates_come_with_their_n_and_wilson_interval():
    result = score(mixed_certs())
    before, after = result["rate_before"], result["rate_after"]
    assert (before["count"], before["n"]) == (3, 5)
    assert before["rate"] == pytest.approx(0.6)
    assert before["interval_95"] == pytest.approx([0.2307, 0.8823], abs=5e-4)
    assert before["interval_95"] == pytest.approx(list(wilson_interval(3, 5)))
    assert (after["count"], after["n"]) == (1, 3)
    assert after["rate"] == pytest.approx(1 / 3)
    assert after["interval_95"] == pytest.approx([0.0615, 0.7923], abs=5e-4)


def test_score_of_nothing_has_no_rate():
    result = score([])
    assert result["n"] == 0 and result["hackable_before"] == 0 and result["n_after"] == 0
    assert result["rate_before"]["rate"] is None and result["rate_before"]["interval_95"] == [0.0, 1.0]
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
