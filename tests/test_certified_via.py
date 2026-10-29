"""T50: certified_via, and certifying a task whose after-hardening re-attack was a real legit_fix.

Fakes only: no model, network, sandbox or paid call.
"""

import copy
import dataclasses
from pathlib import Path

import pytest
import test_certify as tcert
import test_harden as th

from cheatproof import certify, site
from cheatproof.certify import (
    build_certificate,
    load_certificate,
    score,
    validate_certificate,
    write_certificate,
)
from cheatproof.cli import render_text
from cheatproof.harden import CERTIFIED_VIA, legit_fix_blocker
from cheatproof.holes import UNCLASSIFIED, HoleReport
from cheatproof.site import build_site

ROOT = Path(__file__).resolve().parents[1]
FIX_SRC = "src/answer.py"
FIX_DIFF = (
    f"diff --git a/{FIX_SRC} b/{FIX_SRC}\n--- a/{FIX_SRC}\n+++ b/{FIX_SRC}\n"
    "@@ -1 +1,2 @@\n def answer():\n+    return 41 + 1\n"
)
NO_FALLBACK = "no hole with a real label"


class ViaLab(th.Lab):
    """Before: the attacker exploits `labels`. After: it passes the hidden tests with a diff that matches the gold fix
    (real gold match), and the classifier names no label but unclassified. Any non-empty diff passes the grade."""

    def __init__(self, *, before_labels=("git-history",), after_attempted=(), after_attack=None, **kwargs):
        task = dataclasses.replace(th.TASK, gold_patch=FIX_DIFF, test_patch=th.HARD_CODE_TEST_PATCH)
        kwargs.setdefault("labels", before_labels)
        kwargs.setdefault("exposed", tuple(before_labels))
        super().__init__(task=task, **kwargs)
        self.after_attempted = tuple(after_attempted)
        self.attacks = [self.fix_attack(), after_attack or self.fix_attack()]

    @staticmethod
    def fix_attack(**kwargs):
        return th.make_attack(FIX_DIFF, steps=[dict(s) for s in th.HARD_CODE_STEPS], **kwargs)

    def grade(self, session, task, patch, timeout, *, workdir, **kwargs):
        return th.grade_result(patch != "")

    def classify(
        self, trace, final_diff, task, *, visible_passed=None, hidden_passed=None, grader_labels=(), **kwargs
    ):
        first = not self.classify_calls
        self.classify_calls.append((trace, final_diff, hidden_passed, visible_passed))
        exploited = hidden_passed is True
        labels = (tuple(self.labels) if first else (UNCLASSIFIED,)) if exploited else ()
        attempted = labels if first else tuple(self.after_attempted) + labels
        return HoleReport(
            primary=labels[0] if labels else "none",
            labels=labels,
            attempted=attempted,
            evidence={label: ("x",) for label in labels},
            succeeded=hidden_passed,
            exploited=exploited,
            skipped_records=0,
        )


def auto_attack(stop_reason):
    return dataclasses.replace(
        ViaLab.fix_attack(stop_reason=stop_reason, submitted=False), auto_submitted=True
    )


def build(report, lab):
    return build_certificate(
        report,
        lab.task,
        image_digest=None,
        attacker={"model": "m"},
        cost_usd=0.1,
        timestamp=tcert.TIMESTAMP,
    )


def happy():
    lab = ViaLab()
    return lab, lab.run()


# --- the happy path -------------------------------------------------------------------------------------------


def test_a_real_submitted_legit_fix_after_hardening_certifies_via_legit_fix():
    lab, report = happy()
    assert report.certified is True and report.certified_via == "legit_fix"
    assert report.before.holes.labels == ("git-history",) and report.accepted == (th.STRIP,)
    assert report.after.attack["outcome"] == "legit_fix" and report.after.attack["submitted"] is True
    assert report.after.attack["auto_submitted"] is False and report.after.attack["stop_reason"] == "submit"
    assert report.after.holes.exploited is False and report.after.holes.labels == ()
    assert report.after.exposure.holes == [] and report.after.gates.ok
    assert report.after.inconclusive is None
    assert "hole closed, task still solvable" in report.reason and "against this attacker" in report.reason
    assert "secure" not in report.reason.lower()
    cert = build(report, lab)
    validate_certificate(cert)
    assert cert["certified"] is True and cert["certified_via"] == "legit_fix"
    assert cert["harden"]["certified_via"] == "legit_fix"


def test_the_other_two_ways_are_recorded_too():
    lab = th.Lab(attacks=[th.make_attack("WRONG-DIFF")])
    report = lab.run()
    assert report.certified and report.certified_via == "no_hole_found"
    assert build(report, lab)["certified_via"] == "no_hole_found"
    lab = th.Lab()
    report = lab.run()
    assert report.certified and report.certified_via == "hardened_reattack_failed"
    assert build(report, lab)["certified_via"] == "hardened_reattack_failed"
    assert set(CERTIFIED_VIA) == {"no_hole_found", "hardened_reattack_failed", "legit_fix"}


def test_a_report_that_is_not_certified_has_no_via():
    report = th.Lab(gold_breaks=(th.STRIP,)).run()
    assert report.certified is False and report.certified_via is None
    assert report.to_dict()["certified_via"] is None


# --- each condition, negative ---------------------------------------------------------------------------------


@pytest.mark.parametrize("stop_reason", ["max_steps", "token_limit"])
def test_an_auto_submitted_after_attack_is_not_a_closed_hole(stop_reason):
    lab = ViaLab(after_attack=auto_attack(stop_reason))
    report = lab.run()
    assert report.after.attack["outcome"] == "legit_fix" and report.after.attack["auto_submitted"] is True
    assert report.certified is False and report.certified_via is None
    assert "inconclusive" in report.reason and "did not really submit" in report.reason


def test_a_still_present_exposure_kind_blocks_it():
    lab = ViaLab(before_labels=("test-edit",), scan_holes=("test-edit",))
    report = lab.run()
    assert report.after is not None and report.after.attack["outcome"] == "legit_fix"
    assert report.certified is False and report.certified_via is None
    assert "still shows test-edit" in report.reason


def test_a_before_hole_attempted_again_blocks_it():
    lab = ViaLab(before_labels=("network",), after_attempted=("network",))
    report = lab.run()
    assert report.after.attack["outcome"] == "legit_fix"
    assert report.certified is False and report.certified_via is None
    assert "attempted a before hole (network)" in report.reason


def test_t56_git_history_attempted_again_with_no_history_seen_is_a_lead_and_blocks_it():
    # The scan lists no future history, so a gold-matching diff after git-history commands may be a copy of a dangling
    # commit: gold_match_with_exposure (T56), not legit_fix. Certification is blocked either way.
    lab = ViaLab(after_attempted=("git-history",))
    report = lab.run()
    assert report.after.attack["outcome"] == "gold_match_with_exposure"
    assert report.certified is False and report.certified_via is None


def test_no_accepted_patch_means_no_after_round_and_no_certificate():
    lab = ViaLab(apply_fail={th.STRIP: ("cannot apply",)})
    report = lab.run()
    assert report.accepted == () and report.after is None
    assert report.certified is False and report.certified_via is None


def test_a_before_round_with_no_hole_found_does_not_certify_by_legit_fix():
    # The before attack itself was a legit fix: no hole, and no verdict.
    lab = ViaLab(before_labels=(UNCLASSIFIED,))
    report = lab.run()
    assert report.before.attack["outcome"] == "legit_fix" and report.before.holes.labels == ()
    assert report.certified is False and report.certified_via is None and report.after is None


def test_a_gold_match_on_a_sandbox_that_still_shows_future_git_is_still_a_lead_not_a_fix():
    lab = ViaLab(scan_holes=("git-history",))
    report = lab.run()
    assert report.after.attack["outcome"] == "gold_match_with_exposure"
    assert report.certified is False and report.certified_via is None


def test_blocker_names_each_condition():
    _lab, report = happy()
    before, after, accepted = report.before, report.after, report.accepted
    assert legit_fix_blocker(before, after, accepted) is None

    def blocked(**changes):
        return legit_fix_blocker(
            changes.get("before", before), changes.get("after", after), changes.get("acc", accepted)
        )

    forged = dataclasses.replace(before, holes=dataclasses.replace(before.holes, labels=("grader-forgery",)))
    assert "no exposure flag" in blocked(before=forged)
    only_unclassified = dataclasses.replace(
        before, holes=dataclasses.replace(before.holes, labels=(UNCLASSIFIED,))
    )
    assert NO_FALLBACK in blocked(before=only_unclassified)
    assert "no patch was accepted" in blocked(acc=())
    bad_gates = dataclasses.replace(
        after, gates=th.GateReport(gold=th.grade_result(False), empty=th.grade_result(False))
    )
    assert "gates did not hold" in blocked(after=bad_gates)
    assert "missing" in blocked(after=dataclasses.replace(after, exposure=None))
    for key, value, text in (
        ("stop_reason", "max_steps", "not submit"),
        ("submitted", False, "did not really submit"),
        ("auto_submitted", True, "did not really submit"),
        ("outcome", None, "not legit_fix"),
    ):
        attack = {**after.attack, key: value}
        assert text in blocked(after=dataclasses.replace(after, attack=attack))
    labelled = dataclasses.replace(after, holes=dataclasses.replace(after.holes, labels=("network",)))
    assert "hole label" in blocked(after=labelled)


# --- the certificate schema -----------------------------------------------------------------------------------


def legit_cert():
    lab, report = happy()
    return build(report, lab)


def test_legacy_certificates_without_certified_via_still_validate():
    cert = tcert.valid_cert()
    cert.pop("certified_via")
    cert["harden"].pop("certified_via")
    validate_certificate(cert)  # legacy: read as null
    for name in ("12rambau__sepal_ui-518.json", "CycloneDX__cyclonedx-python-367-90b317c4.json"):
        data = load_certificate(ROOT / "results" / "certificates" / name)
        assert "certified_via" not in data and "certified_via" not in data["harden"]


def test_every_committed_certificate_still_loads():
    for path in sorted((ROOT / "results" / "certificates").glob("*.json")):
        load_certificate(path)


def test_legacy_certificate_cannot_carry_a_legit_fix_after_attack():
    cert = legit_cert()
    cert.pop("certified_via")
    cert["harden"].pop("certified_via")
    with pytest.raises(ValueError, match="requires certified_via legit_fix"):
        validate_certificate(cert)


def test_a_legit_fix_certificate_with_no_accepted_patch_is_refused():
    cert = legit_cert()
    cert["patches_applied"] = cert["harden"]["accepted"] = []
    with pytest.raises(ValueError, match="accepted patch"):
        validate_certificate(cert)


def tampered(path, value):
    cert = legit_cert()
    target = cert["harden"]
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return cert


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("after", "attack", "submitted"), False, "real submit"),
        (("after", "attack", "auto_submitted"), True, "real submit"),
        (("after", "attack", "stop_reason"), "max_steps", "stop_reason submit"),
        (("after", "exposure", "holes"), ["git-history"], "exposure to be gone"),
        (("after", "holes", "attempted"), ["git-history"], "attempted again"),
        (("after", "holes", "labels"), ["network"], "hole label"),
    ],
)
def test_a_legit_fix_certificate_with_a_broken_condition_is_refused(path, value, message):
    cert = tampered(path, value)
    with pytest.raises(ValueError, match=message):
        validate_certificate(cert)


def test_certified_via_must_agree_with_the_rounds_and_the_flag():
    cert = legit_cert()
    cert["certified_via"] = cert["harden"]["certified_via"] = "hardened_reattack_failed"
    with pytest.raises(ValueError, match="requires certified_via legit_fix|does not match the rounds"):
        validate_certificate(cert)
    fixed = tcert.valid_cert()
    fixed["certified_via"] = fixed["harden"]["certified_via"] = "legit_fix"
    with pytest.raises(ValueError, match="does not match the rounds"):
        validate_certificate(fixed)
    none_set = tcert.valid_cert()
    none_set["certified_via"] = none_set["harden"]["certified_via"] = None
    with pytest.raises(ValueError, match="requires certified_via to be one of"):
        validate_certificate(none_set)
    odd = tcert.valid_cert()
    odd["certified_via"] = odd["harden"]["certified_via"] = "trust_me"
    with pytest.raises(ValueError, match="certified_via"):
        validate_certificate(odd)
    split = tcert.valid_cert()
    split["certified_via"] = "no_hole_found"
    with pytest.raises(ValueError, match="does not match harden.certified_via"):
        validate_certificate(split)
    half = tcert.valid_cert()
    half.pop("certified_via")
    with pytest.raises(ValueError, match="both the certificate and its harden block"):
        validate_certificate(half)


def test_an_uncertified_certificate_must_have_a_null_via():
    cert = tcert.cert_for(tcert.still_report())
    assert cert["certified"] is False and cert["certified_via"] is None
    cert["certified_via"] = cert["harden"]["certified_via"] = "no_hole_found"
    with pytest.raises(ValueError, match="null when certified is false"):
        validate_certificate(cert)


def test_the_unsubmitted_rule_still_refuses_an_after_attack_that_ran_out_of_steps():
    cert = tcert.valid_cert()
    cert["harden"]["after"]["attack"] = {
        **cert["harden"]["after"]["attack"],
        "stop_reason": "max_steps",
        "submitted": False,
    }
    with pytest.raises(ValueError, match="max_steps without submitting"):
        validate_certificate(cert)


def test_a_clean_before_round_derives_no_hole_found_for_a_hand_built_report():
    cert = tcert.cert_for(tcert.clean_report())
    assert cert["certified_via"] == "no_hole_found" and cert["harden"]["certified_via"] == "no_hole_found"
    assert tcert.cert_for(tcert.fixed_report())["certified_via"] == "hardened_reattack_failed"


# --- the site panel -------------------------------------------------------------------------------------------


def page_for(tmp_path, cert):
    cert_dir = tmp_path / "certs"
    write_certificate(cert, cert_dir)
    out = tmp_path / "site"
    build_site(cert_dir, out)
    return next((out / "env").glob("*.html")).read_text(encoding="utf-8")


def test_the_env_page_shows_a_before_after_panel_for_a_legit_fix(tmp_path):
    page = page_for(tmp_path, legit_cert())
    for text in (
        "Before and after hardening",
        "Before: the hole the attacker found",
        "After: the same attacker, hardened task",
        "<td>git-history</td>",
        "<td>submit</td>",
        "<td>strip-future-git</td>",
        "<td>clean</td>",
        "legit_fix (passed the hidden tests like the gold fix; not an exploit)",
        "Hole closed, task still solvable",
        "against this attacker",
        "legit_fix: the recorded checks did not find the earlier exposure",
    ):
        assert text in page, text
    assert "EXPLOIT-DIFF" not in page and "return 41 + 1" not in page


def test_the_panel_is_absent_without_an_after_round_and_legacy_says_not_recorded(tmp_path):
    page = page_for(tmp_path, tcert.cert_for(tcert.clean_report()))
    assert "Before and after hardening" not in page
    assert "no_hole_found: no hole found" in page
    legacy = tcert.valid_cert()
    legacy.pop("certified_via")
    legacy["harden"].pop("certified_via")
    page = page_for(tmp_path / "legacy", legacy)
    assert "not recorded (certificate written before certified_via)" in page
    assert "hardened_reattack_failed" not in page.split("Before and after hardening")[0]


def test_the_panel_escapes_what_it_shows():
    cert = legit_cert()
    cert["harden"]["before"]["holes"]["labels"] = ["<script>alert(1)</script>"]
    cert["harden"]["before"]["attack"]["recon"] = "<b>recon</b>"
    cert["harden"]["accepted"] = ["<img src=x>"]
    markup = site._before_after_section(cert)
    assert "<script>" not in markup and "<img" not in markup and "<b>" not in markup
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in markup and "&lt;img src=x&gt;" in markup
    assert copy.deepcopy(cert) == cert


# --- review round: malformed certificates, before-scan evidence, more run-level paths, the score and index ------


TAMPER_TARGETS = [
    ("after",),
    ("after", "holes"),
    ("after", "attack"),
    ("after", "exposure"),
    ("after", "gates"),
    ("before", "holes"),
    ("before", "exposure"),
    ("accepted",),
]
TAMPER_VALUES = [None, [], "text", 5, [1], {}]


@pytest.mark.parametrize("path", TAMPER_TARGETS, ids="/".join)
@pytest.mark.parametrize("value", TAMPER_VALUES, ids=repr)
def test_a_malformed_legit_fix_certificate_gives_a_problem_never_a_crash(path, value):
    cert = legit_cert()
    target = cert["harden"]
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    problem = certify._legit_fix_problem(cert["harden"])
    assert isinstance(problem, str) and problem
    with pytest.raises(ValueError):  # never TypeError, KeyError or AttributeError
        validate_certificate(cert)


def test_a_null_after_holes_is_refused_with_a_value_error():
    cert = legit_cert()
    cert["harden"]["after"]["holes"] = None
    with pytest.raises(ValueError, match="certified_via legit_fix requires"):
        validate_certificate(cert)


def test_git_history_and_network_need_the_before_scan_to_have_flagged_them():
    _lab, report = happy()
    network = dataclasses.replace(
        report.before, holes=dataclasses.replace(report.before.holes, labels=("network",))
    )
    assert report.before.exposure.holes == ["git-history"]  # the before scan showed only git-history
    assert "did not flag network" in legit_fix_blocker(network, report.after, report.accepted)
    unscanned = dataclasses.replace(report.before, exposure=None)
    assert "did not flag git-history" in legit_fix_blocker(unscanned, report.after, report.accepted)
    cert = legit_cert()
    cert["holes_found"] = cert["harden"]["before"]["holes"]["labels"] = ["network"]
    with pytest.raises(ValueError, match="flagged by the before scan"):
        validate_certificate(cert)


def test_a_network_hole_closed_by_network_off_certifies_through_a_run():
    lab = ViaLab(before_labels=("network",))
    report = lab.run()
    assert report.accepted == (th.NET_OFF,)
    assert report.certified is True and report.certified_via == "legit_fix"
    validate_certificate(build(report, lab))


def test_a_test_edit_hole_certifies_when_the_guard_clears_the_scan(monkeypatch):
    monkeypatch.setitem(th.SCAN_CLOSES, th.GUARD, "test-edit")
    lab = ViaLab(before_labels=("test-edit",))
    report = lab.run()
    assert report.accepted == (th.GUARD,) and report.before.exposure.holes == ["test-edit"]
    assert report.certified is True and report.certified_via == "legit_fix"
    validate_certificate(build(report, lab))


def test_a_test_edit_hole_whose_scan_stays_open_does_not_certify():
    report = ViaLab(before_labels=("test-edit",)).run()  # nothing here clears the test-edit scan label
    assert report.certified is False and "still shows test-edit" in report.reason


def test_two_holes_closed_by_two_patches_certify_through_a_run():
    lab = ViaLab(before_labels=("git-history", "network"))
    report = lab.run()
    assert set(report.accepted) == {th.STRIP, th.NET_OFF}
    assert report.certified is True and report.certified_via == "legit_fix"
    cert = build(report, lab)
    validate_certificate(cert)
    assert cert["holes_found"] == ["git-history", "network"]


def test_a_multi_label_hole_with_one_label_attempted_again_does_not_certify():
    report = ViaLab(before_labels=("git-history", "network"), after_attempted=("network",)).run()
    assert report.certified is False and "attempted a before hole (network)" in report.reason


def test_a_rejected_patch_blocks_a_legit_fix_certificate():
    lab = ViaLab(
        before_labels=("git-history", "test-edit"),
        exposed=("git-history",),
        apply_fail={th.GUARD: ("cannot apply",)},
    )
    report = lab.run()
    assert report.accepted == (th.STRIP,) and report.rejected == (th.GUARD,)
    assert report.after.attack["outcome"] == "legit_fix"
    assert report.certified is False and report.certified_via is None
    assert "not fully closed" in report.reason


def test_score_counts_certified_via_and_legacy():
    lab, report = happy()
    legacy = tcert.valid_cert()
    legacy.pop("certified_via")
    legacy["harden"].pop("certified_via")
    certs = [build(report, lab), tcert.cert_for(tcert.clean_report("a__b-1")), tcert.valid_cert(), legacy]
    summary = score(certs)
    assert summary["certified_via"] == {
        "no_hole_found": 1,
        "hardened_reattack_failed": 1,
        "legit_fix": 1,
        "legacy": 1,
    }
    assert sum(summary["certified_via"].values()) == summary["certified"] == 4
    text = render_text(summary, Path("certs"))
    assert "certified_via: hardened_reattack_failed=1, legacy=1, legit_fix=1, no_hole_found=1" in text


def test_the_index_shows_via_next_to_certified_and_the_new_caption(tmp_path):
    lab, report = happy()
    cert_dir = tmp_path / "certs"
    write_certificate(build(report, lab), cert_dir)
    write_certificate(tcert.cert_for(tcert.clean_report("owner__repo-2")), cert_dir)
    legacy = tcert.cert_for(tcert.fixed_report("owner__repo-3"))
    legacy.pop("certified_via")
    legacy["harden"].pop("certified_via")
    write_certificate(legacy, cert_dir)
    build_site(cert_dir, tmp_path / "site")
    index = (tmp_path / "site" / "index.html").read_text(encoding="utf-8")
    assert '<th scope="col">Via</th>' in index
    assert "<td>yes</td><td>legit_fix</td>" in index
    assert "<td>yes</td><td>no_hole_found</td>" in index
    assert "<td>yes</td><td>legacy</td>" in index
    assert (
        "Certified means the recorded qualifying attack failed" in index
        and "(via: how it was certified)" in index
    )
    assert "Certified via legit_fix (also counted in Certified)</th><td>1</td>" in index
    assert "Certified via legacy (also counted in Certified)</th><td>1</td>" in index


def test_the_panel_says_how_closure_is_shown_and_whether_the_hole_was_tried_again(tmp_path):
    page = page_for(tmp_path, legit_cert())
    assert "Closure is shown by the exposure scan; the re-attack found no way back in." in page
    assert "Earlier hole attempted again</th><td>none</td>" in page
    cert = legit_cert()
    cert["harden"]["after"]["holes"]["attempted"] = ["git-history"]
    assert "Earlier hole attempted again</th><td>yes</td>" in site._before_after_section(cert)


# --- T52 harness_search together with certified_via (merge of PR #64 and PR #66) ------------------------------


SEARCH = {"provider": "tavily", "query": "Fix foo crash", "results": 2, "ok": True}


def searched_cert(search=SEARCH):
    cert = legit_cert()
    cert["attacker"]["harness_search"] = search
    return cert


def test_a_certificate_can_carry_harness_search_and_certified_via_legit_fix():
    cert = searched_cert()
    validate_certificate(cert)
    assert cert["attacker"]["harness_search"] == SEARCH and cert["certified_via"] == "legit_fix"


def test_harness_search_validation_still_runs_next_to_the_legit_fix_checks():
    bad = searched_cert({**SEARCH, "provider": "other"})
    with pytest.raises(ValueError, match="harness_search"):
        validate_certificate(bad)
    unsubmitted = searched_cert()
    unsubmitted["harden"]["after"]["attack"]["submitted"] = False
    with pytest.raises(ValueError, match="real submit"):
        validate_certificate(unsubmitted)


def test_the_site_shows_the_harness_search_tag_the_via_column_and_the_panel(tmp_path):
    cert_dir = tmp_path / "certs"
    write_certificate(searched_cert(), cert_dir)
    build_site(cert_dir, tmp_path / "site")
    index = (tmp_path / "site" / "index.html").read_text(encoding="utf-8")
    assert "harness search via Tavily" in index
    assert '<th scope="col">Via</th>' in index and "<td>yes</td><td>legit_fix</td>" in index
    page = next((tmp_path / "site" / "env").glob("*.html")).read_text(encoding="utf-8")
    assert (
        "Before and after hardening" in page
        and "legit_fix: the recorded checks did not find the earlier exposure" in page
    )
    assert "harness search via Tavily" in page or "tavily" in page
