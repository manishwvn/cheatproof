"""Tests for cheatproof/confirm.py and its use in `report` and the site (queue T54).

Confirmed holes versus unconfirmed leads, the manifest, the Wilson rule (no interval below n = 10) and replications.
Reports are built by hand with the fixtures of test_certify.py; the committed certificates are read, never written.
No model, network or sandbox run.
"""

import copy
import dataclasses
import json
from pathlib import Path

import pytest
from test_certify import (
    TIMESTAMP,
    cert_for,
    clean_report,
    fixed_report,
    still_report,
    with_before,
)

from cheatproof import cli, confirm
from cheatproof.certify import load_certificate, score, score_directory, write_certificate
from cheatproof.confirm import ConfirmationError
from cheatproof.site import build_site

REPO = Path(__file__).resolve().parent.parent
COMMITTED = REPO / "results" / "certificates"
MANIFEST = REPO / "results" / "confirmations.json"
HERO = "CycloneDX__cyclonedx-python-348"
LEAD = "ArkEcosystem__python-crypto-116"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def with_t53(report, lines=2):
    """The report whose before round has T53 evidence: the exposure scan listed future-added lines."""
    scan = dataclasses.replace(report.before.exposure, future_added_lines=lines, future_added_complete=True)
    return with_before(report, exposure=scan)


def recon_cert(report):
    """The certificate for report, with recon on (the denominator rule needs attacker.recon)."""
    cert = cert_for(report)
    cert["attacker"]["recon"] = "exposure"
    return cert


def write_json(directory: Path, name: str, data) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return path


def report_deps():
    """Deps for `report`: the real scorer and nothing else (Deps.default() would load .env)."""
    return dataclasses.replace(cli.Deps.for_dry_run(), score_directory=score_directory)


def committed_certs():
    return [load_certificate(path) for path in sorted(COMMITTED.glob("*.json"))]


# The manifest


def entry(**changes):
    base = {
        "status": "confirmed",
        "basis": "manual causal check 2026-10-24: steps 12-15",
        "note": "n = 1 run",
    }
    return {**base, **changes}


def test_the_committed_manifest_has_exactly_the_two_entries():
    manifest = confirm.load_manifest(MANIFEST)
    assert sorted(manifest) == [LEAD, HERO]
    assert manifest[HERO]["status"] == "confirmed"
    assert manifest[LEAD]["status"] == "lead"
    assert all(set(item) == {"status", "basis", "note"} for item in manifest.values())
    assert "65bf318" in manifest[HERO]["basis"] and "194d2878fe08" in manifest[HERO]["basis"]
    assert "if isinstance(package_data.get('hashes'), list):" in manifest[HERO]["basis"]
    assert "9f64e184" in manifest[LEAD]["basis"] and "step 31" in manifest[LEAD]["basis"]


@pytest.mark.parametrize(
    "data",
    [
        [],
        {"a": []},
        {"a": entry(extra=1)},
        {"a": entry(status="maybe")},
        {"a": {"status": "lead"}},
        {"a": entry(basis="")},
        {"a": entry(basis=5)},
        {"a": entry(note=None)},
        {"": entry()},
        {"a": {"basis": "x"}},
    ],
)
def test_the_manifest_is_validated_strictly(tmp_path, data):
    path = write_json(tmp_path, "confirmations.json", data)
    with pytest.raises(ConfirmationError):
        confirm.load_manifest(path)


def test_a_missing_manifest_is_empty_and_a_symlink_or_nan_is_refused(tmp_path):
    assert confirm.load_manifest(tmp_path / "confirmations.json") == {}
    real = write_json(tmp_path, "real.json", {})
    link = tmp_path / "link.json"
    link.symlink_to(real)
    with pytest.raises(ConfirmationError, match="symlink"):
        confirm.load_manifest(link)
    nan = tmp_path / "nan.json"
    nan.write_text('{"a": NaN}', encoding="utf-8")
    with pytest.raises(ConfirmationError):
        confirm.load_manifest(nan)


def test_a_note_is_optional(tmp_path):
    item = entry()
    del item["note"]
    path = write_json(tmp_path, "confirmations.json", {"a": item})
    assert confirm.load_manifest(path)["a"]["status"] == "confirmed"


# Status per hole


def test_git_history_without_t53_evidence_is_a_lead():
    cert = cert_for(
        fixed_report("owner__repo-1")
    )  # future_added_lines is 0, as in a certificate written before T53
    status = confirm.hole_status(cert)
    assert status.task == confirm.LEAD
    assert status.before == {"git-history": "lead"}
    assert status.after == {}


def test_git_history_with_a_shared_future_line_is_confirmed():
    status = confirm.hole_status(cert_for(with_t53(fixed_report("owner__repo-1"))))
    assert status.task == confirm.CONFIRMED
    assert status.before == {"git-history": "confirmed"}


def test_a_label_other_than_git_history_carries_its_own_evidence():
    cert = cert_for(fixed_report("owner__repo-1"))
    cert["holes_found"] = ["test-edit"]
    assert confirm.hole_status(cert).task == confirm.CONFIRMED


def test_a_certificate_with_no_hole_has_no_status():
    status = confirm.hole_status(cert_for(clean_report("owner__repo-1")))
    assert status.task == confirm.NO_HOLE and status.before == {}


def test_a_manifest_entry_decides_the_before_round_either_way():
    lead_cert = cert_for(fixed_report("owner__repo-1"))
    confirmed_cert = cert_for(with_t53(fixed_report("owner__repo-2")))
    up = confirm.hole_status(lead_cert, {"owner__repo-1": entry(status="confirmed")})
    down = confirm.hole_status(confirmed_cert, {"owner__repo-2": entry(status="lead")})
    assert up.task == confirm.CONFIRMED and up.manifest and "confirmations.json" in up.source
    assert down.task == confirm.LEAD and down.before == {"git-history": "lead"}


def test_a_manifest_lead_also_downgrades_the_after_labels_but_a_confirmed_entry_does_not_upgrade_them():
    cert = cert_for(still_report("owner__repo-3"))
    assert confirm.hole_status(cert).after == {"git-history": "lead"}
    down = confirm.hole_status(cert, {"owner__repo-3": entry(status="lead")})
    up = confirm.hole_status(cert, {"owner__repo-3": entry(status="confirmed")})
    assert down.after == {"git-history": "lead"}
    assert up.after == {"git-history": "lead"}  # the entry covers the before round only


def test_an_entry_for_a_task_without_a_hole_is_listed_as_unused():
    certs = [cert_for(clean_report("owner__repo-1"))]
    summary = confirm.summarize(certs, {"owner__repo-1": entry(), "elsewhere": entry()})
    assert summary["confirmed_holes"] == 0
    assert summary["manifest_unused"] == ["elsewhere", "owner__repo-1"]


def test_counts_line_wording():
    certs = [cert_for(with_t53(fixed_report("owner__repo-1"))), cert_for(still_report("owner__repo-3"))]
    summary = confirm.summarize(certs)
    assert confirm.counts_line(summary) == (
        "confirmed holes: 1; unconfirmed leads: 1; certified: 1 "
        "(via no_hole_found=0, hardened_reattack_failed=1, legit_fix=0, legacy=0)"
    )


def test_the_committed_certificates_give_one_confirmed_hole_and_one_lead():
    certs = committed_certs()
    summary = confirm.summarize(certs, confirm.load_manifest(MANIFEST))
    assert summary["confirmed_ids"] == [HERO] and summary["lead_ids"] == [LEAD]
    assert confirm.counts_line(summary) == (
        "confirmed holes: 1; unconfirmed leads: 1; certified: 4 "
        "(via no_hole_found=0, hardened_reattack_failed=1, legit_fix=0, legacy=3)"
    )
    # the denominator is computed from the certificates: recon on and future_git true
    assert summary["recon"]["n"] == 9 and summary["recon"]["confirmed"] == 1
    assert summary["after_leads"] == 1  # 116's after-round label is a lead too
    without = confirm.summarize(certs)  # no manifest: 348 has no T53 evidence yet, so nothing is confirmed
    assert without["confirmed_holes"] == 0 and without["unconfirmed_leads"] == 2


def test_a_lead_is_not_counted_as_hackable_in_the_confirmed_rates():
    certs = [cert_for(fixed_report("owner__repo-1")), cert_for(still_report("owner__repo-3"))]
    summary = confirm.summarize(certs)
    assert summary["rate_confirmed_before"]["count"] == 0 and summary["rate_confirmed_before"]["n"] == 2
    assert summary["rate_confirmed_after"]["count"] == 0
    assert score(certs)["hackable_before"] == 2  # the raw label count is unchanged


# The Wilson interval rule


def test_interval_bounds_need_n_of_at_least_ten():
    rate = {"count": 1, "n": 9, "interval_95": [0.0, 0.5]}
    assert confirm.interval_bounds(rate) is None
    assert confirm.interval_bounds({**rate, "n": 10}) == (0.0, 0.5)
    assert confirm.interval_bounds({"count": 1, "n": 10}) is None
    assert confirm.interval_bounds({"count": 1, "n": True, "interval_95": [0, 1]}) is None


def ten_certs(directory: Path):
    for number in range(10):
        write_certificate(cert_for(clean_report(f"owner__repo-{number}")), directory)
    return directory


def test_the_site_shows_an_interval_at_n_ten_and_not_below(tmp_path):
    small = tmp_path / "small"
    write_certificate(cert_for(clean_report("owner__repo-1")), small)
    text = read(build_site(small, tmp_path / "site-small").index)
    assert "95% CI" not in text and "n too small for an interval" in text
    ten = ten_certs(tmp_path / "ten")
    text = read(build_site(ten, tmp_path / "site-ten").index)
    assert "(95% CI 0.0% to 27.8%)" in text and "n too small for an interval" in text.split('id="caveats"')[1]


def test_the_report_shows_an_interval_at_n_ten_and_not_below(tmp_path, capsys):
    small = tmp_path / "small"
    write_certificate(cert_for(clean_report("owner__repo-1")), small)
    deps = report_deps()
    assert cli.main(["report", "--certs", str(small)], deps=deps) == 0
    out = capsys.readouterr().out
    assert "n too small for an interval" in out and "95% CI" not in out
    ten = ten_certs(tmp_path / "ten")
    assert cli.main(["report", "--certs", str(ten)], deps=deps) == 0
    out = capsys.readouterr().out
    assert "95% CI 0.0%–27.8%" in out


# The site on the committed certificates


def test_the_site_builds_from_the_committed_certificates_with_the_hero_block(tmp_path):
    result = build_site(COMMITTED, tmp_path / "site")
    assert result.errors == []
    assert len(result.pages) >= 14
    index = read(result.index)
    hero = index.split('id="hero"')[1].split('id="score"')[0]
    assert '<p class="headline">1 of 9 confirmed</p>' in hero
    assert "confirmed holes: 1; unconfirmed leads: 1; certified: 4 (via " in hero
    for caveat in ("n:", "Recon on:", "One attacker:", "Certified means this attacker did not hack"):
        assert caveat in hero
    assert "What this does not show" in hero
    assert f'<a href="env/{HERO}-93d44b30.html">{HERO}</a>' in hero
    assert "Before -&gt; after, as recorded" in hero and "strip-future-git" in hero
    assert "replication pending" in hero
    assert "Unconfirmed leads are never counted as hackable" in hero and LEAD in hero
    assert "95% CI" not in index
    assert "confirmed holes: 1; unconfirmed leads: 1" in index.split('id="score"')[1]
    # 116 is a lead on its index row and on its page
    row = next(r for r in index.split('id="environments"')[1].split("<tr>") if f">{LEAD}</a>" in r)
    assert "<td>lead (manual check)</td>" in row
    page = read(next(p for p in result.pages if p.name.startswith("ArkEcosystem__python-crypto-116")))
    assert "Hole status" in page and "lead:" in page


def test_the_hero_is_only_counts_when_the_data_has_no_denominator(tmp_path):
    cert_dir = tmp_path / "certs"
    write_certificate(cert_for(with_t53(fixed_report("owner__repo-1"))), cert_dir)  # recon is not recorded
    index = read(build_site(cert_dir, tmp_path / "site").index)
    hero = index.split('id="hero"')[1].split('id="score"')[0]
    assert '<p class="headline">1 confirmed, 0 unconfirmed</p>' in hero
    assert "no denominator, counts only" in hero
    assert " of 9" not in hero


def test_the_hero_denominator_is_computed_not_fixed(tmp_path):
    cert_dir = tmp_path / "certs"
    certs = [
        recon_cert(with_t53(fixed_report("owner__repo-1"))),
        recon_cert(still_report("owner__repo-2")),
        recon_cert(with_t53(still_report("owner__repo-3"))),
        recon_cert(clean_report("owner__repo-4")),  # future_git false: outside the denominator
    ]
    for cert in certs:
        write_certificate(cert, cert_dir)
    index = read(build_site(cert_dir, tmp_path / "site").index)
    hero = index.split('id="hero"')[1].split('id="score"')[0]
    assert '<p class="headline">2 of 3 confirmed</p>' in hero
    assert "confirmed holes: 2; unconfirmed leads: 1" in hero


def test_a_bad_manifest_refuses_the_build_and_writes_nothing(tmp_path):
    cert_dir = tmp_path / "results" / "certificates"
    write_certificate(cert_for(clean_report("owner__repo-1")), cert_dir)
    write_json(tmp_path / "results", "confirmations.json", {"owner__repo-1": entry(status="maybe")})
    out = tmp_path / "site"
    with pytest.raises(ConfirmationError, match="status must be one of"):
        build_site(cert_dir, out)
    assert not out.exists()
    explicit = tmp_path / "missing.json"
    with pytest.raises(ConfirmationError, match="not found"):
        build_site(cert_dir, out, confirmations_file=explicit)


def test_the_site_reads_the_manifest_beside_the_certificates(tmp_path):
    cert_dir = tmp_path / "results" / "certificates"
    write_certificate(cert_for(fixed_report("owner__repo-1")), cert_dir)
    first = read(build_site(cert_dir, tmp_path / "site1").index)
    assert '<p class="headline">0 confirmed, 1 unconfirmed</p>' in first
    write_json(tmp_path / "results", "confirmations.json", {"owner__repo-1": entry()})
    second = read(build_site(cert_dir, tmp_path / "site2").index)
    assert '<p class="headline">1 confirmed, 0 unconfirmed</p>' in second
    assert "<td>confirmed (manual check)</td>" in second


def test_the_report_lists_the_confirmed_and_lead_counts(tmp_path, capsys):
    deps = report_deps()
    assert cli.main(["report", "--certs", str(COMMITTED)], deps=deps) == 0
    out = capsys.readouterr().out
    assert "confirmed holes: 1; unconfirmed leads: 1; certified: 4 (via " in out
    assert "recon on, future_git true: 1 of 9 environments have a confirmed hole" in out
    assert f"replication {HERO}: replication pending" in out
    assert "n too small for an interval" in out and "95% CI" not in out
    assert cli.main(["report", "--certs", str(COMMITTED), "--format", "json"], deps=deps) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["confirmation"]["confirmed_ids"] == [HERO]
    assert shown["confirmation"]["replication"][HERO]["counts"] is None


def test_the_report_refuses_a_bad_manifest(tmp_path, capsys):
    cert_dir = tmp_path / "results" / "certificates"
    write_certificate(cert_for(clean_report("owner__repo-1")), cert_dir)
    write_json(tmp_path / "results", "confirmations.json", {"x": {"status": "lead"}})
    assert cli.main(["report", "--certs", str(cert_dir)], deps=report_deps()) == 2
    assert "confirmations" in capsys.readouterr().err


# Replications


def hero_dir(tmp_path: Path):
    """results/certificates with one environment (a confirmed hole by T53 evidence, closed by hardening)."""
    cert_dir = tmp_path / "results" / "certificates"
    write_certificate(recon_cert(with_t53(fixed_report("owner__repo-1"))), cert_dir)
    return cert_dir, tmp_path / "results" / "replications"


def rep_cert(report):
    return recon_cert(report)


def test_replication_counts_come_from_the_files(tmp_path):
    cert_dir, reps = hero_dir(tmp_path)
    write_json(reps, "owner__repo-1-run1.json", rep_cert(with_t53(fixed_report("owner__repo-1"))))
    other = rep_cert(with_t53(fixed_report("owner__repo-1")))
    other["sandbox_runs"] = 12
    other["harden"]["sandbox_runs"] = 12
    write_json(reps, "owner__repo-1-rep2.json", other)
    write_json(
        reps, "owner__repo-1-run3.json", rep_cert(with_t53(still_report("owner__repo-1")))
    )  # not closed
    no_hole = rep_cert(clean_report("owner__repo-1"))  # a run in which the attacker found nothing
    no_hole["sandbox_runs"] = 7
    no_hole["harden"]["sandbox_runs"] = 7
    write_json(reps, "owner__repo-1-run4.json", no_hole)
    loaded = confirm.load_replications(reps)
    assert loaded.problems == []
    assert confirm.replication_for("owner__repo-1", loaded) == {
        "task": "owner__repo-1",
        "runs": 4,
        "confirmed": 3,
        "reattack_failed": 2,
    }
    text = confirm.replication_text("owner__repo-1", loaded)
    assert text.startswith("replication 3/4 runs had a confirmed hole; re-attack failed in 2/3 of those")
    assert "n too small for an interval" in text
    index = read(build_site(cert_dir, tmp_path / "site").index)
    assert "replication 3/4 runs had a confirmed hole" in index


def test_replication_is_pending_without_files(tmp_path):
    cert_dir, reps = hero_dir(tmp_path)
    assert confirm.replication_text("owner__repo-1", confirm.load_replications(reps)) == "replication pending"
    assert "replication pending" in read(build_site(cert_dir, tmp_path / "site").index)
    reps.mkdir()
    assert confirm.replication_for("owner__repo-1", confirm.load_replications(reps)) is None
    # files for another task do not give this one a number
    write_json(reps, "owner__other-run1.json", rep_cert(with_t53(fixed_report("owner__other"))))
    assert confirm.replication_for("owner__repo-1", confirm.load_replications(reps)) is None


def test_the_manifest_is_never_applied_to_a_replication_run(tmp_path):
    cert_dir, reps = hero_dir(tmp_path)
    write_json(reps, "owner__repo-1-run1.json", rep_cert(fixed_report("owner__repo-1")))  # no T53 evidence
    write_json(tmp_path / "results", "confirmations.json", {"owner__repo-1": entry()})
    loaded = confirm.load_replications(reps)
    assert confirm.replication_for("owner__repo-1", loaded)["confirmed"] == 0
    index = read(build_site(cert_dir, tmp_path / "site").index)
    assert "replication 0/1 runs had a confirmed hole; re-attack failed in 0/0" in index


@pytest.mark.parametrize(
    ("name", "content", "message"),
    [
        ("owner__repo-1-run1.json", "{not json", "not a valid certificate"),
        ("owner__repo-1-run1.json", '{"schema": "cheatproof.certificate"}', "missing"),
        ("run1.json", None, "name must be"),
        ("owner__repo-2-run1.json", None, "name must be"),  # the file holds owner__repo-1
        ("owner__repo-1-final.json", None, "name must be"),
    ],
)
def test_a_bad_replication_file_refuses_every_number(tmp_path, name, content, message):
    cert_dir, reps = hero_dir(tmp_path)
    reps.mkdir(parents=True)
    if content is None:
        write_json(reps, name, rep_cert(with_t53(fixed_report("owner__repo-1"))))
    else:
        (reps / name).write_text(content, encoding="utf-8")
    loaded = confirm.load_replications(reps)
    assert loaded.problems and message in loaded.problems[0][1]
    with pytest.raises(ConfirmationError, match="no numbers shown"):
        confirm.replication_for("owner__repo-1", loaded)
    result = build_site(cert_dir, tmp_path / "site")
    assert result.errors and result.errors[0][0] == f"replications/{name}"
    index = read(result.index)
    assert "replication files invalid" in index and "had a confirmed hole" not in index


def test_a_copied_replication_file_is_not_counted_twice(tmp_path):
    cert_dir, reps = hero_dir(tmp_path)
    data = rep_cert(with_t53(fixed_report("owner__repo-1")))
    write_json(reps, "owner__repo-1-run1.json", data)
    write_json(reps, "owner__repo-1-run2.json", copy.deepcopy(data))
    loaded = confirm.load_replications(reps)
    assert loaded.problems == [("owner__repo-1-run2.json", "same bytes as owner__repo-1-run1.json")]
    assert cert_dir.is_dir()


def test_timestamp_fixture_is_stable():
    assert TIMESTAMP  # the replication tests rely on cert_for writing one fixed timestamp
