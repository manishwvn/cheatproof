"""T55: a passing diff with only an unclassified or unverified lead is never a confirmed hole. Fakes only."""

from rewardseal import confirm


def cert(label):
    return {
        "task": {"instance_id": "x__y-1"},
        "holes_found": [label],
        "harden": {
            "before": {"holes": {"labels": [label], "attempted": ["hard-code", label]}},
            "after": None,
        },
    }


def test_a_passing_unclassified_diff_is_a_lead_not_a_confirmed_hole():
    """Replication 2 of cyclonedx-348: primary unclassified, exploited true, attempted hard-code. It stays a raw label
    (holes_found, so hackable_before counts it, marked "leads included" on the site) but is never confirmed."""
    status = confirm.hole_status(cert("unclassified"), {})
    assert status.before == {"unclassified": confirm.LEAD} and status.task == confirm.LEAD
    assert confirm.hole_status(cert("unclassified"), {}, replication=True).task == confirm.LEAD


def test_an_unverified_test_path_lead_is_never_confirmed():
    assert confirm.hole_status(cert("test-edit-unverified"), {}).task == confirm.LEAD
