"""Synthetic checks for cohort overlap reduction; no real endpoint data."""
import pytest

from deepsnout.shadow_peer_selection import shadow_peer_selection_summary


def _row(training=True, later=True, process=0.1, network=0.1):
    return {
        "training_screening_support": training,
        "later_residual_support": later,
        "seed_persistence_fraction": 0.95,
        "residual_process": {"within": 0.4, "delta": process,
                             "comparable_pairs": 160},
        "residual_network": {"within": 0.4, "delta": network,
                             "comparable_pairs": 160},
    }


def test_one_best_group_per_host_per_view_and_stricter_scenario():
    groups = [
        {"members": [f"h{i}" for i in range(33)]},
        {"members": [f"h{i}" for i in range(25, 54)]},
        {"members": [f"h{i}" for i in range(50, 169)]},
    ]
    rows = [
        _row(process=0.24, network=0.201),
        _row(process=0.065, network=0.081),
        _row(process=0.086, network=0.091),
    ]
    later = {f"h{i}": {"observed_days": 5} for i in range(169)}
    report = shadow_peer_selection_summary(groups, rows, later)
    first, strict = report["scenarios"]
    assert first["hosts_with_any_preferred_pool"] == 169
    assert first["process_hosts_with_preferred_pool"] == 152
    assert first["network_hosts_with_preferred_pool"] == 169
    assert first["hosts_with_both_views"] == 152
    assert first["preferred_view_assignments"] == 321
    assert first["potential_view_memberships"] == 33 * 2 + 29 + 119 * 2
    assert first["distinct_pools_preferred"] == 3
    assert strict["hosts_with_any_preferred_pool"] == 33
    assert strict["distinct_pools_preferred"] == 1
    assert not report["suppression_allowed"]
    assert not report["application_specific_qualification_checked"]
    assert "h33" not in str(report)


def test_insufficient_history_sample_or_unsupported_groups_fail_closed():
    groups = [{"members": [f"h{i}" for i in range(15)]}]
    later = {f"h{i}": {"observed_days": 5} for i in range(15)}
    bad = _row()
    bad["residual_network"]["comparable_pairs"] = 23
    bad["residual_process"]["delta"] = 0.07
    assert shadow_peer_selection_summary(groups, [bad], later)["scenarios"][0][
        "hosts_with_any_preferred_pool"] == 0
    assert shadow_peer_selection_summary(groups, [_row(later=False)], later)[
        "scenarios"][0]["hosts_with_any_preferred_pool"] == 0
    assert shadow_peer_selection_summary(groups, [_row()], {
        k: {"observed_days": 2} for k in later
    })["scenarios"][0]["hosts_with_any_preferred_pool"] == 0


def test_requires_one_validation_row_per_group():
    with pytest.raises(ValueError):
        shadow_peer_selection_summary([{"members": ["h1"]}], [], {})
