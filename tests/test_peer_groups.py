from deepsnout.db import Host, BehaviorDay
from deepsnout.peer_groups import (refresh_peer_groups, suggestion_state, approve_suggestion,
                                   reject_suggestion, peer_group_catalog,
                                   peer_group_suppression_allowed, create_manual_group)
from conftest import DAY, DAY_START


def add_context(db, host_id, day, app, parent="explorer.exe", location="program-files"):
    key = f"{host_id}-{day}-{app}-{parent}-{location}"
    db.add(BehaviorDay(id=key, host_id=host_id, day=day, context=key, app=app,
        parent=parent, location=location, count=10,
        first_seen=day * DAY + 9 * 3600, last_seen=day * DAY + 16 * 3600, sample={}))


def seed_two_groups(db, days):
    today = DAY_START // DAY
    hosts = []
    for prefix in ("cad", "office"):
        for number in range(3):
            host = Host(id=f"{prefix}{number}", name=f"{prefix}{number}.example", namespace="default",
                        cohort="unassigned", first_seen=DAY_START - 8 * DAY, last_seen=DAY_START + 100)
            db.add(host)
            hosts.append(host)
    db.flush()
    for offset in days:
        day = today - offset
        for number in range(3):
            add_context(db, f"cad{number}", day, "acad.exe")
            add_context(db, f"cad{number}", day, "revit.exe", parent="acad.exe")
            add_context(db, f"cad{number}", day, "accoreconsole.exe", parent="acad.exe")
            add_context(db, f"office{number}", day, "winword.exe")
            add_context(db, f"office{number}", day, "excel.exe")
            add_context(db, f"office{number}", day, "outlook.exe")
    db.flush()
    return hosts


def test_groups_are_suggested_immediately_and_provisional(db):
    seed_two_groups(db, [0])
    result = refresh_peer_groups(db, clock=DAY_START + 3600)
    state = suggestion_state(db)
    recommended = [group for group in state["groups"] if group["peer_suitability"] == "recommended"]
    assert result["recommended"] == 2
    assert len(recommended) == 2
    assert state["learning"] is True
    assert {group["size"] for group in recommended} == {3}
    assert all(group["maturity"] == "provisional" for group in recommended)
    assert all(group["includes_current_day"] is True for group in recommended)
    assert all(group["channel_scores"]["applications"] >= 0.9 for group in recommended)
    assert any(any("acad.exe" in feature["label"] for feature in group["features"])
               for group in recommended)


def test_approved_provisional_group_cannot_suppress_then_matures(db):
    seed_two_groups(db, [0])
    refresh_peer_groups(db, clock=DAY_START + 3600)
    cad = next(group for group in suggestion_state(db)["groups"]
               if group["peer_suitability"] == "recommended"
               and any("acad.exe" in feature["label"] for feature in group["features"]))
    approve_suggestion(db, cad["id"], "cad-workstations", "analyst")
    db.flush()
    assert all(db.get(Host, f"cad{i}").cohort == "cad-workstations" for i in range(3))
    assert peer_group_suppression_allowed(db, "cad-workstations") is False

    for offset in range(1, 9):
        day = DAY_START // DAY - offset
        for number in range(3):
            add_context(db, f"cad{number}", day, "acad.exe")
            add_context(db, f"cad{number}", day, "revit.exe", parent="acad.exe")
            add_context(db, f"cad{number}", day, "accoreconsole.exe", parent="acad.exe")
            add_context(db, f"office{number}", day, "winword.exe")
            add_context(db, f"office{number}", day, "excel.exe")
            add_context(db, f"office{number}", day, "outlook.exe")
    db.flush()
    refresh_peer_groups(db, clock=DAY_START + 7200)
    group = peer_group_catalog(db)["cad-workstations"]
    assert group["maturity"] == "stable"
    assert group["includes_current_day"] is False
    assert group["peer_suitability"] == "recommended"
    assert peer_group_suppression_allowed(db, "cad-workstations") is True


def test_platform_only_similarity_is_technical_not_detector_peer(db):
    today = DAY_START // DAY
    for prefix in ("new", "other"):
        for number in range(3):
            db.add(Host(id=f"{prefix}{number}", name=f"{prefix}{number}.example", namespace="default",
                        cohort="unassigned", first_seen=DAY_START, last_seen=DAY_START + 100))
    db.flush()
    for number in range(3):
        add_context(db, f"new{number}", today, "autocathost.exe", parent="svchost.exe", location="windows")
        add_context(db, f"new{number}", today, "workloadssessionhost.exe",
                    parent="svchost.exe", location="windows")
        add_context(db, f"other{number}", today, "notepad.exe", parent="explorer.exe", location="windows")
    db.flush()
    refresh_peer_groups(db, clock=DAY_START + 3600)
    groups = suggestion_state(db)["groups"]
    platform_group = next(group for group in groups
                          if any("autocathost.exe" in feature["label"] for feature in group["features"]))
    assert platform_group["peer_suitability"] == "technical"
    assert not any(group["peer_suitability"] == "recommended"
                   and any("autocathost.exe" in feature["label"] for feature in group["features"])
                   for group in groups)


def test_missing_parent_relationship_is_not_a_grouping_signal(db):
    seed_two_groups(db, [0])
    today = DAY_START // DAY
    for number in range(3):
        add_context(db, f"cad{number}", today, "helper.exe", parent="unknown")
    db.flush()
    refresh_peer_groups(db, clock=DAY_START + 3600)
    cad = next(group for group in suggestion_state(db)["groups"]
               if group["peer_suitability"] == "recommended"
               and any("acad.exe" in feature["label"] for feature in group["features"]))
    assert not any("unknown>helper.exe" in feature["label"] for feature in cad["features"])


def test_explanations_include_application_combinations(db):
    seed_two_groups(db, [0])
    refresh_peer_groups(db, clock=DAY_START + 3600)
    cad = next(group for group in suggestion_state(db)["groups"]
               if group["peer_suitability"] == "recommended"
               and any("acad.exe" in feature["label"] for feature in group["features"]))
    assert any(feature["channel"] == "bundles" for feature in cad["features"])


def test_rejected_fingerprint_is_not_suggested_again(db):
    seed_two_groups(db, [0])
    refresh_peer_groups(db, clock=DAY_START + 3600)
    group = suggestion_state(db)["groups"][0]
    reject_suggestion(db, group["id"])
    refresh_peer_groups(db, clock=DAY_START + 3700)
    assert group["fingerprint"] not in {item["fingerprint"] for item in suggestion_state(db)["groups"]}


def test_manual_group_is_immediately_suppression_eligible(db):
    create_manual_group(db, "admin-workstations", "analyst")
    assert peer_group_catalog(db)["admin-workstations"]["kind"] == "manual"
    assert peer_group_suppression_allowed(db, "admin-workstations") is True
