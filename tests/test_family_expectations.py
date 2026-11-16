"""Future family matching requires a reviewed and unexpired exact scope."""
from deepsnout.db import set_state, now
from deepsnout.finding_quality import (
    family_signature, matching_family_expectation,
)


def _evidence(name="Example_1.2.3.exe", parent="agent.exe"):
    return {
        "process": {
            "image": r"C:\Program Files\Example" + "\\" + name,
            "parent": parent, "location": "program-files",
        },
        "environment": {"category": "rare_application"},
        "flags": {"remote_reference": False},
    }


def test_family_signature_matches_numeric_versions_but_not_unrelated_contexts(db):
    identifier = family_signature("test", "DS-BEH-001", _evidence())
    assert identifier == family_signature("test", "DS-BEH-001", _evidence("Example_1.3.4.exe"))
    assert identifier != family_signature("test", "DS-BEH-001", _evidence(parent="other.exe"))
    assert identifier != family_signature("other", "DS-BEH-001", _evidence())
    assert identifier != family_signature("test", "DS-EXEC-001", _evidence())
    set_state(db, "finding_family_expectations", {
        identifier: {"expires": now() + 86400, "owner": "analyst", "reason": "Reviewed"}
    })
    assert matching_family_expectation(db, "test", "DS-BEH-001", _evidence())
    assert not matching_family_expectation(db, "test", "DS-BEH-001", _evidence(parent="other.exe"))
    assert not matching_family_expectation(db, "test", "DS-EXEC-001", _evidence())
    assert not matching_family_expectation(db, "test", "DS-BEH-001", _evidence(),
                                           clock=now() + 86401)
