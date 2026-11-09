"""Synthetic tests for compact finding rows and safe CSV exports."""
import csv
import io
from types import SimpleNamespace

from deepsnout.finding_table import finding_csv, finding_table_row, HEADERS


def _host(name="ws01.internal.example", identifier="one"):
    return SimpleNamespace(name=name, namespace="test", id=identifier)


def _finding(detector="DS-BEH-001", *, evidence=None, identifier="a"):
    if evidence is None:
        evidence = {
            "process": {
                "parent": "explorer.exe",
                "app": "utility.exe",
                "image": r"C:\Program Files\Vendor\utility.exe",
                "location": "program-files",
            },
            "environment": {
                "category": "rare_launch_relationship",
                "reference": {
                    "fleet_launch_relationship_hosts": 1,
                    "fleet_application_hosts": 420,
                },
            },
        }
    return SimpleNamespace(id=identifier, detector=detector, title="A finding",
                           last_seen=1762000000, evidence=evidence)


def _read(text):
    return list(csv.reader(io.StringIO(text.lstrip("\ufeff"))))


def test_full_row_preserves_compact_parent_path_and_reason():
    row = finding_table_row(_finding(), _host())
    assert row["detector"] == "DS-BEH-001"
    assert row["hostname"] == "ws01.internal.example"
    assert row["parent"] == "explorer.exe"
    assert row["process"] == r"C:\Program Files\Vendor\utility.exe"
    assert row["trigger"] == "Rare launch (1/420 app hosts)"


def test_rare_application_and_other_detector_types():
    finding = _finding(evidence={
        "process": {"image": r"C:\Tools\mystery.exe", "parent": "services.exe"},
        "environment": {"category": "rare_application", "reference": {
            "fleet_application_hosts": 2,
            "fleet_hosts_with_process_coverage": 800}},
    })
    assert finding_table_row(finding, _host())["trigger"] == "Rare application (2/800 hosts)"
    network = _finding("DS-NET-001", evidence={
        "app": "edge.exe", "location": "program-files",
        "current": 122, "baseline_p95": 11})
    row = finding_table_row(network, _host())
    assert row["parent"] == "—"
    assert row["process"] == "edge.exe (path unavailable)"
    assert row["trigger"] == "Network diversity (122 vs prior p95 11)"
    assert finding_table_row(_finding("DS-EXEC-001", evidence={
        "process": {"image": r"C:\Temp\thing.exe", "parent": "cmd.exe"}
    }), _host())["trigger"] == "Remote execution characteristics"


def test_privacy_reduced_csv_has_reusable_host_alias_within_file_and_coarse_path():
    first, second = _finding(identifier="a"), _finding(identifier="b")
    original = _host()
    other = _host("other.sensitive.example", "another")
    csv_text = finding_csv([(first, original), (second, original),
                            (first, other)], privacy_reduced=True)
    rows = _read(csv_text)
    assert rows[0] == list(HEADERS)
    assert len(rows) == 4
    assert rows[1][2] == rows[2][2]
    assert rows[1][2] != rows[3][2]
    assert rows[1][2].startswith("host-")
    assert rows[1][4] == r"program-files\utility.exe"
    assert rows[1][0].count("-") == 2
    assert "ws01.internal.example" not in csv_text
    assert "Vendor" not in csv_text
    assert "Program Files" not in csv_text
    assert finding_csv([(first, original)], privacy_reduced=True) != csv_text


def test_full_csv_preserves_long_paths_and_disarms_spreadsheet_formulas():
    fake = _finding(evidence={
        "process": {"parent": "=SHELL()", "image": r"C:\Path, with comma\test.exe"},
        "environment": {"category": "rare_application", "reference": {
            "fleet_application_hosts": 0, "fleet_hosts_with_process_coverage": 100}},
    })
    rows = _read(finding_csv([(fake, _host("=HYPERLINK('x')"))]))
    assert rows[1][2].startswith("'=")
    assert rows[1][3].startswith("'=")
    assert rows[1][4] == r"C:\Path, with comma\test.exe"
    assert rows[1][5] == "Rare application (0/100 hosts)"
