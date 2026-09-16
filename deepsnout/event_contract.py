"""Shared Sysmon identity and supported-event contract.

Keep source/vendor serialization quirks out of this module. Compatibility adapters
may use these constants, but the core event contract stays transport-neutral.
"""

SUPPORTED_EVENT_IDS = frozenset({1, 3, 22})
SYSMON_PROVIDERS = frozenset({"microsoft-windows-sysmon", "sysmon"})
SYSMON_CHANNEL = "microsoft-windows-sysmon/operational"
SYSMON_PROVIDER_GUID = "5770385f-c22a-43e0-bf4c-06f5698ffbd9"
