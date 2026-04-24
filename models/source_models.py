"""Internal data models for the extraction pipeline.

Frozen dataclasses — immutable after construction, hashable, safe to pass
between concurrent tasks without defensive copying.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class IntuneDevice:
    """A managed device record from the Intune Graph API device inventory."""

    id: str                             # managedDeviceId GUID -- primary join key
    device_name: str
    serial_number: Optional[str]
    user_principal_name: Optional[str]
    operating_system: str
    os_version: str
    model: Optional[str]


@dataclass(frozen=True)
class PolicyDeviceStatus:
    """A single device's compliance state for one Intune compliance policy."""

    device_id: str                      # managedDeviceId, parsed from compound API key
    status: str                         # compliant, noncompliant, unknown, notApplicable, ...
    device_display_name: str            # for logging only


# {check_type: bool} -- maps Drata field names to deterministic compliance bools.
# Only True/False values are stored; indeterminate states are filtered before
# this dict is constructed.
ComplianceState = Dict[str, bool]
