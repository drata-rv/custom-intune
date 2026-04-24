"""Drata API payload model -- the single Pydantic model that governs what we
send to the Custom MDM Connection endpoint.

The five compliance fields (screenLockEnabled, autoUpdateEnabled,
passwordManagerEnabled, encryptionEnabled, antivirusEnabled) are populated
from Intune custom compliance policies. Each maps to a customer-defined policy
whose display name is configured via a POLICY_NAME_* env var.

Critical invariant: a compliance field whose policy is not configured, or whose
device state is indeterminate (unknown, notApplicable, error, etc.), is OMITTED
entirely from the serialized JSON -- never null, never false for those states.
The exception is a confirmed ``noncompliant`` state, which correctly emits False.

This invariant is enforced by defaulting all optional fields to ``None`` and
serializing with ``exclude_none=True`` in ``to_drata_dict()``.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator

AgentPlatformEnum = Literal["WINDOWS", "MACOS", "LINUX", "UNIX", "ANDROID"]

# Keys are lowercased for case-insensitive matching in map_platform().
# Add a new alias here to support additional OS string variants end-to-end.
PLATFORM_MAP: dict[str, AgentPlatformEnum] = {
    "windows":   "WINDOWS",
    "macos":     "MACOS",
    "mac os x":  "MACOS",   # Intune may return either form
    "linux":     "LINUX",
    "ubuntu":    "LINUX",   # Intune sometimes surfaces distro names for Linux
    "debian":    "LINUX",
    "rhel":      "LINUX",
    "android":   "ANDROID",
    # "ios" and "ipados" are intentionally absent -- Drata Custom MDM does not
    # support them. Devices with these OS values are skipped with a WARNING.
}


class DrataDevicePayload(BaseModel):
    """Schema for ``POST /public/v2/custom-connections/{id}/devices``.

    Required fields:  personnelId, platformName, platformVersion
    Recommended:      externalId, serialNumber, alias, model
    Compliance:       screenLockEnabled, autoUpdateEnabled, passwordManagerEnabled,
                      encryptionEnabled, antivirusEnabled
    """

    model_config = ConfigDict(extra="forbid")

    # Required -- from Intune device inventory
    personnelId: str                    # "email:user@domain.com"
    platformName: AgentPlatformEnum
    platformVersion: str               # e.g. "10.0.19045.3930", max 191 chars

    # Recommended -- from Intune device inventory
    externalId: str | None = None      # managedDeviceId GUID -- primary Drata match key
    serialNumber: str | None = None
    alias: str | None = None           # deviceName, max 191 chars
    model: str | None = None           # max 191 chars

    # Compliance -- from Intune custom compliance policies.
    # Omit entirely (leave None) when:
    #   - the corresponding POLICY_NAME_* env var is not set, OR
    #   - the device's policy state is anything other than compliant/noncompliant.
    # Emit False when the state is confirmed "noncompliant" -- that is real evidence.
    screenLockEnabled:      bool | None = None   # POLICY_NAME_SCREEN_LOCK
    autoUpdateEnabled:      bool | None = None   # POLICY_NAME_AUTO_UPDATES
    passwordManagerEnabled: bool | None = None   # POLICY_NAME_PASSWORD_MANAGER
    encryptionEnabled:      bool | None = None   # POLICY_NAME_ENCRYPTION
    antivirusEnabled:       bool | None = None   # POLICY_NAME_ANTIVIRUS

    @field_validator("alias", "model", mode="before")
    @classmethod
    def truncate_to_191(cls, v: str | None) -> str | None:
        """Drata enforces max 191 chars on alias and model. Truncate silently
        rather than failing validation -- a slightly shortened name is better
        than a dropped record."""
        if isinstance(v, str) and len(v) > 191:
            return v[:191]
        return v

    @field_validator("platformVersion", mode="before")
    @classmethod
    def truncate_version_to_191(cls, v: str) -> str:
        """platformVersion also has a 191-char max in the Drata schema."""
        if isinstance(v, str) and len(v) > 191:
            return v[:191]
        return v

    @field_validator("personnelId", mode="before")
    @classmethod
    def validate_personnel_id_format(cls, v: str) -> str:
        """personnelId must start with 'email:' when using email-based lookup."""
        if isinstance(v, str) and not v.startswith("email:"):
            raise ValueError(
                f"personnelId must be prefixed with 'email:' -- got '{v}'"
            )
        return v

    def to_drata_dict(self) -> dict[str, Any]:
        """Serialize for the Drata API.

        None fields are excluded -- this is the omission rule enforcement point.
        False IS included (confirmed non-compliant state is real evidence).
        """
        return self.model_dump(mode="json", exclude_none=True)
