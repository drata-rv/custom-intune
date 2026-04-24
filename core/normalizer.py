"""Normalization and join logic -- bridge between raw Intune records and
the validated Drata payload.

Compliance for each device is sourced entirely from Intune custom compliance
policies. The caller (pipeline/extractor) resolves policy states into a
``ComplianceState`` dict (keyed by Drata field names) before calling
``build_drata_payload``. This module has no knowledge of which policies exist
or how they were fetched.
"""

from __future__ import annotations

import structlog

from models.drata_models import PLATFORM_MAP, AgentPlatformEnum, DrataDevicePayload
from models.source_models import ComplianceState, IntuneDevice

logger: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


def normalize_serial(raw: str | None) -> str | None:
    """Strip whitespace, uppercase. Returns ``None`` if empty after cleaning.

    Not used as a join key in this pipeline (join is by Intune GUID), but
    preserved for the Drata payload's ``serialNumber`` field.
    """
    if not raw:
        return None
    cleaned = raw.strip().upper()
    return cleaned if cleaned else None


def normalize_hostname(raw: str | None) -> str | None:
    """Strip whitespace, lowercase. Returns ``None`` if empty after cleaning."""
    if not raw:
        return None
    cleaned = raw.strip().lower()
    return cleaned if cleaned else None


def map_platform(intune_os: str) -> AgentPlatformEnum | None:
    """Map an Intune ``operatingSystem`` string to a Drata ``AgentPlatformEnum``.

    Matching is case-insensitive. If the OS string starts with a known Linux
    identifier (e.g., "Ubuntu 22.04 LTS"), it is matched via prefix.
    Returns ``None`` for unsupported platforms (iOS, iPadOS, unrecognized).
    """
    if not intune_os:
        return None

    lower_os = intune_os.strip().lower()

    if lower_os in PLATFORM_MAP:
        return PLATFORM_MAP[lower_os]

    # Prefix match for distro names (e.g., "Ubuntu 22.04 LTS" -> "ubuntu" -> LINUX)
    for key, platform in PLATFORM_MAP.items():
        if lower_os.startswith(key):
            return platform

    return None


def map_compliance_state(status: str) -> bool | None:
    """Map an Intune ``deviceStatuses.status`` string to a Python bool or None.

    Only ``"compliant"`` and ``"noncompliant"`` produce a deterministic boolean.
    Everything else (``"unknown"``, ``"notApplicable"``, ``"error"``,
    ``"conflict"``, ``"inGracePeriod"``) returns ``None``.

    The caller must omit the field for ``None`` results -- this is the omission
    rule. Critically, ``"noncompliant"`` returns ``False``, not ``None``:
    a device that is confirmed non-compliant is real evidence and must be
    reported to Drata.
    """
    if status == "compliant":
        return True
    if status == "noncompliant":
        return False
    return None


def build_drata_payload(
    intune: IntuneDevice,
    compliance: ComplianceState,
) -> DrataDevicePayload:
    """Merge device identity and policy compliance state into a Drata payload.

    ``compliance`` is a ``{check_type: bool}`` dict where keys are Drata field
    names (e.g. ``"screenLockEnabled"``). Only True/False values are present --
    indeterminate states are filtered out before this function is called. A
    missing key means "no deterministic data for this check" and the field is
    left unset on the model, so it is excluded by ``to_drata_dict()``.

    Raises:
        ValueError:           Unsupported ``operatingSystem`` (iOS, iPadOS, etc.).
        pydantic.ValidationError: Required Intune fields are missing or malformed.
    """
    platform = map_platform(intune.operating_system)
    if platform is None:
        logger.warning(
            "unsupported_platform_skipped",
            external_id=intune.id,
            operating_system=intune.operating_system,
        )
        raise ValueError(
            f"Unsupported operatingSystem '{intune.operating_system}' for "
            f"device '{intune.id}' -- not in PLATFORM_MAP."
        )

    payload_data: dict[str, object] = {
        "platformName":    platform,
        "platformVersion": intune.os_version,
        "externalId":      intune.id,
        "serialNumber":    intune.serial_number,
        "alias":           intune.device_name,
        "model":           intune.model,
    }

    # Devices without a UPN (shared kiosks, service accounts) get an empty
    # string that intentionally triggers the field_validator -> ValidationError
    # -> caller logs and skips.
    if intune.user_principal_name:
        payload_data["personnelId"] = f"email:{intune.user_principal_name}"
    else:
        payload_data["personnelId"] = ""

    # Merge compliance fields directly. The keys in ``compliance`` are
    # exact Pydantic field names on DrataDevicePayload. The model's
    # ``extra="forbid"`` will raise ValidationError on any unrecognized key,
    # catching misconfigured policy name mappings immediately.
    payload_data.update(compliance)

    return DrataDevicePayload.model_validate(payload_data)
